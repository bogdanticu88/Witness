"""CodeQL SARIF 2.1.0 adapter, preserving every CodeQL run."""

from __future__ import annotations

import re
from typing import Any

from witness.adapters.base import (
    ImportContext,
    ImportResult,
    finding_id,
    first_text,
    instance_key,
)
from witness.errors import InputError
from witness.model.finding import (
    Finding,
    FindingKind,
    FlowStep,
    Provenance,
    ScannerIdentity,
    Severity,
    SourceLocation,
    VulnClass,
)
from witness.security.paths import normalize_reported_path

_CWE_TAG = re.compile(r"cwe-(\d+)$", re.IGNORECASE)

_RULE_CATEGORY = {
    "cs/sql-injection": VulnClass.SQL_INJECTION,
    "cs/path-injection": VulnClass.PATH_TRAVERSAL,
    "cs/web/unvalidated-url-redirection": VulnClass.OPEN_REDIRECT,
}

_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.UNKNOWN,
}


class CodeQLAdapter:
    format = "codeql"

    def detect(self, document: object) -> bool:
        # Only claim SARIF whose driver name identifies CodeQL. Any SARIF
        # 2.1.0 file (for example Mantis' SARIF export) also has
        # runs[].tool.driver, so the structure alone is not a fingerprint.
        if not isinstance(document, dict):
            return False
        runs = document.get("runs")
        if not isinstance(runs, list):
            return False
        for run in runs:
            if not isinstance(run, dict):
                continue
            tool = run.get("tool")
            if not isinstance(tool, dict):
                continue
            driver = tool.get("driver")
            if not isinstance(driver, dict):
                continue
            name = first_text(driver.get("name"))
            if name and name.strip().lower().startswith("codeql"):
                return True
        return False

    def parse(self, document: object, context: ImportContext) -> ImportResult:
        doc = _require_dict(document)
        runs = doc.get("runs")
        if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
            raise InputError("codeql: report must contain at least one run")
        if doc.get("version", "2.1.0") != "2.1.0":
            raise InputError("codeql: expected SARIF version 2.1.0")
        findings: list[Finding] = []
        versions: set[str | None] = set()
        for run_index, run in enumerate(runs):
            if not isinstance(run, dict):
                raise InputError(f"codeql: runs[{run_index}] must be an object")
            tool = run.get("tool")
            driver = tool.get("driver") if isinstance(tool, dict) else None
            if not isinstance(driver, dict):
                raise InputError(f"codeql: runs[{run_index}].tool.driver must be an object")
            driver_name = first_text(driver.get("name"))
            if not driver_name or not driver_name.strip().lower().startswith("codeql"):
                raise InputError(f"codeql: runs[{run_index}] is not a CodeQL run")
            driver_version = first_text(driver.get("semanticVersion"), driver.get("version"))
            versions.add(driver_version)
            rules = driver.get("rules")
            rule_meta = (
                {r["id"]: r for r in rules if isinstance(r, dict) and isinstance(r.get("id"), str)}
                if isinstance(rules, list)
                else {}
            )
            revision, revision_source = _revision(run, context)
            results = run.get("results")
            if not isinstance(results, list):
                raise InputError(f"codeql: runs[{run_index}].results must be a list")
            for i, result in enumerate(results):
                if not isinstance(result, dict):
                    raise InputError(f"codeql: runs[{run_index}].results[{i}] must be an object")
                findings.append(
                    _finding(
                        result,
                        i,
                        rule_meta,
                        driver_name,
                        driver_version,
                        revision,
                        revision_source,
                        context,
                        run_index,
                    ),
                )
        return ImportResult(
            format=self.format,
            tool="CodeQL",
            tool_version=next(iter(versions)) if len(versions) == 1 else None,
            findings=findings,
        )


def _finding(
    result: dict[str, Any],
    index: int,
    rule_meta: dict[str, dict[str, Any]],
    driver_name: str,
    driver_version: str | None,
    revision: str | None,
    revision_source: str,
    context: ImportContext,
    run_index: int,
) -> Finding:
    rule_id = first_text(result.get("ruleId"))
    if not rule_id:
        raise InputError(f"codeql: results[{index}] has no ruleId")
    meta = rule_meta.get(rule_id, {})
    props = meta.get("properties") if isinstance(meta.get("properties"), dict) else {}

    message_text = None
    message = result.get("message")
    if isinstance(message, dict):
        message_text = first_text(message.get("text"))

    level = _level(result, meta)
    category = _RULE_CATEGORY.get(rule_id, VulnClass.UNCLASSIFIED)
    location = _location(result, index, context)
    short_description = meta.get("shortDescription")
    short_text = short_description.get("text") if isinstance(short_description, dict) else None

    return Finding(
        id=finding_id(context, f"/runs/{run_index}/results/{index}"),
        instance_key=instance_key("source", category, location.path, location.start_line, rule_id),
        kind=FindingKind.SOURCE,
        category=category,
        category_basis=rule_id,
        scanner=ScannerIdentity(
            name=driver_name,
            version=driver_version,
            rule_id=rule_id,
            rule_name=first_text(
                meta.get("name"),
                props.get("name") if isinstance(props, dict) else None,
            ),
        ),
        severity=_LEVEL_SEVERITY.get(level, Severity.UNKNOWN),
        severity_original=level,
        title=first_text(short_text, message_text, rule_id) or rule_id,
        message=message_text,
        cwe=_cwe_tags(props.get("tags")) if isinstance(props, dict) else (),
        location=location,
        code_flows=_code_flows(result, context),
        revision=revision,
        revision_source=revision_source,
        provenance=Provenance(
            report_path=str(context.report_path),
            report_sha256=context.report_sha256,
            report_format="codeql",
            record_pointer=f"/runs/{run_index}/results/{index}",
            imported_at=context.imported_at,
        ),
        original=result,
    )


def _level(result: dict[str, Any], meta: dict[str, Any]) -> str:
    level = first_text(result.get("level"))
    if level:
        return level.lower()
    default = meta.get("defaultConfiguration")
    if isinstance(default, dict):
        configured = first_text(default.get("level"))
        if configured:
            return configured.lower()
    return "warning"  # SARIF 2.1.0 §3.27.10 default.


def _location(result: dict[str, Any], index: int, context: ImportContext) -> SourceLocation:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        raise InputError(f"codeql: results[{index}] has no primary location")
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        raise InputError(f"codeql: results[{index}] has no physicalLocation")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        raise InputError(f"codeql: results[{index}] has no artifactLocation")
    uri = first_text(artifact.get("uri"))
    if not uri:
        raise InputError(f"codeql: results[{index}] has an empty artifactLocation.uri")
    region_raw = physical.get("region")
    region = region_raw if isinstance(region_raw, dict) else {}
    return SourceLocation(
        path=normalize_reported_path(uri, strip_prefixes=context.source_prefixes),
        reported_uri=uri,
        start_line=_int(region.get("startLine")),
        end_line=_int(region.get("endLine")),
        start_column=_int(region.get("startColumn")),
        end_column=_int(region.get("endColumn")),
    )


def _code_flows(result: dict[str, Any], context: ImportContext) -> tuple[tuple[FlowStep, ...], ...]:
    flows = result.get("codeFlows")
    if not isinstance(flows, list):
        return ()
    steps: list[tuple[FlowStep, ...]] = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        thread_flows = flow.get("threadFlows")
        if not isinstance(thread_flows, list):
            continue
        for thread in thread_flows:
            if not isinstance(thread, dict):
                continue
            locations = thread.get("locations")
            if not isinstance(locations, list):
                continue
            steps.append(
                tuple(_flow_step(loc, context) for loc in locations if isinstance(loc, dict))
            )
    return tuple(steps)


def _flow_step(location: dict[str, Any], context: ImportContext) -> FlowStep:
    inner_raw = location.get("location")
    inner = inner_raw if isinstance(inner_raw, dict) else location
    message_raw = inner.get("message")
    message = message_raw if isinstance(message_raw, dict) else None
    text = first_text(message.get("text")) if message is not None else None
    step_location = None
    physical_raw = inner.get("physicalLocation")
    physical = physical_raw if isinstance(physical_raw, dict) else None
    if physical is not None:
        artifact_raw = physical.get("artifactLocation")
        artifact = artifact_raw if isinstance(artifact_raw, dict) else None
        uri = first_text(artifact.get("uri")) if artifact is not None else None
        if uri:
            region_raw = physical.get("region")
            region = region_raw if isinstance(region_raw, dict) else {}
            step_location = SourceLocation(
                path=normalize_reported_path(uri, strip_prefixes=context.source_prefixes),
                reported_uri=uri,
                start_line=_int(region.get("startLine")),
                end_line=_int(region.get("endLine")),
                start_column=_int(region.get("startColumn")),
                end_column=_int(region.get("endColumn")),
            )
    return FlowStep(location=step_location, message=text)


def _cwe_tags(tags: object) -> tuple[str, ...]:
    if not isinstance(tags, list):
        return ()
    cwes = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _CWE_TAG.search(tag.strip().lower())
        if match:
            cwes.append(f"CWE-{match.group(1)}")
    return tuple(cwes)


def _revision(run: dict[str, Any], context: ImportContext) -> tuple[str | None, str]:
    provenance = run.get("versionControlProvenance")
    if isinstance(provenance, list):
        for entry in provenance:
            if isinstance(entry, dict):
                revision = first_text(entry.get("revision"))
                if revision:
                    return revision, "report"
    if context.operator_revision:
        return context.operator_revision, "operator"
    return None, "none"


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _require_dict(document: object) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise InputError("codeql: report must be a JSON object")
    return document
