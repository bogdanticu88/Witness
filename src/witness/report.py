"""Triage reports rendered from stored run results.

A report is built only from what the store holds for one run: the run record
and its metadata, findings, assessments, priorities and correlation groups.
Nothing is re-analyzed. Two renderings are produced from the same document:
``report.json`` (``witness.report/1``) and ``report.md``. Every string that
came from a scanner report or the repository is escaped in Markdown.

Reports go to a directory and are never overwritten: if a report file is
already there, nothing is written.
"""

from __future__ import annotations

import collections
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from witness.errors import UsageError
from witness.model.assessment import (
    Assessment,
    AssessmentStatus,
    FindingGroup,
    GroupRelation,
    Priority,
    PriorityLevel,
)
from witness.model.finding import Finding
from witness.security.escape import md_inline
from witness.store import RunRecord, Store

REPORT_SCHEMA = "witness.report/1"
FORMATS = ("json", "md")

_STATUS_ORDER = {
    AssessmentStatus.SUPPORTED: 0,
    AssessmentStatus.INCONCLUSIVE: 1,
    AssessmentStatus.STALE: 2,
    AssessmentStatus.NOT_ASSESSED: 3,
    AssessmentStatus.LIKELY_FALSE_POSITIVE: 4,
}
_RELATION_LABEL = {
    GroupRelation.DUPLICATE: "duplicate",
    GroupRelation.RELATED: "related",
    GroupRelation.INDEPENDENT: "independent",
    GroupRelation.POSSIBLE_CHAIN: "possible chain (not proven)",
}


def build_report(
    store: Store, run_id: str, *, generated_at: datetime | None = None
) -> dict[str, Any]:
    run = store.get_run(run_id)
    findings = store.list_findings(run_id)
    assessments = {a.finding_id: a for a in store.list_assessments(run_id)}
    priorities = {p.finding_id: p for p in store.list_priorities(run_id)}
    groups = store.list_groups(run_id)
    meta = run.metadata

    order = {f.id: n for n, f in enumerate(findings)}

    def rank(finding: Finding) -> tuple[int, int, int]:
        priority = priorities.get(finding.id)
        assessment = assessments.get(finding.id)
        return (
            int(priority.level.value[1]) if priority else 0,
            _STATUS_ORDER[assessment.status] if assessment else -1,
            order[finding.id],
        )

    entries = []
    for finding in sorted(findings, key=rank):
        assessment = assessments.get(finding.id)
        priority = priorities.get(finding.id)
        entries.append(
            {
                "finding": finding.model_dump(mode="json", by_alias=True, exclude={"original"}),
                "assessment": assessment.model_dump(mode="json") if assessment else None,
                "priority": priority.model_dump(mode="json") if priority else None,
                "conditional": _conditional(assessment),
            }
        )
    summary = _summary(run, findings, assessments, priorities)
    intelligence = meta.get("intelligence") or {}
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "run": {
            "run_id": run.run_id,
            "mode": run.mode,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "incomplete_reasons": list(run.incomplete_reasons),
        },
        "snapshot": meta.get("snapshot") or {"root": run.repo_root, "revision": None},
        "helper": meta.get("helper"),
        "analysis_version": meta.get("analysis_version")
        or _versions([a for a in assessments.values()]),
        "profile": meta.get("profile", run.profile),
        "inputs": meta.get("reports", []),
        "intelligence": {
            "recorded": bool(intelligence),
            "as_of": intelligence.get("as_of"),
            "root": intelligence.get("root"),
            "sources": intelligence.get("sources", []),
            "synthetic": any(s["source"]["synthetic"] for s in intelligence.get("sources", [])),
            "config": intelligence.get("config"),
            "rules_version": intelligence.get("rules_version"),
        },
        "summary": summary,
        "findings": entries,
        "groups": [_group(g) for g in groups],
        "warnings": meta.get("warnings", []),
    }


def write_report(
    store: Store,
    run_id: str,
    directory: Path,
    formats: Sequence[str] = FORMATS,
    *,
    generated_at: datetime | None = None,
) -> list[Path]:
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown or not formats:
        raise UsageError(f"unknown report format {', '.join(unknown) or '(none)'}; use json, md")
    targets = [directory / f"report.{fmt}" for fmt in dict.fromkeys(formats)]
    existing = [t for t in targets if t.exists() or t.is_symlink()]
    if existing:
        raise UsageError(
            f"refusing to overwrite {', '.join(str(t) for t in existing)}",
            hint="reports are never overwritten; pass --output with a new directory",
        )
    document = build_report(store, run_id, generated_at=generated_at)
    rendered = {
        "json": json.dumps(document, indent=2, sort_keys=False) + "\n",
        "md": render_markdown(document),
    }
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for target in targets:
        # "x" fails if the file appeared since the check above.
        try:
            with target.open("x", encoding="utf-8") as handle:
                handle.write(rendered[target.suffix[1:]])
        except FileExistsError:
            raise UsageError(
                f"refusing to overwrite {target}", hint="pass --output with a new directory"
            ) from None
        written.append(target)
    return written


# -- document parts ------------------------------------------------------------


def _conditional(assessment: Assessment | None) -> list[str]:
    if assessment is None or assessment.status is not AssessmentStatus.LIKELY_FALSE_POSITIVE:
        return []
    return list(assessment.assumptions)


def _versions(assessments: list[Assessment]) -> str | None:
    versions = sorted({a.analysis_version for a in assessments})
    return ", ".join(versions) or None


def _group(group: FindingGroup) -> dict[str, Any]:
    data = group.model_dump(mode="json")
    data["label"] = _RELATION_LABEL[group.relation]
    data["proven"] = group.relation is GroupRelation.DUPLICATE
    return data


def _summary(
    run: RunRecord,
    findings: list[Finding],
    assessments: dict[str, Assessment],
    priorities: dict[str, Priority],
) -> dict[str, Any]:
    by_status = collections.Counter(a.status.value for a in assessments.values())
    by_priority = collections.Counter(p.level.value for p in priorities.values())
    unfinished = sum(1 for a in assessments.values() if not a.complete)
    missing = sum(1 for f in findings if f.id not in assessments)
    complete = run.status == "completed" and unfinished == 0 and missing == 0
    if run.status == "running":
        analysis = "the run did not finish; results are partial"
    elif complete:
        analysis = "analysis completed: every imported finding has a finished assessment"
    else:
        analysis = (
            f"analysis {run.status}: {unfinished} assessment(s) cut short and {missing} "
            "finding(s) without an assessment; those results are partial"
        )
    supported = by_status.get("supported", 0)
    scope = (
        "Witness checks only the findings the scanners reported. A finished analysis is not a "
        "finding that the code has no vulnerabilities: "
        f"{by_status.get('inconclusive', 0)} finding(s) are inconclusive, "
        f"{by_status.get('not_assessed', 0)} were not assessed, and anything no scanner "
        "reported was never looked at."
    )
    outcome = (
        f"{supported} finding(s) are supported by evidence in the code."
        if supported
        else "No finding was supported by evidence in the code. That does not mean there are "
        "no vulnerabilities."
    )
    return {
        "run_status": run.status,
        "analysis_complete": complete,
        "analysis": analysis,
        "statement": f"{outcome} {scope}",
        "findings": len(findings),
        "assessments": {s.value: by_status.get(s.value, 0) for s in AssessmentStatus},
        "priorities": {p.value: by_priority.get(p.value, 0) for p in PriorityLevel},
        "unfinished_assessments": unfinished,
        "missing_assessments": missing,
        "missing_priorities": sum(1 for f in findings if f.id not in priorities),
    }


# -- Markdown ------------------------------------------------------------------


def _e(value: object, limit: int = 500) -> str:
    return md_inline("" if value is None else str(value), limit=limit)


def render_markdown(doc: dict[str, Any]) -> str:
    lines: list[str] = []
    run = doc["run"]
    summary = doc["summary"]
    snapshot = doc["snapshot"] or {}
    helper = doc["helper"] or {}
    add = lines.append

    add("# Witness triage report")
    add("")
    add(f"Run {_e(run['run_id'])}, generated {_e(doc['generated_at'])}.")
    add("")
    add("## Status")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Run status | **{_e(run['status'])}** |")
    add(f"| Analysis | {_e(summary['analysis'])} |")
    revision = snapshot.get("revision")
    revision_text = (
        f"{revision} ({snapshot.get('revision_source') or 'unknown source'})"
        if revision
        else "unknown"
    )
    add(f"| Snapshot | {_e(snapshot.get('root'))}, revision {_e(revision_text)} |")
    add(f"| Analysis version | {_e(doc['analysis_version'] or 'not recorded')} |")
    if helper:
        add(
            f"| Semantic helper | {_e(helper.get('helper_version'))}, protocol "
            f"{_e(helper.get('protocol'))}, Roslyn {_e(helper.get('roslyn_version'))} |"
        )
    else:
        add("| Semantic helper | not recorded |")
    add(f"| Model | none (profile {_e(doc['profile'])}) |")
    add(f"| Started | {_e(run['started_at'])} |")
    add(f"| Finished | {_e(run['finished_at'] or 'not finished')} |")
    add("")
    for reason in run["incomplete_reasons"]:
        add(f"- Incomplete: {_e(reason)}")
    if run["incomplete_reasons"]:
        add("")
    add(f"**What this shows.** {_e(summary['statement'], limit=2000)}")
    add("")

    add("## Summary")
    add("")
    add("| Assessment | Count |")
    add("|---|---|")
    for status, count in summary["assessments"].items():
        add(f"| {status} | {count} |")
    add("")
    add("| Priority | Count |")
    add("|---|---|")
    for level, count in summary["priorities"].items():
        add(f"| {level} | {count} |")
    add("")
    add(
        "Priority says what to look at first. It is computed after the assessment and never "
        "changes it."
    )
    add("")

    _intel_section(doc["intelligence"], add)
    _inputs_section(doc["inputs"], add)
    _findings_section(doc["findings"], add)
    _groups_section(doc["groups"], doc["findings"], add)

    if doc["warnings"]:
        add("## Warnings")
        add("")
        for warning in doc["warnings"]:
            add(f"- {_e(warning)}")
        add("")
    return "\n".join(lines).rstrip() + "\n"


def _intel_section(intel: dict[str, Any], add: Any) -> None:
    add("## Intelligence")
    add("")
    if not intel["recorded"]:
        add("Intelligence settings were not recorded for this run.")
        add("")
        return
    if intel["synthetic"]:
        add(
            "> **Synthetic intelligence.** At least one source below is marked synthetic: its "
            "values were made up for testing or demonstration and say nothing about the real "
            "vulnerabilities. Priorities that use it are not real priorities."
        )
        add("")
    if not intel["sources"]:
        add(
            "No intelligence snapshot was given. CVSS, KEV and EPSS are unknown for every "
            "dependency finding, and each one lists them as unknown factors."
        )
    else:
        add(f"Freshness is judged as of {_e(intel['as_of'])}.")
        add("")
        add("| Kind | File | Feed date | Retrieved | Freshness | Coverage | Records | Origin |")
        add("|---|---|---|---|---|---|---|---|")
        for status in intel["sources"]:
            source = status["source"]
            synthetic = " **(synthetic)**" if source["synthetic"] else ""
            freshness = (
                f"{status['freshness']} ({status['age_days']} days, limit {status['max_age_days']})"
            )
            add(
                f"| {_e(source['kind'])}{synthetic} | {_e(source['path'])} | "
                f"{_e(source['data_as_of'])} | {_e(source['retrieved_at'])} | {_e(freshness)} | "
                f"{_e(source['coverage'])} | {source['records']} | {_e(source['origin'])} |"
            )
        notes = [s["source"] for s in intel["sources"] if s["source"].get("note")]
        if notes:
            add("")
            for source in notes:
                add(f"- {_e(source['path'])}: {_e(source['note'])}")
    add("")
    config = intel["config"] or {}
    rules = config.get("priority", {})
    ages = config.get("freshness", {})
    lower = "yes" if rules.get("lower_likely_false_positive") else "no"
    add(
        f"Rules {_e(intel['rules_version'])}: EPSS threshold {_e(rules.get('epss_threshold'))}, "
        f"lower likely false positives {lower}, "
        "freshness limits " + ", ".join(f"{_e(k)} {_e(v)} days" for k, v in ages.items()) + "."
    )
    add("")


def _inputs_section(inputs: list[dict[str, Any]], add: Any) -> None:
    add("## Scanner reports")
    add("")
    if not inputs:
        add("Not recorded for this run.")
        add("")
        return
    add("| Report | Tool | Format | Findings | sha256 |")
    add("|---|---|---|---|---|")
    for item in inputs:
        tool = f"{item.get('tool') or '?'} {item.get('tool_version') or ''}".strip()
        add(
            f"| {_e(item['path'])} | {_e(tool)} | {_e(item['format'])} | {item['findings']} | "
            f"{_e((item.get('sha256') or '')[:16])} |"
        )
    add("")


def _where(finding: dict[str, Any]) -> str:
    location = finding.get("location")
    if location:
        line = f":{location['start_line']}" if location.get("start_line") else ""
        return f"{location['path']}{line}"
    package = finding.get("package")
    if package:
        return f"{package['name']} {package.get('version') or '?'}"
    runtime = finding.get("runtime")
    if runtime:
        return f"{runtime.get('method') or '?'} {runtime.get('endpoint') or '?'}"
    return "no location"


def _findings_section(entries: list[dict[str, Any]], add: Any) -> None:
    add("## Findings")
    add("")
    if not entries:
        add("The scanner reports held no findings.")
        add("")
        return
    add("| # | Priority | Assessment | Kind | Scanner | Where | Title |")
    add("|---|---|---|---|---|---|---|")
    for n, entry in enumerate(entries, 1):
        finding = entry["finding"]
        add(
            f"| {n} | {_level(entry)} | {_status(entry)} | {_e(finding['kind'])} | "
            f"{_e(finding['scanner']['name'])} | {_e(_where(finding), 120)} | "
            f"{_e(finding['title'], 120)} |"
        )
    add("")
    for n, entry in enumerate(entries, 1):
        _finding_detail(n, entry, add)


def _level(entry: dict[str, Any]) -> str:
    return entry["priority"]["level"] if entry["priority"] else "none recorded"


def _status(entry: dict[str, Any]) -> str:
    assessment = entry["assessment"]
    if assessment is None:
        return "no assessment"
    text = str(assessment["status"])
    if entry["conditional"]:
        text += " (conditional)"
    if not assessment["complete"]:
        text += " (incomplete)"
    return text


def _finding_detail(n: int, entry: dict[str, Any], add: Any) -> None:
    finding = entry["finding"]
    assessment = entry["assessment"]
    priority = entry["priority"]
    add(f"### {n}. {_level(entry)}, {_status(entry)}: {_e(finding['title'], 200)}")
    add("")
    scanner = finding["scanner"]
    rule = f", rule {_e(scanner.get('rule_id'))}" if scanner.get("rule_id") else ""
    add(f"- Finding {_e(finding['id'])}: {_e(finding['kind'])}, {_e(finding['category'])}")
    add(
        f"- Scanner: {_e(scanner['name'])} {_e(scanner.get('version') or '')}{rule}, severity "
        f"{_e(finding['severity'])} (reported as {_e(finding.get('severity_original') or '?')})"
    )
    add(f"- Where: {_e(_where(finding), 300)}")
    if finding.get("vulnerability_ids"):
        add(f"- Identifiers: {_e(', '.join(finding['vulnerability_ids']))}")
    provenance = finding["provenance"]
    add(f"- Scanner record: {_e(provenance['report_path'])} at {_e(provenance['record_pointer'])}")
    add("")

    if assessment is None:
        add("**Assessment:** none recorded.")
        add("")
    else:
        complete = "complete" if assessment["complete"] else "incomplete, results partial"
        add(
            f"**Assessment: {_e(assessment['status'])}** ({_e(assessment['basis'])}, {complete}). "
            f"Reason: {_e(', '.join(assessment['reason_codes']) or 'none given')}."
        )
        add("")
        add(_e(assessment["explanation"], 2000))
        add("")
        if entry["conditional"]:
            add(
                "**Conditional.** This dismissal holds only if every assumption below holds. "
                "Check them before acting on it:"
            )
            add("")
            for assumption in entry["conditional"]:
                add(f"- {_e(assumption, 1000)}")
            add("")
        elif assessment["assumptions"]:
            add("Assumptions:")
            add("")
            for assumption in assessment["assumptions"]:
                add(f"- {_e(assumption, 1000)}")
            add("")
        if assessment["unresolved"]:
            add("Unresolved context:")
            add("")
            for item in assessment["unresolved"]:
                add(f"- {_e(item, 1000)}")
            add("")
        _evidence(assessment, add)

    if priority is None:
        add("**Priority:** none recorded.")
        add("")
        return
    add(f"**Priority: {_e(priority['level'])}** ({_e(priority['rules_version'])}).")
    add("")
    for rule_entry in priority["rules"]:
        add(
            f"- Rule {_e(rule_entry['rule'])} gave {_e(rule_entry['level'])} from "
            f"{_e(', '.join(rule_entry['inputs']))}: {_e(rule_entry['detail'], 1000)}"
        )
    add("")
    add("Inputs:")
    add("")
    for factor in priority["factors"]:
        extras = []
        if factor.get("as_of"):
            extras.append(f"as of {factor['as_of']}")
        if factor.get("freshness"):
            extras.append(factor["freshness"])
        if factor.get("synthetic"):
            extras.append("SYNTHETIC")
        if not factor.get("used", True):
            extras.append("recorded, not used")
        suffix = f" ({_e(', '.join(extras))})" if extras else ""
        add(
            f"- {_e(factor['name'])}: {_e(factor['value'], 500)} "
            f"from {_e(factor['source'])}{suffix}"
        )
    add("")
    if priority["unknown"]:
        add("Unknown factors (none of them lowered the level):")
        add("")
        for item in priority["unknown"]:
            add(f"- {_e(item, 1000)}")
        add("")
    if priority["conflicts"]:
        add("Conflicting inputs:")
        add("")
        for item in priority["conflicts"]:
            add(f"- {_e(item, 1000)}")
        add("")


def _evidence(assessment: dict[str, Any], add: Any) -> None:
    facts = assessment["facts"]
    checks = assessment["checks"]
    if not facts and not checks:
        return
    add("Evidence:")
    add("")
    for fact in facts:
        kind = "claim" if fact["source"] in ("scanner", "model") else "fact"
        refs = _refs(fact["refs"])
        add(
            f"- {kind} ({_e(fact['source'])}, {_e(fact['kind'])}): "
            f"{_e(fact['statement'], 1000)}{refs}"
        )
    for check in checks:
        refs = _refs(check["refs"])
        add(
            f"- check {_e(check['name'])}: {_e(check['outcome'])}, "
            f"{_e(check['detail'], 1000)}{refs}"
        )
    add("")


def _refs(refs: list[dict[str, Any]]) -> str:
    if not refs:
        return ""
    shown = ", ".join(
        f"{r['path']}:{r['start_line']}"
        + (f"-{r['end_line']}" if r["end_line"] != r["start_line"] else "")
        for r in refs[:8]
    )
    more = f" and {len(refs) - 8} more" if len(refs) > 8 else ""
    return f" (at {_e(shown)}{more})"


def _groups_section(groups: list[dict[str, Any]], entries: list[dict[str, Any]], add: Any) -> None:
    add("## Correlation")
    add("")
    if not groups:
        add("No relationships between findings were found.")
        add("")
        return
    add(
        "Possible chains are a heuristic: one finding's reported flow ends where another's "
        "starts. They are not evidence that the chain can be exploited."
    )
    add("")
    number = {e["finding"]["id"]: n for n, e in enumerate(entries, 1)}
    for group in groups:
        members = ", ".join(f"#{number[f]}" if f in number else _e(f) for f in group["finding_ids"])
        add(
            f"- {_e(group['label'])} ({_e(group['basis'])}): {members}. "
            f"{_e(group['explanation'], 1000)}"
        )
    add("")
