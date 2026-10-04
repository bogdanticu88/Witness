"""Deterministic triage run: import, locate, analyze, store.

Every imported finding gets exactly one assessment, also when the run stops
early. Findings not reached because the helper failed or the run was
interrupted are recorded as incomplete ``inconclusive`` assessments, never as
clean results and never as ``stale``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from witness.adapters.loader import load_report
from witness.correlate import EndpointMapping, correlate
from witness.errors import (
    ExitCode,
    PathRejected,
    SemanticError,
    SemanticRequestError,
    SemanticTimeout,
    UsageError,
)
from witness.intel import IntelSnapshot
from witness.model.assessment import (
    Assessment,
    AssessmentBasis,
    AssessmentStatus,
    CheckOutcome,
    CheckResult,
    CodeRef,
    Fact,
    FactSource,
    FindingGroup,
    Priority,
)
from witness.model.finding import (
    SUPPORTED_SOURCE_CLASSES,
    Finding,
    FindingKind,
)
from witness.priority import RULES_VERSION, IntelContext, compute_priority
from witness.semantic import protocol as p
from witness.semantic.client import SemanticClient, locate_helper
from witness.store import Store
from witness.triage.snapshot import Snapshot, same_revision
from witness.triage.verdict import Investigator, SiteVerdict

ANALYSIS_VERSION = "witness-triage/1"
PROFILE = "none"

RunStatus = Literal["completed", "incomplete", "failed", "interrupted"]


class Helper:
    """Typed, cached queries over a running helper."""

    def __init__(self, client: SemanticClient) -> None:
        self.client = client
        self._callers: dict[str, p.Callers] = {}
        self._registrations: list[p.DiRegistration] | None = None
        self._endpoints: list[p.Endpoint] | None = None
        self._pipeline: list[p.PipelineLayer] | None = None

    @property
    def hello(self) -> p.Hello:
        return self.client.hello

    def load(self, root: Path, package_directory: Path | None) -> p.LoadResult:
        params: dict[str, Any] = {"root": str(root)}
        if package_directory is not None:
            params["package_directory"] = str(package_directory)
        return self.client.call("load", params, p.LoadResult)

    def sites_at(self, path: str, start_line: int, end_line: int, vuln_class: str) -> p.SitesAt:
        params = {
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "classes": [vuln_class],
        }
        return self.client.call("sites_at", params, p.SitesAt)

    def analyze_site(self, site_id: str) -> p.SiteAnalysis:
        return self.client.call("analyze_site", {"site_id": site_id}, p.SiteAnalysis)

    def callers(self, method: str) -> p.Callers:
        if method not in self._callers:
            self._callers[method] = self.client.call("callers", {"symbol": method}, p.Callers)
        return self._callers[method]

    def analyze_argument(
        self, path: str, line: int, column: int, ordinal: int
    ) -> p.ArgumentAnalysis:
        params = {"path": path, "line": line, "column": column, "parameter_ordinal": ordinal}
        return self.client.call("analyze_argument", params, p.ArgumentAnalysis)

    def di_registrations(self) -> list[p.DiRegistration]:
        if self._registrations is None:
            self._registrations = self.client.call_list("di_registrations", {}, p.DiRegistration)
        return self._registrations

    def endpoints(self) -> list[p.Endpoint]:
        if self._endpoints is None:
            self._endpoints = self.client.call_list("endpoints", {}, p.Endpoint)
        return self._endpoints

    def request_pipeline(self) -> list[p.PipelineLayer]:
        if self._pipeline is None:
            self._pipeline = self.client.call_list("request_pipeline", {}, p.PipelineLayer)
        return self._pipeline

    def close(self) -> None:
        self.client.close()


@dataclass
class TriageOutcome:
    run_id: str | None
    status: RunStatus
    snapshot: Snapshot
    helper: p.Hello
    findings: list[Finding]
    assessments: list[Assessment]
    groups: list[FindingGroup]
    incomplete_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    priorities: list[Priority] = field(default_factory=list)

    @property
    def exit_code(self) -> ExitCode:
        return {
            "completed": ExitCode.OK,
            "incomplete": ExitCode.INCOMPLETE,
            "failed": ExitCode.EXECUTION_ERROR,
            "interrupted": ExitCode.INTERRUPTED,
        }[self.status]


def start_helper(helper_path: str | None = None, *, timeout_s: float = 300.0) -> Helper:
    return Helper(SemanticClient(locate_helper(helper_path), timeout_s=timeout_s))


def run_triage(
    reports: Sequence[Path],
    repo: Path,
    *,
    store: Store | None = None,
    helper_factory: Callable[[], Helper] | None = None,
    snapshot_revision: str | None = None,
    report_revision: str | None = None,
    source_prefixes: Sequence[str] = (),
    package_directory: Path | None = None,
    mappings: Sequence[EndpointMapping] = (),
    max_calls_per_finding: int = 200,
    intel: IntelContext | None = None,
) -> TriageOutcome:
    """Run deterministic triage.

    Usage problems, unreadable reports and a missing or incompatible helper
    raise before anything is stored. Later failures are recorded in the run.
    """
    snapshot = Snapshot.open(repo, revision=snapshot_revision)
    if not reports:
        raise UsageError("no reports given", hint="pass at least one --report")
    for report in reports:
        if not report.is_file():
            raise UsageError(f"report not found: {report}")
    findings: list[Finding] = []
    warnings: list[str] = []
    inputs: list[dict[str, Any]] = []
    seen_reports: dict[str, Path] = {}
    for report in reports:
        result = load_report(
            report, source_prefixes=source_prefixes, operator_revision=report_revision
        )
        digest = result.findings[0].provenance.report_sha256 if result.findings else None
        if digest is not None and digest in seen_reports:
            raise UsageError(f"report {report} has the same content as {seen_reports[digest]}")
        if digest is not None:
            seen_reports[digest] = report
        inputs.append(
            {
                "path": str(report),
                "sha256": digest,
                "format": result.format,
                "tool": result.tool,
                "tool_version": result.tool_version,
                "findings": len(result.findings),
            }
        )
        findings.extend(result.findings)
        warnings.extend(f"{report}: {w}" for w in result.warnings)

    helper = (helper_factory or start_helper)()
    try:
        load = helper.load(snapshot.root, package_directory)
    except SemanticError:
        helper.close()
        raise
    for project in load.projects:
        if project.unresolved_symbol_errors:
            warnings.append(
                f"project {project.name}: {project.unresolved_symbol_errors} unresolved symbol "
                "errors (usually unrestored packages); sinks and calls that depend on them stay "
                "unresolved"
            )
    run = TriageRun(
        snapshot, helper, findings, mappings, max_calls_per_finding, intel=intel, inputs=inputs
    )
    try:
        return run.execute(store, warnings)
    finally:
        helper.close()


class TriageRun:
    def __init__(
        self,
        snapshot: Snapshot,
        helper: Helper,
        findings: list[Finding],
        mappings: Sequence[EndpointMapping],
        max_calls: int,
        *,
        intel: IntelContext | None = None,
        inputs: Sequence[dict[str, Any]] = (),
    ) -> None:
        self.snapshot = snapshot
        self.intel = intel or IntelContext(IntelSnapshot.empty(), datetime.now(UTC))
        self.inputs = list(inputs)
        self.helper = helper
        self.findings = findings
        self.mappings = mappings
        self.max_calls = max_calls
        self.producer = f"witness-semantic {helper.hello.helper_version} ({helper.hello.protocol})"
        self.analysis_version = f"{ANALYSIS_VERSION}+semantic-{helper.hello.helper_version}"
        self.helper_failure: str | None = None
        self.helper_timed_out = False
        self.incomplete: list[str] = []
        self.request_failures: list[str] = []

    def execute(self, store: Store | None, warnings: list[str]) -> TriageOutcome:
        run_id = None
        if store is not None:
            record = store.start_run("triage", self.snapshot.root, PROFILE, None, None)
            run_id = record.run_id
            store.set_run_metadata(run_id, self.metadata(warnings))
            store.save_findings(run_id, self.findings)

        def save(assessment: Assessment) -> None:
            if store is not None and run_id is not None:
                store.save_assessment(run_id, assessment)

        assessments: list[Assessment] = []
        status: RunStatus = "completed"
        groups: list[FindingGroup] = []
        try:
            for finding in self.findings:
                assessment = self.assess(finding)
                assessments.append(assessment)
                save(assessment)
            groups = correlate(self.findings, mappings=self.mappings)
            if store is not None and run_id is not None:
                store.save_groups(run_id, groups)
        except KeyboardInterrupt:
            status = "interrupted"
            self.incomplete.append("interrupted")
            done = {a.finding_id for a in assessments}
            for finding in self.findings:
                if finding.id not in done:
                    assessment = self._unfinished(finding, "interrupted", "the run was interrupted")
                    assessments.append(assessment)
                    save(assessment)

        # Priority reads the final assessments and never feeds back into them.
        by_finding = {a.finding_id: a for a in assessments}
        priorities = [
            compute_priority(finding, by_finding[finding.id], self.intel)
            for finding in self.findings
        ]
        if store is not None and run_id is not None:
            for priority in priorities:
                store.save_priority(run_id, priority)

        if status != "interrupted":
            if (self.helper_failure and not self.helper_timed_out) or self.request_failures:
                status = "failed"
            elif any(not a.complete for a in assessments):
                status = "incomplete"
        reasons = tuple(dict.fromkeys([*self.incomplete, *self.request_failures]))
        if store is not None and run_id is not None:
            store.set_run_status(run_id, status, incomplete_reasons=reasons, finished=True)
        return TriageOutcome(
            run_id=run_id,
            status=status,
            snapshot=self.snapshot,
            helper=self.helper.hello,
            findings=self.findings,
            assessments=assessments,
            groups=groups,
            incomplete_reasons=list(reasons),
            warnings=warnings,
            priorities=priorities,
        )

    def metadata(self, warnings: Sequence[str]) -> dict[str, Any]:
        intel = self.intel
        return {
            "snapshot": {
                "root": str(self.snapshot.root),
                "revision": self.snapshot.revision,
                "revision_source": self.snapshot.revision_source,
            },
            "helper": self.helper.hello.model_dump(mode="json"),
            "analysis_version": self.analysis_version,
            "profile": PROFILE,
            "reports": self.inputs,
            "warnings": list(warnings),
            "intelligence": {
                "root": str(intel.snapshot.root) if intel.snapshot.root else None,
                "as_of": intel.as_of.isoformat(),
                "sources": [
                    intel.status(s).model_dump(mode="json") for s in intel.snapshot.sources
                ],
                "config": intel.config.as_dict(),
                "rules_version": RULES_VERSION,
            },
        }

    # -- per finding ---------------------------------------------------------

    def assess(self, finding: Finding) -> Assessment:
        if finding.kind is FindingKind.RUNTIME:
            return self._runtime(finding)
        if finding.kind is FindingKind.DEPENDENCY:
            return self._dependency(finding)
        supported = finding.category in SUPPORTED_SOURCE_CLASSES
        if finding.kind is not FindingKind.SOURCE or not supported:
            return self._make(
                finding,
                AssessmentStatus.NOT_ASSESSED,
                ["class_not_supported"],
                f"{finding.kind.value} finding of class {finding.category.value} "
                f"(basis: {finding.category_basis}) is outside the supported analysis; "
                "it is kept and reported without a verdict",
            )
        return self._source(finding)

    def _source(self, finding: Finding) -> Assessment:
        claims = _scanner_claims(finding)
        stale = self._revision_check(finding)
        if stale is not None:
            return self._make(
                finding, AssessmentStatus.STALE, ["revision_mismatch"], stale, facts=claims
            )
        location = finding.location
        if location is None or location.start_line is None:
            what = "no location" if location is None else f"no line for {location.path}"
            return self._make(
                finding,
                AssessmentStatus.INCONCLUSIVE,
                ["no_location_reported"],
                f"the scanner reported {what}, so the finding cannot be checked against code",
                facts=claims,
            )
        try:
            path = self.snapshot.locate(location.path)
        except PathRejected as exc:
            return self._make(
                finding,
                AssessmentStatus.INCONCLUSIVE,
                ["location_rejected"],
                f"the reported location cannot be used: {exc.message}",
                facts=claims,
            )
        if path is None:
            return self._make(
                finding,
                AssessmentStatus.STALE,
                ["file_not_in_snapshot"],
                f"{location.path} does not exist in the snapshot at {self.snapshot.root}"
                f"{self._revision_note()}",
                facts=claims,
            )
        lines = self.snapshot.line_count(path)
        if location.start_line > lines:
            return self._make(
                finding,
                AssessmentStatus.STALE,
                ["line_not_in_snapshot"],
                f"{location.path} has {lines} lines in the snapshot; the finding points at line "
                f"{location.start_line}{self._revision_note()}",
                facts=claims,
            )
        if self.helper_failure is not None:
            return self._unfinished(finding, "helper_unavailable", self.helper_failure)

        end = max(location.end_line or location.start_line, location.start_line)
        investigator = Investigator(self.helper, max_calls=self.max_calls, producer=self.producer)
        try:
            verdict = investigator.assess(
                location.path,
                location.start_line,
                end,
                finding.category.value,
                start_column=location.start_column,
                end_column=location.end_column,
            )
        except SemanticRequestError as exc:
            if exc.code in ("unknown_document", "bad_position"):
                return self._make(
                    finding,
                    AssessmentStatus.INCONCLUSIVE,
                    ["not_in_workspace"],
                    f"{location.path} exists but the helper did not load it as part of a project "
                    f"({exc.message})",
                    facts=claims,
                )
            # The helper is alive but could not analyze this location: a helper
            # defect, reported as an execution error for the run.
            self.request_failures.append(f"helper request failed for {finding.id}: {exc.message}")
            return self._unfinished(finding, "helper_request_failed", exc.message)
        except SemanticTimeout as exc:
            self.helper_failure = exc.message
            self.helper_timed_out = True
            self.incomplete.append("semantic helper timeout")
            return self._unfinished(finding, "helper_timeout", exc.message)
        except SemanticError as exc:
            self.helper_failure = exc.message
            self.incomplete.append("semantic helper failed")
            return self._unfinished(finding, "helper_failed", exc.message)
        if not verdict.complete:
            self.incomplete.append(f"analysis budget exhausted for {finding.id}")
        return self._from_verdict(finding, verdict, claims)

    def _revision_check(self, finding: Finding) -> str | None:
        snap = self.snapshot.revision
        if not finding.revision or not snap:
            return None
        if same_revision(finding.revision, snap):
            return None
        return (
            f"the finding was produced against revision {finding.revision} "
            f"({finding.revision_source}), the snapshot is at {snap} "
            f"({self.snapshot.revision_source})"
        )

    def _revision_note(self) -> str:
        if self.snapshot.revision:
            return f" (revision {self.snapshot.revision})"
        return " (snapshot revision unknown)"

    def _revision_assumptions(self, finding: Finding) -> list[str]:
        if finding.revision and self.snapshot.revision:
            return []
        missing = (
            "the report declares no revision"
            if not finding.revision
            else ("the snapshot revision is unknown")
        )
        return [f"{missing}; the finding is assumed to describe this snapshot"]

    def _from_verdict(
        self, finding: Finding, verdict: SiteVerdict, claims: list[Fact]
    ) -> Assessment:
        return self._make(
            finding,
            verdict.status,
            verdict.reason_codes,
            verdict.explanation,
            facts=[*verdict.facts, *claims],
            checks=verdict.checks,
            unresolved=verdict.unresolved,
            assumptions=[*verdict.assumptions, *self._revision_assumptions(finding)],
            complete=verdict.complete,
        )

    def _runtime(self, finding: Finding) -> Assessment:
        facts: list[Fact] = []
        associations = finding.scanner_properties.get("exchange_associations")
        if isinstance(associations, list):
            exact = sum(1 for a in associations if a == "matching_endpoint")
            facts.append(
                Fact(
                    source=FactSource.SCANNER,
                    kind="exchange_associations",
                    statement=f"{exact} of {len(associations)} recorded exchanges match the "
                    "finding's endpoint and method exactly; the rest are unconfirmed context",
                    producer=finding.scanner.name,
                    data={"associations": associations},
                )
            )
        runtime = finding.runtime
        where = f"{runtime.method} {runtime.endpoint}" if runtime else "unknown endpoint"
        return self._make(
            finding,
            AssessmentStatus.NOT_ASSESSED,
            ["runtime_finding"],
            f"runtime finding for {where} is kept and correlated, but deterministic triage gives "
            "no code verdict for runtime findings; a matching HTTP exchange shows the endpoint "
            "was exercised, not that the vulnerability exists",
            facts=facts,
        )

    def _dependency(self, finding: Finding) -> Assessment:
        package = finding.package
        artifact = finding.artifact
        if package is None:
            return self._make(
                finding,
                AssessmentStatus.INCONCLUSIVE,
                ["no_package"],
                "dependency finding without package identity",
            )
        fact = Fact(
            source=FactSource.SCANNER,
            kind="dependency",
            statement=f"{package.name} {package.version or '?'} "
            f"({', '.join(finding.vulnerability_ids) or 'no id'}) reported in "
            f"{package.origin or 'unknown origin'}",
            producer=finding.scanner.name,
        )
        if artifact is not None and artifact.kind not in ("filesystem", "repository"):
            check = CheckResult(
                name="package_in_snapshot",
                outcome=CheckOutcome.NOT_APPLICABLE,
                detail=f"the finding is about {artifact.kind} {artifact.name}, whose contents "
                "are not part of the snapshot",
            )
        else:
            check = self._lock_file_check(package.name, package.version, package.origin)
            if check.outcome is CheckOutcome.FAILED:
                return self._make(
                    finding,
                    AssessmentStatus.STALE,
                    ["package_not_in_snapshot"],
                    check.detail,
                    facts=[fact],
                    checks=[check],
                )
        return self._make(
            finding,
            AssessmentStatus.INCONCLUSIVE,
            ["dependency_not_analyzed"],
            "the package is recorded but whether its vulnerable code is used is not analyzed; "
            "deterministic triage gives dependency findings no code verdict",
            facts=[fact],
            checks=[check],
        )

    def _lock_file_check(self, name: str, version: str | None, origin: str | None) -> CheckResult:
        if not origin or not origin.endswith("packages.lock.json") or not version:
            return CheckResult(
                name="package_in_snapshot",
                outcome=CheckOutcome.UNKNOWN,
                detail=f"origin {origin or 'unknown'} is not a NuGet lock file Witness reads",
            )
        try:
            path = self.snapshot.locate(origin)
        except PathRejected as exc:
            return CheckResult(
                name="package_in_snapshot", outcome=CheckOutcome.UNKNOWN, detail=exc.message
            )
        if path is None:
            return CheckResult(
                name="package_in_snapshot",
                outcome=CheckOutcome.FAILED,
                detail=f"{origin} does not exist in the snapshot{self._revision_note()}",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            frameworks = data["dependencies"]
            versions = {
                entry.get("resolved")
                for packages in frameworks.values()
                for package_name, entry in packages.items()
                if package_name.lower() == name.lower() and isinstance(entry, dict)
            }
        except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
            return CheckResult(
                name="package_in_snapshot",
                outcome=CheckOutcome.UNKNOWN,
                detail=f"cannot read {origin}: {exc}",
            )
        ref = (CodeRef(path=origin, start_line=1, end_line=1),)
        if version in versions:
            return CheckResult(
                name="package_in_snapshot",
                outcome=CheckOutcome.PASSED,
                detail=f"{origin} resolves {name} {version}",
                refs=ref,
            )
        found = ", ".join(sorted(v for v in versions if v)) or "nothing"
        return CheckResult(
            name="package_in_snapshot",
            outcome=CheckOutcome.FAILED,
            detail=f"{origin} resolves {name} to {found}, not {version}{self._revision_note()}",
            refs=ref,
        )

    # -- assessment records --------------------------------------------------

    def _unfinished(self, finding: Finding, code: str, why: str) -> Assessment:
        return self._make(
            finding,
            AssessmentStatus.INCONCLUSIVE,
            [code],
            f"not analyzed: {why}",
            complete=False,
        )

    def _make(
        self,
        finding: Finding,
        status: AssessmentStatus,
        codes: Sequence[str],
        explanation: str,
        *,
        facts: Sequence[Fact] = (),
        checks: Sequence[CheckResult] = (),
        unresolved: Sequence[str] = (),
        assumptions: Sequence[str] = (),
        complete: bool = True,
    ) -> Assessment:
        decided = status in (
            AssessmentStatus.SUPPORTED,
            AssessmentStatus.LIKELY_FALSE_POSITIVE,
            AssessmentStatus.STALE,
        )
        return Assessment(
            finding_id=finding.id,
            status=status,
            basis=AssessmentBasis.DETERMINISTIC if decided else AssessmentBasis.NONE,
            reason_codes=tuple(codes),
            explanation=explanation,
            facts=tuple(facts),
            checks=tuple(checks),
            unresolved=tuple(unresolved),
            assumptions=tuple(assumptions),
            profile=PROFILE,
            complete=complete,
            analysis_version=self.analysis_version,
            assessed_at=datetime.now(UTC),
        )


def _scanner_claims(finding: Finding) -> list[Fact]:
    facts = []
    for index, flow in enumerate(finding.code_flows):
        steps = [s.location for s in flow if s.location is not None]
        if not steps:
            continue
        path = " -> ".join(f"{s.path}:{s.start_line}" for s in steps)
        facts.append(
            Fact(
                source=FactSource.SCANNER,
                kind="scanner_code_flow",
                statement=f"scanner claims flow {index + 1}: {path} (not verified by Witness)",
                producer=finding.scanner.name,
            )
        )
    return facts
