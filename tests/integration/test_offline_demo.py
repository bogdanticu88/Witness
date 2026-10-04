"""The offline triage demo: real reports, a fixture app, the real helper.

The intelligence snapshot in fixtures/intel/demo is synthetic and says so.
Nothing here touches the network, and no fixture label or scanner report is
changed to produce these results.
"""

from __future__ import annotations

import collections
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.intel import load_intel
from witness.model.assessment import Assessment, AssessmentStatus, Priority, PriorityLevel
from witness.model.finding import Finding, FindingKind
from witness.priority import IntelContext
from witness.report import write_report
from witness.store import Store
from witness.triage.engine import TriageOutcome, run_triage

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "fixtures" / "apps" / "acme-orders"
REPORTS = [
    ROOT / "fixtures" / "reports" / "codeql" / "acme-orders.sarif",
    ROOT / "fixtures" / "reports" / "trivy" / "acme-orders-fs.json",
    ROOT / "fixtures" / "reports" / "trivy" / "acme-orders-image.json",
    ROOT / "fixtures" / "reports" / "mantis" / "acme-orders.json",
]
INTEL = ROOT / "fixtures" / "intel" / "demo"
AS_OF = datetime(2026, 10, 4, 12, tzinfo=UTC)

Row = tuple[Finding, Assessment, Priority]


@pytest.fixture(scope="module")
def demo(
    helper_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[TriageOutcome, Path]]:
    db = tmp_path_factory.mktemp("demo") / "witness.db"
    with Store.open(db) as store:
        outcome = run_triage(
            REPORTS, APP, store=store, intel=IntelContext(load_intel(INTEL), AS_OF)
        )
    yield outcome, db


def _rows(outcome: TriageOutcome) -> list[Row]:
    assessments = {a.finding_id: a for a in outcome.assessments}
    priorities = {p.finding_id: p for p in outcome.priorities}
    return [(f, assessments[f.id], priorities[f.id]) for f in outcome.findings]


def _where(finding: Finding) -> str:
    if finding.location:
        return f"{finding.location.path}:{finding.location.start_line}"
    return ""


def test_run_completes_and_every_finding_has_both_records(
    demo: tuple[TriageOutcome, Path],
) -> None:
    outcome, _ = demo
    assert outcome.status == "completed"
    assert len(outcome.findings) == len(outcome.assessments) == len(outcome.priorities) == 67


def test_assessments_are_the_same_as_without_intelligence(
    demo: tuple[TriageOutcome, Path], helper_path: Path
) -> None:
    outcome, _ = demo
    plain = run_triage(REPORTS, APP)
    by_id = {a.finding_id: a.status for a in plain.assessments}
    assert {a.finding_id: a.status for a in outcome.assessments} == by_id
    counts = collections.Counter(a.status.value for a in outcome.assessments)
    assert counts == {
        "supported": 12,
        "likely_false_positive": 2,
        "inconclusive": 34,
        "not_assessed": 19,
    }


def test_supported_source_finding(demo: tuple[TriageOutcome, Path]) -> None:
    rows = _rows(demo[0])
    [(_, assessment, priority)] = [
        r for r in rows if _where(r[0]) == "src/Acme.Orders.Data/OrderSearch.cs:36"
    ]
    assert assessment.status is AssessmentStatus.SUPPORTED and assessment.complete
    assert assessment.assumptions
    assert priority.level is PriorityLevel.P2
    assert [r.rule for r in priority.rules] == ["base.severity"]


def test_dismissed_finding_keeps_its_assumptions(demo: tuple[TriageOutcome, Path]) -> None:
    rows = _rows(demo[0])
    dismissed = [r for r in rows if r[1].status is AssessmentStatus.LIKELY_FALSE_POSITIVE]
    assert {_where(f) for f, _, _ in dismissed} == {
        "src/Acme.Orders.Web/Controllers/DocumentsController.cs:30",
        "src/Acme.Orders.Web/Controllers/DocumentsController.cs:43",
    }
    for _, assessment, priority in dismissed:
        assert any("symbolic link" in a for a in assessment.assumptions)
        assert priority.level is PriorityLevel.P4
        assert priority.conditional_on == assessment.assumptions


def test_inconclusive_source_finding(demo: tuple[TriageOutcome, Path]) -> None:
    rows = _rows(demo[0])
    inconclusive = [
        r
        for r in rows
        if r[0].kind is FindingKind.SOURCE and r[1].status is AssessmentStatus.INCONCLUSIVE
    ]
    assert inconclusive
    for _, assessment, priority in inconclusive:
        assert assessment.complete
        assert any(u.startswith("assessment: inconclusive") for u in priority.unknown)
        assert priority.level is PriorityLevel.P2


def _dependency(rows: list[Row], cve: str) -> list[Row]:
    return [
        r for r in rows if r[0].kind is FindingKind.DEPENDENCY and cve in r[0].vulnerability_ids
    ]


def test_dependency_with_available_intelligence(demo: tuple[TriageOutcome, Path]) -> None:
    rows = _rows(demo[0])
    newtonsoft = _dependency(rows, "CVE-2024-21907")
    assert newtonsoft
    for _, assessment, priority in newtonsoft:
        assert assessment.status is AssessmentStatus.INCONCLUSIVE
        used = {f.name for f in priority.factors if f.used and f.freshness == "current"}
        assert {"cvss", "epss"} <= used
        assert all(f.synthetic for f in priority.factors if f.source.startswith("intel:"))
        assert [r.rule for r in priority.rules] == ["base.severity", "raise.epss"]
        assert priority.level is PriorityLevel.P1
    # NVD scores CVE-2021-32840 critical where the scanner said high: kept as a conflict.
    for _, _, priority in _dependency(rows, "CVE-2021-32840"):
        assert priority.level is PriorityLevel.P1
        assert any("scanner severity high" in c for c in priority.conflicts)


def test_dependency_with_missing_and_outdated_intelligence(
    demo: tuple[TriageOutcome, Path],
) -> None:
    rows = _rows(demo[0])
    libc = _dependency(rows, "CVE-2026-18374")
    assert libc
    for finding, _, priority in libc:
        unknown = " ".join(priority.unknown)
        assert "cvss: no CVSS v3 or v4 score" in unknown
        assert "epss: probability for CVE-2026-18374 not established" in unknown
        assert "kev-excerpt.json is outdated" in unknown
        assert priority.level is PriorityLevel.P3 and finding.severity.value == "medium"


def test_runtime_finding_is_kept_without_a_code_verdict(demo: tuple[TriageOutcome, Path]) -> None:
    rows = _rows(demo[0])
    runtime = [r for r in rows if r[0].kind is FindingKind.RUNTIME]
    assert len(runtime) == 19
    for _, assessment, priority in runtime:
        assert assessment.status is AssessmentStatus.NOT_ASSESSED
        assert assessment.reason_codes == ("runtime_finding",)
        assert any("without a code verdict" in u for u in priority.unknown)


def test_report_from_the_stored_run(demo: tuple[TriageOutcome, Path], tmp_path: Path) -> None:
    outcome, db = demo
    with Store.open(db) as store:
        json_path, md_path = write_report(store, outcome.run_id or "", tmp_path / "report")
    doc = json.loads(json_path.read_text())
    assert doc["summary"]["analysis_complete"] is True
    assert doc["summary"]["findings"] == 67
    assert doc["intelligence"]["synthetic"] is True
    freshness = {s["source"]["kind"]: s["freshness"] for s in doc["intelligence"]["sources"]}
    assert freshness == {"cvss": "current", "epss": "current", "kev": "outdated"}
    assert doc["helper"]["protocol"] == "witness.semantic/1"
    assert len(doc["inputs"]) == 4
    markdown = md_path.read_text()
    assert "**Synthetic intelligence.**" in markdown
    assert "likely_false_positive (conditional)" in markdown
    assert "does not mean" not in markdown  # 12 findings are supported
    assert "A finished analysis is not a finding that the code has no vulnerabilities" in markdown
