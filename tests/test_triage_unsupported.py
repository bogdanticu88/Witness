from __future__ import annotations

from pathlib import Path

from factories import dependency, runtime, source
from fakes import FakeHelper, tainted, triage_run, write_lock
from witness.model.assessment import AssessmentStatus
from witness.model.finding import FindingKind, VulnClass

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"


def test_unsupported_findings_stay_in_output_as_not_assessed(repo: Path) -> None:
    findings = [
        source("f-xss", category=VulnClass.UNCLASSIFIED, category_basis="cs/web/xss"),
        source("f-other", kind=FindingKind.OTHER, category=VulnClass.UNCLASSIFIED),
        runtime("f-hdr", category=VulnClass.UNCLASSIFIED),
        runtime("f-sqli"),
    ]
    outcome = triage_run(repo, FakeHelper(), findings).execute(None, [])
    assert len(outcome.assessments) == 4
    assert {a.status for a in outcome.assessments} == {AssessmentStatus.NOT_ASSESSED}
    assert "cs/web/xss" in outcome.assessments[0].explanation


def test_runtime_exchange_association_is_never_a_verdict(repo: Path) -> None:
    finding = runtime("f-r").model_copy(
        update={"scanner_properties": {"exchange_associations": ["matching_endpoint"]}}
    )
    assessment = triage_run(repo, FakeHelper(), [finding]).assess(finding)
    assert assessment.status is AssessmentStatus.NOT_ASSESSED
    assert assessment.facts[0].source.value == "scanner"
    assert "1 of 1" in assessment.facts[0].statement


def test_dependency_never_gets_a_source_verdict(repo: Path) -> None:
    write_lock(repo, "12.0.1")
    statuses = {
        triage_run(repo, tainted(), []).assess(dependency(f"f-{i}")).status for i in range(3)
    }
    assert statuses <= {AssessmentStatus.INCONCLUSIVE, AssessmentStatus.STALE}
