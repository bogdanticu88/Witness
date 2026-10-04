from __future__ import annotations

from pathlib import Path

import pytest

from factories import dependency, runtime, source
from fakes import FakeHelper, failing, tainted, triage_run, write_lock
from witness.errors import (
    ExitCode,
    InputError,
    SemanticError,
    UsageError,
)
from witness.model.assessment import AssessmentStatus
from witness.model.finding import ArtifactIdentity, FindingKind, VulnClass
from witness.store import Store
from witness.triage.engine import run_triage
from witness.triage.snapshot import read_git_head, same_revision

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"


def test_one_assessment_per_finding_in_input_order(repo: Path, tmp_path: Path) -> None:
    findings = [
        source("f-1"),
        source("f-2", category=VulnClass.UNCLASSIFIED),
        runtime("f-3"),
        dependency("f-4", artifact=ArtifactIdentity(kind="image", name="app:1")),
    ]
    with Store.open(tmp_path / "w.db") as store:
        outcome = triage_run(repo, tainted(), findings).execute(store, [])
        assert [a.finding_id for a in outcome.assessments] == ["f-1", "f-2", "f-3", "f-4"]
        assert outcome.status == "completed"
        assert outcome.exit_code is ExitCode.OK
        stored = {a.finding_id: a for a in store.list_assessments(outcome.run_id or "")}
        assert set(stored) == {"f-1", "f-2", "f-3", "f-4"}
        assert [f.id for f in store.list_findings(outcome.run_id or "")] == [
            "f-1",
            "f-2",
            "f-3",
            "f-4",
        ]
        assert store.get_run(outcome.run_id or "").status == "completed"
    assert stored["f-1"].status is AssessmentStatus.SUPPORTED


def test_scanner_code_flow_is_recorded_as_a_claim(repo: Path) -> None:
    from factories import flow

    finding = source("f-1", code_flows=(flow(("src/A.cs", 3), ("src/A.cs", 10)),))
    assessment = triage_run(repo, tainted(), [finding]).assess(finding)
    claims = [f for f in assessment.facts if f.kind == "scanner_code_flow"]
    assert claims and claims[0].source.value == "scanner"
    assert "not verified" in claims[0].statement


# -- locations and revisions -------------------------------------------------


def test_missing_location_is_inconclusive_not_stale(repo: Path) -> None:
    assessment = triage_run(repo, tainted(), []).assess(source("f-1", None))
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.reason_codes == ("no_location_reported",)


def test_missing_line_is_inconclusive(repo: Path) -> None:
    assessment = triage_run(repo, tainted(), []).assess(source("f-1", "src/A.cs", None))
    assert assessment.status is AssessmentStatus.INCONCLUSIVE


def test_file_absent_from_snapshot_is_stale(repo: Path) -> None:
    assessment = triage_run(repo, tainted(), []).assess(source("f-1", "src/Gone.cs", 3))
    assert assessment.status is AssessmentStatus.STALE
    assert assessment.reason_codes == ("file_not_in_snapshot",)


def test_line_beyond_end_of_file_is_stale(repo: Path) -> None:
    assessment = triage_run(repo, tainted(), []).assess(source("f-1", "src/A.cs", 400))
    assert assessment.status is AssessmentStatus.STALE
    assert "has 40 lines" in assessment.explanation


def test_location_escaping_the_snapshot_is_rejected(repo: Path) -> None:
    (repo.parent / "secret.cs").write_text("x\n" * 20)
    assessment = triage_run(repo, tainted(), []).assess(source("f-1", "../secret.cs", 3))
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.reason_codes == ("location_rejected",)


def test_revision_mismatch_is_stale_and_explained(repo: Path) -> None:
    finding = source("f-1", revision="1111111aaaa", revision_source="report")
    assessment = triage_run(repo, tainted(), [], revision="2222222bbbb").assess(finding)
    assert assessment.status is AssessmentStatus.STALE
    assert "1111111aaaa" in assessment.explanation and "2222222bbbb" in assessment.explanation


def test_abbreviated_matching_revision_is_not_stale(repo: Path) -> None:
    full = "0123456789abcdef0123456789abcdef01234567"
    finding = source("f-1", revision="0123456", revision_source="report")
    assessment = triage_run(repo, tainted(), [], revision=full).assess(finding)
    assert assessment.status is AssessmentStatus.SUPPORTED
    assert not any("revision" in a for a in assessment.assumptions)


def test_unknown_revision_is_an_explicit_assumption(repo: Path) -> None:
    assessment = triage_run(repo, tainted(), [], revision="abc1234").assess(source("f-1"))
    assert assessment.status is AssessmentStatus.SUPPORTED
    assert any("declares no revision" in a for a in assessment.assumptions)


@pytest.mark.parametrize(
    ("a", "b", "same"),
    [
        ("abc1234", "abc1234", True),
        ("abc1234", "abc1234ffff", True),
        ("abc123", "abc1234ffff", False),
        ("v1.2", "v1.2.0", False),
        ("ABC1234", "abc1234", True),
    ],
)
def test_revision_comparison(a: str, b: str, same: bool) -> None:
    assert same_revision(a, b) is same


def test_git_head_is_read_without_running_git(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    sha = "a" * 40
    (git / "refs" / "heads" / "main").write_text(sha + "\n")
    (tmp_path / "app").mkdir()
    assert read_git_head(tmp_path / "app") == sha
    (git / "refs" / "heads" / "main").unlink()
    (git / "packed-refs").write_text(f"# pack-refs\n{'b' * 40} refs/heads/main\n")
    assert read_git_head(tmp_path) == "b" * 40


# -- dependencies ------------------------------------------------------------


def test_dependency_in_lock_file_stays_inconclusive(repo: Path) -> None:
    write_lock(repo, "12.0.1")
    assessment = triage_run(repo, FakeHelper(), []).assess(dependency("f-d"))
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.checks[0].outcome.value == "passed"


def test_dependency_upgraded_in_snapshot_is_stale(repo: Path) -> None:
    write_lock(repo, "13.0.3")
    assessment = triage_run(repo, FakeHelper(), []).assess(dependency("f-d"))
    assert assessment.status is AssessmentStatus.STALE
    assert "13.0.3" in assessment.explanation


def test_image_dependency_is_not_checked_against_the_repository(repo: Path) -> None:
    image = ArtifactIdentity(kind="image", name="app:1", digest="sha256:" + "0" * 64)
    assessment = triage_run(repo, FakeHelper(), []).assess(dependency("f-d", artifact=image))
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.checks[0].outcome.value == "not_applicable"


# -- run setup ---------------------------------------------------------------


def test_missing_repository_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        run_triage(
            [REPORTS / "codeql" / "acme-orders.sarif"], tmp_path / "nope", helper_factory=FakeHelper
        )


def test_same_report_twice_is_refused(repo: Path) -> None:
    report = REPORTS / "codeql" / "acme-orders.sarif"
    with pytest.raises(UsageError, match="same content"):
        run_triage([report, report], repo, helper_factory=FakeHelper)


def test_unsupported_report_is_refused_before_anything_runs(repo: Path, tmp_path: Path) -> None:
    started = []

    def factory() -> FakeHelper:
        started.append(True)
        return FakeHelper()

    with pytest.raises(InputError):
        run_triage([REPORTS / "mantis" / "acme-orders.sarif"], repo, helper_factory=factory)
    assert not started


def test_helper_that_cannot_load_the_repository_is_refused(repo: Path, tmp_path: Path) -> None:
    helper = failing(SemanticError("load failed"), after=0, method="load")
    with Store.open(tmp_path / "w.db") as store, pytest.raises(SemanticError):
        run_triage(
            [REPORTS / "codeql" / "acme-orders.sarif"],
            repo,
            store=store,
            helper_factory=lambda: helper,
        )
    assert helper.closed


def test_real_reports_through_the_pipeline_with_a_fake_helper(repo: Path, tmp_path: Path) -> None:
    reports = [
        REPORTS / "codeql" / "acme-orders.sarif",
        REPORTS / "trivy" / "acme-orders-fs.json",
        REPORTS / "trivy" / "acme-orders-image.json",
        REPORTS / "mantis" / "acme-orders.json",
    ]
    with Store.open(tmp_path / "w.db") as store:
        outcome = run_triage(reports, repo, store=store, helper_factory=FakeHelper)
        stored = store.list_assessments(outcome.run_id or "")
    assert len(outcome.findings) == len(outcome.assessments) == len(stored) == 67
    # None of the CodeQL files exist in this empty repository: stale, never dismissed.
    by_id = {f.id: f for f in outcome.findings}
    for assessment in outcome.assessments:
        if by_id[assessment.finding_id].kind is FindingKind.SOURCE:
            assert assessment.status is AssessmentStatus.STALE
