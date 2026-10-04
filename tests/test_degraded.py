from __future__ import annotations

from pathlib import Path

from factories import runtime, source
from fakes import failing, tainted, triage_run
from witness.errors import (
    ExitCode,
    SemanticError,
    SemanticRequestError,
    SemanticTimeout,
)
from witness.model.assessment import AssessmentStatus
from witness.store import Store

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"


def test_helper_crash_fails_the_run_but_assesses_every_finding(repo: Path, tmp_path: Path) -> None:
    findings = [source("f-1"), source("f-2"), runtime("f-3")]
    helper = failing(SemanticError("semantic helper exited (code 139)"), after=1)
    with Store.open(tmp_path / "w.db") as store:
        outcome = triage_run(repo, helper, findings).execute(store, [])
        record = store.get_run(outcome.run_id or "")
    statuses = [a.status for a in outcome.assessments]
    assert statuses[0] is AssessmentStatus.SUPPORTED
    assert statuses[1] is AssessmentStatus.INCONCLUSIVE
    assert not outcome.assessments[1].complete
    assert statuses[2] is AssessmentStatus.NOT_ASSESSED
    assert outcome.status == "failed"
    assert outcome.exit_code is ExitCode.EXECUTION_ERROR
    assert record.status == "failed"
    assert "semantic helper failed" in record.incomplete_reasons


def test_helper_failure_is_never_reported_as_stale_or_clean(repo: Path) -> None:
    findings = [source(f"f-{i}") for i in range(4)]
    outcome = triage_run(repo, failing(SemanticError("broken pipe"), after=0), findings).execute(
        None, []
    )
    for assessment in outcome.assessments:
        assert assessment.status is AssessmentStatus.INCONCLUSIVE
        assert not assessment.complete


def test_helper_timeout_marks_run_incomplete(repo: Path) -> None:
    findings = [source("f-1"), source("f-2")]
    outcome = triage_run(
        repo, failing(SemanticTimeout("no answer within 1s"), after=0), findings
    ).execute(None, [])
    assert outcome.status == "incomplete"
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert [a.reason_codes[0] for a in outcome.assessments] == [
        "helper_timeout",
        "helper_unavailable",
    ]


def test_document_outside_loaded_projects_is_not_a_helper_failure(repo: Path) -> None:
    error = SemanticRequestError("unknown_document", code="unknown_document")
    outcome = triage_run(repo, failing(error, after=0), [source("f-1")]).execute(None, [])
    assert outcome.assessments[0].reason_codes == ("not_in_workspace",)
    assert outcome.status == "completed"


def test_other_request_errors_fail_the_run(repo: Path) -> None:
    # The helper answered, but with an internal error: a defect, not a timeout.
    error = SemanticRequestError("internal", code="internal_error")
    outcome = triage_run(repo, failing(error, after=0), [source("f-1"), source("f-2")]).execute(
        None, []
    )
    assert outcome.status == "failed"
    assert outcome.exit_code is ExitCode.EXECUTION_ERROR
    assert all(not a.complete for a in outcome.assessments)
    assert all(a.status is AssessmentStatus.INCONCLUSIVE for a in outcome.assessments)


def test_interrupt_keeps_completed_work_and_marks_the_rest(repo: Path, tmp_path: Path) -> None:
    findings = [source("f-1"), source("f-2"), source("f-3")]
    helper = failing(KeyboardInterrupt(), after=1)  # type: ignore[arg-type]
    with Store.open(tmp_path / "w.db") as store:
        outcome = triage_run(repo, helper, findings).execute(store, [])
        stored = store.list_assessments(outcome.run_id or "")
        record = store.get_run(outcome.run_id or "")
    assert outcome.status == "interrupted"
    assert outcome.exit_code is ExitCode.INTERRUPTED
    assert record.status == "interrupted"
    assert len(stored) == 3
    by_id = {a.finding_id: a for a in stored}
    assert by_id["f-1"].complete and by_id["f-1"].status is AssessmentStatus.SUPPORTED
    assert by_id["f-2"].reason_codes == ("interrupted",) and not by_id["f-2"].complete
    assert by_id["f-3"].reason_codes == ("interrupted",)


def test_budget_exhaustion_marks_run_incomplete(repo: Path) -> None:
    run = triage_run(repo, tainted(), [source("f-1")], max_calls=1)
    outcome = run.execute(None, [])
    assert outcome.status == "incomplete"
    assert outcome.assessments[0].reason_codes == ("budget_exhausted",)


def test_malformed_facts_fail_the_run_without_a_verdict(repo: Path) -> None:
    from fakes import const, node, single

    broken = node(
        "parameter",
        "name",
        symbol="parameter:name@src/A.cs:3",
        facts={"method": "M:App.Repo.Find(System.String)", "ordinal": "zero"},
    )
    helper = single(node("concat", "a + name", const(), broken))
    outcome = triage_run(repo, helper, [source("f-1")]).execute(None, [])
    assert outcome.status == "failed"
    assert outcome.assessments[0].status is AssessmentStatus.INCONCLUSIVE
    assert not outcome.assessments[0].complete
