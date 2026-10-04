from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from factories import runtime, source
from fakes import FakeHelper, const, failing, node, request, single, tainted, triage_run
from witness.cli import main as cli_main
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


def _truncated_tainted() -> FakeHelper:
    return single(node("concat", "a + q", const(), request()), truncated=True)


def test_truncated_analysis_is_stored_inconclusive_and_marks_the_run_incomplete(
    repo: Path, tmp_path: Path
) -> None:
    with Store.open(tmp_path / "w.db") as store:
        outcome = triage_run(repo, _truncated_tainted(), [source("f-1")]).execute(store, [])
        stored = store.list_assessments(outcome.run_id or "")
        record = store.get_run(outcome.run_id or "")
    assessment = outcome.assessments[0]
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert not assessment.complete
    assert assessment.reason_codes == ("budget_exhausted",)
    assert stored[0].status is AssessmentStatus.INCONCLUSIVE and not stored[0].complete
    assert outcome.status == "incomplete"
    assert outcome.exit_code is ExitCode.INCOMPLETE
    assert record.status == "incomplete"
    assert any("budget exhausted for f-1" in r for r in record.incomplete_reasons)


def test_truncated_analysis_exits_incomplete_from_the_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
) -> None:
    sarif = json.loads((REPORTS / "codeql" / "acme-orders.sarif").read_text())
    run = sarif["runs"][0]
    result = next(r for r in run["results"] if r["ruleId"] == "cs/sql-injection")
    location = result["locations"][0]["physicalLocation"]
    location["artifactLocation"] = {"uri": "src/A.cs", "uriBaseId": "%SRCROOT%"}
    location["region"] = {"startLine": 10}
    location.pop("contextRegion", None)
    result.pop("codeFlows", None)
    result.pop("relatedLocations", None)
    run["results"] = [result]
    run.pop("artifacts", None)
    report = tmp_path / "one.sarif"
    report.write_text(json.dumps(sarif))
    db = tmp_path / "w.db"
    monkeypatch.setattr(cli_main, "start_helper", lambda *a, **k: _truncated_tainted())
    argv = ["witness", "triage", "--report", str(report), "--repo", str(repo), "--db", str(db)]
    monkeypatch.setattr(sys, "argv", [*argv, "--json"])
    with pytest.raises(SystemExit) as exited:
        cli_main.main()
    out = json.loads(capsys.readouterr().out)
    assert exited.value.code == ExitCode.INCOMPLETE == 3
    assert out["status"] == "incomplete"
    [assessment] = out["assessments"]
    assert assessment["status"] == "inconclusive"
    assert assessment["complete"] is False
    with Store.open(db) as store:
        [stored] = store.list_assessments(out["run_id"])
    assert stored.status is AssessmentStatus.INCONCLUSIVE and not stored.complete
