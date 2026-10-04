"""Triage reports rendered from stored runs."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

from factories import dependency, runtime, source
from fakes import const, node, request, single, tainted, triage_run
from intel_builders import CVE_A, context, epss, kev, write_snapshot
from witness.cli import main as cli_main
from witness.errors import ExitCode, UsageError
from witness.model.assessment import AssessmentStatus, FindingGroup, GroupRelation
from witness.model.finding import Finding, Severity
from witness.report import build_report, render_markdown, write_report
from witness.store import Store

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"

HOSTILE = (
    "<script>alert(1)</script> [click](https://evil.example) | col ``` `x` *b* _i_ "
    "\x1b[31mred\x1b[0m\n## injected heading\n<!-- c -->"
)


def _stored(
    repo: Path,
    db: Path,
    findings: list[Finding],
    helper: object = None,
    intel_dir: Path | None = None,
) -> str:
    with Store.open(db) as store:
        run = triage_run(
            repo,
            helper or tainted(),  # type: ignore[arg-type]
            findings,
            intel=context(intel_dir),
        )
        outcome = run.execute(store, ["a warning with <b>markup</b>"])
    assert outcome.run_id is not None
    return outcome.run_id


def _document(db: Path, run_id: str) -> dict[str, object]:
    with Store.open(db) as store:
        return build_report(store, run_id)


def _dep(finding_id: str = "f-2") -> Finding:
    finding = dependency(finding_id, severity=Severity.MEDIUM)
    return finding.model_copy(update={"vulnerability_ids": (CVE_A,)})


def test_report_lists_every_finding_with_assessment_and_priority(
    repo: Path, tmp_path: Path
) -> None:
    db = tmp_path / "w.db"
    findings = [source("f-1"), _dep(), runtime("f-3"), source("f-4", category="unclassified")]
    run_id = _stored(repo, db, findings)
    doc = _document(db, run_id)
    entries = doc["findings"]
    assert isinstance(entries, list)
    assert sorted(e["finding"]["id"] for e in entries) == ["f-1", "f-2", "f-3", "f-4"]
    for entry in entries:
        assert entry["assessment"]["status"]
        assert entry["priority"]["level"] in ("P1", "P2", "P3", "P4")
        assert entry["priority"]["rules"]
        assert "original" not in entry["finding"]
    assert doc["schema"] == "witness.report/1"
    assert doc["run"]["status"] == "completed"  # type: ignore[index]
    assert doc["snapshot"]["root"] == str(repo.resolve())  # type: ignore[index]
    assert doc["helper"]["protocol"] == "witness.semantic/1"  # type: ignore[index]
    assert str(doc["analysis_version"]).startswith("witness-triage/1+semantic-")


def test_runtime_finding_is_kept_without_a_code_verdict(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [runtime("f-1")])
    [entry] = _document(db, run_id)["findings"]  # type: ignore[misc]
    assert entry["assessment"]["status"] == "not_assessed"
    assert entry["assessment"]["reason_codes"] == ["runtime_finding"]
    assert any("without a code verdict" in u for u in entry["priority"]["unknown"])


def test_completed_analysis_is_not_reported_as_no_vulnerabilities(
    repo: Path, tmp_path: Path
) -> None:
    db = tmp_path / "w.db"
    helper = single(node("constant", '"SELECT 1"', detail='"SELECT 1"'))
    run_id = _stored(repo, db, [source("f-1")], helper=helper)
    doc = _document(db, run_id)
    summary = doc["summary"]
    assert summary["analysis_complete"] is True  # type: ignore[index]
    assert summary["assessments"]["supported"] == 0  # type: ignore[index]
    statement = summary["statement"]  # type: ignore[index]
    assert "does not mean there are no vulnerabilities" in statement
    assert "never looked at" in statement
    markdown = render_markdown(doc)
    assert "analysis completed" in markdown
    assert "does not mean there are no vulnerabilities" in markdown


def test_incomplete_run_is_reported_as_partial(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    helper = single(node("concat", "a + q", const(), request()), truncated=True)
    run_id = _stored(repo, db, [source("f-1")], helper=helper)
    doc = _document(db, run_id)
    assert doc["run"]["status"] == "incomplete"  # type: ignore[index]
    assert doc["run"]["incomplete_reasons"]  # type: ignore[index]
    summary = doc["summary"]
    assert summary["analysis_complete"] is False  # type: ignore[index]
    assert summary["unfinished_assessments"] == 1  # type: ignore[index]
    [entry] = doc["findings"]  # type: ignore[misc]
    assert entry["assessment"]["complete"] is False
    markdown = render_markdown(doc)
    assert "**incomplete**" in markdown
    assert "analysis incomplete: 1 assessment(s) cut short" in markdown
    assert "inconclusive (incomplete)" in markdown
    assert "- Incomplete: analysis budget exhausted for f-1" in markdown


def test_dismissal_is_shown_as_conditional_on_its_assumptions(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1")])
    with Store.open(db) as store:
        [assessment] = store.list_assessments(run_id)
        dismissed = assessment.model_copy(
            update={
                "status": AssessmentStatus.LIKELY_FALSE_POSITIVE,
                "assumptions": ("the root is deployment configuration",),
            }
        )
        store.save_assessment(run_id, dismissed)
        doc = build_report(store, run_id)
    [entry] = doc["findings"]  # type: ignore[misc]
    assert entry["conditional"] == ["the root is deployment configuration"]
    markdown = render_markdown(doc)
    assert "likely_false_positive (conditional)" in markdown
    assert "**Conditional.** This dismissal holds only if" in markdown


def test_possible_chain_is_not_presented_as_proven(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1"), source("f-2", line=20)])
    with Store.open(db) as store:
        store.save_groups(
            run_id,
            [
                FindingGroup(
                    id="g-1",
                    relation=GroupRelation.POSSIBLE_CHAIN,
                    finding_ids=("f-1", "f-2"),
                    explanation="flow of f-1 ends where f-2 starts",
                    basis="heuristic",
                )
            ],
        )
        doc = build_report(store, run_id)
    [group] = [g for g in doc["groups"] if g["id"] == "g-1"]  # type: ignore[attr-defined]
    assert group["proven"] is False and group["label"] == "possible chain (not proven)"
    markdown = render_markdown(doc)
    assert "possible chain (not proven) (heuristic)" in markdown
    assert "not evidence that the chain can be exploited" in markdown


def test_intelligence_provenance_freshness_and_synthetic_label(repo: Path, tmp_path: Path) -> None:
    intel = write_snapshot(
        tmp_path / "intel",
        kev_data=kev(CVE_A, released="2026-08-01T00:00:00Z"),
        epss_data=epss({CVE_A: 0.5}),
    )
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [_dep()], intel_dir=intel)
    doc = _document(db, run_id)
    intelligence = doc["intelligence"]
    assert intelligence["synthetic"] is True  # type: ignore[index]
    states = {s["source"]["kind"]: s["freshness"] for s in intelligence["sources"]}  # type: ignore[index]
    assert states == {"kev": "outdated", "epss": "current"}
    markdown = render_markdown(doc)
    assert "**Synthetic intelligence.**" in markdown
    assert "outdated (64.5 days, limit 7)" in markdown
    assert "SYNTHETIC" in markdown


def test_missing_intelligence_is_visible(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [_dep()])
    doc = _document(db, run_id)
    markdown = render_markdown(doc)
    assert "No intelligence snapshot was given" in markdown
    [entry] = doc["findings"]  # type: ignore[misc]
    assert {u.split(":")[0] for u in entry["priority"]["unknown"]} >= {"cvss", "kev", "epss"}


def test_scanner_and_repository_text_is_escaped(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    finding = source("f-1", title=HOSTILE, message=HOSTILE)
    finding = finding.model_copy(
        update={"scanner": finding.scanner.model_copy(update={"name": HOSTILE})}
    )
    run_id = _stored(repo, db, [finding])
    markdown = render_markdown(_document(db, run_id))
    assert "<script>" not in markdown and "<!--" not in markdown and "<b>" not in markdown
    assert not re.search(r"(?<!\\)\]\(https://evil", markdown)
    assert "\x1b" not in markdown
    assert not re.search(r"^## injected heading", markdown, re.MULTILINE)
    for line in markdown.splitlines():
        if line.startswith("| 1 |"):
            # Every pipe from the title is escaped, so the row keeps its columns.
            assert len(re.findall(r"(?<!\\)\|", line)) == 8
    assert "&lt;script&gt;" in markdown


def test_report_files_are_never_overwritten(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1")])
    out = tmp_path / "out"
    with Store.open(db) as store:
        written = write_report(store, run_id, out)
        assert [p.name for p in written] == ["report.json", "report.md"]
        before = {p: p.read_bytes() for p in written}
        with pytest.raises(UsageError, match="refusing to overwrite") as raised:
            write_report(store, run_id, out)
        assert raised.value.exit_code is ExitCode.USAGE
    assert {p: p.read_bytes() for p in written} == before


def test_one_existing_file_stops_both_from_being_written(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1")])
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.md").write_text("mine")
    with Store.open(db) as store, pytest.raises(UsageError):
        write_report(store, run_id, out)
    assert not (out / "report.json").exists()
    assert (out / "report.md").read_text() == "mine"


def test_symlink_in_place_of_a_report_is_not_followed(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1")])
    out = tmp_path / "out"
    out.mkdir()
    target = tmp_path / "elsewhere.txt"
    target.write_text("keep")
    os.symlink(target, out / "report.json")
    os.symlink(tmp_path / "dangling", out / "report.md")
    with Store.open(db) as store, pytest.raises(UsageError):
        write_report(store, run_id, out)
    assert target.read_text() == "keep"
    assert not (tmp_path / "dangling").exists()


def test_json_and_markdown_come_from_the_same_document(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1"), _dep()])
    with Store.open(db) as store:
        json_path, md_path = write_report(store, run_id, tmp_path / "out")
    doc = json.loads(json_path.read_text())
    assert md_path.read_text() == render_markdown(doc)


def test_run_stored_before_metadata_existed_still_reports(repo: Path, tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    run_id = _stored(repo, db, [source("f-1")])
    with Store.open(db) as store:
        store.set_run_metadata(run_id, {})
        doc = build_report(store, run_id)
    markdown = render_markdown(doc)
    assert "Intelligence settings were not recorded" in markdown
    assert "Semantic helper | not recorded" in markdown
    assert str(doc["analysis_version"]).startswith("witness-triage/1")


# -- CLI -----------------------------------------------------------------------


def _cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["witness", *args])
    with pytest.raises(SystemExit) as exited:
        cli_main.main()
    return int(exited.value.code or 0)


def test_cli_report_writes_once_and_refuses_again(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli_main, "start_helper", lambda *a, **k: tainted())
    db = tmp_path / "ws" / "w.db"
    report = str(REPORTS / "mantis" / "acme-orders.json")
    triage = ["triage", "--report", report, "--repo", str(repo), "--db", str(db), "--json"]
    assert _cli(monkeypatch, *triage) == 0
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    assert _cli(monkeypatch, "report", "--db", str(db), "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["run_id"] == run_id and out["run_status"] == "completed"
    default_dir = db.parent / "reports" / run_id
    assert sorted(Path(f) for f in out["files"]) == [
        default_dir / "report.json",
        default_dir / "report.md",
    ]
    assert _cli(monkeypatch, "report", "--db", str(db), "--run", run_id) == ExitCode.USAGE
    assert "refusing to overwrite" in capsys.readouterr().err
    other = tmp_path / "other"
    code = _cli(monkeypatch, "report", "--db", str(db), "--output", str(other), "--format", "md")
    assert code == 0
    assert [p.name for p in other.iterdir()] == ["report.md"]


def test_cli_report_usage_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    db = tmp_path / "w.db"
    assert _cli(monkeypatch, "report", "--db", str(db)) == ExitCode.USAGE
    assert "no workspace database" in capsys.readouterr().err
    Store.open(db).close()
    assert _cli(monkeypatch, "report", "--db", str(db)) == ExitCode.USAGE
    assert "no triage run" in capsys.readouterr().err
    assert _cli(monkeypatch, "report", "--db", str(db), "--run", "r-nope") == ExitCode.USAGE
    assert "unknown run" in capsys.readouterr().err


def test_cli_triage_with_malformed_intel_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli_main, "start_helper", lambda *a, **k: tainted())
    intel = write_snapshot(tmp_path / "intel", epss_data="garbage\n")
    db = tmp_path / "w.db"
    report = str(REPORTS / "mantis" / "acme-orders.json")
    args = ["triage", "--report", report, "--repo", str(repo), "--db", str(db)]
    assert _cli(monkeypatch, *args, "--intel", str(intel)) == ExitCode.EXECUTION_ERROR
    assert "epss.csv" in capsys.readouterr().err
    assert not db.exists()
    assert _cli(monkeypatch, *args, "--intel", str(tmp_path / "none")) == ExitCode.USAGE
    assert _cli(monkeypatch, *args, "--as-of", "2026-10-04") == ExitCode.USAGE
    assert "time zone" in capsys.readouterr().err


def test_cli_incomplete_run_still_reports_and_exit_codes_stay_separate(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
) -> None:
    db = tmp_path / "w.db"
    helper = single(node("concat", "a + q", const(), request()), truncated=True)
    run_id = _stored(repo, db, [source("f-1")], helper=helper)
    assert _cli(monkeypatch, "report", "--db", str(db), "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["run_id"] == run_id and out["run_status"] == "incomplete"
    doc = json.loads(Path(out["files"][0]).read_text())
    assert doc["summary"]["analysis_complete"] is False
