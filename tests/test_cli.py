from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from fakes import tainted
from witness.cli import main as cli_main

REPORTS = Path(__file__).resolve().parent.parent / "fixtures" / "reports"


def _run(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["witness", *args])
    with pytest.raises(SystemExit) as exited:
        cli_main.main()
    return int(exited.value.code or 0)


@pytest.fixture
def fake_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "start_helper", lambda *a, **k: tainted())


def test_triage_json_has_one_assessment_per_finding(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
    fake_helper: None,
) -> None:
    report = str(REPORTS / "mantis" / "acme-orders.json")
    db = str(tmp_path / "w.db")
    code = _run(
        monkeypatch, "triage", "--report", report, "--repo", str(repo), "--db", db, "--json"
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["status"] == "completed"
    assert len(out["assessments"]) == len(out["findings"]) == 19
    assert all("original" not in f for f in out["findings"])


def test_missing_report_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    repo: Path,
    tmp_path: Path,
    fake_helper: None,
) -> None:
    db = str(tmp_path / "w.db")
    code = _run(monkeypatch, "triage", "--report", "nope.json", "--repo", str(repo), "--db", db)
    assert code == 2
    err = capsys.readouterr().err
    assert "report not found" in err and "Traceback" not in err


def test_missing_option_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run(monkeypatch, "triage", "--repo", ".") == 2


def test_unsupported_report_is_an_execution_error(
    monkeypatch: pytest.MonkeyPatch, repo: Path, tmp_path: Path, fake_helper: None
) -> None:
    report = str(REPORTS / "mantis" / "acme-orders.sarif")
    db = str(tmp_path / "w.db")
    assert _run(monkeypatch, "triage", "--report", report, "--repo", str(repo), "--db", db) == 4
