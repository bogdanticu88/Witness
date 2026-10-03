"""Tests for the SQLite store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.errors import StoreError
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
    GroupRelation,
    Priority,
    PriorityFactor,
    PriorityLevel,
    Usage,
)
from witness.model.finding import (
    Finding,
    FindingKind,
    Provenance,
    ScannerIdentity,
    Severity,
    SourceLocation,
    VulnClass,
)
from witness.store import Decision, RunRecord, Store


def _finding(finding_id: str) -> Finding:
    return Finding(
        id=finding_id,
        instance_key=f"key-{finding_id}",
        kind=FindingKind.SOURCE,
        category=VulnClass.SQL_INJECTION,
        category_basis="rule:sqli",
        scanner=ScannerIdentity(name="test-scanner", version="1.0.0", rule_id="R1"),
        severity=Severity.HIGH,
        title=f"Finding {finding_id}",
        message="user input reaches a SQL sink",
        cwe=("CWE-89",),
        vulnerability_ids=("CVE-2026-0001",),
        location=SourceLocation(
            path="src/App/Program.cs", reported_uri="src/App/Program.cs", start_line=3, end_line=9
        ),
        code_flows=((),),
        package=None,
        artifact=None,
        runtime=None,
        revision=None,
        scanner_properties={"confidence": "high"},
        provenance=Provenance(
            report_path="report.json",
            report_sha256="ab" * 32,
            report_format="json",
            record_pointer=f"/findings/{finding_id}",
            imported_at=datetime(2026, 1, 1, tzinfo=UTC),
            scanned_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        original={"rule": finding_id},
    )


def _assessment(finding_id: str) -> Assessment:
    return Assessment(
        finding_id=finding_id,
        status=AssessmentStatus.SUPPORTED,
        basis=AssessmentBasis.DETERMINISTIC,
        reason_codes=("taint_reaches_sink",),
        explanation="Tainted input reaches the sink along a feasible path.",
        facts=(
            Fact(
                source=FactSource.SEMANTIC,
                kind="flow",
                statement="data flows from source to sink",
                refs=(
                    CodeRef(
                        path="src/App/Program.cs",
                        start_line=3,
                        end_line=9,
                        span_sha256="cd" * 32,
                        symbol="App.Program.Main",
                    ),
                ),
                producer="witness-semantic",
                data={"steps": 2},
            ),
        ),
        checks=(
            CheckResult(
                name="sink_reachable",
                outcome=CheckOutcome.PASSED,
                detail="sink is reachable from the entry point",
                refs=(),
            ),
        ),
        unresolved=("exploitability",),
        assumptions=("no custom sanitizer registered",),
        profile="pr",
        complete=True,
        reused_from_cache=False,
        usage=Usage(
            input_tokens=10, output_tokens=20, calls=1, latency_ms=5, estimated_cost_usd=0.01
        ),
        context_fingerprint="fp-1",
        analysis_version="1.0",
        assessed_at=datetime(2026, 1, 2, tzinfo=UTC),
    )


def _priority(finding_id: str) -> Priority:
    return Priority(
        finding_id=finding_id,
        level=PriorityLevel.P1,
        score=90,
        factors=(
            PriorityFactor(name="severity", value="high", points=40, source="scanner"),
            PriorityFactor(name="exposure", value="public", points=50, source="profile"),
        ),
        unknown=("epss",),
        rules_version="1.0",
    )


def _group() -> FindingGroup:
    return FindingGroup(
        id="grp-1",
        relation=GroupRelation.DUPLICATE,
        finding_ids=("f-1", "f-2"),
        explanation="same instance key",
        basis="identity",
    )


def _decision(decision_id: str, *, finding_id: str = "f-1") -> Decision:
    return Decision(
        decision_id=decision_id,
        finding_id=finding_id,
        identity="operator:alice",
        decision="confirmed",
        rationale="reproduced on the analyzed snapshot",
        created_at=datetime(2026, 1, 3, tzinfo=UTC),
        run_id="r-decisions",
    )


def _versions(path: Path) -> list[int]:
    conn = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
        ]
    finally:
        conn.close()


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store.open(tmp_path / "witness.db") as opened:
        yield opened


@pytest.fixture
def run_id(store: Store) -> str:
    return store.start_run(
        mode="triage", repo_root=None, profile="default", provider=None, model=None
    ).run_id


def test_open_creates_database_and_migrates(tmp_path: Path) -> None:
    path = tmp_path / "state" / "witness.db"
    with Store.open(path):
        assert path.is_file()
        assert _versions(path) == [1]


def test_second_open_is_a_noop(tmp_path: Path) -> None:
    path = tmp_path / "witness.db"
    with Store.open(path) as opened:
        run = opened.start_run(
            mode="triage", repo_root=None, profile=None, provider=None, model=None
        )
    with Store.open(path) as reopened:
        assert _versions(path) == [1]
        assert reopened.get_run(run.run_id).mode == "triage"


def test_run_lifecycle(store: Store) -> None:
    run = store.start_run(
        mode="pr", repo_root="/repo", profile="default", provider="anthropic", model="claude"
    )
    assert isinstance(run, RunRecord)
    assert run.run_id.startswith("r-") and len(run.run_id) == 14
    assert run.status == "running"
    assert run.started_at.endswith("+00:00")
    assert run.finished_at is None
    assert run.usage is None
    assert run.incomplete_reasons == ()
    usage = Usage(input_tokens=5, output_tokens=6, calls=2, latency_ms=7)
    store.set_run_status(
        run.run_id, "complete", usage=usage, incomplete_reasons=("budget",), finished=True
    )
    got = store.get_run(run.run_id)
    assert got.status == "complete"
    assert got.usage == usage
    assert got.incomplete_reasons == ("budget",)
    assert got.finished_at is not None and got.finished_at.endswith("+00:00")
    with pytest.raises(StoreError):
        store.set_run_status("r-missing", "complete")
    with pytest.raises(StoreError):
        store.get_run("r-missing")


def test_model_round_trip(store: Store, run_id: str) -> None:
    findings = [_finding("f-1"), _finding("f-2")]
    store.save_findings(run_id, findings)
    assert store.list_findings(run_id) == findings

    assessment = _assessment("f-1")
    store.save_assessment(run_id, assessment)
    assert store.get_assessment(run_id, "f-1") == assessment
    assert store.get_assessment(run_id, "missing") is None
    assert store.list_assessments(run_id) == [assessment]

    priority = _priority("f-1")
    store.save_priority(run_id, priority)
    assert store.list_priorities(run_id) == [priority]

    group = _group()
    store.save_groups(run_id, [group])
    assert store.list_groups(run_id) == [group]


def test_record_report_dir_idempotent_and_rejects_relocation(
    store: Store, run_id: str, tmp_path: Path
) -> None:
    path = tmp_path / "report"
    assert store.record_report_dir(run_id, path) == str(path)
    assert store.record_report_dir(run_id, path) == str(path)
    with pytest.raises(StoreError):
        store.record_report_dir(run_id, tmp_path / "elsewhere")


def test_cache_namespaced_isolation_and_validation(store: Store) -> None:
    store.cache_put("ns", "k", "v1")
    store.cache_put("other", "k", "v2")
    assert store.cache_get("ns", "k") == "v1"
    assert store.cache_get("other", "k") == "v2"
    assert store.cache_get("ns", "missing") is None
    with pytest.raises(StoreError):
        store.cache_put("", "k", "v")
    with pytest.raises(StoreError):
        store.cache_put("   ", "k", "v")


def test_decisions_insert_and_reject_duplicates(store: Store) -> None:
    store.add_decision(_decision("d-1"))
    store.add_decision(_decision("d-2", finding_id="f-2"))
    decisions = store.list_decisions()
    assert [d.decision_id for d in decisions] == ["d-1", "d-2"]
    assert decisions[0].decision == "confirmed"
    with pytest.raises(StoreError):
        store.add_decision(_decision("d-1"))


def test_refuses_database_at_newer_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "witness.db"
    with Store.open(path):
        pass
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (999, "2099-01-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(StoreError, match="newer"):
        Store.open(path)


def test_foreign_keys_enforced(store: Store) -> None:
    with pytest.raises(StoreError) as exc_info:
        store.save_findings("r-missing", [_finding("f-1")])
    assert isinstance(exc_info.value.__cause__, sqlite3.IntegrityError)
