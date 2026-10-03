from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from witness.model.finding import (
    Finding,
    FindingKind,
    Provenance,
    ScannerIdentity,
    Severity,
    SourceLocation,
    VulnClass,
)


def make_finding(**overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "id": "f-1",
        "instance_key": "src/app/Controller.cs:12:sql_injection",
        "kind": FindingKind.SOURCE,
        "category": VulnClass.SQL_INJECTION,
        "category_basis": "rule: csharp/sql-injection",
        "scanner": ScannerIdentity(name="semgrep", version="1.90.0", rule_id="cs.sql"),
        "severity": Severity.HIGH,
        "title": "Possible SQL injection",
        "location": SourceLocation(path="src/app/Controller.cs", reported_uri="file:///repo/src/app/Controller.cs"),
        "provenance": Provenance(
            report_path="reports/scan.sarif",
            report_sha256="ab" * 32,
            report_format="sarif",
            record_pointer="/runs/0/results/0",
            imported_at=datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        ),
    }
    data.update(overrides)
    return Finding(**data)


def test_finding_builds_with_required_fields() -> None:
    finding = make_finding()
    assert finding.id == "f-1"
    assert finding.kind is FindingKind.SOURCE
    assert finding.category is VulnClass.SQL_INJECTION
    assert finding.severity is Severity.HIGH
    assert finding.revision_source == "none"
    assert finding.scanner.name == "semgrep"
    assert finding.location is not None and finding.location.path == "src/app/Controller.cs"
    assert finding.provenance.report_format == "sarif"


def test_schema_alias_maps_to_schema_id() -> None:
    finding = make_finding(schema="witness.finding/1")
    assert finding.schema_id == "witness.finding/1"
    assert finding.model_dump(by_alias=True)["schema"] == "witness.finding/1"
    assert finding.model_dump()["schema_id"] == "witness.finding/1"


def test_schema_alias_accepted_from_dict() -> None:
    dumped = make_finding().model_dump(by_alias=True)
    assert Finding.model_validate(dumped).schema_id == "witness.finding/1"


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        make_finding(bogus_field="nope")


def test_severity_rank_orders_unknown_with_high() -> None:
    assert Severity.CRITICAL.rank < Severity.HIGH.rank
    assert Severity.HIGH.rank == Severity.UNKNOWN.rank
    assert Severity.UNKNOWN.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.LOW.rank
    assert Severity.LOW.rank < Severity.INFO.rank


def test_findings_differing_only_in_id_are_distinct() -> None:
    first = make_finding()
    second = make_finding(id="f-2")
    assert first != second
    assert first.instance_key == second.instance_key
    assert first == make_finding()


def test_finding_is_frozen() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.id = "f-9"  # type: ignore[misc]


def test_model_dump_round_trip() -> None:
    finding = make_finding(
        cwe=("CWE-89",),
        vulnerability_ids=("CVE-2026-1234",),
        severity_original="ERROR",
        scanner_properties={" confidence ": "high"},
    )
    assert Finding.model_validate(finding.model_dump()) == finding
    assert Finding.model_validate(finding.model_dump(by_alias=True)) == finding
