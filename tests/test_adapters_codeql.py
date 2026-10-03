"""Adapter tests for the real CodeQL SARIF fixtures."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.adapters.base import ImportContext
from witness.adapters.codeql import CodeQLAdapter
from witness.errors import InputError
from witness.model.finding import FindingKind, VulnClass

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"
ORDERS_SARIF = REPORTS / "codeql" / "acme-orders.sarif"
BILLING_SARIF = REPORTS / "codeql" / "acme-billing.sarif"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _context() -> ImportContext:
    return ImportContext(
        report_path=Path("report.sarif"),
        report_sha256="a" * 64,
        imported_at=datetime(2026, 10, 3, tzinfo=UTC),
    )


def test_orders_fixture_parses_17_results() -> None:
    result = CodeQLAdapter().parse(_load(ORDERS_SARIF), _context())
    assert len(result.findings) == 17
    assert result.tool == "CodeQL"
    categories = Counter(f.category for f in result.findings)
    assert categories == {
        VulnClass.SQL_INJECTION: 9,
        VulnClass.PATH_TRAVERSAL: 5,
        VulnClass.OPEN_REDIRECT: 3,
    }
    assert all(f.kind is FindingKind.SOURCE for f in result.findings)
    assert all(f.scanner.rule_id for f in result.findings)


def test_orders_rule_ids_and_provenance_pointers_preserved() -> None:
    document = _load(ORDERS_SARIF)
    result = CodeQLAdapter().parse(document, _context())
    for i, finding in enumerate(result.findings):
        assert finding.provenance.record_pointer == f"/runs/0/results/{i}"
        assert finding.original == document["runs"][0]["results"][i]
        assert finding.category_basis == finding.scanner.rule_id


def test_orders_locations_are_repo_relative() -> None:
    result = CodeQLAdapter().parse(_load(ORDERS_SARIF), _context())
    paths = {f.location.path for f in result.findings if f.location}
    assert paths
    assert all(not p.startswith("/") for p in paths)
    assert "src/Acme.Orders.Web/Controllers/AccountController.cs" in paths


def test_orders_code_flows_imported() -> None:
    result = CodeQLAdapter().parse(_load(ORDERS_SARIF), _context())
    assert all(f.code_flows for f in result.findings)


def test_billing_fixture_parses_single_sql_injection() -> None:
    document = _load(BILLING_SARIF)
    result = CodeQLAdapter().parse(document, _context())
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category is VulnClass.SQL_INJECTION
    assert finding.scanner.rule_id == "cs/sql-injection"
    assert finding.original == document["runs"][0]["results"][0]


def test_detect_claims_codeql_sarif_only() -> None:
    adapter = CodeQLAdapter()
    assert adapter.detect(_load(ORDERS_SARIF))
    assert adapter.detect(_load(BILLING_SARIF))


def test_detect_rejects_mantis_sarif() -> None:
    # Regression: any SARIF used to be claimed by structure alone.
    assert not CodeQLAdapter().detect(_load(REPORTS / "mantis" / "acme-orders.sarif"))


def test_detect_rejects_other_formats() -> None:
    adapter = CodeQLAdapter()
    assert not adapter.detect(_load(REPORTS / "mantis" / "acme-orders.json"))
    assert not adapter.detect(_load(REPORTS / "trivy" / "acme-orders-fs.json"))
    assert not adapter.detect(_load(REPORTS / "codeql" / "codeql-version.json"))
    assert not adapter.detect([])
    assert not adapter.detect({"runs": [{"tool": {"driver": {"name": "OtherScanner"}}}]})


def test_parse_rejects_non_object() -> None:
    with pytest.raises(InputError, match="JSON object"):
        CodeQLAdapter().parse([], _context())


def test_parse_rejects_missing_runs() -> None:
    with pytest.raises(InputError, match="at least one run"):
        CodeQLAdapter().parse({}, _context())


def test_parse_rejects_results_not_a_list() -> None:
    document = {"runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": {}}]}
    with pytest.raises(InputError, match="results must be a list"):
        CodeQLAdapter().parse(document, _context())


def test_parse_rejects_result_without_rule_id() -> None:
    document = {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "cs/sql-injection",
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "a.cs"}}},
                        ],
                    },
                    {"message": {"text": "x"}},
                ],
            },
        ],
    }
    with pytest.raises(InputError, match="results\\[1\\] has no ruleId"):
        CodeQLAdapter().parse(document, _context())


def test_parse_rejects_result_without_location() -> None:
    document = {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{"ruleId": "cs/sql-injection"}],
            },
        ],
    }
    with pytest.raises(InputError, match="results\\[0\\] has no primary location"):
        CodeQLAdapter().parse(document, _context())


def test_finding_ids_are_stable_for_same_report_hash() -> None:
    result_one = CodeQLAdapter().parse(_load(ORDERS_SARIF), _context())
    result_two = CodeQLAdapter().parse(_load(ORDERS_SARIF), _context())
    assert [f.id for f in result_one.findings] == [f.id for f in result_two.findings]
    assert len({f.id for f in result_one.findings}) == 17
    assert len({f.instance_key for f in result_one.findings}) == 17


def test_fixture_sha256_matches_provenance_record() -> None:
    expected = {
        ORDERS_SARIF: "d853ea09197e4120e4cbe82824da75ed361011d452f6b336b3aa7fff8c131cb1",
        BILLING_SARIF: "f8ccc2871258418ffde211cbec6a53a43f5929f46d13672fab9a642e5e9c174e",
    }
    for path, digest in expected.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
