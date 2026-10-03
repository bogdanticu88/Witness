"""Tests for the report loader: hashing, sniffing and dispatch."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from witness.adapters.codeql import CodeQLAdapter
from witness.adapters.loader import load_report
from witness.errors import InputError

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"
FIXTURES = {
    "codeql": REPORTS / "codeql" / "acme-orders.sarif",
    "trivy": REPORTS / "trivy" / "acme-orders-fs.json",
    "mantis": REPORTS / "mantis" / "acme-orders.json",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(("format_name", "expected_tool"), [
    ("codeql", "CodeQL"),
    ("trivy", "Trivy"),
    ("mantis", "Mantis"),
])
def test_loads_each_real_fixture(format_name: str, expected_tool: str) -> None:
    path = FIXTURES[format_name]
    result = load_report(path)
    assert result.format == format_name
    assert result.tool == expected_tool
    assert result.findings
    digest = _sha256(path)
    for finding in result.findings:
        assert finding.provenance.report_sha256 == digest
        assert finding.provenance.report_format == format_name
        assert finding.provenance.report_path == str(path)
        assert finding.provenance.imported_at.tzinfo is not None


def test_loads_mantis_fixture_with_expected_contents() -> None:
    result = load_report(FIXTURES["mantis"])
    assert len(result.findings) == 19


def test_fixture_hashes_match_provenance_record() -> None:
    # Hashes are computed from the files, not hardcoded here; the values are
    # recorded in fixtures/reports/PROVENANCE.md.
    assert _sha256(REPORTS / "codeql" / "acme-orders.sarif") == (
        "d853ea09197e4120e4cbe82824da75ed361011d452f6b336b3aa7fff8c131cb1"
    )
    assert _sha256(REPORTS / "trivy" / "acme-orders-fs.json") == (
        "34b9862b1f93c69afe9a3b264089358f8d5c999a651b92e3b33bcb237abe6587"
    )
    assert _sha256(REPORTS / "mantis" / "acme-orders.json") == (
        "3c7393e5681b14c454d6b4650a1327ec3099c761541e734b3b389b426e701665"
    )


def test_unknown_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(InputError, match="unsupported report format"):
        load_report(path)


def test_mantis_sarif_is_rejected_as_unsupported() -> None:
    # Documented adapter decision: the Mantis SARIF export loses evidence,
    # confidence, CWE, OWASP, tags and template identity, so no adapter
    # claims it and the loader refuses it instead of importing a lossy record.
    with pytest.raises(InputError, match="unsupported report format"):
        load_report(REPORTS / "mantis" / "acme-orders.sarif")


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="not valid JSON"):
        load_report(path)


def test_ambiguous_document_is_rejected(tmp_path: Path) -> None:
    document = {
        "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}],
        "SchemaVersion": 2,
        "Results": [{"Target": "t", "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}],
        "application": "a",
        "target": "t",
        "findings": [],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(InputError, match="ambiguous report format.*codeql.*trivy.*mantis"):
        load_report(path)


def test_custom_adapter_list_is_respected(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(InputError, match="recognized formats: codeql"):
        load_report(path, adapters=[CodeQLAdapter()])


def test_operator_revision_flows_into_codeql_findings() -> None:
    result = load_report(REPORTS / "codeql" / "acme-billing.sarif", operator_revision="rev-abc")
    assert len(result.findings) == 1
    assert result.findings[0].revision == "rev-abc"
    assert result.findings[0].revision_source == "operator"


def test_codeql_revision_is_none_without_operator_value() -> None:
    result = load_report(REPORTS / "codeql" / "acme-billing.sarif")
    assert result.findings[0].revision is None
    assert result.findings[0].revision_source == "none"


def test_source_prefixes_reach_codeql_locations(tmp_path: Path) -> None:
    result = load_report(REPORTS / "codeql" / "acme-billing.sarif")
    direct = result.findings[0].location
    prefixed = load_report(
        REPORTS / "codeql" / "acme-billing.sarif", source_prefixes=("/opt/src",)
    ).findings[0].location
    assert direct is not None and prefixed is not None
    assert prefixed.path == direct.path
