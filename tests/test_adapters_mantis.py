"""Adapter tests for the real Mantis DAST JSON fixture."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.adapters.base import ImportContext, ImportResult
from witness.adapters.codeql import CodeQLAdapter
from witness.adapters.mantis import MantisAdapter
from witness.adapters.trivy import TrivyAdapter
from witness.errors import InputError
from witness.model.finding import FindingKind, Severity, VulnClass

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"
MANTIS_JSON = REPORTS / "mantis" / "acme-orders.json"
MANTIS_SARIF = REPORTS / "mantis" / "acme-orders.sarif"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _context() -> ImportContext:
    return ImportContext(
        report_path=Path("report.json"),
        report_sha256="c" * 64,
        imported_at=datetime(2026, 10, 3, tzinfo=UTC),
    )


def _parse() -> tuple[dict, ImportResult]:
    document = _load(MANTIS_JSON)
    result = MantisAdapter().parse(document, _context())
    return document, result


def test_fixture_parses_19_findings() -> None:
    _, result = _parse()
    assert result.format == "mantis"
    assert result.tool == "Mantis"
    assert len(result.findings) == 19
    assert all(f.kind is FindingKind.RUNTIME for f in result.findings)


def test_template_findings_map_to_supported_classes() -> None:
    _, result = _parse()
    categories = Counter(f.category for f in result.findings)
    assert categories == {
        VulnClass.OPEN_REDIRECT: 4,
        VulnClass.PATH_TRAVERSAL: 4,
        VulnClass.SQL_INJECTION: 5,
        VulnClass.UNCLASSIFIED: 6,
    }
    templates = {f.scanner_properties["template"] for f in result.findings}
    assert templates == {
        None,
        "acme-open-redirect",
        "acme-path-traversal",
        "acme-sqli-boolean",
        "acme-sqli-boolean-customers",
    }


def test_passive_header_checks_are_unclassified() -> None:
    _, result = _parse()
    passive = [f for f in result.findings if "passive" in f.scanner_properties["tags"]]
    assert len(passive) == 6
    assert all(f.category is VulnClass.UNCLASSIFIED for f in passive)
    assert all(f.scanner_properties["template"] is None for f in passive)
    assert all(
        f.scanner.rule_id and f.scanner.rule_id.startswith("MANTIS-HEADER-") for f in passive
    )
    assert all(f.severity is not Severity.UNKNOWN for f in passive)


def test_runtime_context_populated_from_report_and_finding() -> None:
    _, result = _parse()
    for finding in result.findings:
        assert finding.runtime is not None
        assert finding.runtime.environment == "staging-local"
        assert finding.runtime.target == "http://127.0.0.1:18080"
        assert finding.runtime.method == "GET"
    endpoints = [f.runtime.endpoint for f in result.findings if f.runtime]
    assert "/api/documents/open?name=..%2F..%2F..%2Fetc%2Fpasswd" in endpoints


def test_all_exchanges_preserved_including_non_matching_endpoints() -> None:
    # PROVENANCE caveat: Mantis accumulates earlier probes of the same
    # template into later findings. Every exchange must survive, even the
    # cross-endpoint one that is unconfirmed context.
    document, result = _parse()
    for i, finding in enumerate(result.findings):
        raw_exchanges = document["findings"][i]["evidence"]["exchanges"]
        assert finding.original == document["findings"][i]
        assert len(finding.runtime.exchanges) == len(raw_exchanges)
    lookup = result.findings[18]
    urls = [exchange.url for exchange in lookup.runtime.exchanges]
    assert any("/api/customers/by-region" in url for url in urls)


def test_provenance_scanned_at_from_finding_timestamp() -> None:
    document, result = _parse()
    for i, finding in enumerate(result.findings):
        assert finding.provenance.record_pointer == f"/findings/{i}"
        expected = datetime.fromisoformat(document["findings"][i]["timestamp"])
        assert finding.provenance.scanned_at == expected
        assert finding.provenance.scanned_at is not None
        assert finding.provenance.scanned_at.utcoffset() is not None


def test_scanned_at_falls_back_to_report_timestamp() -> None:
    document = _load(MANTIS_JSON)
    document["timestamp"] = "2026-10-03T00:53:34.899956+03:00"
    for finding in document["findings"]:
        finding.pop("timestamp", None)
    result = MantisAdapter().parse(document, _context())
    expected = datetime.fromisoformat("2026-10-03T00:53:34.899956+03:00")
    assert all(f.provenance.scanned_at == expected for f in result.findings)


def test_scanner_properties_carry_confidence_owasp_tags() -> None:
    _, result = _parse()
    sqli = next(f for f in result.findings if f.category is VulnClass.SQL_INJECTION)
    assert sqli.scanner_properties["confidence"] == 1
    assert sqli.scanner_properties["owasp"] == "A03:2021-Injection"
    assert sqli.scanner_properties["tags"] == ["sqli", "injection"]
    assert sqli.cwe == ("CWE-89",)


def test_detect_claims_mantis_json_only() -> None:
    assert MantisAdapter().detect(_load(MANTIS_JSON))


def test_detect_rejects_mantis_sarif() -> None:
    # Decision documented in the adapter: the SARIF export loses evidence,
    # confidence, CWE, OWASP, tags and template identity, so it is not claimed
    # and the loader rejects it as unsupported.
    assert not MantisAdapter().detect(_load(MANTIS_SARIF))


def test_detect_rejects_other_formats() -> None:
    adapter = MantisAdapter()
    assert not adapter.detect(_load(REPORTS / "codeql" / "acme-orders.sarif"))
    assert not adapter.detect(_load(REPORTS / "codeql" / "codeql-version.json"))
    assert not adapter.detect(_load(REPORTS / "trivy" / "acme-orders-fs.json"))
    assert not adapter.detect({})
    assert not adapter.detect({"findings": [], "application": "a"})
    assert not adapter.detect({"findings": [], "target": "t"})


def test_parse_rejects_non_object() -> None:
    with pytest.raises(InputError, match="JSON object"):
        MantisAdapter().parse([], _context())


def test_parse_rejects_findings_not_a_list() -> None:
    with pytest.raises(InputError, match="findings must be a list"):
        MantisAdapter().parse({"application": "a", "target": "t"}, _context())


def _doc_with_finding(finding: dict) -> dict:
    return {"application": "a", "target": "t", "findings": [finding]}


def _good_finding() -> dict:
    return {
        "id": "acme-open-redirect",
        "name": "Open Redirect to an external host",
        "severity": "medium",
        "endpoint": "/links/out?next=http%3A%2F%2Fexample.test",
        "method": "GET",
        "cwe": "CWE-601",
        "evidence": {
            "exchanges": [{"method": "GET", "url": "http://t/links/out", "status_code": 302}]
        },
    }


def test_parse_minimal_finding_leaves_unknown_fields_empty() -> None:
    result = MantisAdapter().parse(_doc_with_finding(_good_finding()), _context())
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category is VulnClass.OPEN_REDIRECT
    assert finding.provenance.scanned_at is None
    assert finding.runtime.exchanges[0].status_code == 302
    assert finding.runtime.exchanges[0].response_headers == {}
    assert finding.scanner_properties["confidence"] is None
    assert finding.scanner_properties["owasp"] is None
    assert finding.scanner_properties["tags"] == []


def test_parse_rejects_finding_not_an_object() -> None:
    with pytest.raises(InputError, match="findings\\[0\\] must be an object"):
        MantisAdapter().parse(_doc_with_finding(42), _context())


@pytest.mark.parametrize(
    "field",
    ["name", "severity"],
)
def test_parse_rejects_missing_required_fields(field: str) -> None:
    finding = _good_finding()
    del finding[field]
    with pytest.raises(InputError, match=f"findings\\[0\\] has no {field}"):
        MantisAdapter().parse(_doc_with_finding(finding), _context())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", 3),
        ("endpoint", ["/x"]),
        ("method", {"GET": True}),
        ("confidence", "high"),
        ("tags", "redirect"),
        ("evidence", []),
    ],
)
def test_parse_rejects_wrong_field_types(field: str, value: object) -> None:
    finding = _good_finding()
    finding[field] = value
    with pytest.raises(InputError, match=rf"findings\[0\](\.{field})?"):
        MantisAdapter().parse(_doc_with_finding(finding), _context())


def test_parse_rejects_exchanges_not_a_list() -> None:
    finding = _good_finding()
    finding["evidence"] = {"exchanges": {}}
    with pytest.raises(InputError, match="evidence\\.exchanges must be a list"):
        MantisAdapter().parse(_doc_with_finding(finding), _context())


def test_parse_rejects_exchange_not_an_object() -> None:
    finding = _good_finding()
    finding["evidence"] = {"exchanges": ["nope"]}
    with pytest.raises(InputError, match="exchanges\\[0\\] must be an object"):
        MantisAdapter().parse(_doc_with_finding(finding), _context())


def test_detect_fingerprints_do_not_collide_with_codeql_or_trivy() -> None:
    mantis_doc = _load(MANTIS_JSON)
    assert not CodeQLAdapter().detect(mantis_doc)
    assert not TrivyAdapter().detect(mantis_doc)
