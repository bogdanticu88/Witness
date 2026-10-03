"""Adapter tests for the real Trivy JSON fixtures."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.adapters.base import ImportContext
from witness.adapters.codeql import CodeQLAdapter
from witness.adapters.mantis import MantisAdapter
from witness.adapters.trivy import TrivyAdapter
from witness.errors import InputError
from witness.model.finding import FindingKind

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"
ORDERS_FS = REPORTS / "trivy" / "acme-orders-fs.json"
BILLING_FS = REPORTS / "trivy" / "acme-billing-fs.json"
ORDERS_IMAGE = REPORTS / "trivy" / "acme-orders-image.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _context() -> ImportContext:
    return ImportContext(
        report_path=Path("report.json"),
        report_sha256="b" * 64,
        imported_at=datetime(2026, 10, 3, tzinfo=UTC),
    )


def test_orders_fs_fixture_parses_five_distinct_cves() -> None:
    result = TrivyAdapter().parse(_load(ORDERS_FS), _context())
    assert result.format == "trivy"
    assert len(result.findings) == 12
    # vulnerability_ids also carries vendor (GHSA) aliases; the CVE is first.
    cves = {f.vulnerability_ids[0] for f in result.findings}
    assert cves == {
        "CVE-2021-32840",
        "CVE-2021-32841",
        "CVE-2021-32842",
        "CVE-2024-21907",
        "CVE-2025-6965",
    }
    assert "CVE-2024-21907" in cves
    assert "CVE-2025-6965" in cves


def test_orders_fs_findings_are_dependency_kind_with_packages() -> None:
    result = TrivyAdapter().parse(_load(ORDERS_FS), _context())
    assert all(f.kind is FindingKind.DEPENDENCY for f in result.findings)
    packages = {f.package.name for f in result.findings if f.package}
    assert "Newtonsoft.Json" in packages
    assert "SQLitePCLRaw.lib.e_sqlite3" in packages
    assert all(f.package.ecosystem for f in result.findings if f.package)


def test_billing_fs_fixture_parses_two_cves() -> None:
    result = TrivyAdapter().parse(_load(BILLING_FS), _context())
    assert len(result.findings) == 4
    cves = {f.vulnerability_ids[0] for f in result.findings}
    assert cves == {"CVE-2024-21907", "CVE-2025-6965"}


def test_image_fixture_parses_as_image_artifact() -> None:
    document = _load(ORDERS_IMAGE)
    result = TrivyAdapter().parse(document, _context())
    assert len(result.findings) == 19
    assert all(f.artifact and f.artifact.kind == "image" for f in result.findings)
    assert result.findings[0].artifact is not None
    assert result.findings[0].artifact.name == "witness-fixture/acme-orders:rc"
    os_cves = {
        f.vulnerability_ids[0]
        for f in result.findings
        if f.package and f.package.ecosystem == "ubuntu"
    }
    assert len(os_cves) == 10
    assert sum(bool(f.package and f.package.ecosystem == "ubuntu") for f in result.findings) == 14


def test_fs_fixture_provenance_and_original() -> None:
    document = _load(ORDERS_FS)
    result = TrivyAdapter().parse(document, _context())
    scanned_at = datetime.fromisoformat("2026-10-03T00:50:51.607453+03:00")
    for finding in result.findings:
        assert finding.provenance.report_sha256 == "b" * 64
        assert finding.provenance.scanned_at == scanned_at
    first = result.findings[0]
    assert first.provenance.record_pointer == "/Results/0/Vulnerabilities/0"
    assert first.original == document["Results"][0]["Vulnerabilities"][0]


def test_detect_claims_trivy_json_only() -> None:
    adapter = TrivyAdapter()
    assert adapter.detect(_load(ORDERS_FS))
    assert adapter.detect(_load(BILLING_FS))
    assert adapter.detect(_load(ORDERS_IMAGE))


def test_detect_rejects_other_formats() -> None:
    adapter = TrivyAdapter()
    assert not adapter.detect(_load(REPORTS / "codeql" / "acme-orders.sarif"))
    assert not adapter.detect(_load(REPORTS / "codeql" / "codeql-version.json"))
    assert not adapter.detect(_load(REPORTS / "mantis" / "acme-orders.json"))
    assert not adapter.detect(_load(REPORTS / "mantis" / "acme-orders.sarif"))
    assert not adapter.detect({})
    assert not adapter.detect({"Results": []})


def test_parse_rejects_non_object() -> None:
    with pytest.raises(InputError, match="JSON object"):
        TrivyAdapter().parse([], _context())


def test_parse_rejects_wrong_schema_version() -> None:
    with pytest.raises(InputError, match="SchemaVersion 2"):
        TrivyAdapter().parse({"SchemaVersion": 1, "Results": []}, _context())


def test_parse_rejects_results_not_a_list() -> None:
    with pytest.raises(InputError, match="Results must be a list"):
        TrivyAdapter().parse({"SchemaVersion": 2, "Results": {}}, _context())


def test_parse_rejects_result_entry_not_an_object() -> None:
    document = {"SchemaVersion": 2, "Results": ["nope"]}
    with pytest.raises(InputError, match="Results\\[0\\] must be an object"):
        TrivyAdapter().parse(document, _context())


def test_parse_rejects_vulnerability_entry_without_id() -> None:
    document = {
        "SchemaVersion": 2,
        "Results": [{"Target": "packages.lock.json", "Vulnerabilities": [{"Title": "x"}]}],
    }
    with pytest.raises(InputError, match="Vulnerabilities\\[0\\] is not a vulnerability entry"):
        TrivyAdapter().parse(document, _context())


def test_detect_fingerprints_do_not_collide_with_codeql_or_mantis() -> None:
    trivy_doc = _load(ORDERS_FS)
    assert not CodeQLAdapter().detect(trivy_doc)
    assert not MantisAdapter().detect(trivy_doc)
