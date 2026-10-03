"""Import integrity regressions, including real scanner evidence attachment."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from witness.adapters.base import ImportContext, instance_key
from witness.adapters.codeql import CodeQLAdapter
from witness.adapters.loader import load_report
from witness.adapters.mantis import MantisAdapter
from witness.adapters.trivy import TrivyAdapter
from witness.errors import InputError

REPORTS = Path(__file__).resolve().parents[1] / "fixtures" / "reports"


def context() -> ImportContext:
    return ImportContext(Path("report.json"), "d" * 64, datetime(2026, 10, 3, tzinfo=UTC))


def read_report(relative: str) -> dict:
    return json.loads((REPORTS / relative).read_text())


def resolve_pointer(document: dict, pointer: str) -> object:
    value = document
    for part in pointer.lstrip("/").split("/"):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


@pytest.mark.parametrize(
    "relative",
    [
        "codeql/acme-orders.sarif",
        "codeql/acme-billing.sarif",
        "trivy/acme-orders-fs.json",
        "trivy/acme-billing-fs.json",
        "trivy/acme-orders-image.json",
        "mantis/acme-orders.json",
    ],
)
def test_every_real_finding_pointer_resolves_to_its_original(relative: str) -> None:
    doc = read_report(relative)
    for finding in load_report(REPORTS / relative).findings:
        assert resolve_pointer(doc, finding.provenance.record_pointer) == finding.original


def test_instance_key_cannot_collide_on_separators_or_none_markers() -> None:
    assert instance_key("a|b", "c") != instance_key("a", "b|c")
    assert instance_key(None) != instance_key("\x00none")
    assert instance_key(1) != instance_key("1")


def test_codeql_preserves_all_runs_and_per_run_metadata() -> None:
    doc = read_report("codeql/acme-billing.sarif")
    run = copy.deepcopy(doc["runs"][0])
    run["tool"]["driver"]["semanticVersion"] = "other-version"
    run["versionControlProvenance"] = [{"revision": "second-revision"}]
    doc["runs"].append(run)
    result = CodeQLAdapter().parse(doc, context())
    assert len(result.findings) == 2
    first, second = result.findings
    assert first.id != second.id
    assert second.scanner.version == "other-version"
    assert second.revision == "second-revision"
    assert second.revision_source == "report"
    assert second.provenance.record_pointer == "/runs/1/results/0"
    assert result.tool_version is None


@pytest.mark.parametrize("later_run", [None, {"tool": {"driver": {"name": "Other"}}}])
def test_codeql_does_not_silently_discard_invalid_or_foreign_runs(later_run: object) -> None:
    doc = read_report("codeql/acme-billing.sarif")
    doc["runs"].append(later_run)
    with pytest.raises(InputError, match=r"runs\[1\]"):
        CodeQLAdapter().parse(doc, context())


def test_codeql_empty_run_is_supported_and_wrong_version_rejected() -> None:
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
    assert CodeQLAdapter().detect(doc)
    assert CodeQLAdapter().parse(doc, context()).findings == []
    doc["version"] = "1.0"
    with pytest.raises(InputError, match="SARIF version"):
        CodeQLAdapter().parse(doc, context())


def test_trivy_empty_scan_loads_without_inventing_findings(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactType": "filesystem",
                "Results": [],
            }
        )
    )
    assert load_report(path).findings == []


def test_trivy_reads_real_version_name_digest_and_time() -> None:
    doc = read_report("trivy/acme-orders-image.json")
    result = TrivyAdapter().parse(doc, context())
    assert result.tool_version == "0.75.0"
    for finding in result.findings:
        assert finding.scanner.version == "0.75.0"
        assert finding.artifact.name == doc["ArtifactName"]
        assert finding.artifact.digest == doc["ArtifactID"]
        assert finding.provenance.scanned_at == datetime.fromisoformat(doc["CreatedAt"])


def test_trivy_image_without_os_packages_is_still_an_image() -> None:
    doc = read_report("trivy/acme-orders-image.json")
    doc["Results"] = [r for r in doc["Results"] if r.get("Class") != "os-pkgs"]
    assert TrivyAdapter().parse(doc, context()).findings
    assert all(f.artifact.kind == "image" for f in TrivyAdapter().parse(doc, context()).findings)


def test_trivy_keeps_package_origins_and_artifacts_distinct() -> None:
    doc = read_report("trivy/acme-orders-fs.json")
    result = TrivyAdapter().parse(doc, context())
    assert len({f.instance_key for f in result.findings}) == len(result.findings)
    other = copy.deepcopy(doc)
    other["ArtifactName"] = "other-repository"
    assert result.findings[0].instance_key != (
        TrivyAdapter().parse(other, context()).findings[0].instance_key
    )


@pytest.mark.parametrize("value", [{}, "not-a-list", 0])
def test_trivy_malformed_vulnerabilities_are_not_treated_as_empty(value: object) -> None:
    doc = {"SchemaVersion": 2, "Results": [{"Vulnerabilities": value}]}
    with pytest.raises(InputError, match="Vulnerabilities must be a list"):
        TrivyAdapter().parse(doc, context())


def test_mantis_marks_cross_endpoint_exchanges_and_preserves_every_record() -> None:
    doc = read_report("mantis/acme-orders.json")
    result = MantisAdapter().parse(doc, context())
    assert result.warnings
    for raw, finding in zip(doc["findings"], result.findings, strict=True):
        assert finding.original == raw
        associations = finding.scanner_properties["exchange_associations"]
        assert len(associations) == len(finding.runtime.exchanges)
        for exchange, association in zip(finding.runtime.exchanges, associations, strict=True):
            if association == "matching_endpoint":
                assert exchange.url == finding.runtime.target + finding.runtime.endpoint
                assert exchange.method == finding.runtime.method
    contaminated = result.findings[18]
    assert "unconfirmed_context" in contaminated.scanner_properties["exchange_associations"]


@pytest.mark.parametrize(
    ("url", "method"),
    [
        ("http://other.test/api/check?x=1", "GET"),
        ("http://target.test/api/check?x=2", "GET"),
        ("http://target.test/api/check?x=1", "POST"),
    ],
)
def test_mantis_does_not_associate_other_hosts_queries_or_methods(url: str, method: str) -> None:
    doc = {
        "application": "test",
        "target": "http://target.test",
        "findings": [
            {
                "name": "check",
                "severity": "high",
                "endpoint": "/api/check?x=1",
                "method": "GET",
                "evidence": {"exchanges": [{"url": url, "method": method}]},
            }
        ],
    }
    finding = MantisAdapter().parse(doc, context()).findings[0]
    assert finding.scanner_properties["exchange_associations"] == ["unconfirmed_context"]


def test_mantis_different_targets_are_not_duplicates() -> None:
    doc = read_report("mantis/acme-orders.json")
    first = MantisAdapter().parse(doc, context()).findings[0]
    doc["target"] = "http://different-target.test"
    for record in doc["findings"]:
        record["target"] = doc["target"]
    second = MantisAdapter().parse(doc, context()).findings[0]
    assert first.instance_key != second.instance_key
