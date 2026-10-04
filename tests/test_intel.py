"""Offline intelligence snapshots: validation, provenance and freshness."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from intel_builders import AS_OF, CVE_A, CVE_B, epss, kev, nvd, source_entry, write_snapshot
from witness.errors import ExitCode, InputError, UsageError
from witness.intel import Freshness, IntelKind, freshness, load_intel


def _full(tmp_path: Path) -> Path:
    return write_snapshot(
        tmp_path / "intel",
        kev_data=kev(CVE_A),
        epss_data=epss({CVE_A: 0.2, CVE_B: 0.01}),
        nvd_data=nvd({CVE_A: [("3.1", 9.8), ("2.0", 7.5)], CVE_B: []}),
    )


def _manifest(directory: Path) -> dict[str, Any]:
    return json.loads((directory / "intel.json").read_text())


def _rewrite(directory: Path, manifest: dict[str, Any]) -> None:
    (directory / "intel.json").write_text(json.dumps(manifest))


def test_loads_each_feed_with_provenance(tmp_path: Path) -> None:
    directory = _full(tmp_path)
    snapshot = load_intel(directory)
    by_kind = {s.kind: s for s in snapshot.sources}
    assert set(by_kind) == {IntelKind.KEV, IntelKind.EPSS, IntelKind.CVSS}
    kev_source = by_kind[IntelKind.KEV]
    assert kev_source.sha256 == hashlib.sha256((directory / "kev.json").read_bytes()).hexdigest()
    assert kev_source.data_as_of.isoformat() == "2026-10-04T08:00:00+00:00"
    assert kev_source.retrieved_at.isoformat() == "2026-10-04T09:00:00+00:00"
    assert kev_source.synthetic and kev_source.coverage == "full" and kev_source.records == 1
    assert snapshot.kev[CVE_A][0].due_date is not None
    assert snapshot.epss[CVE_A][0].probability == pytest.approx(0.2)
    assert snapshot.epss[CVE_A][0].model_version == "v2025.03.14"
    versions = sorted(s.version for s in snapshot.cvss[CVE_A])
    assert versions == ["2.0", "3.1"]
    # NVD writes UTC timestamps without a zone.
    assert by_kind[IntelKind.CVSS].data_as_of.isoformat() == "2026-10-04T06:00:00+00:00"


def test_gzipped_epss_is_read(tmp_path: Path) -> None:
    directory = tmp_path / "intel"
    directory.mkdir()
    (directory / "epss.csv.gz").write_bytes(gzip.compress(epss({CVE_A: 0.3}).encode()))
    _rewrite(
        directory, {"schema": "witness.intel/1", "sources": [source_entry("epss", "epss.csv.gz")]}
    )
    assert load_intel(directory).epss[CVE_A][0].probability == pytest.approx(0.3)


def test_missing_directory_or_manifest_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        load_intel(tmp_path / "nowhere")
    (tmp_path / "empty").mkdir()
    with pytest.raises(UsageError, match=r"intel\.json"):
        load_intel(tmp_path / "empty")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda m: m.update(schema="witness.intel/2"), "schema"),
        (lambda m: m.update(extra=1), "unknown field"),
        (lambda m: m.update(sources=[]), "non-empty"),
        (lambda m: m["sources"][0].update(kind="nvd"), "kind"),
        (lambda m: m["sources"][0].update(coverage="most"), "coverage"),
        (lambda m: m["sources"][0].update(synthetic="no"), "synthetic"),
        (lambda m: m["sources"][0].pop("origin"), "missing origin"),
        (lambda m: m["sources"][0].pop("synthetic"), "missing synthetic"),
        (lambda m: m["sources"][0].update(retrieved_at="2026-10-04T09:00:00"), "time zone"),
        (lambda m: m["sources"][0].update(retrieved_at="yesterday"), "ISO 8601"),
        (lambda m: m["sources"][0].update(sha256="0" * 64), "sha256"),
        (lambda m: m["sources"][0].update(sha256="ABC"), "sha256"),
        (lambda m: m["sources"][0].update(path="../kev.json"), "inside"),
        (lambda m: m["sources"][0].update(path="/etc/hosts"), "inside"),
        (lambda m: m["sources"][0].update(path="missing.json"), "not found"),
        (lambda m: m["sources"].append(dict(m["sources"][0])), "listed twice"),
    ],
)
def test_malformed_manifest_is_refused(tmp_path: Path, change: Any, message: str) -> None:
    directory = _full(tmp_path)
    manifest = _manifest(directory)
    change(manifest)
    _rewrite(directory, manifest)
    with pytest.raises(InputError, match=message) as raised:
        load_intel(directory)
    assert raised.value.exit_code is ExitCode.EXECUTION_ERROR


def test_symlink_out_of_the_snapshot_is_refused(tmp_path: Path) -> None:
    directory = _full(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(kev(CVE_A)))
    os.symlink(outside, directory / "link.json")
    manifest = _manifest(directory)
    manifest["sources"][0]["path"] = "link.json"
    _rewrite(directory, manifest)
    with pytest.raises(InputError, match="outside"):
        load_intel(directory)


def test_matching_sha256_is_accepted(tmp_path: Path) -> None:
    directory = _full(tmp_path)
    manifest = _manifest(directory)
    manifest["sources"][0]["sha256"] = hashlib.sha256(
        (directory / "kev.json").read_bytes()
    ).hexdigest()
    _rewrite(directory, manifest)
    assert load_intel(directory).kev


def _kev_bad(change: Any) -> dict[str, Any]:
    data = kev(CVE_A)
    change(data)
    return data


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_kev_bad(lambda d: d.pop("dateReleased")), "dateReleased"),
        (_kev_bad(lambda d: d.update(count=5)), "count"),
        (_kev_bad(lambda d: d["vulnerabilities"][0].update(cveID="CVE-1")), "CVE id"),
        (_kev_bad(lambda d: d["vulnerabilities"][0].update(dateAdded="soon")), "date"),
        (_kev_bad(lambda d: d.update(vulnerabilities={})), "list"),
        (_kev_bad(lambda d: d.update(extra=True)), "unknown field"),
    ],
)
def test_malformed_kev_is_refused(tmp_path: Path, data: dict[str, Any], message: str) -> None:
    directory = write_snapshot(tmp_path / "intel", kev_data=data)
    with pytest.raises(InputError, match=message):
        load_intel(directory)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("cve,epss,percentile\nCVE-2099-0001,0.1,0.5\n", "model_version"),
        ("#model_version:v1,score_date:2026-10-04T00:00:00+0000\ncve,score\n", "header"),
        (epss({CVE_A: 0.1}).replace("0.10000", "1.5"), "outside 0 to 1"),
        (epss({CVE_A: 0.1}).replace("0.10000", "nan"), "outside 0 to 1"),
        (epss({CVE_A: 0.1}).replace("0.10000", "high"), "not a number"),
        (epss({CVE_A: 0.1}) + f"{CVE_A},0.2,0.5\n", "twice"),
        (epss({CVE_A: 0.1}) + "CVE-2099-0002,0.2\n", "3 columns"),
        (epss({CVE_A: 0.1}, score_date="soon"), "score_date"),
    ],
)
def test_malformed_epss_is_refused(tmp_path: Path, text: str, message: str) -> None:
    directory = write_snapshot(tmp_path / "intel", epss_data=text)
    with pytest.raises(InputError, match=message):
        load_intel(directory)


def _nvd_bad(change: Any) -> dict[str, Any]:
    data = nvd({CVE_A: [("3.1", 9.8)]})
    change(data)
    return data


def _metric(data: dict[str, Any]) -> dict[str, Any]:
    metric: dict[str, Any] = data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    return metric


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_nvd_bad(lambda d: d.update(format="CVE")), "NVD CVE API 2.0"),
        (_nvd_bad(lambda d: d.update(version="1.0")), "NVD CVE API 2.0"),
        (_nvd_bad(lambda d: _metric(d)["cvssData"].update(baseScore=11)), "baseScore"),
        (_nvd_bad(lambda d: _metric(d)["cvssData"].update(baseScore=True)), "baseScore"),
        (_nvd_bad(lambda d: _metric(d)["cvssData"].update(version="3.0")), "expected 3.1"),
        (_nvd_bad(lambda d: _metric(d).pop("cvssData")), "cvssData"),
        (_nvd_bad(lambda d: d["vulnerabilities"].append(d["vulnerabilities"][0])), "twice"),
        (_nvd_bad(lambda d: d["vulnerabilities"][0].pop("cve")), "cve object"),
    ],
)
def test_malformed_nvd_is_refused(tmp_path: Path, data: dict[str, Any], message: str) -> None:
    directory = write_snapshot(tmp_path / "intel", nvd_data=data)
    with pytest.raises(InputError, match=message):
        load_intel(directory)


def test_one_malformed_file_refuses_the_whole_snapshot(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "intel", kev_data=kev(CVE_A), epss_data="not a csv\n")
    with pytest.raises(InputError, match=r"epss\.csv"):
        load_intel(directory)


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    from witness.security.limits import Limits

    directory = _full(tmp_path)
    with pytest.raises(InputError, match="limit"):
        load_intel(directory, Limits(max_bytes=100))


def test_freshness_uses_the_feed_date(tmp_path: Path) -> None:
    source = next(s for s in load_intel(_full(tmp_path)).sources if s.kind is IntelKind.KEV)
    assert freshness(source, AS_OF, 7).freshness is Freshness.CURRENT
    later = source.data_as_of + timedelta(days=7, seconds=1)
    assert freshness(source, later, 7).freshness is Freshness.OUTDATED
    assert freshness(source, source.data_as_of + timedelta(days=7), 7).freshness is (
        Freshness.CURRENT
    )
    earlier = source.data_as_of - timedelta(days=2)
    assert freshness(source, earlier, 7).freshness is Freshness.FUTURE
    status = freshness(source, source.data_as_of + timedelta(days=10), 7)
    assert status.age_days == 10 and status.max_age_days == 7


def test_retrieval_date_does_not_make_old_data_fresh(tmp_path: Path) -> None:
    directory = write_snapshot(
        tmp_path / "intel",
        kev_data=kev(CVE_A, released="2026-01-01T00:00:00Z"),
        entries={"kev": {"retrieved_at": "2026-10-04T00:00:00Z"}},
    )
    [source] = load_intel(directory).sources
    assert freshness(source, AS_OF, 7).freshness is Freshness.OUTDATED
