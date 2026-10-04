"""Builders for intelligence snapshot directories used in tests.

All data here is synthetic. CVE ids under CVE-2099 do not exist.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from witness.intel import IntelSnapshot, load_intel
from witness.priority import IntelContext, PriorityConfig

AS_OF = datetime(2026, 10, 4, 12, tzinfo=UTC)
CVE_A = "CVE-2099-0001"
CVE_B = "CVE-2099-0002"


def kev(*cves: str, released: str = "2026-10-04T08:00:00.000Z", **extra: Any) -> dict[str, Any]:
    return {
        "title": "test catalog",
        "catalogVersion": "2099.01.01",
        "dateReleased": released,
        "count": len(cves),
        "vulnerabilities": [
            {
                "cveID": cve,
                "vendorProject": "v",
                "product": "p",
                "vulnerabilityName": "n",
                "dateAdded": "2026-09-01",
                "dueDate": "2026-09-22",
                "knownRansomwareCampaignUse": "Unknown",
                **extra,
            }
            for cve in cves
        ],
    }


def epss(scores: dict[str, float], score_date: str = "2026-10-04T00:00:00+0000") -> str:
    rows = "".join(f"{cve},{value:.5f},0.50000\n" for cve, value in scores.items())
    return f"#model_version:v2025.03.14,score_date:{score_date}\ncve,epss,percentile\n{rows}"


def nvd(
    scores: dict[str, list[tuple[str, float]]], timestamp: str = "2026-10-04T06:00:00.000"
) -> dict[str, Any]:
    keys = {
        "4.0": "cvssMetricV40",
        "3.1": "cvssMetricV31",
        "3.0": "cvssMetricV30",
        "2.0": "cvssMetricV2",
    }
    vulnerabilities = []
    for cve, metrics in scores.items():
        grouped: dict[str, list[dict[str, Any]]] = {}
        for version, score in metrics:
            grouped.setdefault(keys[version], []).append(
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": version,
                        "vectorString": f"CVSS:{version}/AV:N",
                        "baseScore": score,
                    },
                }
            )
        vulnerabilities.append({"cve": {"id": cve, "metrics": grouped}})
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": 0,
        "totalResults": len(vulnerabilities),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": timestamp,
        "vulnerabilities": vulnerabilities,
    }


def source_entry(kind: str, path: str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "kind": kind,
        "path": path,
        "origin": "test data",
        "retrieved_at": "2026-10-04T09:00:00Z",
        "coverage": "full",
        "synthetic": True,
    }
    entry.update(overrides)
    return entry


def write_snapshot(
    directory: Path,
    *,
    kev_data: dict[str, Any] | None = None,
    epss_data: str | None = None,
    nvd_data: dict[str, Any] | None = None,
    entries: dict[str, dict[str, Any]] | None = None,
) -> Path:
    """Write the given feeds and a manifest. ``entries`` overrides manifest fields per kind."""
    directory.mkdir(parents=True, exist_ok=True)
    entries = entries or {}
    sources = []
    if kev_data is not None:
        (directory / "kev.json").write_text(json.dumps(kev_data))
        sources.append(source_entry("kev", "kev.json", **entries.get("kev", {})))
    if epss_data is not None:
        (directory / "epss.csv").write_text(epss_data)
        sources.append(source_entry("epss", "epss.csv", **entries.get("epss", {})))
    if nvd_data is not None:
        (directory / "nvd.json").write_text(json.dumps(nvd_data))
        sources.append(source_entry("cvss", "nvd.json", **entries.get("cvss", {})))
    manifest = {"schema": "witness.intel/1", "sources": sources}
    (directory / "intel.json").write_text(json.dumps(manifest))
    return directory


def context(
    directory: Path | None = None,
    *,
    as_of: datetime = AS_OF,
    config: PriorityConfig | None = None,
) -> IntelContext:
    snapshot = load_intel(directory) if directory is not None else IntelSnapshot.empty()
    return IntelContext(snapshot, as_of, config)
