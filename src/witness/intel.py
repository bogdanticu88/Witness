"""Offline vulnerability intelligence: CVSS, CISA KEV and EPSS snapshots.

An intelligence snapshot is a directory the operator prepares in advance.
Witness never downloads anything. The directory holds an ``intel.json``
manifest (``witness.intel/1``) that lists each data file with where it came
from, when it was retrieved, whether it covers the whole feed and whether it
is synthetic. The data files keep their published formats:

- ``kev``: the CISA Known Exploited Vulnerabilities catalog JSON.
- ``epss``: the FIRST EPSS daily CSV, plain or gzip, with its
  ``#model_version:...,score_date:...`` comment line.
- ``cvss``: an NVD CVE API 2.0 response (``format`` ``NVD_CVE``).

Every file is validated as a whole and refused if any part is malformed,
like a scanner report. Intelligence feeds priority only; it never changes an
assessment.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from witness.errors import InputError, UsageError
from witness.security.limits import DEFAULT_LIMITS, Limits, load_json, loads_json, read_bounded

INTEL_SCHEMA = "witness.intel/1"
MANIFEST = "intel.json"

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EPSS_COMMENT = re.compile(r"^#model_version:(?P<model>[^,]+),score_date:(?P<date>\S+)$")


class IntelKind(StrEnum):
    KEV = "kev"
    EPSS = "epss"
    CVSS = "cvss"


class Freshness(StrEnum):
    CURRENT = "current"
    OUTDATED = "outdated"
    # Dated after the evaluation time: a clock or data problem.
    FUTURE = "future"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class IntelSource(_Model):
    """Provenance of one data file in a snapshot."""

    kind: IntelKind
    path: str
    sha256: str
    origin: str
    retrieved_at: datetime
    # The feed's own date: KEV dateReleased, EPSS score_date, NVD timestamp.
    data_as_of: datetime
    coverage: Literal["full", "partial"]
    synthetic: bool
    records: int
    detail: str
    note: str | None = None


class SourceStatus(_Model):
    """A source as judged at one evaluation time."""

    source: IntelSource
    freshness: Freshness
    age_days: float
    max_age_days: int


@dataclass(frozen=True)
class KevEntry:
    cve: str
    date_added: date
    due_date: date | None
    ransomware: str | None
    source: IntelSource


@dataclass(frozen=True)
class EpssScore:
    cve: str
    probability: float
    percentile: float
    model_version: str
    source: IntelSource


@dataclass(frozen=True)
class CvssScore:
    cve: str
    version: str
    base_score: float
    vector: str
    # Who scored it, as NVD records it (NVD itself or the CNA), and whether
    # NVD lists it as Primary or Secondary.
    scored_by: str
    score_type: str
    source: IntelSource


@dataclass
class IntelSnapshot:
    root: Path | None
    sources: list[IntelSource] = field(default_factory=list)
    kev: dict[str, list[KevEntry]] = field(default_factory=dict)
    epss: dict[str, list[EpssScore]] = field(default_factory=dict)
    cvss: dict[str, list[CvssScore]] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> IntelSnapshot:
        return cls(root=None)

    def sources_of(self, kind: IntelKind) -> list[IntelSource]:
        return [s for s in self.sources if s.kind is kind]


def freshness(source: IntelSource, as_of: datetime, max_age_days: int) -> SourceStatus:
    age = as_of - source.data_as_of
    # A day of slack absorbs time zones in date-only feed stamps.
    if age < -timedelta(days=1):
        state = Freshness.FUTURE
    elif age > timedelta(days=max_age_days):
        state = Freshness.OUTDATED
    else:
        state = Freshness.CURRENT
    return SourceStatus(
        source=source,
        freshness=state,
        age_days=round(age.total_seconds() / 86400, 2),
        max_age_days=max_age_days,
    )


def load_intel(directory: Path, limits: Limits = DEFAULT_LIMITS) -> IntelSnapshot:
    """Load and validate a snapshot directory. Any malformed part refuses all of it."""
    directory = Path(directory)
    manifest_path = directory / MANIFEST
    if not directory.is_dir():
        raise UsageError(f"intelligence directory not found: {directory}")
    if not manifest_path.is_file():
        raise UsageError(
            f"no {MANIFEST} in {directory}",
            hint="an intelligence snapshot needs a witness.intel/1 manifest listing its files",
        )
    manifest = load_json(manifest_path, limits)
    label = str(manifest_path)
    _require_keys(manifest, label, required={"schema", "sources"}, optional={"note"})
    if manifest["schema"] != INTEL_SCHEMA:
        raise InputError(f"{label}: schema must be {INTEL_SCHEMA!r}, got {manifest['schema']!r}")
    entries = manifest["sources"]
    if not isinstance(entries, list) or not entries:
        raise InputError(f"{label}: sources must be a non-empty list")
    snapshot = IntelSnapshot(root=directory.resolve())
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{label}: sources[{index}]"
        _require_keys(
            entry,
            where,
            required={"kind", "path", "origin", "retrieved_at", "coverage", "synthetic"},
            optional={"sha256", "note"},
        )
        try:
            kind = IntelKind(entry["kind"])
        except ValueError:
            raise InputError(f"{where}: kind must be kev, epss or cvss") from None
        rel = _text(entry["path"], f"{where}.path")
        if rel in seen:
            raise InputError(f"{where}: {rel} is listed twice")
        seen.add(rel)
        path = _confined(directory, rel, where)
        if entry["coverage"] not in ("full", "partial"):
            raise InputError(f"{where}: coverage must be 'full' or 'partial'")
        if not isinstance(entry["synthetic"], bool):
            raise InputError(f"{where}: synthetic must be true or false")
        data = read_bounded(path, limits)
        digest = hashlib.sha256(data).hexdigest()
        expected = entry.get("sha256")
        if expected is not None:
            if not isinstance(expected, str) or not _SHA256.match(expected):
                raise InputError(f"{where}: sha256 must be 64 lowercase hex digits")
            if expected != digest:
                raise InputError(f"{where}: {rel} does not match its recorded sha256")
        base = {
            "kind": kind,
            "path": rel,
            "sha256": digest,
            "origin": _text(entry["origin"], f"{where}.origin"),
            "retrieved_at": _timestamp(entry["retrieved_at"], f"{where}.retrieved_at"),
            "coverage": entry["coverage"],
            "synthetic": entry["synthetic"],
            "note": _optional_text(entry.get("note"), f"{where}.note"),
        }
        file_label = f"{directory / rel}"
        if kind is IntelKind.KEV:
            _load_kev(snapshot, data, file_label, base, limits)
        elif kind is IntelKind.EPSS:
            _load_epss(snapshot, data, file_label, base, limits)
        else:
            _load_cvss(snapshot, data, file_label, base, limits)
    return snapshot


# -- KEV -----------------------------------------------------------------------


def _load_kev(
    snapshot: IntelSnapshot, data: bytes, label: str, base: dict[str, Any], limits: Limits
) -> None:
    document = loads_json(data, label, limits)
    _require_keys(
        document,
        label,
        required={"catalogVersion", "dateReleased", "vulnerabilities"},
        optional={"title", "count"},
    )
    released = _timestamp(document["dateReleased"], f"{label}: dateReleased")
    items = document["vulnerabilities"]
    if not isinstance(items, list):
        raise InputError(f"{label}: vulnerabilities must be a list")
    count = document.get("count")
    if count is not None and count != len(items):
        raise InputError(f"{label}: count is {count} but {len(items)} entries are listed")
    source = IntelSource(
        **base,
        data_as_of=released,
        records=len(items),
        detail=f"CISA KEV catalog {_text(document['catalogVersion'], label + ': catalogVersion')}",
    )
    entries: dict[str, list[KevEntry]] = {}
    for index, item in enumerate(items):
        where = f"{label}: vulnerabilities[{index}]"
        if not isinstance(item, dict):
            raise InputError(f"{where} is not an object")
        cve = _cve(item.get("cveID"), f"{where}.cveID")
        due = item.get("dueDate")
        ransomware = item.get("knownRansomwareCampaignUse")
        entries.setdefault(cve, []).append(
            KevEntry(
                cve=cve,
                date_added=_date(item.get("dateAdded"), f"{where}.dateAdded"),
                due_date=_date(due, f"{where}.dueDate") if due is not None else None,
                ransomware=_optional_text(ransomware, f"{where}.knownRansomwareCampaignUse"),
                source=source,
            )
        )
    snapshot.sources.append(source)
    for cve, found in entries.items():
        snapshot.kev.setdefault(cve, []).extend(found)


# -- EPSS ----------------------------------------------------------------------


def _load_epss(
    snapshot: IntelSnapshot, data: bytes, label: str, base: dict[str, Any], limits: Limits
) -> None:
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
                data = handle.read(limits.max_bytes + 1)
        except (OSError, EOFError) as exc:
            raise InputError(f"{label}: not a valid gzip file ({exc})") from exc
        if len(data) > limits.max_bytes:
            raise InputError(f"{label}: over the {limits.max_bytes} byte limit when unpacked")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{label}: not UTF-8 text") from exc
    lines = text.splitlines()
    if not lines:
        raise InputError(f"{label}: empty file")
    comment = _EPSS_COMMENT.match(lines[0].strip())
    if comment is None:
        raise InputError(
            f"{label}: first line must be '#model_version:...,score_date:...' as FIRST publishes"
        )
    score_date = _timestamp(comment["date"], f"{label}: score_date")
    rows = list(csv.reader(lines[1:]))
    if not rows or [c.strip() for c in rows[0]] != ["cve", "epss", "percentile"]:
        raise InputError(f"{label}: header must be cve,epss,percentile")
    if len(rows) - 1 > limits.max_items:
        raise InputError(f"{label}: more than {limits.max_items} rows")
    source = IntelSource(
        **base,
        data_as_of=score_date,
        records=len(rows) - 1,
        detail=f"FIRST EPSS model {comment['model']}",
    )
    scores: dict[str, EpssScore] = {}
    for number, row in enumerate(rows[1:], start=3):
        where = f"{label}: line {number}"
        if len(row) != 3:
            raise InputError(f"{where}: expected 3 columns")
        cve = _cve(row[0].strip(), where)
        if cve in scores:
            raise InputError(f"{where}: {cve} appears twice")
        scores[cve] = EpssScore(
            cve=cve,
            probability=_unit(row[1], f"{where} epss"),
            percentile=_unit(row[2], f"{where} percentile"),
            model_version=comment["model"],
            source=source,
        )
    snapshot.sources.append(source)
    for cve, score in scores.items():
        snapshot.epss.setdefault(cve, []).append(score)


# -- CVSS (NVD CVE API 2.0) ----------------------------------------------------

_NVD_METRICS = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV30": "3.0",
    "cvssMetricV2": "2.0",
}


def _load_cvss(
    snapshot: IntelSnapshot, data: bytes, label: str, base: dict[str, Any], limits: Limits
) -> None:
    document = loads_json(data, label, limits)
    _require_keys(
        document,
        label,
        required={"format", "version", "timestamp", "vulnerabilities"},
        optional={"resultsPerPage", "startIndex", "totalResults"},
    )
    if document["format"] != "NVD_CVE" or document["version"] != "2.0":
        raise InputError(f"{label}: expected an NVD CVE API 2.0 response (format NVD_CVE, 2.0)")
    # NVD documents its timestamps as UTC and writes them without a zone.
    timestamp = _timestamp(document["timestamp"], f"{label}: timestamp", naive_utc=True)
    items = document["vulnerabilities"]
    if not isinstance(items, list):
        raise InputError(f"{label}: vulnerabilities must be a list")
    source = IntelSource(**base, data_as_of=timestamp, records=len(items), detail="NVD CVE API 2.0")
    scores: dict[str, list[CvssScore]] = {}
    for index, item in enumerate(items):
        where = f"{label}: vulnerabilities[{index}]"
        cve_record = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve_record, dict):
            raise InputError(f"{where}: missing cve object")
        cve = _cve(cve_record.get("id"), f"{where}.cve.id")
        if cve in scores:
            raise InputError(f"{where}: {cve} appears twice")
        metrics = cve_record.get("metrics", {})
        if not isinstance(metrics, dict):
            raise InputError(f"{where}.cve.metrics must be an object")
        found: list[CvssScore] = []
        for key, version in _NVD_METRICS.items():
            entries = metrics.get(key, [])
            if not isinstance(entries, list):
                raise InputError(f"{where}.cve.metrics.{key} must be a list")
            for n, metric in enumerate(entries):
                found.append(_nvd_metric(metric, cve, version, f"{where}.{key}[{n}]", source))
        scores[cve] = found
    snapshot.sources.append(source)
    for cve, found in scores.items():
        snapshot.cvss.setdefault(cve, []).extend(found)


def _nvd_metric(
    metric: object, cve: str, version: str, where: str, source: IntelSource
) -> CvssScore:
    if not isinstance(metric, dict) or not isinstance(metric.get("cvssData"), dict):
        raise InputError(f"{where}: missing cvssData")
    data = metric["cvssData"]
    declared = data.get("version")
    if declared != version:
        raise InputError(f"{where}: cvssData.version is {declared!r}, expected {version}")
    score = data.get("baseScore")
    if isinstance(score, bool) or not isinstance(score, int | float) or not 0 <= score <= 10:
        raise InputError(f"{where}: baseScore must be a number from 0 to 10")
    vector = _text(data.get("vectorString"), f"{where}.vectorString")
    return CvssScore(
        cve=cve,
        version=version,
        base_score=float(score),
        vector=vector,
        scored_by=_text(metric.get("source"), f"{where}.source"),
        score_type=_text(metric.get("type"), f"{where}.type"),
        source=source,
    )


# -- validation helpers --------------------------------------------------------


def _require_keys(value: object, label: str, *, required: set[str], optional: set[str]) -> None:
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected an object")
    missing = sorted(required - value.keys())
    if missing:
        raise InputError(f"{label}: missing {', '.join(missing)}")
    unknown = sorted(value.keys() - required - optional)
    if unknown:
        raise InputError(f"{label}: unknown field {', '.join(unknown)}")


def _confined(directory: Path, rel: str, where: str) -> Path:
    candidate = Path(rel)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise InputError(f"{where}: path must stay inside the snapshot directory")
    root = directory.resolve()
    path = (root / candidate).resolve()
    if not path.is_relative_to(root):
        raise InputError(f"{where}: {rel} resolves outside the snapshot directory")
    if not path.is_file():
        raise InputError(f"{where}: {rel} not found")
    return path


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label}: expected non-empty text")
    return value.strip()


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _timestamp(value: object, label: str, *, naive_utc: bool = False) -> datetime:
    text = _text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise InputError(f"{label}: {text!r} is not an ISO 8601 timestamp") from None
    if parsed.tzinfo is None:
        if len(text) == 10 or naive_utc:
            return parsed.replace(tzinfo=UTC)
        raise InputError(f"{label}: {text!r} has no time zone")
    return parsed.astimezone(UTC)


def _date(value: object, label: str) -> date:
    text = _text(value, label)
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise InputError(f"{label}: {text!r} is not a date") from None


def _cve(value: object, label: str) -> str:
    if not isinstance(value, str) or not _CVE.match(value.strip()):
        raise InputError(f"{label}: {value!r} is not a CVE id")
    return value.strip()


def _unit(value: str, label: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise InputError(f"{label}: {value!r} is not a number") from None
    if not 0.0 <= number <= 1.0:
        raise InputError(f"{label}: {number} is outside 0 to 1")
    return number
