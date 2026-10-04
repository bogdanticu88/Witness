"""Deterministic remediation priority, separate from assessment.

Rules (``witness-priority/1``), applied in this order:

1. ``base.severity``: the most severe of the scanner's severity and any CVSS
   v3/v4 base score in the intelligence snapshot, banded as the CVSS
   specification does (critical 9.0+, high 7.0+, medium 4.0+, low below).
   Critical is P1, high P2, medium P3, low and info P4. An unknown severity
   counts as high so it is never ranked down.
2. ``raise.epss``: an EPSS probability at or above the configured threshold
   raises the level by one.
3. ``raise.kev``: a CISA KEV listing makes it P1.
4. ``lower.likely_false_positive``: a complete deterministic
   ``likely_false_positive`` assessment sets P4, conditional on the
   assessment's assumptions. Configurable.

Intelligence that is missing, outdated or partial is listed as unknown with
what it could change. Outdated data can still raise a level (a KEV listing
does not stop being one), but never rules anything out, and nothing unknown
lowers a level. The assessment is read, never changed.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from witness.errors import ConfigError
from witness.intel import (
    CvssScore,
    Freshness,
    IntelKind,
    IntelSnapshot,
    IntelSource,
    SourceStatus,
    freshness,
)
from witness.model.assessment import (
    Assessment,
    AssessmentStatus,
    Priority,
    PriorityFactor,
    PriorityLevel,
    PriorityRule,
)
from witness.model.finding import Finding, FindingKind, Severity

RULES_VERSION = "witness-priority/1"

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_LEVELS = (PriorityLevel.P1, PriorityLevel.P2, PriorityLevel.P3, PriorityLevel.P4)
_SEVERITY_LEVEL = {
    Severity.CRITICAL: PriorityLevel.P1,
    Severity.HIGH: PriorityLevel.P2,
    Severity.UNKNOWN: PriorityLevel.P2,
    Severity.MEDIUM: PriorityLevel.P3,
    Severity.LOW: PriorityLevel.P4,
    Severity.INFO: PriorityLevel.P4,
}
# CVSS v2 bands differ from v3 and v4 and are not used for the level.
_BANDED_VERSIONS = ("3.0", "3.1", "4.0")


@dataclass(frozen=True)
class PriorityConfig:
    """Operator-tunable settings. The defaults are Witness's, not a vendor's.

    ``epss_threshold`` 0.1 (a 10% modeled chance of exploitation activity in
    the next 30 days) is a starting point; FIRST publishes no cut-off.
    Freshness limits follow how often each feed is published: KEV and EPSS
    change daily, so a week; NVD scores change rarely, so 30 days.
    """

    epss_threshold: float = 0.1
    lower_likely_false_positive: bool = True
    max_age_days: dict[IntelKind, int] = field(
        default_factory=lambda: {IntelKind.KEV: 7, IntelKind.EPSS: 7, IntelKind.CVSS: 30}
    )

    @classmethod
    def load(cls, path: Path) -> PriorityConfig:
        try:
            document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"cannot read priority config {path}: {exc.strerror}") from exc
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{path}: not valid TOML ({exc})") from exc
        return cls.from_dict(document, str(path))

    @classmethod
    def from_dict(cls, document: dict[str, Any], label: str = "priority config") -> PriorityConfig:
        unknown = sorted(document.keys() - {"priority", "freshness"})
        if unknown:
            raise ConfigError(f"{label}: unknown section {', '.join(unknown)}")
        rules = document.get("priority", {})
        ages = document.get("freshness", {})
        if not isinstance(rules, dict) or not isinstance(ages, dict):
            raise ConfigError(f"{label}: [priority] and [freshness] must be tables")
        extra = sorted(rules.keys() - {"epss_threshold", "lower_likely_false_positive"})
        extra += sorted(f"freshness.{k}" for k in ages.keys() - {k.value for k in IntelKind})
        if extra:
            raise ConfigError(f"{label}: unknown setting {', '.join(extra)}")
        default = cls()
        threshold = rules.get("epss_threshold", default.epss_threshold)
        if isinstance(threshold, bool) or not isinstance(threshold, int | float):
            raise ConfigError(f"{label}: epss_threshold must be a number")
        if not 0 < threshold <= 1:
            raise ConfigError(f"{label}: epss_threshold must be above 0 and at most 1")
        lower = rules.get("lower_likely_false_positive", default.lower_likely_false_positive)
        if not isinstance(lower, bool):
            raise ConfigError(f"{label}: lower_likely_false_positive must be true or false")
        max_age = dict(default.max_age_days)
        for key, value in ages.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ConfigError(f"{label}: freshness.{key} must be a whole number of days, 1+")
            max_age[IntelKind(key)] = value
        return cls(
            epss_threshold=float(threshold), lower_likely_false_positive=lower, max_age_days=max_age
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "priority": {
                "epss_threshold": self.epss_threshold,
                "lower_likely_false_positive": self.lower_likely_false_positive,
            },
            "freshness": {k.value: v for k, v in sorted(self.max_age_days.items())},
        }

    def digest(self) -> str:
        text = json.dumps(self.as_dict(), sort_keys=True)
        return hashlib.sha256(text.encode()).hexdigest()[:16]


class IntelContext:
    """A snapshot judged at one evaluation time, with the settings in force."""

    def __init__(
        self, snapshot: IntelSnapshot, as_of: datetime, config: PriorityConfig | None = None
    ) -> None:
        self.snapshot = snapshot
        self.as_of = as_of
        self.config = config or PriorityConfig()
        self.statuses = {
            s.path: freshness(s, as_of, self.config.max_age_days[s.kind]) for s in snapshot.sources
        }

    def status(self, source: IntelSource) -> SourceStatus:
        return self.statuses[source.path]

    def current(self, source: IntelSource) -> bool:
        return self.status(source).freshness is Freshness.CURRENT


def cvss_band(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def compute_priority(finding: Finding, assessment: Assessment, intel: IntelContext) -> Priority:
    return _Builder(finding, assessment, intel).build()


class _Builder:
    def __init__(self, finding: Finding, assessment: Assessment, intel: IntelContext) -> None:
        self.finding = finding
        self.assessment = assessment
        self.intel = intel
        self.factors: list[PriorityFactor] = []
        self.rules: list[PriorityRule] = []
        self.unknown: list[str] = []
        self.conflicts: list[str] = []
        self.conditional: list[str] = []

    def build(self) -> Priority:
        finding = self.finding
        scanner = PriorityFactor(
            name="scanner_severity",
            value=finding.severity.value
            + (f" (reported as {finding.severity_original})" if finding.severity_original else ""),
            source=f"scanner:{finding.scanner.name}",
        )
        self.factors.append(scanner)
        if finding.severity is Severity.UNKNOWN:
            self.unknown.append(
                "severity: the scanner gave no usable severity; counted as high so it is not "
                "ranked down"
            )
        severities: list[tuple[Severity, str, str]] = [
            (finding.severity, "scanner_severity", f"scanner severity {finding.severity.value}")
        ]
        epss_hits: list[str] = []
        kev_hits: list[str] = []
        if finding.kind is FindingKind.DEPENDENCY:
            cves = sorted({i for i in finding.vulnerability_ids if _CVE.match(i)})
            if not cves:
                self.unknown.append(
                    "intelligence: the finding has no CVE id, so CVSS, KEV and EPSS cannot be "
                    "looked up"
                )
            for cve in cves:
                severities.extend(self._cvss(cve))
                kev_hits.extend(self._kev(cve))
                epss_hits.extend(self._epss(cve))

        level = self._base(severities)
        if epss_hits:
            raised = _LEVELS[max(_LEVELS.index(level) - 1, 0)]
            self.rules.append(
                PriorityRule(
                    rule="raise.epss",
                    level=raised,
                    inputs=("epss",),
                    detail=f"{'; '.join(epss_hits)} at or above the threshold "
                    f"{self.intel.config.epss_threshold}; raised one level",
                )
            )
            level = raised
        if kev_hits:
            level = PriorityLevel.P1
            self.rules.append(
                PriorityRule(
                    rule="raise.kev",
                    level=level,
                    inputs=("kev",),
                    detail=f"{'; '.join(kev_hits)}: known exploited, so P1",
                )
            )
        level = self._assessment(level)
        return Priority(
            finding_id=finding.id,
            level=level,
            rules=tuple(self.rules),
            factors=tuple(self.factors),
            unknown=tuple(dict.fromkeys(self.unknown)),
            conflicts=tuple(dict.fromkeys(self.conflicts)),
            conditional_on=tuple(self.conditional),
            rules_version=RULES_VERSION,
            evaluated_at=self.intel.as_of,
        )

    # -- severity --------------------------------------------------------------

    def _base(self, severities: list[tuple[Severity, str, str]]) -> PriorityLevel:
        level = min(_SEVERITY_LEVEL[s] for s, _, _ in severities)
        deciding = [(n, d) for s, n, d in severities if _SEVERITY_LEVEL[s] == level]
        bands = {s for s, _, _ in severities if s is not Severity.UNKNOWN}
        if len(bands) > 1:
            self.conflicts.append(
                "severity sources disagree: " + "; ".join(d for _, _, d in severities)
            )
        detail = "; ".join(d for _, d in deciding)
        if len(severities) > 1:
            detail = f"most severe input: {detail}"
        self.rules.append(
            PriorityRule(
                rule="base.severity",
                level=level,
                inputs=tuple(dict.fromkeys(n for n, _ in deciding)),
                detail=detail,
            )
        )
        return level

    def _cvss(self, cve: str) -> list[tuple[Severity, str, str]]:
        sources = self.intel.snapshot.sources_of(IntelKind.CVSS)
        if not sources:
            self.unknown.append(
                f"cvss: no CVSS source in the intelligence snapshot for {cve}; the level rests "
                "on the scanner severity"
            )
            return []
        found: list[tuple[Severity, str, str]] = []
        for score in self.intel.snapshot.cvss.get(cve, []):
            banded = score.version in _BANDED_VERSIONS
            band = cvss_band(score.base_score)
            self.factors.append(self._cvss_factor(score, band, banded))
            if banded:
                state = self.intel.status(score.source).freshness
                note = "" if state is Freshness.CURRENT else f", {state.value} source"
                found.append(
                    (
                        band,
                        "cvss",
                        f"{cve} CVSS {score.version} {score.base_score} {band.value} by "
                        f"{score.scored_by}{note}",
                    )
                )
        if not found:
            listed = any(self.intel.current(s) for s in sources)
            self.unknown.append(
                f"cvss: no CVSS v3 or v4 score for {cve} in "
                f"{'the snapshot' if listed else 'a current source'}; a score above the scanner "
                "severity would raise the level"
            )
        elif not any(self.intel.current(s) for s in sources):
            self.unknown.append(
                f"cvss: the CVSS data for {cve} is outdated; a newer score could be higher"
            )
        return found

    def _cvss_factor(self, score: CvssScore, band: Severity, banded: bool) -> PriorityFactor:
        return PriorityFactor(
            name="cvss",
            value=f"{score.cve} CVSS {score.version} {score.base_score} ({band.value}) "
            f"{score.vector} by {score.scored_by} ({score.score_type})",
            **self._source_fields(score.source),
            used=banded,
        )

    # -- KEV -------------------------------------------------------------------

    def _kev(self, cve: str) -> list[str]:
        sources = self.intel.snapshot.sources_of(IntelKind.KEV)
        entries = self.intel.snapshot.kev.get(cve, [])
        for entry in entries:
            due = f", due {entry.due_date}" if entry.due_date else ""
            ransomware = f", ransomware use {entry.ransomware}" if entry.ransomware else ""
            self.factors.append(
                PriorityFactor(
                    name="kev",
                    value=f"{cve} listed, added {entry.date_added}{due}{ransomware}",
                    **self._source_fields(entry.source),
                )
            )
        if entries:
            return [f"{cve} is in the CISA KEV catalog"]
        complete = [s for s in sources if s.coverage == "full" and self.intel.current(s)]
        if complete:
            for source in complete:
                self.factors.append(
                    PriorityFactor(
                        name="kev",
                        value=f"{cve} not listed",
                        **self._source_fields(source),
                        used=False,
                    )
                )
            return []
        why = (
            "; ".join(self._why_not_conclusive(s) for s in sources)
            if sources
            else "no KEV source in the intelligence snapshot"
        )
        self.unknown.append(f"kev: listing of {cve} not established ({why}); a listing makes it P1")
        return []

    # -- EPSS ------------------------------------------------------------------

    def _epss(self, cve: str) -> list[str]:
        sources = self.intel.snapshot.sources_of(IntelKind.EPSS)
        threshold = self.intel.config.epss_threshold
        hits: list[str] = []
        current_low = False
        for score in self.intel.snapshot.epss.get(cve, []):
            above = score.probability >= threshold
            self.factors.append(
                PriorityFactor(
                    name="epss",
                    value=f"{cve} {score.probability:.5f} (percentile {score.percentile:.5f}, "
                    f"model {score.model_version})",
                    **self._source_fields(score.source),
                    used=above,
                )
            )
            if above:
                hits.append(f"{cve} EPSS {score.probability:.5f}")
            elif self.intel.current(score.source):
                current_low = True
        if hits or current_low:
            return hits
        if not sources:
            why = "no EPSS source in the intelligence snapshot"
        elif cve in self.intel.snapshot.epss:
            why = "only an outdated score below the threshold"
        else:
            why = "; ".join(self._why_not_conclusive(s) for s in sources)
        self.unknown.append(
            f"epss: probability for {cve} not established ({why}); a score at or above "
            f"{threshold} raises the level by one"
        )
        return []

    # -- assessment ------------------------------------------------------------

    def _assessment(self, level: PriorityLevel) -> PriorityLevel:
        assessment = self.assessment
        status = assessment.status
        self.factors.append(
            PriorityFactor(
                name="assessment",
                value=status.value + ("" if assessment.complete else " (incomplete)"),
                source="witness:" + assessment.analysis_version,
                used=status is AssessmentStatus.LIKELY_FALSE_POSITIVE,
            )
        )
        if not assessment.complete:
            self.unknown.append(
                "assessment: the analysis was cut short, so the finding may be real; the level "
                "is not lowered"
            )
            return level
        if status is AssessmentStatus.LIKELY_FALSE_POSITIVE:
            self.conditional.extend(assessment.assumptions)
            if not self.intel.config.lower_likely_false_positive:
                return level
            conditions = (
                f"; holds only if: {'; '.join(assessment.assumptions)}"
                if assessment.assumptions
                else ""
            )
            self.rules.append(
                PriorityRule(
                    rule="lower.likely_false_positive",
                    level=PriorityLevel.P4,
                    inputs=("assessment",),
                    detail=f"a deterministic check found the reported value cannot carry an "
                    f"attack ({', '.join(assessment.reason_codes)}){conditions}",
                )
            )
            return PriorityLevel.P4
        if status is AssessmentStatus.INCONCLUSIVE:
            self.unknown.append(
                "assessment: inconclusive, so whether the finding is real is not established; "
                "the level is not lowered"
            )
        elif status is AssessmentStatus.STALE:
            self.unknown.append(
                "assessment: stale, the finding may describe another revision; the level is "
                "not lowered"
            )
        elif status is AssessmentStatus.NOT_ASSESSED:
            self.unknown.append(
                f"assessment: {self.finding.kind.value} finding without a code verdict; the "
                "level rests on the scanner"
            )
        return level

    # -- helpers ---------------------------------------------------------------

    def _source_fields(self, source: IntelSource) -> dict[str, Any]:
        status = self.intel.status(source)
        return {
            "source": f"intel:{source.kind.value} {source.path}",
            "as_of": source.data_as_of,
            "freshness": status.freshness.value,
            "synthetic": source.synthetic,
        }

    def _why_not_conclusive(self, source: IntelSource) -> str:
        status = self.intel.status(source)
        if status.freshness is not Freshness.CURRENT:
            return (
                f"{source.path} is {status.freshness.value} ({status.age_days} days old, "
                f"limit {status.max_age_days})"
            )
        if source.coverage == "partial":
            return f"{source.path} covers only part of the feed"
        return f"{source.path} has no entry for it"
