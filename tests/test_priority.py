"""Priority rules: separate from assessment, explicit about what is unknown."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from factories import dependency, runtime, source
from fakes import tainted, triage_run
from intel_builders import AS_OF, CVE_A, CVE_B, context, epss, kev, nvd, write_snapshot
from witness.errors import ConfigError, ExitCode
from witness.intel import IntelKind
from witness.model.assessment import (
    Assessment,
    AssessmentBasis,
    AssessmentStatus,
    Priority,
    PriorityLevel,
)
from witness.model.finding import Finding, Severity
from witness.priority import PriorityConfig, compute_priority, cvss_band

P1, P2, P3, P4 = PriorityLevel.P1, PriorityLevel.P2, PriorityLevel.P3, PriorityLevel.P4


def _assessment(
    status: AssessmentStatus = AssessmentStatus.INCONCLUSIVE,
    *,
    complete: bool = True,
    assumptions: tuple[str, ...] = (),
    finding_id: str = "f-1",
) -> Assessment:
    return Assessment(
        finding_id=finding_id,
        status=status,
        basis=AssessmentBasis.DETERMINISTIC,
        reason_codes=("test",),
        explanation="test",
        assumptions=assumptions,
        profile="none",
        complete=complete,
        analysis_version="witness-triage/1",
        assessed_at=AS_OF,
    )


def _dep(*cves: str, severity: Severity = Severity.HIGH) -> Finding:
    finding = dependency("f-1", severity=severity)
    return finding.model_copy(update={"vulnerability_ids": (*cves, "GHSA-xxxx-xxxx-xxxx")})


def _priority(finding: Finding, directory: Path | None = None, **kwargs: Any) -> Priority:
    status = kwargs.pop("status", AssessmentStatus.INCONCLUSIVE)
    return compute_priority(finding, _assessment(status), context(directory, **kwargs))


def _rules(priority: Priority) -> list[str]:
    return [r.rule for r in priority.rules]


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, P1),
        (Severity.HIGH, P2),
        (Severity.MEDIUM, P3),
        (Severity.LOW, P4),
        (Severity.INFO, P4),
    ],
)
def test_base_level_follows_scanner_severity(severity: Severity, level: PriorityLevel) -> None:
    priority = _priority(source("f-1", severity=severity))
    assert priority.level is level
    assert priority.rules[0].rule == "base.severity"
    assert priority.rules[0].inputs == ("scanner_severity",)


def test_unknown_severity_is_ranked_as_high_and_listed() -> None:
    priority = _priority(source("f-1", severity=Severity.UNKNOWN))
    assert priority.level is P2
    assert any(u.startswith("severity:") for u in priority.unknown)


@pytest.mark.parametrize(
    ("score", "band"),
    [(10.0, Severity.CRITICAL), (9.0, Severity.CRITICAL), (8.9, Severity.HIGH),
     (7.0, Severity.HIGH), (6.9, Severity.MEDIUM), (4.0, Severity.MEDIUM),
     (3.9, Severity.LOW), (0.1, Severity.LOW), (0.0, Severity.INFO)],
)  # fmt: skip
def test_cvss_bands_follow_the_specification(score: float, band: Severity) -> None:
    assert cvss_band(score) is band


def test_no_intelligence_lists_every_factor_and_keeps_the_scanner_level() -> None:
    priority = _priority(_dep(CVE_A))
    assert priority.level is P2
    for name in ("cvss:", "kev:", "epss:"):
        assert any(u.startswith(name) and "no " in u for u in priority.unknown), name
    assert _rules(priority) == ["base.severity"]


def test_dependency_without_a_cve_says_intelligence_cannot_be_looked_up(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", kev_data=kev(CVE_A))
    priority = _priority(dependency("f-1"), directory)
    assert any("no CVE id" in u for u in priority.unknown)


def test_cvss_above_the_scanner_raises_and_records_the_conflict(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", nvd_data=nvd({CVE_A: [("3.1", 9.8)]}))
    priority = _priority(_dep(CVE_A), directory)
    assert priority.level is P1
    assert priority.rules[0].inputs == ("cvss",)
    assert any("scanner severity high" in c and "9.8 critical" in c for c in priority.conflicts)


def test_cvss_below_the_scanner_never_lowers(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", nvd_data=nvd({CVE_A: [("3.1", 5.3)]}))
    priority = _priority(_dep(CVE_A), directory)
    assert priority.level is P2
    assert priority.rules[0].inputs == ("scanner_severity",)
    assert priority.conflicts
    assert not any(u.startswith("cvss:") for u in priority.unknown)


def test_cvss_v2_is_recorded_but_not_used(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", nvd_data=nvd({CVE_A: [("2.0", 10.0)]}))
    priority = _priority(_dep(CVE_A, severity=Severity.MEDIUM), directory)
    assert priority.level is P3
    [factor] = [f for f in priority.factors if f.name == "cvss"]
    assert not factor.used and factor.synthetic
    assert any("no CVSS v3 or v4" in u for u in priority.unknown)


def test_outdated_cvss_can_raise_but_is_flagged(tmp_path: Path) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        nvd_data=nvd({CVE_A: [("3.1", 9.8)]}, timestamp="2026-01-01T00:00:00"),
    )
    priority = _priority(_dep(CVE_A), directory)
    assert priority.level is P1
    assert "outdated" in priority.rules[0].detail
    assert any("outdated" in u for u in priority.unknown)


def test_kev_listing_makes_it_p1(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", kev_data=kev(CVE_A))
    priority = _priority(_dep(CVE_A, severity=Severity.LOW), directory)
    assert priority.level is P1
    assert _rules(priority) == ["base.severity", "raise.kev"]
    [factor] = [f for f in priority.factors if f.name == "kev"]
    assert "listed" in factor.value and factor.freshness == "current"


@pytest.mark.parametrize("entries", [{"coverage": "partial"}, {}])
def test_kev_listing_counts_even_when_outdated_or_partial(
    tmp_path: Path, entries: dict[str, str]
) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        kev_data=kev(CVE_A, released="2025-01-01T00:00:00Z"),
        entries={"kev": entries},
    )
    assert _priority(_dep(CVE_A, severity=Severity.LOW), directory).level is P1


def test_absence_from_a_full_current_catalog_is_established(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", kev_data=kev(CVE_B))
    priority = _priority(_dep(CVE_A), directory)
    assert not any(u.startswith("kev:") for u in priority.unknown)
    assert any(f.name == "kev" and f.value.endswith("not listed") for f in priority.factors)


@pytest.mark.parametrize(
    ("released", "coverage", "why"),
    [
        ("2026-09-01T00:00:00Z", "full", "outdated"),
        ("2026-10-04T08:00:00Z", "partial", "only part"),
        ("2026-12-01T00:00:00Z", "full", "future"),
    ],
)
def test_absence_from_an_outdated_partial_or_future_catalog_is_unknown(
    tmp_path: Path, released: str, coverage: str, why: str
) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        kev_data=kev(CVE_B, released=released),
        entries={"kev": {"coverage": coverage}},
    )
    priority = _priority(_dep(CVE_A), directory)
    [unknown] = [u for u in priority.unknown if u.startswith("kev:")]
    assert why in unknown and "makes it P1" in unknown
    assert priority.level is P2


def test_epss_at_the_threshold_raises_one_level(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", epss_data=epss({CVE_A: 0.1}))
    priority = _priority(_dep(CVE_A, severity=Severity.MEDIUM), directory)
    assert priority.level is P2
    assert _rules(priority) == ["base.severity", "raise.epss"]


def test_epss_below_the_threshold_from_a_current_source_is_known(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", epss_data=epss({CVE_A: 0.09999}))
    priority = _priority(_dep(CVE_A, severity=Severity.MEDIUM), directory)
    assert priority.level is P3
    assert not any(u.startswith("epss:") for u in priority.unknown)


def test_outdated_low_epss_is_unknown_and_outdated_high_epss_still_raises(tmp_path: Path) -> None:
    old = "2026-08-01T00:00:00+0000"
    low = write_snapshot(tmp_path / "low", epss_data=epss({CVE_A: 0.01}, score_date=old))
    priority = _priority(_dep(CVE_A, severity=Severity.MEDIUM), low)
    assert priority.level is P3
    assert any(u.startswith("epss:") and "outdated" in u for u in priority.unknown)
    high = write_snapshot(tmp_path / "high", epss_data=epss({CVE_A: 0.5}, score_date=old))
    assert _priority(_dep(CVE_A, severity=Severity.MEDIUM), high).level is P2


def test_cve_without_an_epss_score_is_unknown(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", epss_data=epss({CVE_B: 0.9}))
    priority = _priority(_dep(CVE_A), directory)
    assert any(u.startswith("epss:") and "no entry" in u for u in priority.unknown)


def test_epss_threshold_is_configurable(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", epss_data=epss({CVE_A: 0.05}))
    config = PriorityConfig(epss_threshold=0.01)
    priority = _priority(_dep(CVE_A, severity=Severity.MEDIUM), directory, config=config)
    assert priority.level is P2


def test_freshness_limits_are_configurable(tmp_path: Path) -> None:
    directory = write_snapshot(tmp_path / "i", kev_data=kev(CVE_B, released="2026-09-01T00:00:00Z"))
    config = PriorityConfig(max_age_days={IntelKind.KEV: 60, IntelKind.EPSS: 7, IntelKind.CVSS: 30})
    priority = _priority(_dep(CVE_A), directory, config=config)
    assert not any(u.startswith("kev:") for u in priority.unknown)


def _scanner_only_level(finding: Finding) -> PriorityLevel:
    return compute_priority(finding, _assessment(), context()).level


@pytest.mark.parametrize(
    ("released", "coverage", "score_date", "nvd_time"),
    list(
        itertools.product(
            ["2026-10-04T08:00:00Z", "2026-01-01T00:00:00Z"],
            ["full", "partial"],
            ["2026-10-04T00:00:00+0000", "2026-01-01T00:00:00+0000"],
            ["2026-10-04T06:00:00", "2026-01-01T00:00:00"],
        )
    ),
)
def test_intelligence_never_ranks_below_the_scanner_alone(
    tmp_path: Path, released: str, coverage: str, score_date: str, nvd_time: str
) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        kev_data=kev(CVE_B, released=released),
        epss_data=epss({CVE_A: 0.0001}, score_date=score_date),
        nvd_data=nvd({CVE_A: [("3.1", 0.1)]}, timestamp=nvd_time),
        entries={k: {"coverage": coverage} for k in ("kev", "epss", "cvss")},
    )
    for severity in Severity:
        finding = _dep(CVE_A, severity=severity)
        with_intel = _priority(finding, directory).level
        assert with_intel.value <= _scanner_only_level(finding).value


def test_likely_false_positive_drops_to_p4_and_stays_conditional() -> None:
    assumptions = ("ContentRootPath is deployment configuration", "no escaping symlink")
    assessment = _assessment(AssessmentStatus.LIKELY_FALSE_POSITIVE, assumptions=assumptions)
    priority = compute_priority(source("f-1", severity=Severity.CRITICAL), assessment, context())
    assert priority.level is P4
    assert priority.conditional_on == assumptions
    rule = priority.rules[-1]
    assert rule.rule == "lower.likely_false_positive"
    assert all(a in rule.detail for a in assumptions)


def test_lowering_likely_false_positives_can_be_turned_off() -> None:
    assessment = _assessment(AssessmentStatus.LIKELY_FALSE_POSITIVE, assumptions=("a",))
    config = PriorityConfig(lower_likely_false_positive=False)
    priority = compute_priority(source("f-1"), assessment, context(config=config))
    assert priority.level is P2
    assert priority.conditional_on == ("a",)


def test_incomplete_assessment_never_lowers() -> None:
    assessment = _assessment(AssessmentStatus.LIKELY_FALSE_POSITIVE, complete=False)
    priority = compute_priority(source("f-1"), assessment, context())
    assert priority.level is P2
    assert any("cut short" in u for u in priority.unknown)


@pytest.mark.parametrize(
    "status",
    [
        AssessmentStatus.SUPPORTED,
        AssessmentStatus.INCONCLUSIVE,
        AssessmentStatus.STALE,
        AssessmentStatus.NOT_ASSESSED,
    ],
)
def test_other_assessments_do_not_change_the_level(status: AssessmentStatus) -> None:
    priority = compute_priority(source("f-1"), _assessment(status), context())
    assert priority.level is P2
    assert _rules(priority) == ["base.severity"]


def test_runtime_finding_keeps_scanner_priority_and_says_there_is_no_code_verdict() -> None:
    finding = runtime("f-1", severity=Severity.CRITICAL)
    priority = compute_priority(finding, _assessment(AssessmentStatus.NOT_ASSESSED), context())
    assert priority.level is P1
    assert any("without a code verdict" in u for u in priority.unknown)


def test_every_rule_names_its_inputs_and_every_input_its_source(tmp_path: Path) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        kev_data=kev(CVE_A),
        epss_data=epss({CVE_A: 0.5}),
        nvd_data=nvd({CVE_A: [("3.1", 5.0)]}),
    )
    priority = _priority(_dep(CVE_A, severity=Severity.LOW), directory)
    names = {f.name for f in priority.factors}
    for rule in priority.rules:
        assert rule.inputs and set(rule.inputs) <= names
    for factor in priority.factors:
        assert factor.source
        if factor.source.startswith("intel:"):
            assert factor.as_of is not None and factor.freshness == "current"
    assert priority.rules_version == "witness-priority/1"
    assert priority.evaluated_at == AS_OF


def test_intelligence_does_not_change_assessments(repo: Path, tmp_path: Path) -> None:
    directory = write_snapshot(
        tmp_path / "i",
        kev_data=kev(CVE_A),
        epss_data=epss({CVE_A: 0.9}),
        nvd_data=nvd({CVE_A: [("3.1", 10.0)]}),
    )
    findings = [source("f-1"), _dep(CVE_A).model_copy(update={"id": "f-2"})]
    plain = triage_run(repo, tainted(), findings).execute(None, [])
    enriched = triage_run(repo, tainted(), findings, intel=context(directory)).execute(None, [])

    def strip(a: Assessment) -> Assessment:
        return a.model_copy(update={"assessed_at": AS_OF})

    assert [strip(a) for a in plain.assessments] == [strip(a) for a in enriched.assessments]
    assert [p.level for p in enriched.priorities] == [P2, P1]
    assert [p.level for p in plain.priorities] == [P2, P2]


def test_config_file_is_validated(tmp_path: Path) -> None:
    path = tmp_path / "priority.toml"
    path.write_text(
        "[priority]\nepss_threshold = 0.2\nlower_likely_false_positive = false\n"
        "[freshness]\nkev = 3\n"
    )
    config = PriorityConfig.load(path)
    assert config.epss_threshold == 0.2 and not config.lower_likely_false_positive
    assert config.max_age_days[IntelKind.KEV] == 3
    assert config.max_age_days[IntelKind.CVSS] == 30
    assert config.digest() != PriorityConfig().digest()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[priority]\nepss_threshold = 0\n", "above 0"),
        ("[priority]\nepss_threshold = 'high'\n", "number"),
        ("[priority]\nlower_likely_false_positive = 1\n", "true or false"),
        ("[priority]\nthreshold = 0.1\n", "unknown setting"),
        ("[freshness]\nnvd = 3\n", "unknown setting"),
        ("[freshness]\nkev = 0\n", "whole number"),
        ("[freshness]\nkev = 1.5\n", "whole number"),
        ("[policy]\nx = 1\n", "unknown section"),
        ("not toml [", "TOML"),
    ],
)
def test_bad_config_is_a_usage_error(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "priority.toml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=message) as raised:
        PriorityConfig.load(path)
    assert raised.value.exit_code is ExitCode.USAGE


def test_evaluation_time_is_recorded() -> None:
    when = datetime(2027, 1, 1, tzinfo=UTC) + timedelta(hours=3)
    priority = compute_priority(source("f-1"), _assessment(), context(as_of=when))
    assert priority.evaluated_at == when
