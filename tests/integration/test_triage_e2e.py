"""Deterministic triage against the real helper, fixture apps and reports.

Ground truth is the fixture LABELS.yaml. The ``expected`` field there is what
a correct conservative tool should output with no package directory.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from factories import source
from witness.model.assessment import AssessmentStatus
from witness.model.finding import FindingKind, VulnClass
from witness.store import Store
from witness.triage.engine import Helper, TriageRun, run_triage, start_helper
from witness.triage.snapshot import Snapshot

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
APPS = ROOT / "fixtures" / "apps"
REPORTS = ROOT / "fixtures" / "reports"
PACKAGES = Path.home() / ".nuget" / "packages"

# Sites whose result without restored packages differs from the label, and
# why. These are abstentions, never errors in the other direction.
WITHOUT_PACKAGES = {
    "billing-sql-01": (
        AssessmentStatus.INCONCLUSIVE,
        "the connection string comes from an unrestored Microsoft.Data.Sqlite type, so the "
        "call into ForCustomer does not resolve and only a name match would link it",
    ),
}


def _labels(app: str) -> list[dict[str, Any]]:
    data = yaml.safe_load((APPS / app / "LABELS.yaml").read_text())
    return list(data["sites"])


def _cases() -> Iterator[Any]:
    for app in ("acme-orders", "acme-billing"):
        for label in _labels(app):
            yield pytest.param(app, label, id=label["id"])


@pytest.fixture(scope="module")
def helpers(helper_path: Path) -> Iterator[dict[tuple[str, bool], Helper]]:
    started: dict[tuple[str, bool], Helper] = {}
    yield started
    for helper in started.values():
        helper.close()


def _helper(helpers: dict[tuple[str, bool], Helper], app: str, packages: bool) -> Helper:
    key = (app, packages)
    if key not in helpers:
        helper = start_helper(timeout_s=120)
        helper.load(APPS / app, PACKAGES if packages else None)
        helpers[key] = helper
    return helpers[key]


def _argument_column(app: str, label: dict[str, Any]) -> int | None:
    """Column of the first call argument on the sink line.

    Labels have no columns. CodeQL locates a sink finding at the tainted
    argument, so synthetic findings do the same; only findings whose line has
    no recognized sink depend on it.
    """
    line = (APPS / app / label["file"]).read_text().splitlines()[label["sink_line"] - 1]
    paren = line.find("(")
    return paren + 2 if paren >= 0 else None


def _assess(helper: Helper, app: str, label: dict[str, Any]):  # type: ignore[no-untyped-def]
    finding = source(
        label["id"], label["file"], label["sink_line"], category=VulnClass(label["class"])
    )
    assert finding.location is not None
    located = finding.location.model_copy(update={"start_column": _argument_column(app, label)})
    finding = finding.model_copy(update={"location": located})
    run = TriageRun(Snapshot.open(APPS / app), helper, [finding], (), 200)
    return run.assess(finding)


@pytest.mark.parametrize(("app", "label"), list(_cases()))
def test_label_sites_without_packages(
    helpers: dict[tuple[str, bool], Helper], app: str, label: dict[str, Any]
) -> None:
    assessment = _assess(_helper(helpers, app, False), app, label)
    expected, _ = WITHOUT_PACKAGES.get(label["id"], (AssessmentStatus(label["expected"]), ""))
    assert assessment.status is expected, assessment.explanation
    assert assessment.complete
    if label["truth"] == "vulnerable":
        # Never dismiss a real vulnerability, whatever else happens.
        assert assessment.status is not AssessmentStatus.LIKELY_FALSE_POSITIVE
    if assessment.status is AssessmentStatus.LIKELY_FALSE_POSITIVE:
        assert assessment.checks and all(c.outcome.value == "passed" for c in assessment.checks)


@pytest.mark.skipif(
    not (PACKAGES / "microsoft.data.sqlite").is_dir(), reason="no local NuGet package cache"
)
def test_restored_packages_resolve_the_abstentions(
    helpers: dict[tuple[str, bool], Helper],
) -> None:
    billing = _labels("acme-billing")[0]
    assessment = _assess(_helper(helpers, "acme-billing", True), "acme-billing", billing)
    assert assessment.status is AssessmentStatus.SUPPORTED


def _orders_reports() -> list[Path]:
    return [
        REPORTS / "codeql" / "acme-orders.sarif",
        REPORTS / "trivy" / "acme-orders-fs.json",
        REPORTS / "trivy" / "acme-orders-image.json",
        REPORTS / "mantis" / "acme-orders.json",
    ]


def test_real_reports_end_to_end(helper_path: Path, tmp_path: Path) -> None:
    with Store.open(tmp_path / "witness.db") as store:
        outcome = run_triage(_orders_reports(), APPS / "acme-orders", store=store)
        record = store.get_run(outcome.run_id or "")
        stored = store.list_assessments(outcome.run_id or "")
        groups = store.list_groups(outcome.run_id or "")

    assert outcome.status == "completed"
    assert record.status == "completed" and record.finished_at
    assert outcome.helper.protocol == "witness.semantic/1"
    assert len(outcome.findings) == len(stored) == 67
    assert len({a.finding_id for a in stored}) == 67
    assert groups == outcome.groups

    by_id = {f.id: f for f in outcome.findings}
    labels = {(lab["file"], lab["sink_line"]): lab for lab in _labels("acme-orders")}
    checked = 0
    for assessment in stored:
        finding = by_id[assessment.finding_id]
        if finding.kind is FindingKind.SOURCE:
            assert finding.location is not None
            label = labels[(finding.location.path, finding.location.start_line)]
            assert assessment.status.value == label["expected"], label["id"]
            checked += 1
        elif finding.kind is FindingKind.RUNTIME:
            assert assessment.status is AssessmentStatus.NOT_ASSESSED
        else:
            assert assessment.status in (AssessmentStatus.INCONCLUSIVE, AssessmentStatus.STALE)
    assert checked == 17
    # CodeQL's two false positives on this app are dismissed by checks.
    dismissed = [a for a in stored if a.status is AssessmentStatus.LIKELY_FALSE_POSITIVE]
    assert {by_id[a.finding_id].location.start_line for a in dismissed} == {30, 43}  # type: ignore[union-attr]


def test_billing_reports_end_to_end(helper_path: Path) -> None:
    reports = [
        REPORTS / "codeql" / "acme-billing.sarif",
        REPORTS / "trivy" / "acme-billing-fs.json",
    ]
    outcome = run_triage(reports, APPS / "acme-billing")
    assert outcome.status == "completed"
    assert len(outcome.assessments) == len(outcome.findings) == 5
    sql = [a for a in outcome.assessments if by_kind(outcome, a.finding_id) is FindingKind.SOURCE]
    assert [a.status for a in sql] == [AssessmentStatus.INCONCLUSIVE]


def by_kind(outcome: Any, finding_id: str) -> FindingKind:
    return next(f.kind for f in outcome.findings if f.id == finding_id)
