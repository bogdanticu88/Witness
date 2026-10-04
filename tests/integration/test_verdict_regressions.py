"""Verdicts on small purpose-built cases, with the real helper.

Each case is a sink line marked `// case: Vnn` in tests/integration/samples.
The expected verdict is what the analysis can justify within its boundary,
not what is true at runtime: a validator Witness cannot interpret leaves the
finding inconclusive even when it happens to be effective.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from factories import source
from witness.model.assessment import Assessment, AssessmentStatus
from witness.model.finding import VulnClass
from witness.triage.engine import Helper, TriageRun, start_helper
from witness.triage.snapshot import Snapshot

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parent / "samples"
S, LFP, INC = (
    AssessmentStatus.SUPPORTED,
    AssessmentStatus.LIKELY_FALSE_POSITIVE,
    AssessmentStatus.INCONCLUSIVE,
)
SQL, REDIRECT, PATH = VulnClass.SQL_INJECTION, VulnClass.OPEN_REDIRECT, VulnClass.PATH_TRAVERSAL

CASES = [
    # (case, class, expected, text that must appear in the explanation)
    ("V01", SQL, S, "request data"),  # validator on another value
    ("V02", SQL, S, "request data"),  # validated on one branch only
    ("V03", SQL, S, "request data"),  # validator failure swallowed
    ("V04", SQL, INC, "validator"),  # validator failure leaves the method
    ("V05", SQL, S, "Request.Query"),  # reassigned from the request after validation
    ("V06", SQL, INC, "CheckAsync"),  # awaited validator
    ("V07", SQL, S, "request data"),  # validator task never awaited
    ("V08", SQL, INC, "unknown effect"),  # validation result checked later
    ("V09", SQL, S, "request data"),  # validation result ignored
    ("V10", SQL, INC, "validator"),  # caller validates before calling
    ("V11", SQL, INC, "validator"),  # wrapper validates before delegating
    ("V12", SQL, INC, "another method"),  # inlined helper throws on bad input
    ("V13", SQL, INC, "another method"),  # constructor validates the field
    ("V14", SQL, INC, "RegularExpression"),  # model validation attribute
    ("V15", SQL, S, "request data"),  # length-only attribute
    ("V16", SQL, INC, "alpha"),  # route constraint on content
    ("V17", SQL, S, "request data"),  # route constraint on length only
    ("V18", SQL, INC, "RejectQuotes"),  # action filter that reads and rejects
    ("V19", SQL, S, "request data"),  # action filter that does neither
    ("V20", REDIRECT, LFP, "constant prefix"),  # destination fixed by "/search?q="
    ("V21", REDIRECT, S, "request data"),  # "/" + value allows "//host"
    ("V22", REDIRECT, INC, "only part"),  # local URL embedded after "https:"
    ("V23", PATH, S, "request data"),  # file name used as a directory
    ("V24", PATH, LFP, "strips directory"),  # file name as the last component
    ("V25", PATH, INC, "case-insensitive"),  # prefix check ignores case
    ("V26", PATH, S, "request data"),  # check passes, a different value is read
    ("V27a", PATH, S, "request data"),  # read on a path before the check
    ("V27b", PATH, LFP, "trusted root"),  # read after the check
    ("V28", SQL, LFP, "constant"),  # tainted value overwritten before the sink
    ("V29", SQL, LFP, "constant"),  # endpoint parameter overwritten
    ("V30", SQL, S, "Request.Query"),  # helper reads the request itself
    ("V31", SQL, S, "request data"),  # tainted on one branch
    ("V32", SQL, LFP, "constant or a safe type"),  # int[] joined
    ("V33", SQL, INC, "not shown to be called"),  # request read outside any endpoint path
    ("V34", SQL, S, "request data"),  # appended with +=
    ("V35", SQL, LFP, "constant"),  # tainted write after the sink
    ("V36", SQL, INC, "delegate"),  # called through a delegate
    ("V37", SQL, S, "Request.Query"),  # helper reads the request on one branch
    ("V38", SQL, INC, "not shown to be called"),  # HttpContext read in a minimal API lambda
]


def _locate(root: Path, case: str) -> tuple[str, int]:
    marker = f"// case: {case}"
    for path in sorted(root.rglob("*.cs")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.rstrip().endswith(marker):
                return path.relative_to(root).as_posix(), number
    raise AssertionError(f"marker {marker} not found")


@pytest.fixture(scope="module")
def helpers(helper_path: Path) -> Iterator[dict[str, Helper]]:
    started: dict[str, Helper] = {}
    yield started
    for helper in started.values():
        helper.close()


def _assess(
    helpers: dict[str, Helper], sample: str, case: str, vuln_class: VulnClass
) -> Assessment:
    root = SAMPLES / sample
    if sample not in helpers:
        helper = start_helper(timeout_s=120)
        helper.load(root, None)
        helpers[sample] = helper
    path, line = _locate(root, case)
    finding = source(case, path, line, category=vuln_class)
    run = TriageRun(Snapshot.open(root), helpers[sample], [finding], (), 200)
    return run.assess(finding)


@pytest.mark.parametrize(
    ("case", "vuln_class", "expected", "says"), CASES, ids=[c[0] for c in CASES]
)
def test_verdict(
    helpers: dict[str, Helper],
    case: str,
    vuln_class: VulnClass,
    expected: AssessmentStatus,
    says: str,
) -> None:
    assessment = _assess(helpers, "Verdicts", case, vuln_class)
    assert assessment.status is expected, assessment.explanation
    assert says in assessment.explanation or any(says in c.detail for c in assessment.checks), (
        assessment.explanation
    )
    assert assessment.complete


def test_dismissals_carry_their_assumptions(helpers: dict[str, Helper]) -> None:
    by_file_name = _assess(helpers, "Verdicts", "V24", PATH)
    assert any("ContentRootPath" in a for a in by_file_name.assumptions)
    assert any("symbolic link" in a for a in by_file_name.assumptions)
    by_prefix = _assess(helpers, "Verdicts", "V27b", PATH)
    assert any("ContentRootPath" in a for a in by_prefix.assumptions)
    assert any("symbolic link" in a for a in by_prefix.assumptions)


def test_middleware_that_can_reject_on_input_blocks_confirmation(
    helpers: dict[str, Helper],
) -> None:
    assessment = _assess(helpers, "RejectingMiddleware", "M01", SQL)
    assert assessment.status is INC
    assert "middleware" in assessment.explanation


def test_middleware_that_ignores_input_does_not(helpers: dict[str, Helper]) -> None:
    assert _assess(helpers, "HeaderMiddleware", "M01", SQL).status is S
