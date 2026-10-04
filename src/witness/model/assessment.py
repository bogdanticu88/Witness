"""Evidence, assessment and priority records.

These are deliberately separate types. A fact says what was observed, a claim
says what someone (a scanner or a model) asserted, a check says whether a
condition held, and an assessment is the deterministic conclusion drawn from
them. Priority and the CI gate are computed later and stored separately.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AssessmentStatus(StrEnum):
    SUPPORTED = "supported"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    INCONCLUSIVE = "inconclusive"
    STALE = "stale"
    NOT_ASSESSED = "not_assessed"


class AssessmentBasis(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL_VERIFIED = "model_verified"
    NONE = "none"


class CodeRef(_Model):
    path: str
    start_line: int
    end_line: int
    # sha256 of the cited lines in the analyzed snapshot.
    span_sha256: str | None = None
    symbol: str | None = None


class FactSource(StrEnum):
    SEMANTIC = "semantic"
    SCANNER = "scanner"
    MODEL = "model"
    CHECK = "check"
    OPERATOR = "operator"


class Fact(_Model):
    """One recorded piece of evidence.

    ``source`` says who produced it. Scanner and model entries are claims, not
    observations, and are labelled as such everywhere they are rendered.
    """

    source: FactSource
    kind: str
    statement: str
    refs: tuple[CodeRef, ...] = ()
    producer: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class CheckOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class CheckResult(_Model):
    name: str
    outcome: CheckOutcome
    detail: str
    refs: tuple[CodeRef, ...] = ()


class Usage(_Model):
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    latency_ms: int = 0
    estimated_cost_usd: float | None = None

    def __add__(self, other: Usage) -> Usage:
        # An unknown price anywhere makes the total unknown. A record with no
        # calls contributes nothing, so it does not poison the sum.
        cost: float | None
        if self.calls == 0:
            cost = other.estimated_cost_usd
        elif other.calls == 0:
            cost = self.estimated_cost_usd
        elif self.estimated_cost_usd is None or other.estimated_cost_usd is None:
            cost = None
        else:
            cost = self.estimated_cost_usd + other.estimated_cost_usd
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            calls=self.calls + other.calls,
            latency_ms=self.latency_ms + other.latency_ms,
            estimated_cost_usd=cost,
        )


class Assessment(_Model):
    finding_id: str
    status: AssessmentStatus
    basis: AssessmentBasis
    # Short machine-readable reason codes, then a human explanation.
    reason_codes: tuple[str, ...] = ()
    explanation: str
    facts: tuple[Fact, ...] = ()
    checks: tuple[CheckResult, ...] = ()
    unresolved: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    profile: str
    # False when budgets, timeouts, provider failures or interruption cut the
    # investigation short. Incomplete assessments are never cached.
    complete: bool
    reused_from_cache: bool = False
    usage: Usage = Field(default_factory=Usage)
    context_fingerprint: str | None = None
    analysis_version: str
    assessed_at: datetime


class PriorityLevel(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class PriorityFactor(_Model):
    """One input to a priority, with where it came from."""

    name: str
    value: str
    source: str
    # When the value came from time-sensitive intelligence: the feed's own
    # date, and whether it was current at evaluation time.
    as_of: datetime | None = None
    freshness: str | None = None
    synthetic: bool = False
    # False when the factor is recorded but did not decide anything.
    used: bool = True


class PriorityRule(_Model):
    """A rule that fired, the level it produced and the factors it read."""

    rule: str
    level: PriorityLevel
    inputs: tuple[str, ...]
    detail: str


class Priority(_Model):
    """How urgently a finding deserves attention. Separate from its assessment.

    ``level`` is the result of ``rules`` applied in order. ``unknown`` lists
    factors that could not be established and what each could change; none of
    them lowered the level. ``conflicts`` keeps disagreeing inputs.
    """

    finding_id: str
    level: PriorityLevel
    rules: tuple[PriorityRule, ...]
    factors: tuple[PriorityFactor, ...]
    unknown: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    conditional_on: tuple[str, ...] = ()
    rules_version: str
    evaluated_at: datetime


class GroupRelation(StrEnum):
    DUPLICATE = "duplicate"
    RELATED = "related"
    INDEPENDENT = "independent"
    POSSIBLE_CHAIN = "possible_chain"


class FindingGroup(_Model):
    id: str
    relation: GroupRelation
    finding_ids: tuple[str, ...]
    explanation: str
    basis: Literal["identity", "semantic", "declared_mapping", "heuristic"]
