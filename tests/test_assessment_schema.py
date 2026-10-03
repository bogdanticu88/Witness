from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from witness.model.assessment import (
    Assessment,
    AssessmentBasis,
    AssessmentStatus,
    CodeRef,
    Fact,
    FactSource,
    FindingGroup,
    GroupRelation,
    Priority,
    PriorityFactor,
    PriorityLevel,
    Usage,
)

NOW = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def make_assessment(**overrides: Any) -> Assessment:
    data: dict[str, Any] = {
        "finding_id": "f-1",
        "status": AssessmentStatus.SUPPORTED,
        "basis": AssessmentBasis.DETERMINISTIC,
        "explanation": "sink is reached with tainted input",
        "profile": "default",
        "complete": True,
        "analysis_version": "1",
        "assessed_at": NOW,
    }
    data.update(overrides)
    return Assessment(**data)


def test_each_assessment_status_constructs() -> None:
    for status in AssessmentStatus:
        assessment = make_assessment(status=status)
        assert assessment.status is status
    assert AssessmentStatus.LIKELY_FALSE_POSITIVE == "likely_false_positive"
    assert AssessmentStatus.INCONCLUSIVE == "inconclusive"


def test_complete_flag_round_trips() -> None:
    complete = make_assessment(complete=True)
    cut_short = make_assessment(complete=False, status=AssessmentStatus.INCONCLUSIVE)
    assert complete.complete is True
    assert complete.reused_from_cache is False
    assert cut_short.complete is False


def test_assessment_requires_documented_fields() -> None:
    with pytest.raises(ValidationError):
        Assessment(finding_id="f-1", status=AssessmentStatus.SUPPORTED)


def test_usage_add_accumulates_totals() -> None:
    first = Usage(
        input_tokens=10, output_tokens=5, calls=2, latency_ms=100, estimated_cost_usd=0.1
    )
    second = Usage(
        input_tokens=20, output_tokens=15, calls=3, latency_ms=200, estimated_cost_usd=0.2
    )
    total = first + second
    assert total.input_tokens == 30
    assert total.output_tokens == 20
    assert total.calls == 5
    assert total.latency_ms == 300
    assert total.estimated_cost_usd == pytest.approx(0.3)


def test_usage_add_no_call_record_contributes_nothing() -> None:
    no_calls = Usage(estimated_cost_usd=0.9)
    priced = Usage(calls=1, input_tokens=7, estimated_cost_usd=0.1)
    assert (no_calls + priced).estimated_cost_usd == pytest.approx(0.1)
    assert (priced + no_calls).estimated_cost_usd == pytest.approx(0.1)
    assert (no_calls + priced).input_tokens == 7


def test_usage_add_unknown_cost_propagates_only_across_calls() -> None:
    unpriced = Usage(calls=2)
    priced = Usage(calls=1, estimated_cost_usd=0.5)
    free = Usage(calls=0, estimated_cost_usd=None)
    assert (unpriced + priced).estimated_cost_usd is None
    assert (priced + free).estimated_cost_usd == pytest.approx(0.5)
    assert (Usage() + Usage()).estimated_cost_usd is None


def test_priority_constructs_and_validates() -> None:
    priority = Priority(
        finding_id="f-1",
        level=PriorityLevel.P1,
        score=85,
        factors=(
            PriorityFactor(
                name="severity",
                value="critical",
                points=50,
                source="rules",
                as_of=NOW,
            ),
        ),
        rules_version="2026.10",
    )
    assert Priority.model_validate(priority.model_dump()) == priority
    assert priority.level is PriorityLevel.P1


def test_finding_group_constructs_and_validates() -> None:
    group = FindingGroup(
        id="g-1",
        relation=GroupRelation.DUPLICATE,
        finding_ids=("f-1", "f-2"),
        explanation="same instance key",
        basis="identity",
    )
    assert FindingGroup.model_validate(group.model_dump()) == group
    assert group.relation is GroupRelation.DUPLICATE


def test_fact_with_refs_round_trips() -> None:
    fact = Fact(
        source=FactSource.SEMANTIC,
        kind="sink_reached",
        statement="SqlCommand executes tainted text",
        refs=(
            CodeRef(
                path="src/app/Controller.cs",
                start_line=10,
                end_line=14,
                span_sha256="cd" * 32,
                symbol="App.Controller.Run",
            ),
        ),
        producer="witness-semantic",
        data={"confidence": "high"},
    )
    assert Fact.model_validate(fact.model_dump()) == fact
    assert fact.refs[0].symbol == "App.Controller.Run"
