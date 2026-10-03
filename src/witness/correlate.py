"""Deterministic pairwise correlation of normalized findings.

Correlation answers "how do these two findings relate?" with rules that are
pure functions of the ``witness.finding/1`` record. No model is involved.
``correlate`` evaluates every unordered pair, so it is O(n²) in the number of
findings; reports in the hundreds of findings are fine, but the pairwise API
does not scale to tens of thousands.

Rules, in precedence order. The first rule that matches decides the pair:

1. ``duplicate`` (basis ``identity``): the findings share the same
   ``instance_key``, the adapter-computed identity of the affected instance.
   Two distinct records with one instance key describe the same affected
   thing.
2. ``possible_chain`` (basis ``heuristic``): a code-flow sink of one finding
   (the last located step of any of its flows) coincides (same path and start
   line) with the other finding's primary location or with the origin (first
   located step) of any of its flows. This flags a value that may flow out of
   one reported weakness straight into another.
3. ``related`` (basis ``semantic``): a weaker but deterministic tie:
   the same supported ``VulnClass`` and the same ``location.path``, or two
   dependency findings naming the same ``package.name``.
4. ``related`` (basis ``declared_mapping``): a runtime finding whose
   ``runtime.endpoint`` (and ``runtime.method``, when both sides record one)
   matches the endpoint a source finding declares in
   ``scanner_properties["endpoint"]`` (optional ``scanner_properties
   ["method"]``). Exact string equality is required; nothing is URL-parsed or
   fuzzed.
5. ``independent``: the explicit "evaluated, nothing matched" outcome. It is
   emitted only when ``relate`` is asked for it (``mark_independent=True``),
   because recording every unrelated pair would drown real groups in noise.
   Its basis is ``heuristic``: the deterministic rule set was applied and no
   rule fired.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Literal

from witness.model.assessment import FindingGroup, GroupRelation
from witness.model.finding import (
    SUPPORTED_SOURCE_CLASSES,
    Finding,
    FindingKind,
    SourceLocation,
)

_Basis = Literal["identity", "semantic", "declared_mapping", "heuristic"]


def relate(a: Finding, b: Finding, *, mark_independent: bool = False) -> FindingGroup | None:
    """Relate two findings, or return None when nothing matches.

    Comparing a finding to itself is not a relation between two records and
    returns None. The result is order-independent: swapping ``a`` and ``b``
    yields the same relation, explanation and sorted ``finding_ids``.
    """
    if a.id == b.id:
        return None
    match = _classify(a, b)
    if match is None:
        if not mark_independent:
            return None
        relation: GroupRelation = GroupRelation.INDEPENDENT
        basis: _Basis = "heuristic"
        explanation = (
            "no rule matched: distinct instance keys, no shared flow location, "
            "no shared class/path, package or declared endpoint"
        )
    else:
        relation, basis, explanation = match
    return FindingGroup(
        id=_group_id(a, b),
        relation=relation,
        finding_ids=tuple(sorted((a.id, b.id))),
        explanation=explanation,
        basis=basis,
    )


def correlate(findings: Sequence[Finding]) -> list[FindingGroup]:
    """Group all unordered pairs. O(n²) pairs are evaluated.

    Only duplicate, possible_chain and related groups are emitted; unrelated
    pairs produce no group. Input order decides pair evaluation order, and
    group ids are hashes of the member ids, so the output is deterministic
    for a given input sequence.
    """
    groups: list[FindingGroup] = []
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            group = relate(findings[i], findings[j])
            if group is not None:
                groups.append(group)
    return groups


def _classify(a: Finding, b: Finding) -> tuple[GroupRelation, _Basis, str] | None:
    if a.instance_key == b.instance_key:
        return (
            GroupRelation.DUPLICATE,
            "identity",
            f"identical instance key {a.instance_key}: both records describe the same "
            "affected instance",
        )
    link = _chain_link(a, b)
    if link is not None:
        return (
            GroupRelation.POSSIBLE_CHAIN,
            "heuristic",
            f"possible chain: {link}",
        )
    return _weaker_tie(a, b)


def _chain_link(a: Finding, b: Finding) -> str | None:
    for first, second in ((a, b), (b, a)):
        for sink in _flow_sinks(first):
            primary = second.location
            if primary is not None and _same_spot(sink, primary):
                return (
                    f"flow sink of {first.id} at {sink.path}:{sink.start_line} coincides "
                    f"with the primary location of {second.id}"
                )
            for origin in _flow_origins(second):
                if _same_spot(sink, origin):
                    return (
                        f"flow sink of {first.id} at {sink.path}:{sink.start_line} coincides "
                        f"with the flow origin of {second.id}"
                    )
    return None


def _weaker_tie(a: Finding, b: Finding) -> tuple[GroupRelation, _Basis, str] | None:
    if (
        a.category is b.category
        and a.category in SUPPORTED_SOURCE_CLASSES
        and a.location is not None
        and b.location is not None
        and a.location.path == b.location.path
    ):
        return (
            GroupRelation.RELATED,
            "semantic",
            f"same supported class ({a.category.value}) in the same file ({a.location.path})",
        )
    if (
        a.kind is FindingKind.DEPENDENCY
        and b.kind is FindingKind.DEPENDENCY
        and a.package is not None
        and b.package is not None
        and a.package.name == b.package.name
    ):
        return (
            GroupRelation.RELATED,
            "semantic",
            f"dependency findings share package {a.package.name}",
        )
    endpoint_tie = _declared_endpoint_tie(a, b)
    if endpoint_tie is not None:
        return endpoint_tie
    return None


def _declared_endpoint_tie(a: Finding, b: Finding) -> tuple[GroupRelation, _Basis, str] | None:
    for runtime_finding, source in ((a, b), (b, a)):
        if runtime_finding.kind is not FindingKind.RUNTIME or runtime_finding.runtime is None:
            continue
        endpoint = source.scanner_properties.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            continue
        if endpoint != (runtime_finding.runtime.endpoint or ""):
            continue
        method = source.scanner_properties.get("method")
        if (
            isinstance(method, str)
            and method
            and runtime_finding.runtime.method
            and method != runtime_finding.runtime.method
        ):
            continue
        return (
            GroupRelation.RELATED,
            "declared_mapping",
            f"runtime endpoint {endpoint} matches the endpoint declared by {source.id}",
        )
    return None


def _flow_sinks(finding: Finding) -> list[SourceLocation]:
    sinks: list[SourceLocation] = []
    for flow in finding.code_flows:
        located = [step.location for step in flow if step.location is not None]
        if located:
            sinks.append(located[-1])
    return sinks


def _flow_origins(finding: Finding) -> list[SourceLocation]:
    origins: list[SourceLocation] = []
    for flow in finding.code_flows:
        for step in flow:
            if step.location is not None:
                origins.append(step.location)
                break
    return origins


def _same_spot(a: SourceLocation, b: SourceLocation) -> bool:
    return a.path == b.path and a.start_line is not None and a.start_line == b.start_line


def _group_id(a: Finding, b: Finding) -> str:
    digest = hashlib.sha256("|".join(sorted((a.id, b.id))).encode()).hexdigest()
    return "g-" + digest[:12]
