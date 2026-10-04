"""Deterministic pairwise correlation of normalized findings.

Correlation answers "how do these two findings relate?" with rules that are
pure functions of the ``witness.finding/1`` records and an optional list of
operator-declared endpoint mappings. No model is involved. ``correlate``
evaluates every unordered pair, so it is O(n²) in the number of findings.

Before any rule, the pair must be in the same scope: two findings whose
artifacts or revisions are both known and differ never relate, and a finding
with a known artifact is not compared by location with one whose artifact is
unknown. Source findings without an artifact are assumed to come from the
snapshot being triaged, which is how the triage pipeline uses them.

Rules, in precedence order. The first rule that matches decides the pair:

1. ``duplicate`` (basis ``identity``): equal ``instance_key``.
2. ``possible_chain`` (basis ``heuristic``): a code-flow sink of one finding
   (the last located step of one of its flows) is at the same path and start
   line as the other finding's primary location or the origin of one of its
   flows. This only says a value may pass from one reported weakness into
   another. It is never evidence of an exploitable chain.
3. ``related`` (basis ``semantic``): the same supported ``VulnClass`` in the
   same file, or two dependency findings for the same package identity
   (purl type and name, or ecosystem and name when there is no purl). The
   package tie also applies across artifacts, for example a repository and
   an image built from it, and the explanation names both.
4. ``related`` (basis ``declared_mapping``): the operator declared that a
   runtime endpoint is served by code in the source finding's file. The
   runtime endpoint path (the part before ``?``) and method must equal the
   mapping exactly. Nothing is inferred from names.
5. ``independent``: rules were applied and none matched. Emitted only when
   asked for (``mark_independent=True``).

Relations and explanations do not depend on argument order.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from witness.model.assessment import FindingGroup, GroupRelation
from witness.model.finding import (
    SUPPORTED_SOURCE_CLASSES,
    ArtifactIdentity,
    Finding,
    FindingKind,
    PackageRef,
    SourceLocation,
)

_Basis = Literal["identity", "semantic", "declared_mapping", "heuristic"]


@dataclass(frozen=True)
class EndpointMapping:
    """Operator-declared link from a runtime endpoint to source code."""

    endpoint: str
    source_path: str
    method: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    target: str | None = None
    environment: str | None = None


def relate(
    a: Finding,
    b: Finding,
    *,
    mappings: Sequence[EndpointMapping] = (),
    mark_independent: bool = False,
) -> FindingGroup | None:
    """Relate two findings, or return None when nothing matches.

    Comparing a finding to itself returns None.
    """
    if a.id == b.id:
        return None
    if b.id < a.id:
        a, b = b, a
    match = _classify(a, b, mappings)
    if match is None:
        if not mark_independent:
            return None
        relation = GroupRelation.INDEPENDENT
        basis: _Basis = "heuristic"
        scope = _scope_conflict(a, b)
        explanation = (
            f"no rule applies across scopes: {scope}"
            if scope
            else "no rule matched: distinct instance keys, no shared flow location, "
            "no shared class and file, package or declared endpoint"
        )
    else:
        relation, basis, explanation = match
    return FindingGroup(
        id=_group_id(a, b),
        relation=relation,
        finding_ids=(a.id, b.id),
        explanation=explanation,
        basis=basis,
    )


def correlate(
    findings: Sequence[Finding], *, mappings: Sequence[EndpointMapping] = ()
) -> list[FindingGroup]:
    """Relate all unordered pairs and return the groups sorted by id.

    Unrelated pairs produce no group. Every finding stays a separate record;
    a group only links two of them.
    """
    groups: list[FindingGroup] = []
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            group = relate(findings[i], findings[j], mappings=mappings)
            if group is not None:
                groups.append(group)
    return sorted(groups, key=lambda g: g.id)


def _classify(
    a: Finding, b: Finding, mappings: Sequence[EndpointMapping]
) -> tuple[GroupRelation, _Basis, str] | None:
    # Two ties cross scopes on purpose: the same package in a repository and
    # in an image built from it, and an operator mapping from a deployment's
    # endpoint to source code. Location-based rules never do.
    scope = _scope_conflict(a, b)
    if scope:
        package = _package_tie(a, b)
        if package is not None:
            relation, basis, explanation = package
            return relation, basis, f"{explanation}, in {scope}"
        return _declared_endpoint_tie(a, b, mappings)
    if a.instance_key == b.instance_key:
        return (
            GroupRelation.DUPLICATE,
            "identity",
            f"identical instance key {a.instance_key}: both records describe the same "
            "affected instance",
        )
    links = _chain_links(a, b) + _chain_links(b, a)
    if links:
        return (
            GroupRelation.POSSIBLE_CHAIN,
            "heuristic",
            f"possible chain, not a verified exploit path: {min(links)}",
        )
    return _weaker_tie(a, b) or _declared_endpoint_tie(a, b, mappings)


def _scope_conflict(a: Finding, b: Finding) -> str | None:
    if a.revision and b.revision and a.revision != b.revision:
        return f"different revisions ({a.revision} and {b.revision})"
    if a.artifact is None and b.artifact is None:
        return None
    if a.artifact is None or b.artifact is None:
        return "artifact identity known for only one finding"
    if not _same_artifact(a.artifact, b.artifact):
        first, second = _artifact_text(a.artifact), _artifact_text(b.artifact)
        return f"different artifacts ({first} and {second})"
    return None


def _same_artifact(a: ArtifactIdentity, b: ArtifactIdentity) -> bool:
    if a.kind != b.kind:
        return False
    if a.digest and b.digest:
        return a.digest == b.digest
    if a.digest or b.digest:
        return False
    if a.revision and b.revision and a.revision != b.revision:
        return False
    return a.name is not None and a.name == b.name


def _artifact_text(artifact: ArtifactIdentity) -> str:
    return f"{artifact.kind}:{artifact.name or '?'}@{artifact.digest or artifact.revision or '?'}"


def _chain_links(first: Finding, second: Finding) -> list[str]:
    links: list[str] = []
    for sink in _flow_sinks(first):
        primary = second.location
        if primary is not None and _same_spot(sink, primary):
            links.append(
                f"flow sink of {first.id} at {sink.path}:{sink.start_line} is the primary "
                f"location of {second.id}"
            )
        for origin in _flow_origins(second):
            if _same_spot(sink, origin):
                links.append(
                    f"flow sink of {first.id} at {sink.path}:{sink.start_line} is the flow "
                    f"origin of {second.id}"
                )
    return links


def _weaker_tie(a: Finding, b: Finding) -> tuple[GroupRelation, _Basis, str] | None:
    if (
        a.kind is FindingKind.SOURCE
        and b.kind is FindingKind.SOURCE
        and a.category is b.category
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
    return _package_tie(a, b)


def _package_tie(a: Finding, b: Finding) -> tuple[GroupRelation, _Basis, str] | None:
    if a.kind is not FindingKind.DEPENDENCY or b.kind is not FindingKind.DEPENDENCY:
        return None
    key = _package_identity(a.package)
    if key is None or key != _package_identity(b.package):
        return None
    return (
        GroupRelation.RELATED,
        "semantic",
        f"dependency findings share package {key[0]}/{key[1]}",
    )


def _package_identity(package: PackageRef | None) -> tuple[str, str] | None:
    if package is None:
        return None
    if package.purl and package.purl.startswith("pkg:") and "/" in package.purl:
        kind = package.purl[4:].split("/", 1)[0]
        return (kind, package.name)
    if package.ecosystem:
        return (package.ecosystem, package.name)
    return None


def _declared_endpoint_tie(
    a: Finding, b: Finding, mappings: Sequence[EndpointMapping]
) -> tuple[GroupRelation, _Basis, str] | None:
    found: list[str] = []
    for runtime_finding, source in ((a, b), (b, a)):
        runtime = runtime_finding.runtime
        if runtime_finding.kind is not FindingKind.RUNTIME or runtime is None:
            continue
        if source.kind is not FindingKind.SOURCE or source.location is None:
            continue
        path = (runtime.endpoint or "").split("?", 1)[0]
        for mapping in mappings:
            if not path or mapping.endpoint != path:
                continue
            if mapping.method and mapping.method != runtime.method:
                continue
            if mapping.target and mapping.target != runtime.target:
                continue
            if mapping.environment and mapping.environment != runtime.environment:
                continue
            if not _mapping_covers(mapping, source.location):
                continue
            found.append(
                f"operator mapping declares {mapping.method or 'any method'} {path} as served by "
                f"{mapping.source_path}, where {source.id} is located"
            )
    if not found:
        return None
    return (GroupRelation.RELATED, "declared_mapping", min(found))


def _mapping_covers(mapping: EndpointMapping, location: SourceLocation) -> bool:
    if location.path != mapping.source_path:
        return False
    if mapping.start_line is None:
        return True
    if location.start_line is None:
        return False
    end = mapping.end_line if mapping.end_line is not None else mapping.start_line
    return mapping.start_line <= location.start_line <= end


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
