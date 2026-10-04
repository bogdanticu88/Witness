"""Deterministic verdicts for source findings, from semantic helper facts.

The investigator walks the helper's value-flow tree for a sink argument and
sorts what reaches the sink:

- tainted: request data reaches the sink through plain propagation, from an
  endpoint or a method shown to be called from one, with no layer on the way
  whose effect on the value is unknown.
- uncertain: request data passes through something whose effect is not
  established here: an unknown call, a content-altering transform, a custom
  validator or check, a model validation attribute, a route constraint, or a
  middleware or filter that reads the request and can reject it. Blocks both
  confirmation and dismissal.
- untrusted: a value of unknown trust, such as configuration, environment or
  a non-HTTP entry point argument. Blocks both.
- unknown: a value the slice could not resolve. Blocks dismissal only.

A site whose analysis did not finish (a truncated slice, the caller depth
limit, the query budget) is ``inconclusive`` whatever was found in the part
that was analyzed. Otherwise it is ``supported`` when at least one tainted
path exists and the sink is resolved, and ``likely_false_positive`` only when
nothing is tainted, uncertain, untrusted or unknown, every caller set used
was complete, and no symbol was unresolved. Everything else is
``inconclusive``.

The helper lists every definition of a variable with ordering facts.
Definitions are filtered here so that a value overwritten before the sink
does not count as reaching it. A self reference (``x = x.Trim()``) is a
separate read with its own definitions; one the helper could not resolve (a
loop-carried value) is unknown, never safe.

Guards come from the helper as observations. Whether one mitigates is decided
here, per class, and only for guard shapes whose semantics are known, at the
position in the value where those semantics hold.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol

from pydantic import ValidationError

from witness.errors import SemanticError, SemanticRequestError
from witness.model.assessment import (
    AssessmentStatus,
    CheckOutcome,
    CheckResult,
    CodeRef,
    Fact,
    FactSource,
)
from witness.semantic import protocol as p

# Host-provided paths: deployment configuration, not request data.
_HOST_PATHS = frozenset(
    {
        "P:Microsoft.Extensions.Hosting.IHostEnvironment.ContentRootPath",
        "P:Microsoft.AspNetCore.Hosting.IWebHostEnvironment.WebRootPath",
        "P:Microsoft.AspNetCore.Hosting.IHostingEnvironment.ContentRootPath",
        "P:Microsoft.AspNetCore.Hosting.IHostingEnvironment.WebRootPath",
    }
)
_HOST_PATH_ASSUMPTION = "{name} is host configuration set at deployment, not request data"
_LINK_ASSUMPTION = "no symbolic link or junction inside the checked directory points outside it"

# Calls that run before a sink but cannot reject a malicious value: logging,
# console output, string and path helpers, null/empty argument checks.
_NON_VALIDATING_PREFIXES = (
    "M:Microsoft.Extensions.Logging.",
    "M:System.Console.Write",
    "M:System.Diagnostics.Debug.",
    "M:System.Diagnostics.Trace.",
    "M:System.String.",
    "M:System.IO.Path.",
    "M:System.ArgumentNullException.ThrowIfNull",
    "M:System.ArgumentException.ThrowIfNullOrEmpty",
    "M:System.ArgumentException.ThrowIfNullOrWhiteSpace",
)

# Validation attributes and route constraints that limit presence, length or
# type but not content. They cannot stop an injection.
_CONTENT_NEUTRAL_ATTRIBUTES = frozenset(
    {"Required", "StringLength", "MaxLength", "MinLength", "Length"}
)
_CONTENT_NEUTRAL_CONSTRAINT = re.compile(
    r"^(int|long|guid|bool|datetime|decimal|double|float|required|nonfile"
    r"|minlength\(\d+\)|maxlength\(\d+\)|length\(\d+(,\d+)?\))$"
)

_PATH_JOINS = ("M:System.IO.Path.Combine(", "M:System.IO.Path.Join(")
_PATH_NORMALIZE = "M:System.IO.Path.GetFullPath("

_SAFE_PREFIX_ABSOLUTE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+/")

_SLICE_TRUNCATED = "the helper's value-flow slice hit its node or depth budget"

_SUPPORT_ASSUMPTIONS = (
    "the endpoint is routed and reachable as its mapping or attributes declare",
    "branch conditions on the path that do not involve the value can be satisfied",
)


class BudgetExhausted(Exception):
    pass


class SemanticSource(Protocol):
    """The helper queries the investigator needs. Raises SemanticError."""

    def sites_at(self, path: str, start_line: int, end_line: int, vuln_class: str) -> p.SitesAt: ...

    def analyze_site(self, site_id: str) -> p.SiteAnalysis: ...

    def callers(self, method: str) -> p.Callers: ...

    def analyze_argument(
        self, path: str, line: int, column: int, ordinal: int
    ) -> p.ArgumentAnalysis: ...

    def di_registrations(self) -> list[p.DiRegistration]: ...

    def endpoints(self) -> list[p.Endpoint]: ...

    def request_pipeline(self) -> list[p.PipelineLayer]: ...


def _dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


@dataclass
class Flow:
    tainted: list[str] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)
    untrusted: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)

    def add(self, other: Flow) -> Flow:
        for name in (
            "tainted",
            "uncertain",
            "untrusted",
            "unknown",
            "mitigations",
            "assumptions",
            "incomplete",
        ):
            merged = _dedupe([*getattr(self, name), *getattr(other, name)])
            setattr(self, name, merged)
        return self

    @property
    def clean(self) -> bool:
        return not (self.tainted or self.uncertain or self.untrusted or self.unknown)

    def blocked(self, reason: str) -> Flow:
        """The same flow after passing through something with unknown effect."""
        uncertain = [f"{t}, then {reason}" for t in self.tainted]
        return replace(self, tainted=[], uncertain=_dedupe([*self.uncertain, *uncertain]))


@dataclass
class SiteVerdict:
    status: AssessmentStatus
    reason_codes: list[str]
    explanation: str
    facts: list[Fact] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    complete: bool = True


@dataclass(frozen=True)
class _Effect:
    kind: str  # "mitigate" or "block"
    description: str
    assumptions: tuple[str, ...] = ()
    # The guard's meaning holds only when the checked value is the whole sink
    # value, not a piece concatenated into it.
    whole_value_only: bool = False


@dataclass(frozen=True)
class _Context:
    vuln_class: str
    role: str
    effects: dict[str, _Effect]
    depth: int
    expanding: frozenset[str]
    # Method in which values read here are evaluated, for request reachability.
    method: str | None
    # This subtree is the whole sink value (nothing concatenated around it).
    whole: bool = True
    # This subtree ends the path: nothing with a separator follows it.
    tail: bool = True
    # Open redirect: a constant prefix already fixes the destination.
    fixed: bool = False

    def but(self, **changes: object) -> _Context:
        return replace(self, **changes)  # type: ignore[arg-type]


def _ref(span: p.Span | None, symbol: str | None = None) -> tuple[CodeRef, ...]:
    if span is None:
        return ()
    ref = CodeRef(
        path=span.path, start_line=span.start_line, end_line=span.end_line, symbol=symbol
    )
    return (ref,)


def _where(node: p.ValueNode) -> str:
    if node.location is None:
        return f"`{node.text}`"
    return f"`{node.text}` ({node.location.path}:{node.location.start_line})"


def _constant_text(node: p.ValueNode) -> str | None:
    if node.kind != "constant" or not node.detail:
        return None
    detail = node.detail
    if len(detail) >= 2 and detail.startswith('"'):
        return detail[1:-1] if detail.endswith('"') else detail[1:]
    return None


def _fixes_destination(text: str) -> bool:
    """A redirect target starting with this text cannot leave the site."""
    if len(text) >= 2 and text[0] == "/" and text[1] not in "/\\\t\n\r ":
        return True
    return bool(_SAFE_PREFIX_ABSOLUTE.match(text))


class Investigator:
    def __init__(
        self,
        source: SemanticSource,
        *,
        max_calls: int = 200,
        max_caller_depth: int = 4,
        producer: str = "witness-semantic",
    ) -> None:
        self._source = source
        self._max_calls = max_calls
        self._max_depth = max_caller_depth
        self._producer = producer
        self._calls = 0
        self._registrations: list[p.DiRegistration] | None = None
        self._handlers: dict[str, str] | None = None
        self._layers: list[p.PipelineLayer] | None = None
        self._reachable: dict[str, frozenset[str]] = {}

    # -- helper access, counted against the per-finding budget ---------------

    def _spend(self) -> None:
        self._calls += 1
        if self._calls > self._max_calls:
            raise BudgetExhausted(f"semantic query budget of {self._max_calls} calls used up")

    def _callers(self, method: str) -> p.Callers:
        self._spend()
        try:
            return self._source.callers(method)
        except SemanticRequestError as exc:
            if exc.code != "unknown_symbol":
                raise
            # Compiler-generated members (top-level Main, for one) have no
            # symbol the helper can look up: their callers are unknown.
            target = p.SymbolInfo(id=method, display=method, kind="unknown")
            reason = f"the helper cannot resolve {method}"
            return p.Callers(target=target, calls=(), complete=False, incomplete_reasons=(reason,))

    def _argument(self, call: p.CallSite, ordinal: int) -> p.ArgumentAnalysis:
        self._spend()
        loc = call.location
        return self._source.analyze_argument(loc.path, loc.start_line, loc.start_column, ordinal)

    def _di(self) -> list[p.DiRegistration]:
        if self._registrations is None:
            self._spend()
            self._registrations = self._source.di_registrations()
        return self._registrations

    def _endpoint_kinds(self) -> dict[str, str]:
        if self._handlers is None:
            self._spend()
            self._handlers = {e.handler.id: e.kind for e in self._source.endpoints()}
        return self._handlers

    def _pipeline(self) -> list[p.PipelineLayer]:
        if self._layers is None:
            self._spend()
            self._layers = self._source.request_pipeline()
        return self._layers

    # -- entry point ---------------------------------------------------------

    def assess(
        self,
        path: str,
        start_line: int,
        end_line: int,
        vuln_class: str,
        *,
        start_column: int | None = None,
        end_column: int | None = None,
    ) -> SiteVerdict:
        """Assess the sink sites of one class at a location.

        Raises SemanticError when the helper fails or sends facts that cannot
        be interpreted; the caller decides what that means for the run.
        """
        self._calls = 0
        try:
            self._spend()
            found = self._source.sites_at(path, start_line, end_line, vuln_class)
            sites = [s for s in found.sites if s.vuln_class == vuln_class]
            if not sites:
                return self._no_site(found, path, start_line, vuln_class, start_column, end_column)
            verdicts = [self._assess_site(site, vuln_class) for site in sites]
        except BudgetExhausted as exc:
            return SiteVerdict(
                status=AssessmentStatus.INCONCLUSIVE,
                reason_codes=["budget_exhausted"],
                explanation=f"analysis stopped before a decision: {exc}",
                complete=False,
            )
        except (ValueError, KeyError, TypeError, ValidationError) as exc:
            raise SemanticError(f"the helper sent facts Witness cannot interpret: {exc}") from exc
        return _combine(verdicts)

    def _no_site(
        self,
        found: p.SitesAt,
        path: str,
        line: int,
        vuln_class: str,
        start_column: int | None,
        end_column: int | None,
    ) -> SiteVerdict:
        if found.safe_apis and vuln_class in ("open_redirect", "sql_injection"):
            if start_column is None:
                return SiteVerdict(
                    status=AssessmentStatus.INCONCLUSIVE,
                    reason_codes=["safe_api_column_unknown"],
                    explanation=f"{path}:{line} has a safe API call but no recognized sink; the "
                    "finding gives no column, so it cannot be tied to that call",
                )
            hits = [
                h for h in found.safe_apis if _starts_within(h.location, line, start_column)
            ]
            if not hits:
                return SiteVerdict(
                    status=AssessmentStatus.INCONCLUSIVE,
                    reason_codes=["no_sink_at_location"],
                    explanation=f"the finding's span at {path}:{line} is neither a recognized "
                    "sink nor a safe API call",
                )
            hit = hits[0]
            check = CheckResult(
                name="safe_api_at_location",
                outcome=CheckOutcome.PASSED,
                detail=hit.description,
                refs=_ref(hit.location),
            )
            return SiteVerdict(
                status=AssessmentStatus.LIKELY_FALSE_POSITIVE,
                reason_codes=["safe_api"],
                explanation=f"the flagged call at {path}:{line} is a safe API, not a sink: "
                f"{hit.description}",
                checks=[check],
                facts=[
                    Fact(
                        source=FactSource.SEMANTIC,
                        kind="safe_api",
                        statement=hit.description,
                        refs=_ref(hit.location),
                        producer=self._producer,
                    )
                ],
            )
        return SiteVerdict(
            status=AssessmentStatus.INCONCLUSIVE,
            reason_codes=["no_sink_at_location"],
            explanation=f"no {vuln_class} sink the helper recognizes is at {path}:{line}; the "
            "scanner may point at another step of the flow, or use a sink outside the catalogue",
        )

    # -- one sink site -------------------------------------------------------

    def _assess_site(self, site: p.Site, vuln_class: str) -> SiteVerdict:
        self._spend()
        analysis = self._source.analyze_site(site.site_id)
        facts = [
            Fact(
                source=FactSource.SEMANTIC,
                kind="sink",
                statement=f"{site.sink.display} ({site.sink.resolution}) receives "
                f"`{site.argument_text}`",
                refs=_ref(site.location, site.sink.symbol),
                producer=self._producer,
                data={"site_id": site.site_id, "argument_role": site.sink.argument_role},
            )
        ]
        for guard in analysis.guards:
            facts.append(
                Fact(
                    source=FactSource.SEMANTIC,
                    kind="guard",
                    statement=f"{guard.kind} on {guard.subject_text}: `{guard.condition_text}` "
                    f"(holds at sink: {guard.holds_at_sink})",
                    refs=_ref(guard.location, guard.subject_symbol),
                    producer=self._producer,
                    data=dict(guard.facts),
                )
            )

        if site.sink.resolution != "resolved":
            return SiteVerdict(
                status=AssessmentStatus.INCONCLUSIVE,
                reason_codes=["unresolved_sink"],
                explanation=f"the sink `{site.sink.display}` is an unresolved candidate (its "
                "symbols did not resolve, usually an unrestored package); it can neither support "
                "nor dismiss the finding",
                facts=facts,
                unresolved=[site.sink.display],
            )

        context = _Context(
            vuln_class=vuln_class,
            role=site.sink.argument_role,
            effects={},
            depth=0,
            expanding=frozenset(),
            method=site.containing.id if site.containing else None,
        )
        flow = self._with_guards(analysis.value, analysis.guards, context)
        if analysis.truncated:
            flow.incomplete.append(_SLICE_TRUNCATED)
            flow.unknown.append("parts of the value were not sliced (truncated)")
        return _decide(flow, facts, list(analysis.unresolved), site)

    # -- value tree ----------------------------------------------------------

    def _with_guards(
        self, value: p.ValueNode, guards: Iterable[p.Guard], context: _Context
    ) -> Flow:
        effects = dict(context.effects)
        for guard in guards:
            effect = self._guard_effect(guard, value, context)
            if effect is not None:
                effects[guard.subject_symbol] = effect
        return self._eval(value, context.but(effects=effects))

    def _eval(self, node: p.ValueNode, ctx: _Context) -> Flow:
        flow = self._eval_node(node, ctx)
        hop = node.facts.get("hop_guards")
        if hop:
            reason = self._hop_block(hop)
            if reason is not None:
                flow = flow.blocked(reason)
        return flow

    def _eval_node(self, node: p.ValueNode, ctx: _Context) -> Flow:
        if node.symbol is not None and node.symbol in ctx.effects:
            effect = ctx.effects[node.symbol]
            rest = ctx.but(effects={k: v for k, v in ctx.effects.items() if k != node.symbol})
            if effect.kind == "mitigate" and (ctx.whole or not effect.whole_value_only):
                return Flow(mitigations=[effect.description], assumptions=list(effect.assumptions))
            reason = effect.description
            if effect.kind == "mitigate":
                reason += ", but the checked value is only part of the sink value"
            return self._eval_node(node, rest).blocked(reason)

        kind = node.kind
        if (kind in ("local", "field", "property") and node.detail == "cycle") or node.facts.get(
            "cycle"
        ) == "true":
            # The value at this read depends on itself (a loop-carried or
            # recursive definition). Other definitions reaching the read are
            # evaluated where the cycle started; this one is not resolved.
            return Flow(
                unknown=[f"{kind} {_where(node)} depends on its own earlier value; not resolved"]
            )
        if kind in ("constant", "typed_safe"):
            return Flow()
        if kind == "endpoint_parameter":
            return self._endpoint_parameter(node, ctx)
        if kind == "request_source":
            return self._request_source(node, ctx)
        if kind in ("config_source", "environment_source"):
            source = "configuration" if kind == "config_source" else "environment"
            return Flow(untrusted=[f"{source} value {_where(node)}, trust unknown"])
        if kind == "parameter":
            return self._parameter(node, ctx)
        if kind == "sanitizer":
            return self._sanitizer(node, ctx)
        if kind == "unknown_call":
            inner = self._children(node, ctx.but(whole=False, tail=False))
            result = inner.blocked(f"passes through unknown call {node.detail or node.text}")
            result.unknown.append(f"result of unknown call {_where(node)}")
            return result
        if kind == "propagator":
            return self._propagator(node, ctx)
        if kind in ("concat", "interpolation"):
            return self._concat(node, ctx)
        if kind == "call" and not node.children:
            return Flow(unknown=[f"call {_where(node)} not expanded ({node.detail})"])
        if kind == "local":
            if not node.children:
                return Flow(unknown=[f"local {_where(node)} has no known value ({node.detail})"])
            return self._definitions(node, ctx, initial=None)
        if kind in ("field", "property"):
            return self._member(node, ctx)
        if kind in ("argument", "call", "conditional", "formattable"):
            if not node.children:
                return Flow(unknown=[f"{kind} {_where(node)} has no known value ({node.detail})"])
            if kind == "formattable":
                ctx = ctx.but(whole=False, tail=False)
            return self._children(node, ctx)
        if kind == "truncated":
            return Flow(
                unknown=[f"slice truncated at {_where(node)}"],
                incomplete=[_SLICE_TRUNCATED],
            )
        return Flow(unknown=[f"{kind} {_where(node)} ({node.detail or 'no detail'})"])

    def _children(self, node: p.ValueNode, ctx: _Context) -> Flow:
        flow = Flow()
        for child in node.children:
            flow.add(self._eval(child, ctx))
        return flow

    def _concat(self, node: p.ValueNode, ctx: _Context) -> Flow:
        flow = Flow()
        fixed = ctx.fixed
        children = node.children
        for index, child in enumerate(children):
            later = [_constant_text(c) for c in children[index + 1 :]]
            tail = ctx.tail and all(t is not None and "/" not in t and "\\" not in t for t in later)
            flow.add(self._eval(child, ctx.but(whole=False, tail=tail, fixed=fixed)))
            text = _constant_text(child)
            if ctx.vuln_class == "open_redirect" and index == 0 and text is not None:
                fixed = fixed or _fixes_destination(text)
        return flow

    def _propagator(self, node: p.ValueNode, ctx: _Context) -> Flow:
        if node.symbol in _HOST_PATHS:
            return Flow(assumptions=[_HOST_PATH_ASSUMPTION.format(name=node.detail)])
        detail = node.detail or ""
        if detail.startswith(("compound ", "mutation ")):
            return self._children(node, ctx)
        symbol = node.symbol or ""
        if symbol.startswith(_PATH_JOINS):
            flow = Flow()
            last = len(node.children) - 1
            for index, child in enumerate(node.children):
                child_ctx = ctx.but(whole=False, tail=ctx.tail and index == last)
                flow.add(self._eval(child, child_ctx))
        elif symbol.startswith(_PATH_NORMALIZE):
            flow = self._children(node, ctx.but(whole=False))
        else:
            flow = self._children(node, ctx.but(whole=False, tail=False))
        if node.facts.get("alters_content") == "true":
            return flow.blocked(f"content-altering transform {node.detail or node.text}")
        return flow

    def _sanitizer(self, node: p.ValueNode, ctx: _Context) -> Flow:
        effect = node.facts.get("effect")
        if (
            ctx.vuln_class == "path_traversal"
            and effect == "strips_directory_components"
            and ctx.role == "file_path"
            and ctx.tail
        ):
            inner = self._children(node, ctx.but(whole=False, tail=False))
            # The value can no longer name a directory and nothing after it adds
            # one, so it cannot move the file operation out of its directory.
            return Flow(
                mitigations=[
                    f"{node.detail} strips directory components from the last path component "
                    f"of a file operation ({_where(node)})"
                ],
                assumptions=[*inner.assumptions, _LINK_ASSUMPTION],
                incomplete=inner.incomplete,
            )
        return self._children(node, ctx.but(whole=False, tail=False))

    # -- definitions ---------------------------------------------------------

    def _definitions(self, node: p.ValueNode, ctx: _Context, *, initial: Flow | None) -> Flow:
        """The value of a local or parameter at the read, from its definitions.

        ``initial`` is the value a parameter enters with; it counts only when
        no definition before the read replaces it on every path.
        """
        live = [c for c in node.children if c.facts.get("def_order", "unordered") != "after"]
        assigns = [
            c
            for c in live
            if c.facts.get("def_kind", "assign") == "assign" and c.facts.get("def_killed") != "true"
        ]
        accumulations = [c for c in live if c.facts.get("def_kind") == "accumulate"]
        dominating = [c for c in assigns if c.facts.get("def_dominates") == "true"]
        if dominating:
            cut = max(int(c.facts["def_position"]) for c in dominating)

            def reaches(c: p.ValueNode) -> bool:
                if c.facts.get("def_order") == "unordered":
                    return True
                return int(c.facts.get("def_position", "-1")) >= cut

            assigns = [c for c in assigns if reaches(c)]
            accumulations = [c for c in accumulations if reaches(c)]
            initial = None
        flow = Flow()
        if initial is not None:
            flow.add(initial)
        for child in [*assigns, *accumulations]:
            flow.add(self._eval(child, ctx))
        if not assigns and initial is None and not accumulations:
            flow.unknown.append(f"no definition of {_where(node)} reaches the read")
        return flow

    @staticmethod
    def _replaced_before_read(node: p.ValueNode) -> bool:
        return any(
            c.facts.get("def_dominates") == "true"
            and c.facts.get("def_order") == "before"
            and c.facts.get("def_kind", "assign") == "assign"
            for c in node.children
        )

    def _member(self, node: p.ValueNode, ctx: _Context) -> Flow:
        if not node.children:
            return Flow(unknown=[f"{node.kind} {_where(node)} has no known value ({node.detail})"])
        flows = [self._eval(child, ctx) for child in node.children]
        merged = Flow()
        for flow in flows:
            merged.add(flow)
        # Fields and properties are written from other methods, so which write
        # is current at the sink is not known. A tainted write counts only when
        # every write is tainted.
        if len(flows) > 1 and merged.tainted and not all(f.tainted for f in flows):
            merged = merged.blocked(
                f"{node.kind} {node.detail} also has other writes; which one is current at the "
                "sink is not established"
            )
        validation = node.facts.get("validation")
        if validation:
            reason = self._validation_block(validation, f"property {node.detail}")
            if reason is not None:
                merged = merged.blocked(reason)
        return merged

    # -- request data --------------------------------------------------------

    def _fixed_prefix(self, node: p.ValueNode) -> Flow:
        return Flow(
            mitigations=[
                f"request value {_where(node)} follows a constant prefix that keeps the redirect "
                "on the site"
            ]
        )

    def _endpoint_parameter(self, node: p.ValueNode, ctx: _Context) -> Flow:
        handler = node.facts.get("handler", "")
        if ctx.fixed:
            initial = self._fixed_prefix(node)
        else:
            initial = Flow(tainted=[f"request data {_where(node)} [{node.detail or 'request'}]"])
            for reason in [*self._binding_blocks(node), *self._layer_blocks({handler})]:
                initial = initial.blocked(reason)
        if node.children:
            return self._definitions(node, ctx, initial=initial)
        return initial

    def _binding_blocks(self, node: p.ValueNode) -> list[str]:
        reasons = []
        validation = node.facts.get("validation")
        if validation:
            reason = self._validation_block(validation, f"parameter {node.text}")
            if reason is not None:
                reasons.append(reason)
        if "model_binder" in node.facts:
            reasons.append(f"custom model binder {node.facts['model_binder']} produces {node.text}")
        constraints = [c for c in node.facts.get("route_constraints", "").split(";") if c]
        unknown = [c for c in constraints if not _CONTENT_NEUTRAL_CONSTRAINT.match(c.lower())]
        if unknown:
            reasons.append(f"route constraint {', '.join(unknown)} on {node.text}")
        return reasons

    @staticmethod
    def _validation_block(validation: str, what: str) -> str | None:
        names = [n for n in validation.split(",") if n]
        effective = [n for n in names if n not in _CONTENT_NEUTRAL_ATTRIBUTES]
        if not effective:
            return None
        return f"model validation ({', '.join(effective)}) on {what}"

    def _request_source(self, node: p.ValueNode, ctx: _Context) -> Flow:
        if ctx.fixed:
            return self._fixed_prefix(node)
        handlers, cut, _ = self._reaching_handlers(ctx.method, 0, frozenset())
        if cut:
            where = ctx.method or "an unknown method"
            return Flow(
                unknown=[
                    f"request data {_where(node)} is read in {where}; the search for "
                    f"endpoints calling it stopped at depth {self._max_depth}"
                ],
                incomplete=[f"caller expansion depth limit {self._max_depth} reached"],
            )
        if not handlers:
            where = ctx.method or "an unknown method"
            return Flow(
                uncertain=[
                    f"request data {_where(node)} is read in {where}, which is not shown to be "
                    "called from an HTTP endpoint"
                ]
            )
        flow = Flow(tainted=[f"request data {_where(node)} [{node.detail}]"])
        for reason in self._layer_blocks(handlers):
            flow = flow.blocked(reason)
        return flow

    def _reaching_handlers(
        self, method: str | None, depth: int, stack: frozenset[str]
    ) -> tuple[frozenset[str], bool, bool]:
        """Endpoint handlers from which ``method`` is called, possibly none.

        Also returns whether the search was cut at the depth limit, and
        whether it skipped a method already on the search stack. Only a
        search that did neither is cached: a skipped method's other callers
        are covered by its own frame, but not when the result is reused.
        """
        if not method:
            return frozenset(), False, False
        if method in self._reachable:
            return self._reachable[method], False, False
        if method in stack:
            return frozenset(), False, True
        if method in self._endpoint_kinds():
            result, cut, skipped = frozenset({method}), False, False
        elif depth >= self._max_depth:
            return frozenset(), True, False
        else:
            found: set[str] = set()
            cut = skipped = False
            for call in self._callers(method).calls:
                if call.caller is not None:
                    handlers, deeper_cut, deeper_skipped = self._reaching_handlers(
                        call.caller.id, depth + 1, stack | {method}
                    )
                    found |= handlers
                    cut |= deeper_cut
                    skipped |= deeper_skipped
            result = frozenset(found)
        if not cut and not skipped:
            self._reachable[method] = result
        return result, cut, skipped

    def _layer_blocks(self, handlers: Iterable[str]) -> list[str]:
        kinds = self._endpoint_kinds()
        reasons = []
        for layer in self._pipeline():
            if not layer.can_affect_input:
                continue
            for handler in handlers:
                kind = kinds.get(handler)
                applies = (
                    layer.scope == "all"
                    or (layer.scope == "controllers" and kind == "controller_action")
                    or (layer.scope == "minimal_apis" and kind == "minimal_api")
                    or handler in layer.handlers
                )
                if applies:
                    where = ""
                    if layer.location:
                        where = f" ({layer.location.path}:{layer.location.start_line})"
                    reasons.append(
                        f"{layer.kind} {layer.name}{where} runs before the handler, reads request "
                        f"input ({layer.reads_request_input}) and can reject or rewrite the "
                        "request; its effect on this value is not analyzed"
                    )
                    break
        return reasons

    # -- callers -------------------------------------------------------------

    def _parameter(self, node: p.ValueNode, ctx: _Context) -> Flow:
        if node.children and self._replaced_before_read(node):
            # The incoming value never reaches the read; callers do not matter.
            return self._definitions(node, ctx, initial=None)
        if node.facts.get("entry_point") == "true":
            method = node.facts.get("method", "?")
            incoming = Flow(
                untrusted=[f"argument {_where(node)} of entry point {method}, trust unknown"]
            )
        else:
            incoming = self._expand_callers(node, ctx)
        if node.children:
            return self._definitions(node, ctx, initial=incoming)
        return incoming

    def _expand_callers(self, node: p.ValueNode, ctx: _Context) -> Flow:
        method = node.facts.get("method", "")
        if not method or method in ctx.expanding:
            return Flow(unknown=[f"parameter {_where(node)} cannot be expanded"])
        if ctx.depth >= self._max_depth:
            return Flow(
                unknown=[f"caller expansion of {method} stopped at depth {self._max_depth}"],
                incomplete=[f"caller expansion depth limit {self._max_depth} reached"],
            )
        ordinal = int(node.facts["ordinal"])
        callers = self._callers(method)
        flow = Flow()
        if not callers.complete:
            reasons = "; ".join(callers.incomplete_reasons) or "unknown reason"
            flow.unknown.append(f"callers of {method} may be incomplete: {reasons}")
        for call in callers.calls:
            if call.via_dispatch and not self._registered(method):
                flow.unknown.append(
                    f"call at {call.location.path}:{call.location.start_line} reaches "
                    f"{method} only through dispatch, and no registration for it was found"
                )
                continue
            if call.via_dispatch:
                flow.assumptions.append(
                    f"{_type_of(method)} is registered for dependency injection, so the "
                    f"dispatched call at {call.location.path}:{call.location.start_line} can "
                    "reach it under at least one configuration"
                )
            argument = self._argument(call, ordinal)
            caller = argument.containing.id if argument.containing else None
            deeper = ctx.but(
                effects={},
                depth=ctx.depth + 1,
                expanding=ctx.expanding | {method},
                method=caller,
            )
            flow.add(self._with_guards(argument.value, argument.guards, deeper))
            if argument.truncated:
                flow.incomplete.append(_SLICE_TRUNCATED)
            for name in argument.unresolved:
                flow.unknown.append(f"unresolved symbol {name}")
        if not callers.calls and callers.complete:
            flow.mitigations.append(f"{method} has no callers in the analyzed code")
        return flow

    def _registered(self, method: str) -> bool:
        owner = _type_of(method)
        return any(r.implementation == owner for r in self._di())

    # -- guards --------------------------------------------------------------

    def _guard_effect(self, guard: p.Guard, value: p.ValueNode, ctx: _Context) -> _Effect | None:
        if guard.holds_at_sink != "true" or guard.reassigned_before_sink:
            return None
        where = f"`{guard.condition_text}` ({guard.location.path}:{guard.location.start_line})"
        kind = guard.kind
        if kind in ("null_or_empty_check", "rooted_check"):
            return None
        if kind == "is_local_url":
            if ctx.vuln_class == "open_redirect":
                return _Effect(
                    "mitigate",
                    f"Url.IsLocalUrl check {where} holds at the redirect",
                    whole_value_only=True,
                )
            return None
        if kind == "starts_with":
            return self._prefix_effect(guard, value, ctx, where)
        if kind == "validator_call":
            return self._validator_effect(guard, where)
        # regex, contains, equals, custom predicates, derived checks and
        # unclassified conditions
        return _Effect("block", f"check of unknown effect {where}")

    @staticmethod
    def _validator_effect(guard: p.Guard, where: str) -> _Effect | None:
        facts = guard.facts
        callee = facts.get("callee", "")
        if callee.startswith(_NON_VALIDATING_PREFIXES):
            return None
        if facts.get("may_throw") == "false":
            return None  # it cannot reject the value, whatever it returns
        if (
            facts.get("returns_task") == "true"
            and facts.get("awaited") == "false"
            and facts.get("is_async") == "true"
        ):
            return None  # its exception stays inside a task nobody awaits
        return _Effect("block", f"validator {callee or guard.condition_text} at {where}")

    def _prefix_effect(
        self, guard: p.Guard, value: p.ValueNode, ctx: _Context, where: str
    ) -> _Effect | None:
        facts = guard.facts
        if ctx.vuln_class == "open_redirect":
            if facts.get("prefix", "").strip() in ("'/'", '"/"'):
                # "//host" and "/\\host" pass this check.
                return None
            return _Effect("block", f"prefix check of unknown sufficiency {where}")
        if ctx.vuln_class != "path_traversal":
            return None
        if facts.get("subject_from_get_full_path") != "true":
            return None  # "../" in an unnormalized path passes the check
        if facts.get("prefix_ends_with_separator") == "false":
            return None  # a sibling directory sharing the prefix passes
        if facts.get("comparison") == "StringComparison.OrdinalIgnoreCase":
            return _Effect(
                "block",
                f"case-insensitive prefix check {where}; on a case-sensitive file system a "
                "differently cased directory outside the root passes it",
            )
        if (
            facts.get("prefix_ends_with_separator") != "true"
            or facts.get("comparison") != "StringComparison.Ordinal"
            or not guard.sink_argument_is_subject
        ):
            return _Effect("block", f"prefix check {where} not shown to be complete")
        # The helper says whether it listed everything the prefix is built
        # from. Without that, an empty symbol list proves nothing.
        origin = facts.get("prefix_origin")
        symbols = [s for s in facts.get("prefix_symbols", "").split(";") if s]
        if origin not in ("constant", "symbols") or (origin == "constant") == bool(symbols):
            return _Effect("block", f"origin of the prefix in {where} is not established")
        assumptions = [_LINK_ASSUMPTION]
        for symbol in symbols:
            if symbol.startswith("unsupported:"):
                return _Effect("block", f"prefix in {where} built from an unanalyzed expression")
            subtree = _find_symbol(value, symbol)
            if subtree is None:
                return _Effect("block", f"origin of prefix {symbol} in {where} not found")
            prefix = self._eval(subtree, ctx.but(effects={}, whole=True, tail=True, fixed=False))
            if not prefix.clean or prefix.incomplete:
                return _Effect("block", f"prefix {symbol} in {where} is not a trusted value")
            assumptions.extend(prefix.assumptions)
        return _Effect(
            "mitigate",
            "normalized path is checked ordinally against a trusted root plus separator, "
            f"with an early exit, at {where}",
            assumptions=tuple(_dedupe(assumptions)),
        )

    def _hop_block(self, raw: str) -> str | None:
        """A check between this value and the sink, in another member.

        Such checks are never used as mitigations. Whether they constrain the
        value is not established, so any that might blocks confirmation.
        """
        guards = [p.Guard.model_validate(g) for g in json.loads(raw)]
        for guard in guards:
            if guard.holds_at_sink != "true" or guard.reassigned_before_sink:
                continue
            if guard.kind in ("null_or_empty_check", "rooted_check"):
                continue
            where = f"`{guard.condition_text}` ({guard.location.path}:{guard.location.start_line})"
            if guard.kind == "validator_call" and self._validator_effect(guard, where) is None:
                continue
            return f"check in another method {where}"
        return None


def _starts_within(span: p.Span, line: int, start: int) -> bool:
    """The flagged expression begins inside this call, as a sink argument would.

    A region that merely overlaps the call (a whole statement or line) can
    contain other calls, so it does not tie the finding to this one.
    """
    if not span.start_line <= line <= span.end_line:
        return False
    after_start = line > span.start_line or start >= span.start_column
    before_end = line < span.end_line or start < span.end_column
    return after_start and before_end


def _find_symbol(node: p.ValueNode, symbol: str) -> p.ValueNode | None:
    for candidate in node.walk():
        if candidate.symbol == symbol and candidate.children:
            return candidate
    return None


def _type_of(method: str) -> str:
    name = method[2:] if method.startswith("M:") else method
    return name.split("(", 1)[0].rsplit(".", 1)[0]


def _decide(flow: Flow, facts: list[Fact], unresolved: list[str], site: p.Site) -> SiteVerdict:
    where = f"{site.location.path}:{site.location.start_line}"
    assumptions = list(flow.assumptions)
    if flow.incomplete:
        # Part of the value was not analyzed. A path found in the analyzed
        # part could still pass a check in the rest, so it is reported but
        # does not decide the finding.
        partial = [*flow.tainted, *flow.uncertain, *flow.untrusted, *flow.unknown]
        return SiteVerdict(
            status=AssessmentStatus.INCONCLUSIVE,
            reason_codes=["budget_exhausted"],
            explanation=f"analysis of the sink at {where} did not finish: "
            f"{'; '.join(_dedupe(flow.incomplete))}",
            facts=facts,
            checks=[
                CheckResult(
                    name="analysis_complete",
                    outcome=CheckOutcome.FAILED,
                    detail=reason,
                    refs=_ref(site.location),
                )
                for reason in _dedupe(flow.incomplete)
            ]
            + [
                CheckResult(name="partial_result", outcome=CheckOutcome.UNKNOWN, detail=item)
                for item in partial
            ],
            unresolved=unresolved,
            assumptions=_dedupe(assumptions),
            complete=False,
        )
    if flow.tainted:
        status = AssessmentStatus.SUPPORTED
        codes = ["request_data_reaches_sink"]
        explanation = (
            f"{flow.tainted[0]} reaches the sink at {where} with no transformation, check or "
            "request-pipeline layer whose effect on it is unknown"
        )
        checks = [
            CheckResult(
                name="tainted_path",
                outcome=CheckOutcome.PASSED,
                detail=t,
                refs=_ref(site.location),
            )
            for t in flow.tainted
        ]
        assumptions.extend(_SUPPORT_ASSUMPTIONS)
    elif flow.uncertain or flow.untrusted or flow.unknown or unresolved:
        status = AssessmentStatus.INCONCLUSIVE
        blockers = [*flow.uncertain, *flow.untrusted, *flow.unknown]
        codes = []
        if flow.uncertain:
            codes.append("unknown_transformation_or_check")
        if flow.untrusted:
            codes.append("input_of_unknown_trust")
        if flow.unknown:
            codes.append("unresolved_value")
        if unresolved:
            codes.append("unresolved_symbols")
        first = (blockers or [f"unresolved symbols: {', '.join(unresolved)}"])[0]
        explanation = f"no decision for the sink at {where}: {first}"
        checks = [
            CheckResult(name="blocking_factor", outcome=CheckOutcome.UNKNOWN, detail=b)
            for b in blockers
        ]
    else:
        status = AssessmentStatus.LIKELY_FALSE_POSITIVE
        reasons = flow.mitigations or ["every value reaching the sink is a constant or a safe type"]
        codes = ["mitigated" if flow.mitigations else "constant_or_typed_input"]
        explanation = f"the value at {where} cannot carry an attack: {'; '.join(reasons)}"
        checks = [
            CheckResult(
                name="all_inputs_safe",
                outcome=CheckOutcome.PASSED,
                detail=r,
                refs=_ref(site.location),
            )
            for r in reasons
        ]
    return SiteVerdict(
        status=status,
        reason_codes=codes,
        explanation=explanation,
        facts=facts,
        checks=checks,
        unresolved=unresolved,
        assumptions=_dedupe(assumptions),
    )


def _combine(verdicts: Sequence[SiteVerdict]) -> SiteVerdict:
    if len(verdicts) == 1:
        return verdicts[0]
    statuses = {v.status for v in verdicts}
    unfinished = [v for v in verdicts if not v.complete]
    if unfinished:
        # One finding, one location: a site left unanalyzed leaves the
        # finding undecided even when another site has a verdict.
        chosen = unfinished[0]
    elif AssessmentStatus.SUPPORTED in statuses:
        chosen = next(v for v in verdicts if v.status is AssessmentStatus.SUPPORTED)
    elif statuses == {AssessmentStatus.LIKELY_FALSE_POSITIVE}:
        chosen = verdicts[0]
    else:
        chosen = next(v for v in verdicts if v.status is AssessmentStatus.INCONCLUSIVE)
    explanation = f"{len(verdicts)} sink sites at this location; " + chosen.explanation
    codes = _dedupe(c for v in verdicts for c in v.reason_codes)
    if unfinished:
        codes = _dedupe(c for v in unfinished for c in v.reason_codes)
        others = [v.status.value for v in verdicts if v.complete]
        if others:
            explanation += f" (other sites, not used: {', '.join(others)})"
    return SiteVerdict(
        status=chosen.status,
        reason_codes=codes,
        explanation=explanation,
        facts=[f for v in verdicts for f in v.facts],
        checks=[c for v in verdicts for c in v.checks],
        unresolved=_dedupe(u for v in verdicts for u in v.unresolved),
        assumptions=_dedupe(a for v in verdicts for a in v.assumptions),
        complete=all(v.complete for v in verdicts),
    )


__all__ = [
    "BudgetExhausted",
    "Flow",
    "Investigator",
    "SemanticError",
    "SemanticSource",
    "SiteVerdict",
]
