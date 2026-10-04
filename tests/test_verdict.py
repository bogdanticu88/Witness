from __future__ import annotations

import pytest

from fakes import FakeHelper, const, guard, node, request, single, site, span
from witness.model.assessment import AssessmentStatus
from witness.semantic import protocol as p
from witness.triage.verdict import Investigator

SUPPORTED = AssessmentStatus.SUPPORTED
LFP = AssessmentStatus.LIKELY_FALSE_POSITIVE
INCONCLUSIVE = AssessmentStatus.INCONCLUSIVE


def assess(helper: FakeHelper, vuln_class: str = "sql_injection", **kwargs: int):  # type: ignore[no-untyped-def]
    return Investigator(helper, **kwargs).assess("src/A.cs", 10, 10, vuln_class)


def concat(*parts: p.ValueNode) -> p.ValueNode:
    return node("concat", "a + b", *parts)


# -- SQL injection -----------------------------------------------------------


def test_request_value_concatenated_into_sql_is_supported() -> None:
    verdict = assess(single(concat(const(), request())))
    assert verdict.status is SUPPORTED
    assert verdict.complete
    assert "request data" in verdict.explanation


def test_constant_sql_is_likely_false_positive() -> None:
    verdict = assess(single(const()))
    assert verdict.status is LFP
    assert verdict.reason_codes == ["constant_or_typed_input"]


def test_typed_value_is_likely_false_positive() -> None:
    verdict = assess(single(concat(const(), node("typed_safe", "id", detail="int"))))
    assert verdict.status is LFP


def test_unresolved_sink_neither_supports_nor_dismisses() -> None:
    assert (
        assess(single(concat(const(), request()), resolution="unresolved_candidate")).status
        is INCONCLUSIVE
    )
    assert assess(single(const(), resolution="unresolved_candidate")).status is INCONCLUSIVE


def test_unknown_library_call_blocks_both_directions() -> None:
    call = node("unknown_call", "Lib.Do(q)", request(), detail="Lib.Do")
    verdict = assess(single(concat(const(), call)))
    assert verdict.status is INCONCLUSIVE
    assert "unknown_transformation_or_check" in verdict.reason_codes


def test_content_altering_transform_blocks_confirmation() -> None:
    escaped = node(
        "propagator",
        "q.Replace",
        request(),
        detail="String.Replace",
        facts={"alters_content": "true"},
    )
    assert assess(single(concat(const(), escaped))).status is INCONCLUSIVE


def test_plain_propagator_keeps_taint() -> None:
    trimmed = node("propagator", "q.Trim()", request(), detail="String.Trim")
    assert assess(single(concat(const(), trimmed))).status is SUPPORTED


def test_configuration_value_is_of_unknown_trust() -> None:
    config = node("config_source", '_config["X"]', detail="IConfiguration.this[]")
    verdict = assess(single(concat(const(), config)))
    assert verdict.status is INCONCLUSIVE
    assert "input_of_unknown_trust" in verdict.reason_codes


def test_unresolved_value_blocks_dismissal_only() -> None:
    unknown = node("unknown", "y", detail="unresolved expression")
    assert assess(single(concat(const(), unknown))).status is INCONCLUSIVE
    assert assess(single(concat(request(), unknown))).status is SUPPORTED


def test_unresolved_symbols_block_dismissal() -> None:
    verdict = assess(single(const(), unresolved=("Dapper.SqlMapper",)))
    assert verdict.status is INCONCLUSIVE
    assert "unresolved_symbols" in verdict.reason_codes


def test_truncated_slice_is_incomplete_and_never_clean() -> None:
    verdict = assess(single(const(), truncated=True))
    assert verdict.status is INCONCLUSIVE
    assert not verdict.complete


def test_custom_validator_call_blocks_confirmation() -> None:
    q = request()
    validator = guard(
        "validator_call",
        q.symbol or "",
        sink_argument_is_subject=False,
        facts={"callee": "M:App.Rules.Check(System.String)", "declared_in_source": "true"},
    )
    verdict = assess(single(concat(const(), q), guards=(validator,)))
    assert verdict.status is INCONCLUSIVE


def test_logging_call_before_sink_is_not_a_validator() -> None:
    q = request()
    logging = guard(
        "validator_call",
        q.symbol or "",
        sink_argument_is_subject=False,
        facts={"callee": "M:Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(...)"},
    )
    assert assess(single(concat(const(), q), guards=(logging,))).status is SUPPORTED


def test_guard_on_another_value_does_not_protect_the_sink() -> None:
    other = guard("unknown_condition", "parameter:status@src/A.cs:5")
    assert assess(single(concat(const(), request("sort")), guards=(other,))).status is SUPPORTED


def test_null_check_is_not_a_mitigation() -> None:
    q = request()
    check = guard("null_or_empty_check", q.symbol or "")
    assert assess(single(q, guards=(check,))).status is SUPPORTED


# -- open redirect -----------------------------------------------------------


def test_is_local_url_guard_dismisses_redirect() -> None:
    q = request("returnUrl")
    verdict = assess(
        single(
            q,
            vuln_class="open_redirect",
            role="url",
            guards=(guard("is_local_url", q.symbol or ""),),
        ),
        "open_redirect",
    )
    assert verdict.status is LFP
    assert verdict.reason_codes == ["mitigated"]


@pytest.mark.parametrize(
    "overrides",
    [{"holds_at_sink": "unknown"}, {"holds_at_sink": "false"}, {"reassigned_before_sink": True}],
)
def test_guard_that_may_not_hold_is_not_a_mitigation(overrides: dict[str, object]) -> None:
    q = request("returnUrl")
    check = guard("is_local_url", q.symbol or "", **overrides)
    helper = single(q, vuln_class="open_redirect", role="url", guards=(check,))
    assert assess(helper, "open_redirect").status is SUPPORTED


def test_guarded_branch_does_not_cover_unguarded_branch() -> None:
    returned = request("returnUrl")
    nxt = node("request_source", "Request.Query", detail="HttpRequest.Query")
    value = node("conditional", "a ? b : c", returned, nxt)
    check = guard("is_local_url", returned.symbol or "", sink_argument_is_subject=False)
    helper = single(value, vuln_class="open_redirect", role="url", guards=(check,))
    assert assess(helper, "open_redirect").status is SUPPORTED


def test_slash_prefix_check_does_not_stop_open_redirect() -> None:
    q = request("returnUrl")
    check = guard("starts_with", q.symbol or "", facts={"prefix": "'/'"})
    helper = single(q, vuln_class="open_redirect", role="url", guards=(check,))
    assert assess(helper, "open_redirect").status is SUPPORTED


def _safe_api_helper() -> FakeHelper:
    hit = p.SafeApiHit(
        description="LocalRedirect rejects non-local URLs",
        location=p.Span(
            path="src/A.cs", start_line=10, end_line=10, start_column=16, end_column=40
        ),
    )
    return FakeHelper(safe_apis={("src/A.cs", 10): [hit]})


def test_safe_redirect_api_at_the_flagged_column_is_dismissed() -> None:
    verdict = Investigator(_safe_api_helper()).assess(
        "src/A.cs", 10, 10, "open_redirect", start_column=30, end_column=39
    )
    assert verdict.status is LFP
    assert verdict.reason_codes == ["safe_api"]


def test_safe_api_elsewhere_on_the_line_dismisses_nothing() -> None:
    # The scanner flagged a call later on the line that is not in the catalogue.
    verdict = Investigator(_safe_api_helper()).assess(
        "src/A.cs", 10, 10, "open_redirect", start_column=50, end_column=70
    )
    assert verdict.status is INCONCLUSIVE


def test_statement_wide_region_is_not_tied_to_the_safe_call() -> None:
    verdict = Investigator(_safe_api_helper()).assess(
        "src/A.cs", 10, 10, "open_redirect", start_column=9, end_column=80
    )
    assert verdict.status is INCONCLUSIVE


def test_safe_api_without_a_column_dismisses_nothing() -> None:
    assert assess(_safe_api_helper(), "open_redirect").status is INCONCLUSIVE


def test_no_sink_at_location_is_inconclusive() -> None:
    assert assess(FakeHelper()).status is INCONCLUSIVE


# -- path traversal ----------------------------------------------------------


def _host_root() -> p.ValueNode:
    host = node(
        "propagator",
        "env.ContentRootPath",
        symbol="P:Microsoft.Extensions.Hosting.IHostEnvironment.ContentRootPath",
        detail="Microsoft.Extensions.Hosting.IHostEnvironment.ContentRootPath",
    )
    return node(
        "field",
        "_root",
        node("propagator", "Path.Combine", host, const('"docs"')),
        symbol="F:App._root",
    )


def _combine(*parts: p.ValueNode) -> p.ValueNode:
    return node(
        "propagator",
        "Path.Combine(...)",
        *parts,
        symbol="M:System.IO.Path.Combine(System.String,System.String)",
        detail="Path.Combine",
    )


def test_file_name_sanitizer_dismisses_file_read() -> None:
    clean = node(
        "sanitizer",
        "Path.GetFileName(name)",
        request("name"),
        detail="Path.GetFileName",
        facts={"effect": "strips_directory_components"},
    )
    value = _combine(_host_root(), clean)
    verdict = assess(single(value, vuln_class="path_traversal", role="file_path"), "path_traversal")
    assert verdict.status is LFP
    assert any("host configuration" in a for a in verdict.assumptions)


def test_file_name_sanitizer_does_not_cover_directory_operations() -> None:
    clean = node(
        "sanitizer",
        "Path.GetFileName(name)",
        request("name"),
        facts={"effect": "strips_directory_components"},
    )
    value = _combine(_host_root(), clean)
    verdict = assess(
        single(value, vuln_class="path_traversal", role="directory_path"), "path_traversal"
    )
    assert verdict.status is SUPPORTED


def test_file_name_sanitizer_means_nothing_for_sql() -> None:
    clean = node(
        "sanitizer",
        "Path.GetFileName(q)",
        request(),
        facts={"effect": "strips_directory_components"},
    )
    assert assess(single(concat(const(), clean))).status is SUPPORTED


def _checked_path(**facts: str) -> tuple[p.ValueNode, p.Guard]:
    root_full = node(
        "local",
        "rootFull",
        node("propagator", "Path.GetFullPath(_root)", _host_root()),
        symbol="local:rootFull@src/A.cs:7",
    )
    full = node(
        "local",
        "full",
        node(
            "propagator",
            "Path.GetFullPath(...)",
            node("propagator", "Path.Combine", root_full, request("name")),
        ),
        symbol="local:full@src/A.cs:8",
    )
    values = {
        "prefix": "rootFull + Path.DirectorySeparatorChar",
        "prefix_ends_with_separator": "true",
        "comparison": "StringComparison.Ordinal",
        "subject_from_get_full_path": "true",
        "prefix_symbols": "local:rootFull@src/A.cs:7",
    }
    values.update(facts)
    return full, guard("starts_with", "local:full@src/A.cs:8", facts=values)


def _path(value: p.ValueNode, check: p.Guard):  # type: ignore[no-untyped-def]
    return assess(
        single(value, vuln_class="path_traversal", role="file_path", guards=(check,)),
        "path_traversal",
    )


def test_complete_normalized_prefix_check_dismisses_path_traversal() -> None:
    verdict = _path(*_checked_path())
    assert verdict.status is LFP
    assert verdict.reason_codes == ["mitigated"]


def test_prefix_check_on_unnormalized_path_does_not_help() -> None:
    assert _path(*_checked_path(subject_from_get_full_path="false")).status is SUPPORTED


def test_prefix_without_separator_does_not_help() -> None:
    assert _path(*_checked_path(prefix_ends_with_separator="false")).status is SUPPORTED


@pytest.mark.parametrize(
    "facts",
    [
        {"comparison": "culture_sensitive_default"},
        {"prefix_ends_with_separator": "unknown"},
        {"prefix_symbols": "local:elsewhere@src/A.cs:3"},
        {"prefix_symbols": "unsupported:GetRoot()"},
    ],
)
def test_prefix_check_not_shown_complete_is_inconclusive(facts: dict[str, str]) -> None:
    assert _path(*_checked_path(**facts)).status is INCONCLUSIVE


def test_prefix_built_from_request_data_is_not_trusted() -> None:
    value, check = _checked_path()
    tainted_root = node("local", "rootFull", request("root"), symbol="local:rootFull@src/A.cs:7")
    value = node(
        "local",
        "full",
        node("propagator", "Path.Combine", tainted_root, request("name")),
        symbol="local:full@src/A.cs:8",
    )
    assert _path(value, check).status is INCONCLUSIVE


# -- caller expansion --------------------------------------------------------

METHOD = "M:App.Repo.Find(System.String)"


def _parameter(**facts: str) -> p.ValueNode:
    values = {"method": METHOD, "ordinal": "0", "entry_point": "false"}
    values.update(facts)
    return node("parameter", "name", symbol="parameter:name@src/A.cs:3", facts=values)


def _call(line: int, *, via_dispatch: bool = False) -> p.CallSite:
    return p.CallSite(location=span("src/B.cs", line), target=METHOD, via_dispatch=via_dispatch)


def _callers(*calls: p.CallSite, complete: bool = True) -> dict[str, p.Callers]:
    target = p.SymbolInfo(id=METHOD, display="Find", kind="Ordinary")
    reasons = () if complete else ("externally visible member",)
    return {
        METHOD: p.Callers(target=target, calls=calls, complete=complete, incomplete_reasons=reasons)
    }


def _helper(
    value: p.ValueNode,
    callers: dict[str, p.Callers],
    arguments: dict[tuple[str, int], p.ValueNode],
    **kwargs: object,
) -> FakeHelper:
    s = site()
    analysis = p.SiteAnalysis(site=s, value=value)
    return FakeHelper(
        sites={("src/A.cs", 10): [(s, analysis)]},
        callers=callers,
        arguments={k: p.ArgumentAnalysis(value=v) for k, v in arguments.items()},
        **kwargs,  # type: ignore[arg-type]
    )


def test_tainted_caller_supports_finding() -> None:
    helper = _helper(
        concat(const(), _parameter()),
        _callers(_call(20), complete=False),
        {("src/B.cs", 20): request()},
    )
    assert assess(helper).status is SUPPORTED


def test_complete_constant_callers_dismiss_finding() -> None:
    helper = _helper(
        concat(const(), _parameter()),
        _callers(_call(20), _call(30)),
        {("src/B.cs", 20): const("'east'"), ("src/B.cs", 30): const("'west'")},
    )
    assert assess(helper).status is LFP


def test_incomplete_callers_prevent_dismissal() -> None:
    helper = _helper(
        concat(const(), _parameter()),
        _callers(_call(20), complete=False),
        {("src/B.cs", 20): const()},
    )
    verdict = assess(helper)
    assert verdict.status is INCONCLUSIVE
    assert "unresolved_value" in verdict.reason_codes


def test_dispatched_call_needs_a_registration() -> None:
    callers = _callers(_call(20, via_dispatch=True), complete=False)
    unregistered = _helper(concat(const(), _parameter()), callers, {("src/B.cs", 20): request()})
    assert assess(unregistered).status is INCONCLUSIVE
    registration = p.DiRegistration(
        service="App.IRepo",
        implementation="App.Repo",
        lifetime="scoped",
        conditional=True,
        location=span(),
    )
    registered = _helper(
        concat(const(), _parameter()),
        callers,
        {("src/B.cs", 20): request()},
        registrations=[registration],
    )
    verdict = assess(registered)
    assert verdict.status is SUPPORTED
    assert any("registered" in a for a in verdict.assumptions)


def test_entry_point_argument_is_of_unknown_trust() -> None:
    helper = _helper(concat(const(), _parameter(entry_point="true")), {}, {})
    assert assess(helper).status is INCONCLUSIVE


def test_caller_depth_limit_makes_the_result_incomplete() -> None:
    helper = _helper(
        concat(const(), _parameter()), _callers(_call(20)), {("src/B.cs", 20): const()}
    )
    verdict = assess(helper, max_caller_depth=0)
    assert verdict.status is INCONCLUSIVE
    assert not verdict.complete


def test_query_budget_exhaustion_is_incomplete_and_never_clean() -> None:
    helper = _helper(
        concat(const(), _parameter()), _callers(_call(20)), {("src/B.cs", 20): const()}
    )
    verdict = assess(helper, max_calls=2)
    assert verdict.status is INCONCLUSIVE
    assert verdict.reason_codes == ["budget_exhausted"]
    assert not verdict.complete


def test_one_supported_site_on_a_line_decides_the_finding() -> None:
    safe = site(site_id="s1")
    unsafe = site(site_id="s2")
    helper = FakeHelper(
        sites={
            ("src/A.cs", 10): [
                (safe, p.SiteAnalysis(site=safe, value=const())),
                (unsafe, p.SiteAnalysis(site=unsafe, value=concat(const(), request()))),
            ]
        }
    )
    assert assess(helper).status is SUPPORTED


# -- review regressions ------------------------------------------------------


def _def(child: p.ValueNode, **facts: str) -> p.ValueNode:
    return child.model_copy(update={"facts": {**child.facts, **facts}})


def test_field_with_mixed_writes_is_not_confirmed() -> None:
    field = node("field", "_sql", request(), const(), symbol="F:App._sql", detail="_sql")
    verdict = assess(single(concat(const(), field)))
    assert verdict.status is INCONCLUSIVE
    assert "other writes" in verdict.explanation


def test_field_written_only_from_requests_is_confirmed() -> None:
    field = node("field", "_sql", request("a"), request("b"), symbol="F:App._sql", detail="_sql")
    assert assess(single(concat(const(), field))).status is SUPPORTED


def test_definition_in_a_loop_after_the_read_still_counts() -> None:
    local = node(
        "local",
        "s",
        _def(
            const(), def_kind="assign", def_order="before", def_dominates="true", def_position="10"
        ),
        _def(request(), def_kind="assign", def_order="unordered", def_position="90"),
        symbol="local:s@src/A.cs:3",
    )
    assert assess(single(local)).status is SUPPORTED


def test_definition_killed_by_a_later_sibling_does_not_count() -> None:
    local = node(
        "local",
        "s",
        _def(
            request(), def_kind="assign", def_order="before", def_killed="true", def_position="10"
        ),
        _def(const(), def_kind="assign", def_order="before", def_position="20"),
        symbol="local:s@src/A.cs:3",
    )
    assert assess(single(local)).status is LFP


def _layer(scope: str, handlers: tuple[str, ...] = (), **flags: str) -> p.PipelineLayer:
    data = {"reads_request_input": "true", "can_reject": "true", "rewrites_request": "false"}
    data.update(flags)
    return p.PipelineLayer(kind="middleware", name="Gate", scope=scope, handlers=handlers, **data)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("layer", "blocks"),
    [
        (_layer("all"), True),
        (_layer("controllers"), True),
        (_layer("minimal_apis"), False),
        (_layer("endpoint", ("M:Other.Handler",)), False),
        (_layer("all", reads_request_input="false"), False),
        (_layer("all", can_reject="false"), False),
        (_layer("all", can_reject="false", rewrites_request="true"), True),
        (_layer("all", reads_request_input="unknown", can_reject="unknown"), True),
    ],
)
def test_pipeline_layers_block_only_where_they_apply(layer: p.PipelineLayer, blocks: bool) -> None:
    q = request()
    q = q.model_copy(update={"facts": {"handler": "M:App.Controller.Action(System.String)"}})
    helper = single(concat(const(), q))
    helper._layers = [layer]
    expected = INCONCLUSIVE if blocks else SUPPORTED
    assert assess(helper).status is expected


def _hop(*guards: p.Guard) -> str:
    return "[" + ",".join(g.model_dump_json() for g in guards) + "]"


def test_check_in_another_method_blocks_confirmation() -> None:
    call = node(
        "call",
        "Clean(q)",
        request(),
        facts={"hop_guards": _hop(guard("unknown_check", "parameter:v@src/B.cs:1"))},
    )
    assert assess(single(concat(const(), call))).status is INCONCLUSIVE


def test_null_check_in_another_method_is_ignored() -> None:
    call = node(
        "call",
        "Clean(q)",
        request(),
        facts={"hop_guards": _hop(guard("null_or_empty_check", "parameter:v@src/B.cs:1"))},
    )
    assert assess(single(concat(const(), call))).status is SUPPORTED


def test_check_in_another_method_never_dismisses() -> None:
    check = guard("is_local_url", "parameter:v@src/B.cs:1")
    call = node("call", "Normalize(u)", request("u"), facts={"hop_guards": _hop(check)})
    helper = single(call, vuln_class="open_redirect", role="url")
    assert assess(helper, "open_redirect").status is INCONCLUSIVE


def test_malformed_facts_are_a_helper_error() -> None:
    from witness.errors import SemanticError

    broken = node(
        "parameter",
        "name",
        symbol="parameter:name@src/A.cs:3",
        facts={"method": METHOD, "ordinal": "zero"},
    )
    helper = _helper(concat(const(), broken), _callers(_call(20)), {("src/B.cs", 20): const()})
    with pytest.raises(SemanticError, match="cannot interpret"):
        assess(helper)


def test_request_data_outside_any_endpoint_path_is_not_confirmed() -> None:
    read = node("request_source", "Request.Query", detail="HttpRequest.Query")
    helper = single(concat(const(), read))
    helper._endpoints = []
    target = p.SymbolInfo(
        id="M:App.Controller.Action(System.String)", display="Action", kind="Ordinary"
    )
    helper._callers = {target.id: p.Callers(target=target, calls=(), complete=False)}
    verdict = assess(helper)
    assert verdict.status is INCONCLUSIVE
    assert "not shown to be called" in verdict.explanation


def test_unresolvable_caller_symbol_means_unknown_callers() -> None:
    from witness.errors import SemanticRequestError

    class NoSymbol(FakeHelper):
        def callers(self, method: str) -> p.Callers:
            raise SemanticRequestError("symbol not found", code="unknown_symbol")

    helper = NoSymbol(
        sites={
            ("src/A.cs", 10): [
                (site(), p.SiteAnalysis(site=site(), value=concat(const(), _parameter())))
            ]
        }
    )
    verdict = assess(helper)
    assert verdict.status is INCONCLUSIVE
    assert "cannot resolve" in verdict.explanation
