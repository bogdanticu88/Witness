using Witness.Semantic.Protocol;

namespace Witness.Semantic.Tests;

[Collection("shop")]
public sealed class LoadingTests(ShopFixture shop)
{
    [Fact]
    public void Loads_both_projects_without_unresolved_framework_symbols()
    {
        var web = shop.Load.Projects.Single(p => p.Name == "Shop.Web");
        var data = shop.Load.Projects.Single(p => p.Name == "Shop.Data");
        Assert.Contains("Shop.Data", web.ProjectReferences);
        Assert.Equal(0, data.ErrorCount);
        // The only errors in Shop.Web come from the unrestored Dapper package:
        // the using directive and the Query extension call.
        Assert.InRange(web.ErrorCount, 1, 3);
        Assert.All(web.DiagnosticSample, d => Assert.True(
            d.Message.Contains("Dapper", StringComparison.Ordinal) || d.Message.Contains("Query", StringComparison.Ordinal),
            d.Message));
    }

    [Fact]
    public void Reports_approximations_instead_of_evaluating_msbuild()
    {
        var web = shop.Load.Projects.Single(p => p.Name == "Shop.Web");
        Assert.Contains(web.Approximations, a => a.Contains("Directory.Build.props not evaluated", StringComparison.Ordinal));
        Assert.Contains(web.Approximations, a => a.Contains("under condition", StringComparison.Ordinal));
        Assert.Contains(web.Approximations, a => a.Contains("source generators", StringComparison.Ordinal));
    }

    [Fact]
    public void Unrestored_package_is_reported_unresolved()
    {
        var web = shop.Load.Projects.Single(p => p.Name == "Shop.Web");
        var dapper = Assert.Single(web.PackageReferences, p => p.Name == "Dapper");
        Assert.False(dapper.Resolved);
    }

    [Fact]
    public void Symlinks_are_not_followed()
    {
        var root = Directory.CreateTempSubdirectory("witness-symlink-");
        try
        {
            var outside = Directory.CreateTempSubdirectory("witness-outside-");
            File.WriteAllText(Path.Combine(outside.FullName, "Secret.cs"), "class Secret {}");
            File.WriteAllText(Path.Combine(root.FullName, "App.cs"), "class App {}");
            File.CreateSymbolicLink(Path.Combine(root.FullName, "Linked.cs"), Path.Combine(outside.FullName, "Secret.cs"));
            Directory.CreateSymbolicLink(Path.Combine(root.FullName, "linkeddir"), outside.FullName);

            var server = new Server(Loading.ReferenceResolver.DefaultRefPackDirectory());
            var result = (LoadResultDto)server.Handle("load", System.Text.Json.JsonSerializer.SerializeToElement(new { root = root.FullName }))!;

            Assert.Contains(result.Skipped, s => s.Path == "Linked.cs" && s.Reason.Contains("symbolic link", StringComparison.Ordinal));
            Assert.Contains(result.Skipped, s => s.Path == "linkeddir");
            Assert.Equal(1, result.Projects.Sum(p => p.Documents));
            outside.Delete(recursive: true);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}

[Collection("shop")]
public sealed class SqlTests(ShopFixture shop)
{
    [Fact]
    public void Concatenated_query_parameter_reaches_command_text()
    {
        var site = shop.Site("Concat", "sql_injection");
        Assert.Equal(Resolution.Resolved, site.Sink.Resolution);
        Assert.Equal("P:System.Data.Common.DbCommand.CommandText", site.Sink.Symbol);
        var analysis = shop.Analyze(site);
        Assert.Equal("concat", analysis.Value.Kind);
        Assert.Contains(Trees.Leaves(analysis.Value), n => n.Kind == "endpoint_parameter" && n.Text == "q");
    }

    [Fact]
    public void Constant_query_has_only_constant_leaves()
    {
        var analysis = shop.Analyze(shop.Site("Constant", "sql_injection"));
        Assert.All(Trees.Leaves(analysis.Value), n => Assert.Equal("constant", n.Kind));
    }

    [Fact]
    public void Integer_values_are_typed_safe()
    {
        var analysis = shop.Analyze(shop.Site("Typed", "sql_injection"));
        Assert.Contains(Trees.Leaves(analysis.Value), n => n.Kind == "typed_safe" && n.Detail == "int");
        Assert.DoesNotContain(Trees.Leaves(analysis.Value), n => n.Kind == "endpoint_parameter");
    }

    [Fact]
    public void Cross_project_sink_stops_at_public_parameter_with_incomplete_callers()
    {
        var site = shop.Site("FindByName", "sql_injection");
        var analysis = shop.Analyze(site);
        var parameter = Assert.Single(Trees.Leaves(analysis.Value), n => n.Kind == "parameter");
        Assert.Equal("public", parameter.Facts!["accessibility"]);

        var callers = (CallersDto)shop.Call("callers", new { symbol = parameter.Facts["method"] })!;
        Assert.False(callers.Complete);
        var call = Assert.Single(callers.Calls);
        Assert.Contains("Cross", call.Caller!.Id, StringComparison.Ordinal);

        var argument = (ArgumentAnalysisDto)shop.Call("analyze_argument", new
        {
            path = call.Location.Path,
            line = call.Location.StartLine,
            column = call.Location.StartColumn,
            parameter_ordinal = 0,
        })!;
        Assert.Equal("endpoint_parameter", argument.Value.Kind);
    }

    [Fact]
    public void Private_helper_called_with_constants_has_complete_callers()
    {
        var analysis = shop.Analyze(shop.Site("CountWhere", "sql_injection"));
        var parameter = Assert.Single(Trees.Leaves(analysis.Value), n => n.Kind == "parameter");
        var callers = (CallersDto)shop.Call("callers", new { symbol = parameter.Facts!["method"] })!;
        Assert.True(callers.Complete, string.Join("; ", callers.IncompleteReasons));
        Assert.Equal(2, callers.Calls.Count);
    }

    [Fact]
    public void Source_helper_is_inlined_with_argument_substitution()
    {
        var analysis = shop.Analyze(shop.Site("Helper", "sql_injection"));
        Assert.Equal("call", analysis.Value.Kind);
        Assert.Equal("true", analysis.Value.Facts!["inlined"]);
        Assert.Contains(Trees.Leaves(analysis.Value), n => n.Kind == "endpoint_parameter" && n.Text == "q");
    }

    [Fact]
    public void Replace_based_escaping_is_marked_as_altering_content()
    {
        var analysis = shop.Analyze(shop.Site("Escaped", "sql_injection"));
        Assert.Contains(Trees.All(analysis.Value), n => n.Kind == "propagator" && n.Facts?.GetValueOrDefault("alters_content") == "true");
    }

    [Fact]
    public void Interface_implementation_parameter_is_reachable_through_dispatch()
    {
        var site = shop.Site("ConcatenatingFinder.Find", "sql_injection");
        Assert.Contains("ConcatenatingFinder", site.Containing!.Id, StringComparison.Ordinal);
        var parameter = Assert.Single(Trees.Leaves(shop.Analyze(site).Value), n => n.Kind == "parameter");
        Assert.Equal("direct", parameter.Facts!["dispatch"]);

        var callers = (CallersDto)shop.Call("callers", new { symbol = parameter.Facts["method"] })!;
        var call = Assert.Single(callers.Calls);
        Assert.True(call.ViaDispatch);
        Assert.False(callers.Complete);
        Assert.Contains(callers.IncompleteReasons, r => r.Contains("IProductFinder", StringComparison.Ordinal));
    }

    [Fact]
    public void Conditional_di_registration_is_reported()
    {
        var registrations = (List<DiRegistrationDto>)shop.Call("di_registrations", new { })!;
        Assert.Equal(2, registrations.Count(r => r.Service == "Shop.Data.IProductFinder" && r.Conditional));
    }

    [Fact]
    public void Unresolved_dapper_call_is_only_a_candidate()
    {
        var site = shop.Site("Dapper", "sql_injection");
        Assert.Equal(Resolution.UnresolvedCandidate, site.Sink.Resolution);
        Assert.StartsWith("unresolved:", site.Sink.Symbol, StringComparison.Ordinal);
    }

    [Fact]
    public void StringBuilder_appends_are_followed()
    {
        var analysis = shop.Analyze(shop.Site("Builder", "sql_injection"));
        Assert.Contains(Trees.Leaves(analysis.Value), n => n.Kind == "endpoint_parameter" && n.Text == "q");
    }

    [Fact]
    public void TryGetValue_out_argument_traces_to_request()
    {
        var analysis = shop.Analyze(shop.Site("TryGet", "sql_injection"));
        Assert.Contains(Trees.All(analysis.Value), n => n.Kind == "request_source");
    }

    [Fact]
    public void Ternary_keeps_both_branches()
    {
        var analysis = shop.Analyze(shop.Site("Branch", "sql_injection"));
        Assert.True(Trees.Has(analysis.Value, "conditional"));
        Assert.Contains(Trees.Leaves(analysis.Value), n => n.Kind == "endpoint_parameter");
    }

    [Fact]
    public void Site_ids_do_not_depend_on_line_numbers()
    {
        var site = shop.Site("Concat", "sql_injection");
        var again = ((SitesDto)shop.Call("find_sinks", new { classes = new[] { "sql_injection" } })!).Sites;
        Assert.Contains(again, s => s.SiteId == site.SiteId);
        Assert.Equal(16, site.SiteId.Length);
    }
}

[Collection("shop")]
public sealed class RedirectAndPathTests(ShopFixture shop)
{
    [Fact]
    public void IsLocalUrl_guard_holds_on_the_redirected_value()
    {
        var site = shop.Site("Go", "open_redirect", ordinal: 0);
        var guard = Assert.Single(shop.Analyze(site).Guards);
        Assert.Equal("is_local_url", guard.Kind);
        Assert.Equal("true", guard.HoldsAtSink);
        Assert.True(guard.SinkArgumentIsSubject);
        Assert.False(guard.ReassignedBeforeSink);
    }

    [Fact]
    public void Guard_on_a_different_value_is_not_attached()
    {
        var analysis = shop.Analyze(shop.Site("GoOther", "open_redirect"));
        Assert.DoesNotContain(analysis.Guards, g => g.Kind == "is_local_url");
    }

    [Fact]
    public void Reassignment_after_guard_is_detected()
    {
        var analysis = shop.Analyze(shop.Site("GoReassigned", "open_redirect"));
        var guard = Assert.Single(analysis.Guards, g => g.Kind == "is_local_url");
        Assert.True(guard.ReassignedBeforeSink);
    }

    [Fact]
    public void LocalRedirect_is_a_safe_api_not_a_sink()
    {
        Assert.DoesNotContain(shop.Sites, s => s.Containing?.Id.Contains("GoLocal", StringComparison.Ordinal) == true);
        var site = shop.Sites.First(s => s.Containing?.Id.Contains(".Go(", StringComparison.Ordinal) == true);
        var path = site.Location.Path;
        var source = File.ReadAllLines(Path.Combine(shop.Root, path));
        var line = Array.FindIndex(source, l => l.Contains("LocalRedirect(returnUrl)", StringComparison.Ordinal)) + 1;
        var result = (SitesAtDto)shop.Call("sites_at", new { path, start_line = line })!;
        Assert.Single(result.SafeApis);
    }

    [Fact]
    public void Minimal_api_lambda_parameter_is_request_bound_and_service_is_not()
    {
        var endpoints = (List<EndpointDto>)shop.Call("endpoints", new { })!;
        var next = Assert.Single(endpoints, e => e.Route == "/api/next");
        Assert.Equal("inferred", next.Parameters.Single().Binding);
        var count = Assert.Single(endpoints, e => e.Route == "/api/count");
        Assert.Equal("services", count.Parameters.Single(p => p.Name == "repository").Binding);

        var site = shop.Sites.Single(s => s.VulnClass == "open_redirect" && s.Location.Path.EndsWith("Program.cs", StringComparison.Ordinal));
        Assert.Contains("Main", site.Containing!.Id, StringComparison.Ordinal);
        Assert.Equal("endpoint_parameter", shop.Analyze(site).Value.Kind);
    }

    [Fact]
    public void Prefix_check_without_full_path_normalization_is_reported_as_such()
    {
        var analysis = shop.Analyze(shop.Site("FileNaive", "path_traversal"));
        var guard = Assert.Single(analysis.Guards, g => g.Kind == "starts_with");
        Assert.Equal("false", guard.Facts!["subject_from_get_full_path"]);
        Assert.Equal("false", guard.Facts["prefix_ends_with_separator"]);
    }

    [Fact]
    public void GetFileName_is_a_sanitizer_node()
    {
        var analysis = shop.Analyze(shop.Site("FileName", "path_traversal"));
        Assert.Contains(Trees.All(analysis.Value), n => n.Kind == "sanitizer" && n.Detail == "Path.GetFileName");
    }

    [Fact]
    public void Configuration_values_are_config_sources()
    {
        var analysis = shop.Analyze(shop.Site("FileConfig", "path_traversal"));
        Assert.Contains(Trees.All(analysis.Value), n => n.Kind == "config_source");
    }
}

[Collection("shop")]
public sealed class PrecedingCallAndPrefixTests(ShopFixture shop)
{
    [Fact]
    public void Call_on_the_value_before_the_sink_is_reported_as_a_validator_call()
    {
        var guard = Assert.Single(shop.Analyze(shop.Site("Validated", "sql_injection")).Guards);
        Assert.Equal("validator_call", guard.Kind);
        Assert.Equal("q", guard.SubjectText);
        Assert.Equal("true", guard.Facts!["declared_in_source"]);
        Assert.Contains("Rules.Check", guard.Facts!["callee"], StringComparison.Ordinal);
    }

    [Fact]
    public void Awaited_call_on_the_value_is_reported_too()
    {
        var guard = Assert.Single(shop.Analyze(shop.Site("ValidatedAsync", "sql_injection")).Guards);
        Assert.Equal("validator_call", guard.Kind);
        Assert.Contains("Rules.CheckAsync", guard.Facts!["callee"], StringComparison.Ordinal);
    }

    [Fact]
    public void Sink_without_preceding_calls_has_no_validator_call()
    {
        Assert.DoesNotContain(shop.Analyze(shop.Site("Concat", "sql_injection")).Guards, g => g.Kind == "validator_call");
    }

    [Fact]
    public void Prefix_check_lists_the_symbols_the_prefix_is_built_from()
    {
        var analysis = shop.Analyze(shop.Site("FileChecked", "path_traversal"));
        var guard = Assert.Single(analysis.Guards, g => g.Kind == "starts_with");
        Assert.Equal("true", guard.Facts!["prefix_ends_with_separator"]);
        Assert.Equal("true", guard.Facts!["subject_from_get_full_path"]);
        var symbol = Assert.Single(guard.Facts!["prefix_symbols"].Split(';'));
        Assert.StartsWith("local:rootFull@", symbol, StringComparison.Ordinal);
    }

    [Fact]
    public void Constant_prefix_has_no_prefix_symbols()
    {
        var guard = Assert.Single(shop.Analyze(shop.Site("FileNaive", "path_traversal")).Guards, g => g.Kind == "starts_with");
        Assert.Equal("", guard.Facts!["prefix_symbols"]);
    }
}

[Collection("shop")]
public sealed class ReviewRegressionTests(ShopFixture shop)
{
    [Fact]
    public void Array_of_ints_is_a_safe_type()
    {
        var value = shop.Analyze(shop.Site("Ids", "sql_injection")).Value;
        Assert.DoesNotContain(Walk(value), n => n.Kind == "endpoint_parameter");
        Assert.Contains(Walk(value), n => n.Kind == "typed_safe");
    }

    [Fact]
    public void Overwritten_definition_is_marked_as_replaced()
    {
        var local = Assert.Single(Walk(shop.Analyze(shop.Site("Overwritten", "sql_injection")).Value), n => n.Kind == "local");
        Assert.Equal(2, local.Children!.Count);
        var first = local.Children[0];
        var second = local.Children[1];
        Assert.Equal("true", first.Facts!["def_killed"]);
        Assert.Equal("true", second.Facts!["def_dominates"]);
        Assert.Equal("before", second.Facts["def_order"]);
    }

    [Fact]
    public void Swallowed_validator_is_not_reported()
    {
        Assert.DoesNotContain(shop.Analyze(shop.Site("Swallowed", "sql_injection")).Guards, g => g.Kind == "validator_call");
    }

    [Fact]
    public void Validator_reports_whether_it_can_throw()
    {
        var guard = Assert.Single(shop.Analyze(shop.Site("Validated", "sql_injection")).Guards);
        Assert.Equal("true", guard.Facts!["may_throw"]);
        Assert.Equal("false", guard.Facts["awaited"]);
    }

    private static IEnumerable<ValueNode> Walk(ValueNode node) =>
        new[] { node }.Concat((node.Children ?? []).SelectMany(Walk));
}
