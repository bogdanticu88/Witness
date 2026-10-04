using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Analysis;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic;

internal sealed record SitesDto(IReadOnlyList<SiteDto> Sites);

internal sealed record SitesAtDto(IReadOnlyList<SiteDto> Sites, IReadOnlyList<SafeApiHit> SafeApis);

internal sealed record ArgumentAnalysisDto(
    ValueNode Value,
    IReadOnlyList<GuardDto> Guards,
    IReadOnlyList<string> Unresolved,
    bool Truncated,
    SymbolInfoDto? Containing);

// Request dispatch for witness.semantic/1. One workspace is loaded at a time.
internal sealed class Server
{
    private const int DefaultMaxFiles = 20_000;
    private const long DefaultMaxFileBytes = 2 * 1024 * 1024;

    private readonly string _refPackDirectory;
    private AnalysisWorkspace? _workspace;
    private EndpointIndex? _endpoints;
    private CallIndex? _calls;
    private Dictionary<string, FoundSite>? _sites;

    public Server(string refPackDirectory)
    {
        _refPackDirectory = refPackDirectory;
    }

    public bool ShutdownRequested { get; private set; }

    public object? Handle(string method, JsonElement? parameters) => method switch
    {
        "hello" => Hello(),
        "load" => Load(parameters),
        "find_sinks" => FindSinks(parameters),
        "sites_at" => SitesAt(parameters),
        "analyze_site" => AnalyzeSite(parameters),
        "analyze_argument" => AnalyzeArgument(parameters),
        "callers" => Calls().Callers(MethodParam(parameters), Endpoints()),
        "callees" => Navigation.Callees(Workspace(), SymbolParam(parameters)),
        "implementations" => Calls().Implementations(MethodParam(parameters)).Select(Symbols.Describe).ToList(),
        "references" => Navigation.References(Workspace(), SymbolParam(parameters)),
        "dependencies" => Navigation.Dependencies(Workspace(), SymbolParam(parameters)),
        "definition" => Symbols.Describe(SymbolParam(parameters)),
        "members" => Navigation.Members(Workspace(), RequiredString(parameters, "path")),
        "symbol_at" => Navigation.SymbolAt(Workspace(), RequiredString(parameters, "path"), RequiredInt(parameters, "line")),
        "endpoints" => Endpoints().Endpoints,
        "di_registrations" => Endpoints().Registrations,
        "entry_points" => Endpoints().EntryPoints,
        "request_pipeline" => Analysis.Pipeline.Build(Workspace(), Endpoints()),
        "shutdown" => Shutdown(),
        _ => throw new ProtocolException("unknown_method", $"unknown method: {method}"),
    };

    private object Hello()
    {
        var resolver = new ReferenceResolver(_refPackDirectory, null);
        return new
        {
            Protocol = ProtocolInfo.Version,
            HelperVersion = typeof(Server).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
            RoslynVersion = typeof(Compilation).Assembly.GetName().Version?.ToString() ?? "unknown",
            RefPacks = resolver.AvailablePacks().Select(p => new { p.Name, p.Version }).ToList(),
            Strategy = "static_project_reconstruction",
        };
    }

    private LoadResultDto Load(JsonElement? parameters)
    {
        var options = new LoadOptions(
            RequiredString(parameters, "root"),
            OptionalString(parameters, "package_directory"),
            _refPackDirectory,
            OptionalInt(parameters, "max_files") ?? DefaultMaxFiles,
            OptionalInt(parameters, "max_file_bytes") ?? DefaultMaxFileBytes);
        _workspace = AnalysisWorkspace.Load(options);
        _endpoints = EndpointIndex.Build(_workspace);
        _calls = CallIndex.Build(_workspace);
        _sites = null;

        var projects = _workspace.Projects.Select(project =>
        {
            var diagnostics = project.Compilation.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .ToList();
            var unresolved = diagnostics.Count(d => d.Id is "CS0246" or "CS0234" or "CS0103" or "CS1061" or "CS0117" or "CS0012");
            return new ProjectDto(
                project.Name,
                project.File is null ? "" : _workspace.Relative(project.File.FullPath),
                project.File?.Property("TargetFramework") ?? project.File?.Property("TargetFrameworks"),
                project.File?.Sdk ?? "",
                project.Documents.Count,
                project.ProjectReferenceNames,
                project.Packages,
                project.Approximations.Distinct(StringComparer.Ordinal).ToList(),
                diagnostics.Count,
                unresolved,
                diagnostics.Take(25).Select(d =>
                {
                    var span = Symbols.SpanOf(d.Location);
                    return new DiagnosticSampleDto(d.Id, d.GetMessage(System.Globalization.CultureInfo.InvariantCulture), span?.Path, span?.StartLine ?? 0);
                }).ToList());
        }).ToList();

        return new LoadResultDto(_workspace.Root, projects, _workspace.Skipped, "static_project_reconstruction", _workspace.LoadMs);
    }

    private SitesDto FindSinks(JsonElement? parameters)
    {
        var classes = Classes(parameters);
        var paths = OptionalStringArray(parameters, "paths")?.ToHashSet(StringComparer.Ordinal);
        var sites = SinkFinder.Find(Workspace(), classes, paths);
        return new SitesDto(sites.Select(s => s.Dto).ToList());
    }

    private SitesAtDto SitesAt(JsonElement? parameters)
    {
        var path = RequiredString(parameters, "path");
        var start = RequiredInt(parameters, "start_line");
        var end = OptionalInt(parameters, "end_line") ?? start;
        var (sites, safe) = SinkFinder.FindAt(Workspace(), path, start, end, Classes(parameters));
        return new SitesAtDto(sites.Select(s => s.Dto).ToList(), safe);
    }

    private SiteAnalysisDto AnalyzeSite(JsonElement? parameters)
    {
        var id = RequiredString(parameters, "site_id");
        _sites ??= SinkFinder.Find(Workspace(), VulnClasses.All.ToHashSet(), null).ToDictionary(s => s.Dto.SiteId, StringComparer.Ordinal);
        if (!_sites.TryGetValue(id, out var site))
        {
            throw new ProtocolException("unknown_site", $"no sink site with id {id}");
        }

        var flow = new ValueFlow(Workspace(), Endpoints(), Calls());
        ValueNode value;
        IReadOnlyList<GuardDto> guards = [];
        if (site.Argument is null)
        {
            value = new ValueNode("unknown", site.Dto.ArgumentText, site.Dto.Location, Detail: "sink argument not bound");
        }
        else
        {
            value = flow.Analyze(site.Argument);
            guards = GuardFinder.Find(site.Node, site.Argument, site.Model);
        }
        var safe = site.Model.GetOperation(site.Node) is IInvocationOperation invocation ? Catalog.SafeApi(invocation.TargetMethod) : null;
        return new SiteAnalysisDto(site.Dto, value, guards, flow.Unresolved, flow.Truncated, safe);
    }

    private ArgumentAnalysisDto AnalyzeArgument(JsonElement? parameters)
    {
        var path = RequiredString(parameters, "path");
        var line = RequiredInt(parameters, "line");
        var column = RequiredInt(parameters, "column");
        var ordinal = RequiredInt(parameters, "parameter_ordinal");
        var workspace = Workspace();
        if (!workspace.TryGetDocument(path, out var project, out var tree))
        {
            throw new ProtocolException("unknown_document", $"{path} is not part of the loaded workspace");
        }
        var model = project.Compilation.GetSemanticModel(tree);
        var lines = tree.GetText().Lines;
        if (line < 1 || line > lines.Count)
        {
            throw new ProtocolException("bad_position", $"line {line} outside {path}");
        }
        var position = lines[line - 1].Start + Math.Max(0, column - 1);
        var call = tree.GetRoot().FindToken(position).Parent?.AncestorsAndSelf()
            .FirstOrDefault(n => n is InvocationExpressionSyntax or BaseObjectCreationExpressionSyntax && n.SpanStart == position)
            ?? throw new ProtocolException("no_call", $"no call starts at {path}:{line}:{column}");

        var arguments = model.GetOperation(call) switch
        {
            IInvocationOperation invocation => invocation.Arguments,
            IObjectCreationOperation creation => creation.Arguments,
            _ => throw new ProtocolException("no_call", $"call at {path}:{line}:{column} is not resolved"),
        };
        var argument = arguments.FirstOrDefault(a => a.Parameter?.Ordinal == ordinal)?.Value
            ?? throw new ProtocolException("no_argument", $"no argument for parameter {ordinal} at {path}:{line}:{column}");

        var flow = new ValueFlow(workspace, Endpoints(), Calls());
        var value = flow.Analyze(argument);
        var guards = GuardFinder.Find(call, argument, model);
        var containing = Symbols.EnclosingMember(model, call);
        return new ArgumentAnalysisDto(value, guards, flow.Unresolved, flow.Truncated, containing is null ? null : Symbols.Describe(containing));
    }

    private object Shutdown()
    {
        ShutdownRequested = true;
        return new { Ok = true };
    }

    private AnalysisWorkspace Workspace() =>
        _workspace ?? throw new ProtocolException("not_loaded", "call load before querying");

    private EndpointIndex Endpoints() =>
        _endpoints ?? throw new ProtocolException("not_loaded", "call load before querying");

    private CallIndex Calls() =>
        _calls ?? throw new ProtocolException("not_loaded", "call load before querying");

    private ISymbol SymbolParam(JsonElement? parameters) =>
        Navigation.Resolve(Workspace(), RequiredString(parameters, "symbol"));

    private IMethodSymbol MethodParam(JsonElement? parameters) =>
        SymbolParam(parameters) as IMethodSymbol
        ?? throw new ProtocolException("not_a_method", "symbol is not a method");

    private static HashSet<string> Classes(JsonElement? parameters)
    {
        var requested = OptionalStringArray(parameters, "classes");
        if (requested is null)
        {
            return VulnClasses.All.ToHashSet(StringComparer.Ordinal);
        }
        foreach (var name in requested.Where(n => !VulnClasses.All.Contains(n)))
        {
            throw new ProtocolException("bad_class", $"unsupported vulnerability class: {name}");
        }
        return requested.ToHashSet(StringComparer.Ordinal);
    }

    private static string RequiredString(JsonElement? parameters, string name) =>
        OptionalString(parameters, name) ?? throw new ProtocolException("bad_params", $"missing string parameter '{name}'");

    private static int RequiredInt(JsonElement? parameters, string name) =>
        OptionalInt(parameters, name) ?? throw new ProtocolException("bad_params", $"missing integer parameter '{name}'");

    private static string? OptionalString(JsonElement? parameters, string name) =>
        parameters is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static int? OptionalInt(JsonElement? parameters, string name) =>
        parameters is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)
            ? i
            : null;

    private static List<string>? OptionalStringArray(JsonElement? parameters, string name)
    {
        if (parameters is not { ValueKind: JsonValueKind.Object } p || !p.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        return v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList();
    }
}
