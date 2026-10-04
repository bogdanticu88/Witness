using System.Text.Json;
using System.Text.Json.Serialization;

namespace Witness.Semantic.Protocol;

// Wire types for witness.semantic/1. Property names are snake_case on the
// wire; see docs/PROTOCOL.md. Adding optional fields is compatible; renaming
// or removing one requires a protocol version bump.

internal static class ProtocolInfo
{
    public const string Version = "witness.semantic/1";
}

internal sealed record Request(long Id, string Method, JsonElement? Params);

internal sealed record ErrorBody(string Code, string Message);

internal sealed record Response(long Id, object? Result, ErrorBody? Error);

internal sealed class ProtocolException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

internal static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
        MaxDepth = 64,
        WriteIndented = false,
    };
}

internal sealed record Span(string Path, int StartLine, int EndLine, int StartColumn, int EndColumn);

internal sealed record SymbolInfoDto(
    string Id,
    string Display,
    string Kind,
    Span? Location,
    string? Accessibility = null);

internal enum Resolution
{
    Resolved,
    UnresolvedCandidate,
}

internal sealed record SinkDto(
    string Symbol,
    string Display,
    Resolution Resolution,
    string ArgumentRole,
    int ArgumentIndex,
    string? Note = null);

internal sealed record SiteDto(
    string SiteId,
    string VulnClass,
    SinkDto Sink,
    Span Location,
    SymbolInfoDto? Containing,
    int Ordinal,
    string ArgumentText);

// One node of a backward value-flow tree. ``Kind`` is one of the values
// documented in docs/PROTOCOL.md (constant, typed_safe, request_source,
// endpoint_parameter, parameter, field, property, invocation, propagator,
// sanitizer, unknown_call, concat, interpolation, conditional, local,
// config_source, environment_source, unknown).
internal sealed record ValueNode(
    string Kind,
    string Text,
    Span? Location,
    string? Symbol = null,
    string? Detail = null,
    IReadOnlyList<ValueNode>? Children = null,
    IReadOnlyDictionary<string, string>? Facts = null);

internal sealed record GuardDto(
    string Kind,
    string SubjectSymbol,
    string SubjectText,
    // Whether the recognized predicate is known to hold where the sink runs.
    string HoldsAtSink,
    bool ReassignedBeforeSink,
    bool SinkArgumentIsSubject,
    Span Location,
    string ConditionText,
    IReadOnlyDictionary<string, string>? Facts = null);

internal sealed record SiteAnalysisDto(
    SiteDto Site,
    ValueNode Value,
    IReadOnlyList<GuardDto> Guards,
    IReadOnlyList<string> Unresolved,
    bool Truncated,
    string? SafeApi);

internal sealed record CallArgumentDto(int Index, string? ParameterName, string Text, Span Location);

internal sealed record CallSiteDto(
    SymbolInfoDto? Caller,
    Span Location,
    string Target,
    bool ViaDispatch,
    IReadOnlyList<CallArgumentDto> Arguments);

internal sealed record CallersDto(
    SymbolInfoDto Target,
    IReadOnlyList<CallSiteDto> Calls,
    bool Complete,
    IReadOnlyList<string> IncompleteReasons);

internal sealed record CalleeDto(string Symbol, string Display, Resolution Resolution, Span Location, string? DeclaredIn);

internal sealed record EndpointParameterDto(string Name, string Type, string Binding);

// One piece of code that runs on requests before their handler. Scope is
// "all", "controllers", "minimal_apis" or "endpoint" (then Handlers lists
// the handler ids). Reads, CanReject and Rewrites are "true", "false" or
// "unknown".
internal sealed record PipelineLayerDto(
    string Kind,
    string Name,
    Span? Location,
    string ReadsRequestInput,
    string CanReject,
    string RewritesRequest,
    string Scope,
    IReadOnlyList<string> Handlers);

internal sealed record EndpointDto(
    string Kind,
    IReadOnlyList<string> HttpMethods,
    string? Route,
    SymbolInfoDto Handler,
    IReadOnlyList<EndpointParameterDto> Parameters,
    IReadOnlyList<string> AuthorizationAttributes,
    bool AllowAnonymous);

internal sealed record DiRegistrationDto(
    string Service,
    string? Implementation,
    string Lifetime,
    bool Conditional,
    Span Location);

internal sealed record EntryPointDto(string Kind, SymbolInfoDto Symbol, string? Detail);

internal sealed record PackageReferenceDto(string Name, string? Version, bool Resolved, string? Source);

internal sealed record DiagnosticSampleDto(string Id, string Message, string? Path, int Line);

internal sealed record ProjectDto(
    string Name,
    string Path,
    string? TargetFramework,
    string Sdk,
    int Documents,
    IReadOnlyList<string> ProjectReferences,
    IReadOnlyList<PackageReferenceDto> PackageReferences,
    IReadOnlyList<string> Approximations,
    int ErrorCount,
    int UnresolvedSymbolErrors,
    IReadOnlyList<DiagnosticSampleDto> DiagnosticSample);

internal sealed record SkippedFileDto(string Path, string Reason);

internal sealed record LoadResultDto(
    string Root,
    IReadOnlyList<ProjectDto> Projects,
    IReadOnlyList<SkippedFileDto> Skipped,
    string Strategy,
    long LoadMs);

internal sealed record MemberDto(SymbolInfoDto Symbol, Span Span);

internal sealed record SourceDto(string Path, int StartLine, int EndLine, int TotalLines, string Text, string Sha256);

internal sealed record DependenciesDto(
    string Symbol,
    IReadOnlyList<string> Files,
    IReadOnlyList<string> Symbols,
    int UnresolvedReferences);
