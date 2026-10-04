using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

// Code that runs on a request before its handler: custom middleware, MVC
// filters and endpoint filters. Framework middleware from Microsoft.AspNetCore
// is left out. For each layer the helper reports whether it reads request
// input and whether it can reject or rewrite the request; "unknown" means its
// code is not in the analyzed source.
internal static class Pipeline
{
    private const string FilterMetadata = "Microsoft.AspNetCore.Mvc.Filters.IFilterMetadata";

    public static List<PipelineLayerDto> Build(AnalysisWorkspace workspace, EndpointIndex endpoints)
    {
        var layers = new List<PipelineLayerDto>();
        var actions = endpoints.Endpoints.Where(e => e.Kind == "controller_action").Select(e => e.Handler.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var project in workspace.Projects)
        {
            foreach (var tree in project.Compilation.SyntaxTrees)
            {
                if (tree.FilePath.StartsWith('<'))
                {
                    continue;
                }
                var model = project.Compilation.GetSemanticModel(tree);
                var root = tree.GetRoot();
                foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (model.GetOperation(invocation) is IInvocationOperation operation && Registered(operation, project.Compilation) is { } layer)
                    {
                        layers.Add(layer);
                    }
                }
                foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
                {
                    if (model.GetDeclaredSymbol(method) is IMethodSymbol symbol && actions.Contains(Symbols.Id(symbol)))
                    {
                        layers.AddRange(AttributeFilters(symbol, project.Compilation));
                    }
                }
            }
        }
        return layers;
    }

    private static PipelineLayerDto? Registered(IInvocationOperation invocation, Compilation compilation)
    {
        var method = invocation.TargetMethod.ReducedFrom ?? invocation.TargetMethod;
        var owner = Symbols.FullName(method.ContainingType);
        var location = Symbols.SpanOf(invocation.Syntax);
        switch (method.Name)
        {
            case "UseMiddleware" when owner == "Microsoft.AspNetCore.Builder.UseMiddlewareExtensions":
                return FromType("middleware", RegisteredType(invocation), "all", [], location, compilation);
            case "Use" when owner.StartsWith("Microsoft.AspNetCore.Builder.", StringComparison.Ordinal):
                return FromDelegate("middleware", invocation, "all", [], location, compilation);
            case "Add" or "AddService" when owner == "Microsoft.AspNetCore.Mvc.Filters.FilterCollection":
                return FromType("mvc_filter", RegisteredType(invocation), "controllers", [], location, compilation);
            case "AddEndpointFilter" or "AddEndpointFilterFactory" when owner.StartsWith("Microsoft.AspNetCore.Http.", StringComparison.Ordinal):
                var handler = MappedHandler(invocation);
                var scope = handler is null ? "minimal_apis" : "endpoint";
                IReadOnlyList<string> handlers = handler is null ? [] : [handler];
                return method.IsGenericMethod
                    ? FromType("endpoint_filter", method.TypeArguments[0], scope, handlers, location, compilation)
                    : FromDelegate("endpoint_filter", invocation, scope, handlers, location, compilation);
        }
        return null;
    }

    private static ITypeSymbol? RegisteredType(IInvocationOperation invocation)
    {
        var method = invocation.TargetMethod;
        if (method.IsGenericMethod)
        {
            return method.TypeArguments[0];
        }
        foreach (var argument in invocation.Arguments)
        {
            switch (argument.Value)
            {
                case ITypeOfOperation typeOf:
                    return typeOf.TypeOperand;
                case IObjectCreationOperation creation:
                    return creation.Type;
                case IConversionOperation { Operand: IObjectCreationOperation converted }:
                    return converted.Type;
            }
        }
        return null;
    }

    // app.MapGet(...).AddEndpointFilter(...): the filter applies to that handler.
    private static string? MappedHandler(IInvocationOperation invocation)
    {
        var receiver = invocation.Arguments.FirstOrDefault()?.Value;
        while (receiver is IConversionOperation conversion)
        {
            receiver = conversion.Operand;
        }
        if (receiver is not IInvocationOperation map || !map.TargetMethod.Name.StartsWith("Map", StringComparison.Ordinal))
        {
            return null;
        }
        foreach (var argument in map.Arguments)
        {
            var value = argument.Value;
            while (value is IConversionOperation or IDelegateCreationOperation)
            {
                value = value is IConversionOperation c ? c.Operand : ((IDelegateCreationOperation)value).Target;
            }
            switch (value)
            {
                case IAnonymousFunctionOperation lambda:
                    return Symbols.Id(lambda.Symbol);
                case IMethodReferenceOperation reference:
                    return Symbols.Id(reference.Method);
            }
        }
        return null;
    }

    private static IEnumerable<PipelineLayerDto> AttributeFilters(IMethodSymbol action, Compilation compilation)
    {
        var holders = new List<ISymbol> { action };
        for (var type = action.ContainingType; type is not null; type = type.BaseType)
        {
            holders.Add(type);
        }
        foreach (var attribute in holders.SelectMany(h => h.GetAttributes()))
        {
            var type = attribute.AttributeClass;
            if (type is null)
            {
                continue;
            }
            ITypeSymbol? filter = null;
            if (type.Name is "TypeFilterAttribute" or "ServiceFilterAttribute")
            {
                filter = attribute.ConstructorArguments.FirstOrDefault().Value as ITypeSymbol;
            }
            else if (Symbols.Implements(type, FilterMetadata) && !IsFramework(type))
            {
                filter = type;
            }
            if (filter is not null)
            {
                yield return FromType("mvc_filter", filter, "endpoint", [Symbols.Id(action)], Symbols.SpanOf(action.Locations.FirstOrDefault()), compilation)!;
            }
        }
    }

    private static PipelineLayerDto? FromType(string kind, ITypeSymbol? type, string scope, IReadOnlyList<string> handlers, Span? location, Compilation compilation)
    {
        if (type is null)
        {
            return new PipelineLayerDto(kind, "unresolved", location, "unknown", "unknown", "false", scope, handlers);
        }
        if (IsFramework(type))
        {
            return null;
        }
        var bodies = type.GetMembers().OfType<IMethodSymbol>()
            .SelectMany(m => m.DeclaringSyntaxReferences)
            .Select(r => r.GetSyntax())
            .ToList();
        if (bodies.Count == 0 || !bodies.All(b => compilation.ContainsSyntaxTree(b.SyntaxTree)))
        {
            return new PipelineLayerDto(kind, type.ToDisplayString(), location, "unknown", "unknown", "false", scope, handlers);
        }
        var (reads, rejects, rewrites) = Inspect(bodies, compilation);
        return new PipelineLayerDto(kind, type.ToDisplayString(), location, reads, rejects, rewrites, scope, handlers);
    }

    private static PipelineLayerDto FromDelegate(string kind, IInvocationOperation invocation, string scope, IReadOnlyList<string> handlers, Span? location, Compilation compilation)
    {
        var lambda = invocation.Arguments.Select(a => a.Value).SelectMany(v => v.DescendantsAndSelf()).OfType<IAnonymousFunctionOperation>().FirstOrDefault();
        if (lambda is null)
        {
            return new PipelineLayerDto(kind, invocation.Syntax.ToString(), location, "unknown", "unknown", "false", scope, handlers);
        }
        var (reads, rejects, rewrites) = Inspect([lambda.Syntax], compilation);
        return new PipelineLayerDto(kind, "inline " + kind + " at line " + location?.StartLine, location, reads, rejects, rewrites, scope, handlers);
    }

    private static (string Reads, string Rejects, string Rewrites) Inspect(IEnumerable<SyntaxNode> bodies, Compilation compilation)
    {
        var reads = "false";
        var rejects = "false";
        var rewrites = "false";
        foreach (var body in bodies)
        {
            var model = compilation.GetSemanticModel(body.SyntaxTree);
            if (body.DescendantNodes().Any(n => n is ThrowStatementSyntax or ThrowExpressionSyntax)
                || body.DescendantNodes().OfType<IfStatementSyntax>().Any(i => i.DescendantNodes().OfType<ReturnStatementSyntax>().Any()))
            {
                rejects = "true";
            }
            foreach (var node in body.DescendantNodes())
            {
                var operation = model.GetOperation(node);
                switch (operation)
                {
                    case IPropertyReferenceOperation property when Catalog.PropertySource(property.Property) == Catalog.SourceKind.Request
                        || property.Property.Name is "ActionArguments" or "Arguments" && !IsFrameworkOnly(property.Property.ContainingType, "Microsoft.AspNetCore.Http.HttpContext"):
                        reads = "true";
                        break;
                    case IInvocationOperation call when Catalog.MethodSource(call.TargetMethod) == Catalog.SourceKind.Request
                        || call.TargetMethod.Name == "GetArgument":
                        reads = "true";
                        break;
                    case IInvocationOperation call when Symbols.FullName(call.TargetMethod.ContainingType) is "Microsoft.AspNetCore.Http.Results" or "Microsoft.AspNetCore.Http.TypedResults"
                        || call.TargetMethod.Name.StartsWith("Write", StringComparison.Ordinal) && Symbols.FullName(call.TargetMethod.ContainingType).StartsWith("Microsoft.AspNetCore.Http.", StringComparison.Ordinal):
                        rejects = "true";
                        break;
                    case ISimpleAssignmentOperation assignment when assignment.Target is IPropertyReferenceOperation target:
                        if (target.Property.Name is "Result" or "StatusCode")
                        {
                            rejects = "true";
                        }
                        if (Symbols.FullName(target.Property.ContainingType) == "Microsoft.AspNetCore.Http.HttpRequest")
                        {
                            rewrites = "true";
                        }
                        break;
                    case IArgumentOperation argument when reads != "true" && CarriesRequest(argument.Value.Type)
                        && argument.Parent is IInvocationOperation { TargetMethod: var target } && !IsFramework(target.ContainingType):
                        // The request is handed to code that is not inspected here.
                        reads = Symbols.IsDeclaredInSource(target) ? reads : "unknown";
                        break;
                }
            }
        }
        return (reads, rejects, rewrites);
    }

    private static bool CarriesRequest(ITypeSymbol? type)
    {
        var name = Symbols.FullName(type);
        return name is "Microsoft.AspNetCore.Http.HttpContext" or "Microsoft.AspNetCore.Http.HttpRequest"
            or "Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext" or "Microsoft.AspNetCore.Http.EndpointFilterInvocationContext";
    }

    private static bool IsFrameworkOnly(ITypeSymbol? type, string name) => Symbols.FullName(type) == name;

    private static bool IsFramework(ITypeSymbol type)
    {
        var ns = type.ContainingNamespace?.ToDisplayString() ?? "";
        return ns == "Microsoft.AspNetCore" || ns.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal)
            || ns.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal);
    }
}
