using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

// Framework entry points that Witness recognizes: MVC/API controller actions,
// minimal API handlers, hosted services and program entry. Authorization
// attributes are reported as declared; global filters and policies are not
// evaluated, so a missing attribute proves nothing.
internal sealed class EndpointIndex
{
    private static readonly HashSet<string> MapMethods = ["MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods", "Map"];
    private static readonly HashSet<string> BindingAttributes =
        ["FromQuery", "FromRoute", "FromForm", "FromBody", "FromHeader", "AsParameters"];
    private static readonly HashSet<string> ServiceAttributes = ["FromServices", "FromKeyedServices"];

    // Handler symbol id -> parameter name -> binding.
    private readonly Dictionary<string, Dictionary<string, string>> _requestBound = new(StringComparer.Ordinal);

    public List<EndpointDto> Endpoints { get; } = [];
    public List<DiRegistrationDto> Registrations { get; } = [];
    public List<EntryPointDto> EntryPoints { get; } = [];

    public bool TryGetBinding(IParameterSymbol parameter, out string binding)
    {
        binding = "";
        if (parameter.ContainingSymbol is not IMethodSymbol method)
        {
            return false;
        }
        return _requestBound.TryGetValue(Symbols.Id(method), out var map) && map.TryGetValue(parameter.Name, out binding!);
    }

    public bool IsEntryPoint(IMethodSymbol method) =>
        _requestBound.ContainsKey(Symbols.Id(method)) || EntryPoints.Any(e => e.Symbol.Id == Symbols.Id(method));

    public static EndpointIndex Build(AnalysisWorkspace workspace)
    {
        var index = new EndpointIndex();
        foreach (var project in workspace.Projects)
        {
            var compilation = project.Compilation;
            foreach (var tree in compilation.SyntaxTrees)
            {
                if (tree.FilePath.StartsWith('<'))
                {
                    continue;
                }
                var model = compilation.GetSemanticModel(tree);
                var root = tree.GetRoot();
                foreach (var type in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
                {
                    if (model.GetDeclaredSymbol(type) is INamedTypeSymbol symbol)
                    {
                        index.IndexType(symbol);
                    }
                }
                foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (model.GetOperation(invocation) is IInvocationOperation operation)
                    {
                        index.IndexInvocation(operation, model);
                    }
                }
                if (root is CompilationUnitSyntax unit && unit.Members.OfType<GlobalStatementSyntax>().Any()
                    && model.GetEnclosingSymbol(unit.Members.OfType<GlobalStatementSyntax>().First().SpanStart) is IMethodSymbol main)
                {
                    index.EntryPoints.Add(new EntryPointDto("program_main", Symbols.Describe(main), "top-level statements"));
                }
            }
        }
        index.ReclassifyRegisteredServices();
        return index;
    }

    // Minimal API parameters of a concrete type are bound from the request
    // unless the type is registered as a service. Registrations are only
    // known after the whole workspace is indexed.
    private void ReclassifyRegisteredServices()
    {
        var services = Registrations
            .SelectMany(r => new[] { r.Service, r.Implementation })
            .Where(n => n is not null)
            .ToHashSet(StringComparer.Ordinal);
        for (var i = 0; i < Endpoints.Count; i++)
        {
            var endpoint = Endpoints[i];
            if (endpoint.Kind != "minimal_api")
            {
                continue;
            }
            var changed = endpoint.Parameters
                .Select(p => p.Binding == "inferred" && services.Contains(p.Type) ? p with { Binding = "services" } : p)
                .ToList();
            if (_requestBound.TryGetValue(endpoint.Handler.Id, out var bound))
            {
                foreach (var parameter in changed.Where(p => p.Binding == "services"))
                {
                    bound.Remove(parameter.Name);
                }
            }
            Endpoints[i] = endpoint with { Parameters = changed };
        }
    }

    private void IndexType(INamedTypeSymbol type)
    {
        if (type.IsAbstract || type.DeclaredAccessibility != Accessibility.Public && type.DeclaredAccessibility != Accessibility.Internal)
        {
            return;
        }

        if (Symbols.InheritsFrom(type, "Microsoft.Extensions.Hosting.BackgroundService"))
        {
            foreach (var method in type.GetMembers("ExecuteAsync").OfType<IMethodSymbol>())
            {
                EntryPoints.Add(new EntryPointDto("hosted_service", Symbols.Describe(method), "BackgroundService.ExecuteAsync"));
            }
        }
        else if (Symbols.Implements(type, "Microsoft.Extensions.Hosting.IHostedService"))
        {
            foreach (var method in type.GetMembers("StartAsync").OfType<IMethodSymbol>())
            {
                EntryPoints.Add(new EntryPointDto("hosted_service", Symbols.Describe(method), "IHostedService.StartAsync"));
            }
        }
        foreach (var method in type.GetMembers("Main").OfType<IMethodSymbol>().Where(m => m.IsStatic))
        {
            EntryPoints.Add(new EntryPointDto("program_main", Symbols.Describe(method), null));
        }

        var isController = Symbols.InheritsFrom(type, "Microsoft.AspNetCore.Mvc.ControllerBase")
            || HasAttribute(type, "ApiController") || HasAttribute(type, "Controller");
        if (!isController || HasAttribute(type, "NonController"))
        {
            return;
        }

        var classRoute = AttributeArgument(type, "Route");
        var classAuth = AuthorizationAttributes(type);
        foreach (var method in type.GetMembers().OfType<IMethodSymbol>())
        {
            if (method.MethodKind != MethodKind.Ordinary || method.DeclaredAccessibility != Accessibility.Public
                || method.IsStatic || HasAttribute(method, "NonAction") || !Symbols.IsDeclaredInSource(method))
            {
                continue;
            }
            var verbs = new List<string>();
            string? methodRoute = null;
            foreach (var attribute in method.GetAttributes())
            {
                var name = attribute.AttributeClass?.Name ?? "";
                if (name.StartsWith("Http", StringComparison.Ordinal) && name.EndsWith("Attribute", StringComparison.Ordinal))
                {
                    verbs.Add(name["Http".Length..^"Attribute".Length].ToUpperInvariant());
                    methodRoute ??= attribute.ConstructorArguments.FirstOrDefault().Value as string;
                }
                else if (name == "RouteAttribute")
                {
                    methodRoute ??= attribute.ConstructorArguments.FirstOrDefault().Value as string;
                }
            }

            var parameters = new List<EndpointParameterDto>();
            var bound = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var parameter in method.Parameters)
            {
                var binding = ControllerBinding(parameter);
                parameters.Add(new EndpointParameterDto(parameter.Name, parameter.Type.ToDisplayString(), binding));
                if (binding != "services")
                {
                    bound[parameter.Name] = binding;
                }
            }
            _requestBound[Symbols.Id(method)] = bound;

            var auth = classAuth.Concat(AuthorizationAttributes(method)).ToList();
            Endpoints.Add(new EndpointDto(
                "controller_action",
                verbs.Count == 0 ? ["ANY"] : verbs,
                CombineRoutes(classRoute, methodRoute, type.Name),
                Symbols.Describe(method),
                parameters,
                auth.Where(a => a != "AllowAnonymous").ToList(),
                auth.Contains("AllowAnonymous")));
        }
    }

    private void IndexInvocation(IInvocationOperation invocation, SemanticModel model)
    {
        var method = invocation.TargetMethod.ReducedFrom ?? invocation.TargetMethod;
        var type = Symbols.FullName(method.ContainingType);

        if (type == "Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions"
            && method.Name is "AddScoped" or "AddTransient" or "AddSingleton" or "AddKeyedScoped" or "AddKeyedTransient" or "AddKeyedSingleton")
        {
            string? service = null;
            string? implementation = null;
            if (method.IsGenericMethod)
            {
                service = method.TypeArguments.ElementAtOrDefault(0)?.ToDisplayString();
                implementation = method.TypeArguments.ElementAtOrDefault(1)?.ToDisplayString();
            }
            var typeofArgs = invocation.Arguments.Select(a => a.Value).OfType<ITypeOfOperation>().ToList();
            service ??= typeofArgs.ElementAtOrDefault(0)?.TypeOperand.ToDisplayString();
            implementation ??= typeofArgs.ElementAtOrDefault(1)?.TypeOperand.ToDisplayString();
            if (service is not null)
            {
                Registrations.Add(new DiRegistrationDto(
                    service,
                    implementation ?? (method.TypeArguments.Length == 1 ? service : null),
                    method.Name.Replace("AddKeyed", "", StringComparison.Ordinal).Replace("Add", "", StringComparison.Ordinal).ToLowerInvariant(),
                    IsConditional(invocation.Syntax),
                    Symbols.SpanOf(invocation.Syntax)));
            }
            return;
        }

        if (!MapMethods.Contains(method.Name) || !type.StartsWith("Microsoft.AspNetCore.Builder.", StringComparison.Ordinal))
        {
            return;
        }

        string? route = null;
        IMethodSymbol? handler = null;
        foreach (var argument in invocation.Arguments)
        {
            switch (argument.Parameter?.Name)
            {
                case "pattern":
                    route = argument.Value.ConstantValue.HasValue ? argument.Value.ConstantValue.Value as string : null;
                    break;
                case "handler" or "requestDelegate":
                    handler = HandlerSymbol(argument.Value);
                    break;
            }
        }
        if (handler is null)
        {
            return;
        }

        var prefix = GroupPrefix(invocation, model);
        var parameters = new List<EndpointParameterDto>();
        var bound = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var parameter in handler.Parameters)
        {
            var binding = MinimalApiBinding(parameter);
            parameters.Add(new EndpointParameterDto(parameter.Name, parameter.Type.ToDisplayString(), binding));
            if (binding != "services")
            {
                bound[parameter.Name] = binding;
            }
        }
        _requestBound[Symbols.Id(handler)] = bound;

        var verbs = method.Name switch
        {
            "MapGet" => new List<string> { "GET" },
            "MapPost" => ["POST"],
            "MapPut" => ["PUT"],
            "MapDelete" => ["DELETE"],
            "MapPatch" => ["PATCH"],
            _ => ["ANY"],
        };
        var auth = AuthorizationAttributes(handler);
        Endpoints.Add(new EndpointDto(
            "minimal_api",
            verbs,
            prefix is null ? route : prefix.TrimEnd('/') + "/" + (route ?? "").TrimStart('/'),
            Symbols.Describe(handler),
            parameters,
            auth.Where(a => a != "AllowAnonymous").ToList(),
            auth.Contains("AllowAnonymous")));
    }

    private static IMethodSymbol? HandlerSymbol(IOperation value)
    {
        while (value is IConversionOperation or IDelegateCreationOperation)
        {
            value = value switch
            {
                IConversionOperation c => c.Operand,
                IDelegateCreationOperation d => d.Target,
                _ => value,
            };
        }
        return value switch
        {
            IAnonymousFunctionOperation lambda => lambda.Symbol,
            IMethodReferenceOperation reference => reference.Method,
            _ => null,
        };
    }

    // Follows `var api = app.MapGroup("/api")` one assignment back.
    private static string? GroupPrefix(IInvocationOperation invocation, SemanticModel model)
    {
        var receiver = invocation.Arguments.FirstOrDefault()?.Value;
        if (receiver is IConversionOperation conversion)
        {
            receiver = conversion.Operand;
        }
        if (receiver is ILocalReferenceOperation local)
        {
            var declarator = local.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
            if (declarator?.Initializer?.Value is { } init && model.GetOperation(init) is IInvocationOperation group
                && group.TargetMethod.Name == "MapGroup")
            {
                var pattern = group.Arguments.FirstOrDefault(a => a.Parameter?.Name == "prefix")?.Value;
                return pattern?.ConstantValue.Value as string;
            }
        }
        return null;
    }

    private static string ControllerBinding(IParameterSymbol parameter)
    {
        foreach (var attribute in parameter.GetAttributes())
        {
            var name = (attribute.AttributeClass?.Name ?? "").Replace("Attribute", "", StringComparison.Ordinal);
            if (ServiceAttributes.Contains(name))
            {
                return "services";
            }
            if (BindingAttributes.Contains(name))
            {
                return name;
            }
        }
        if (Symbols.FullName(parameter.Type) is "System.Threading.CancellationToken")
        {
            return "services";
        }
        // MVC binds unattributed simple types from route or query and complex
        // types from the body or form.
        return "inferred";
    }

    private static string MinimalApiBinding(IParameterSymbol parameter)
    {
        foreach (var attribute in parameter.GetAttributes())
        {
            var name = (attribute.AttributeClass?.Name ?? "").Replace("Attribute", "", StringComparison.Ordinal);
            if (ServiceAttributes.Contains(name))
            {
                return "services";
            }
            if (BindingAttributes.Contains(name))
            {
                return name;
            }
        }
        var type = parameter.Type;
        var fullName = Symbols.FullName(type);
        if (fullName is "Microsoft.AspNetCore.Http.HttpContext" or "Microsoft.AspNetCore.Http.HttpRequest")
        {
            return "request_object";
        }
        if (fullName is "System.Threading.CancellationToken" or "Microsoft.AspNetCore.Http.HttpResponse"
            or "System.Security.Claims.ClaimsPrincipal" || type.TypeKind == TypeKind.Interface)
        {
            // Interfaces are treated as DI services; minimal APIs cannot bind
            // an interface from the request.
            return "services";
        }
        return "inferred";
    }

    private static bool IsConditional(SyntaxNode node)
    {
        for (var current = node.Parent; current is not null; current = current.Parent)
        {
            switch (current)
            {
                case IfStatementSyntax or ElseClauseSyntax or SwitchSectionSyntax or ConditionalExpressionSyntax:
                    return true;
                case BaseMethodDeclarationSyntax or CompilationUnitSyntax:
                    return false;
            }
        }
        return false;
    }

    private static bool HasAttribute(ISymbol symbol, string shortName) =>
        symbol.GetAttributes().Any(a => a.AttributeClass?.Name == shortName + "Attribute" || a.AttributeClass?.Name == shortName);

    private static string? AttributeArgument(ISymbol symbol, string shortName) =>
        symbol.GetAttributes()
            .FirstOrDefault(a => a.AttributeClass?.Name == shortName + "Attribute")?
            .ConstructorArguments.FirstOrDefault().Value as string;

    private static List<string> AuthorizationAttributes(ISymbol symbol) =>
        symbol.GetAttributes()
            .Select(a => a.AttributeClass?.Name.Replace("Attribute", "", StringComparison.Ordinal) ?? "")
            .Where(n => n is "Authorize" or "AllowAnonymous" || n.Contains("Authoriz", StringComparison.Ordinal))
            .ToList();

    private static string? CombineRoutes(string? classRoute, string? methodRoute, string controllerName)
    {
        if (methodRoute is not null && methodRoute.StartsWith('/'))
        {
            return methodRoute;
        }
        var controller = controllerName.EndsWith("Controller", StringComparison.Ordinal)
            ? controllerName[..^"Controller".Length]
            : controllerName;
        var baseRoute = classRoute?.Replace("[controller]", controller.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        if (baseRoute is null)
        {
            return methodRoute;
        }
        return methodRoute is null ? "/" + baseRoute.Trim('/') : "/" + baseRoute.Trim('/') + "/" + methodRoute.TrimStart('/');
    }
}
