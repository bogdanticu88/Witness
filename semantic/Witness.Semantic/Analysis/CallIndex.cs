using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

// Workspace-wide index of resolved calls, delegate references, overrides and
// interface implementations. Built once per load.
internal sealed class CallIndex
{
    private readonly Dictionary<string, List<(IOperation Call, IMethodSymbol Target)>> _callsByTarget = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<IMethodSymbol>> _implementations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IMethodSymbol> _contractsByImplementation = new(StringComparer.Ordinal);
    private readonly HashSet<string> _delegateReferences = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _unresolvedByName = new(StringComparer.Ordinal);

    public static CallIndex Build(AnalysisWorkspace workspace)
    {
        var index = new CallIndex();
        foreach (var project in workspace.Projects)
        {
            foreach (var tree in project.Compilation.SyntaxTrees)
            {
                if (tree.FilePath.StartsWith('<'))
                {
                    continue;
                }
                var model = project.Compilation.GetSemanticModel(tree);
                foreach (var node in tree.GetRoot().DescendantNodes())
                {
                    switch (node)
                    {
                        case InvocationExpressionSyntax invocation:
                            index.IndexInvocation(invocation, model);
                            break;
                        case BaseObjectCreationExpressionSyntax creation when model.GetOperation(creation) is IObjectCreationOperation { Constructor: { } ctor } op:
                            index.Add(ctor, op);
                            break;
                        case TypeDeclarationSyntax type when model.GetDeclaredSymbol(type) is INamedTypeSymbol symbol:
                            index.IndexImplementations(symbol);
                            break;
                        // A method name used without being invoked is a method
                        // group: converted to a delegate, subscribed to an
                        // event, or passed to a framework API.
                        case SimpleNameSyntax name when !IsInvoked(name)
                            && model.GetSymbolInfo(name).Symbol is IMethodSymbol { MethodKind: MethodKind.Ordinary } group:
                            index._delegateReferences.Add(Symbols.Id(group));
                            break;
                    }
                }
            }
        }
        return index;
    }

    private static bool IsInvoked(SimpleNameSyntax name)
    {
        SyntaxNode expression = name.Parent is MemberAccessExpressionSyntax access && access.Name == name ? access : name;
        return expression.Parent is InvocationExpressionSyntax invocation && invocation.Expression == expression
            || name.Parent is MemberAccessExpressionSyntax outer && outer.Expression == name;
    }

    public IReadOnlyList<IMethodSymbol> Implementations(IMethodSymbol contract) =>
        _implementations.TryGetValue(Symbols.Id(contract), out var list) ? list : [];

    public CallersDto Callers(IMethodSymbol method, EndpointIndex endpoints)
    {
        var id = Symbols.Id(method);
        var calls = new List<CallSiteDto>();
        var reasons = new List<string>();

        void Collect(string targetId, bool viaDispatch)
        {
            if (!_callsByTarget.TryGetValue(targetId, out var found))
            {
                return;
            }
            foreach (var (call, target) in found)
            {
                calls.Add(Describe(call, target, viaDispatch));
            }
        }

        Collect(id, false);
        // Calls through an interface or base member may land here at runtime.
        foreach (var contract in Contracts(method))
        {
            Collect(Symbols.Id(contract), true);
            reasons.Add($"reachable through {contract.ToDisplayString()}; other implementations share these call sites");
        }

        if (method.DeclaredAccessibility is Accessibility.Public or Accessibility.Protected or Accessibility.ProtectedOrInternal)
        {
            reasons.Add("externally visible member; callers outside the analyzed code are possible");
        }
        if (method.IsVirtual || method.IsAbstract || method.IsOverride || method.ContainingType.TypeKind == TypeKind.Interface)
        {
            reasons.Add("virtual dispatch; framework or derived code may call it");
        }
        if (endpoints.IsEntryPoint(method))
        {
            reasons.Add("framework entry point; invoked by the host, not by analyzed code");
        }
        if (_delegateReferences.Contains(id))
        {
            reasons.Add("referenced as a delegate; invocations through the delegate are not tracked");
        }
        if (method.MethodKind is MethodKind.AnonymousFunction or MethodKind.LocalFunction)
        {
            reasons.Add("lambda or local function; invocation through delegates is not tracked");
        }
        if (_unresolvedByName.TryGetValue(method.Name, out var unresolved) && unresolved > 0)
        {
            reasons.Add($"{unresolved} unresolved call(s) named {method.Name} could target it");
        }
        if (method.GetAttributes().Length > 0)
        {
            reasons.Add("member has attributes; reflection-based invocation not ruled out");
        }

        return new CallersDto(Symbols.Describe(method), calls, reasons.Count == 0, reasons);
    }

    private IEnumerable<IMethodSymbol> Contracts(IMethodSymbol method)
    {
        if (_contractsByImplementation.TryGetValue(Symbols.Id(method), out var contract))
        {
            yield return contract;
        }
        for (var overridden = method.OverriddenMethod; overridden is not null; overridden = overridden.OverriddenMethod)
        {
            yield return overridden;
        }
    }

    private void IndexInvocation(InvocationExpressionSyntax invocation, SemanticModel model)
    {
        var operation = model.GetOperation(invocation);
        if (operation is IInvocationOperation resolved)
        {
            Add(resolved.TargetMethod, resolved);
        }
        else
        {
            var name = invocation.Expression switch
            {
                MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
                IdentifierNameSyntax identifier => identifier.Identifier.ValueText,
                GenericNameSyntax generic => generic.Identifier.ValueText,
                _ => null,
            };
            if (name is not null)
            {
                _unresolvedByName[name] = _unresolvedByName.GetValueOrDefault(name) + 1;
            }
        }

    }

    private void Add(IMethodSymbol target, IOperation call)
    {
        var id = Symbols.Id(target.ReducedFrom ?? target);
        if (!_callsByTarget.TryGetValue(id, out var list))
        {
            list = [];
            _callsByTarget[id] = list;
        }
        list.Add((call, target));
    }

    private void IndexImplementations(INamedTypeSymbol type)
    {
        foreach (var member in type.GetMembers().OfType<IMethodSymbol>())
        {
            for (var overridden = member.OverriddenMethod; overridden is not null; overridden = overridden.OverriddenMethod)
            {
                AddImplementation(overridden, member);
            }
        }
        foreach (var contract in type.AllInterfaces.SelectMany(i => i.GetMembers().OfType<IMethodSymbol>()))
        {
            if (type.FindImplementationForInterfaceMember(contract) is IMethodSymbol implementation
                && SymbolEqualityComparer.Default.Equals(implementation.ContainingType, type))
            {
                AddImplementation(contract, implementation);
                _contractsByImplementation.TryAdd(Symbols.Id(implementation), contract.OriginalDefinition);
            }
        }
    }

    private void AddImplementation(IMethodSymbol contract, IMethodSymbol implementation)
    {
        var id = Symbols.Id(contract);
        if (!_implementations.TryGetValue(id, out var list))
        {
            list = [];
            _implementations[id] = list;
        }
        if (!list.Any(m => Symbols.Id(m) == Symbols.Id(implementation)))
        {
            list.Add(implementation);
        }
    }

    private static CallSiteDto Describe(IOperation call, IMethodSymbol target, bool viaDispatch)
    {
        var arguments = call switch
        {
            IInvocationOperation invocation => invocation.Arguments,
            IObjectCreationOperation creation => creation.Arguments,
            _ => [],
        };
        var model = call.SemanticModel!;
        var caller = Symbols.EnclosingMember(model, call.Syntax);
        return new CallSiteDto(
            caller is null ? null : Symbols.Describe(caller),
            Symbols.SpanOf(call.Syntax),
            Symbols.Id(target.ReducedFrom ?? target),
            viaDispatch,
            arguments
                .Where(a => a.Parameter is not null)
                .Select(a => new CallArgumentDto(a.Parameter!.Ordinal, a.Parameter.Name, a.Value.Syntax.ToString(), Symbols.SpanOf(a.Value.Syntax)))
                .ToList());
    }
}
