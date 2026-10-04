using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

// Builds a backward value-flow tree for one expression.
//
// This is a bounded slice, not a taint engine:
// * Within a method it is flow-insensitive: a local's tree contains every
//   assignment to it anywhere in the member, which over-approximates origins.
// * Calls to source-declared methods are inlined through their return
//   expressions, up to MaxInlineDepth, with parameters substituted by the
//   caller's argument trees. Virtual and interface calls are inlined only
//   when exactly one source implementation exists.
// * Parameters of non-entry-point methods are leaves; the orchestrator
//   expands them through the callers query.
// * Unknown library calls are kept as unknown_call nodes with their inputs as
//   children. They are not assumed to sanitize, and the orchestrator must not
//   treat them as plain propagation when deciding a verdict.
internal sealed class ValueFlow
{
    private const int MaxNodes = 600;
    private const int MaxDepth = 28;
    private const int MaxInlineDepth = 3;
    private const int MaxTextLength = 160;

    private readonly AnalysisWorkspace _workspace;
    private readonly EndpointIndex _endpoints;
    private readonly CallIndex _calls;
    private int _nodes;

    public ValueFlow(AnalysisWorkspace workspace, EndpointIndex endpoints, CallIndex calls)
    {
        _workspace = workspace;
        _endpoints = endpoints;
        _calls = calls;
    }

    public bool Truncated { get; private set; }
    public List<string> Unresolved { get; } = [];

    private sealed record Context(
        ImmutableHashSet<string> Visiting,
        ImmutableDictionary<string, ValueNode> Substitution,
        int InlineDepth,
        int Depth)
    {
        public static Context Root => new(ImmutableHashSet<string>.Empty, ImmutableDictionary<string, ValueNode>.Empty, 0, 0);

        public Context Deeper() => this with { Depth = Depth + 1 };
    }

    public ValueNode Analyze(IOperation operation) => Build(operation, Context.Root);

    private ValueNode Build(IOperation operation, Context context)
    {
        if (++_nodes > MaxNodes || context.Depth > MaxDepth)
        {
            Truncated = true;
            return Node("truncated", operation, detail: "node or depth budget reached");
        }
        var next = context.Deeper();

        if (operation.ConstantValue.HasValue)
        {
            return Node("constant", operation, detail: Preview(operation.ConstantValue.Value));
        }
        if (operation is not IConversionOperation && Symbols.IsSafeType(operation.Type))
        {
            return Node("typed_safe", operation, detail: operation.Type!.ToDisplayString());
        }

        switch (operation)
        {
            case IConversionOperation conversion:
                if (Symbols.IsSafeType(conversion.Operand.Type))
                {
                    return Node("typed_safe", operation, detail: conversion.Operand.Type!.ToDisplayString());
                }
                if (Symbols.FullName(conversion.Type) == "System.FormattableString")
                {
                    return Node("formattable", operation, children: [Build(conversion.Operand, next)],
                        facts: Facts(("note", "interpolated values become parameters only if the receiving API is FormattableString-aware")));
                }
                return Build(conversion.Operand, next);

            case IParenthesizedOperation parenthesized:
                return Build(parenthesized.Operand, next);

            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } binary:
                return Node("concat", operation, children: Flatten(binary).Select(o => Build(o, next)).ToList());

            case IInterpolatedStringOperation interpolated:
                return Node("interpolation", operation, children: interpolated.Parts.Select(part => part switch
                {
                    IInterpolationOperation hole => Build(hole.Expression, next),
                    IInterpolatedStringTextOperation text => Node("constant", text, detail: Preview(text.Text.ConstantValue.Value)),
                    _ => Node("unknown", part, detail: part.Kind.ToString()),
                }).ToList());

            case IConditionalOperation { WhenFalse: not null } conditional:
                return Node("conditional", operation, children: [Build(conditional.WhenTrue, next), Build(conditional.WhenFalse, next)]);

            case ICoalesceOperation coalesce:
                return Node("conditional", operation, children: [Build(coalesce.Value, next), Build(coalesce.WhenNull, next)]);

            case ISwitchExpressionOperation switchExpression:
                return Node("conditional", operation, children: switchExpression.Arms.Select(a => Build(a.Value, next)).ToList());

            case ILocalReferenceOperation local:
                return ExpandLocal(local.Local, operation, next);

            case IParameterReferenceOperation parameter:
                return ExpandParameter(parameter.Parameter, operation, next);

            case IFieldReferenceOperation field:
                return ExpandField(field, next);

            case IPropertyReferenceOperation property:
                return ExpandProperty(property, next);

            case IInvocationOperation invocation:
                return ExpandInvocation(invocation, next);

            case IObjectCreationOperation creation:
                return ExpandCreation(creation, next);

            case IAwaitOperation awaited:
                return Build(awaited.Operation, next);

            case IArrayElementReferenceOperation element:
                return Node("propagator", operation, detail: "array element", children: [Build(element.ArrayReference, next)]);

            case IArrayCreationOperation array:
                return Node("propagator", operation, detail: "array",
                    children: array.Initializer?.ElementValues.Select(v => Build(v, next)).ToList() ?? []);

            case IDefaultValueOperation:
                return Node("constant", operation, detail: "default");

            case IInvalidOperation:
                Unresolved.Add($"unresolved expression at {Location(operation)}: {Text(operation)}");
                return Node("unknown", operation, detail: "unresolved expression",
                    children: operation.ChildOperations.Select(c => Build(c, next)).ToList());

            case IInstanceReferenceOperation:
                return Node("unknown", operation, detail: "instance reference");

            default:
                return Node("unknown", operation, detail: operation.Kind.ToString());
        }
    }

    private ValueNode ExpandLocal(ILocalSymbol local, IOperation reference, Context context)
    {
        var id = Symbols.Id(local);
        if (context.Visiting.Contains(id))
        {
            return Node("local", reference, symbol: id, detail: "cycle");
        }
        var inner = context with { Visiting = context.Visiting.Add(id) };
        var declaration = local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
        var body = declaration is null ? null : MemberBody(declaration);
        if (body is null)
        {
            return Node("local", reference, symbol: id, detail: "declaration not found");
        }

        var model = _workspace.Model(body.SyntaxTree);
        var children = Definitions(local, body, model, reference.Syntax, inner, includeMutations: true);
        return Node("local", reference, symbol: id, detail: local.Name, children: children,
            facts: Facts(("assignments", children.Count.ToString())));
    }

    private ValueNode ExpandParameter(IParameterSymbol parameter, IOperation reference, Context context)
    {
        var id = Symbols.Id(parameter);
        if (context.Substitution.TryGetValue(id, out var substituted))
        {
            return Node("argument", reference, symbol: id, detail: parameter.Name, children: [substituted]);
        }
        var method = parameter.ContainingSymbol as IMethodSymbol;
        var children = new List<ValueNode>();
        if (!context.Visiting.Contains(id))
        {
            var inner = context with { Visiting = context.Visiting.Add(id) };
            var declaration = parameter.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
            var body = declaration is null ? null : MemberBody(declaration);
            if (body is not null)
            {
                children = Definitions(parameter, body, _workspace.Model(body.SyntaxTree), reference.Syntax, inner, includeMutations: false);
            }
        }

        if (_endpoints.TryGetBinding(parameter, out var binding))
        {
            var facts = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["handler"] = Symbols.Id(parameter.ContainingSymbol),
                ["type"] = parameter.Type.ToDisplayString(),
                ["reassigned"] = children.Count > 0 ? "true" : "false",
            };
            foreach (var (key, value) in Binding.ParameterFacts(parameter, _endpoints))
            {
                facts[key] = value;
            }
            return Node("endpoint_parameter", reference, symbol: id, detail: binding, children: children, facts: facts);
        }

        return Node("parameter", reference, symbol: id, detail: parameter.Name, children: children, facts: Facts(
            ("method", method is null ? "" : Symbols.Id(method)),
            ("ordinal", parameter.Ordinal.ToString()),
            ("accessibility", method?.DeclaredAccessibility.ToString().ToLowerInvariant() ?? ""),
            ("method_kind", method?.MethodKind.ToString() ?? ""),
            ("dispatch", method is null ? "" : DispatchKind(method)),
            ("entry_point", method is not null && _endpoints.IsEntryPoint(method) ? "true" : "false"),
            ("reassigned", children.Count > 0 ? "true" : "false")));
    }

    private ValueNode ExpandField(IFieldReferenceOperation reference, Context context)
    {
        var field = reference.Field;
        if (field.HasConstantValue)
        {
            return Node("constant", reference, detail: Preview(field.ConstantValue));
        }
        var id = Symbols.Id(field);
        if (!Symbols.IsDeclaredInSource(field))
        {
            // Framework fields such as string.Empty or Path.DirectorySeparatorChar.
            var ns = field.ContainingNamespace?.ToDisplayString() ?? "";
            return ns == "System" || ns.StartsWith("System.", StringComparison.Ordinal)
                ? Node("constant", reference, symbol: id, detail: "framework field " + field.ToDisplayString())
                : Node("unknown", reference, symbol: id, detail: "library field " + field.ToDisplayString());
        }
        if (context.Visiting.Contains(id))
        {
            return Node("field", reference, symbol: id, detail: "cycle");
        }
        var inner = context with { Visiting = context.Visiting.Add(id) };
        var children = MemberAssignments(field, inner);
        return Node("field", reference, symbol: id, detail: field.Name, children: children,
            facts: Facts(("readonly", field.IsReadOnly ? "true" : "false"), ("static", field.IsStatic ? "true" : "false")));
    }

    private ValueNode ExpandProperty(IPropertyReferenceOperation reference, Context context)
    {
        var property = reference.Property;
        switch (Catalog.PropertySource(property))
        {
            case Catalog.SourceKind.Request:
                return Node("request_source", reference, detail: property.ContainingType.Name + "." + property.Name);
            case Catalog.SourceKind.Configuration:
                return Node("config_source", reference, detail: property.ToDisplayString());
            case Catalog.SourceKind.Environment:
                return Node("environment_source", reference, detail: property.ToDisplayString());
        }

        var id = Symbols.Id(property);
        if (Symbols.IsDeclaredInSource(property))
        {
            if (reference.Instance is null or IInstanceReferenceOperation)
            {
                if (context.Visiting.Contains(id))
                {
                    return Node("property", reference, symbol: id, detail: "cycle");
                }
                var inner = context with { Visiting = context.Visiting.Add(id) };
                return Node("property", reference, symbol: id, detail: property.Name, children: MemberAssignments(property, inner),
                    facts: Facts(("scope", "own_member")));
            }
            var propertyFacts = new Dictionary<string, string>(StringComparer.Ordinal) { ["scope"] = "instance_member" };
            var validation = Binding.ValidationAttributes(property);
            if (validation.Length > 0)
            {
                propertyFacts["validation"] = validation;
            }
            return Node("property", reference, symbol: id, detail: property.Name, children: [Build(reference.Instance, context)],
                facts: propertyFacts);
        }

        var children = new List<ValueNode>();
        if (reference.Instance is not null)
        {
            children.Add(Build(reference.Instance, context));
        }
        return Node("propagator", reference, symbol: id, detail: property.ToDisplayString(), children: children);
    }

    private ValueNode ExpandInvocation(IInvocationOperation invocation, Context context)
    {
        var method = invocation.TargetMethod;
        var id = Symbols.Id(method);

        switch (Catalog.MethodSource(method))
        {
            case Catalog.SourceKind.Request:
                return Node("request_source", invocation, symbol: id, detail: method.ToDisplayString());
            case Catalog.SourceKind.Configuration:
                return Node("config_source", invocation, symbol: id, detail: method.ToDisplayString());
            case Catalog.SourceKind.Environment:
                return Node("environment_source", invocation, symbol: id, detail: method.ToDisplayString());
        }

        if (Catalog.Sanitizer(method) is { } sanitizer)
        {
            return Node("sanitizer", invocation, symbol: id, detail: sanitizer.Name,
                children: InvocationInputs(invocation).Select(o => Build(o, context)).ToList(),
                facts: Facts(("effect", sanitizer.Effect)));
        }
        if (Catalog.IsPropagator(method))
        {
            return Node("propagator", invocation, symbol: id, detail: method.ContainingType.Name + "." + method.Name,
                children: InvocationInputs(invocation).Select(o => Build(o, context)).ToList(),
                facts: Catalog.AltersContent(method) ? Facts(("alters_content", "true")) : null);
        }

        if (Symbols.IsDeclaredInSource(method) && context.InlineDepth < MaxInlineDepth)
        {
            var target = method;
            var dispatch = DispatchKind(method);
            if (dispatch != "direct")
            {
                var implementations = _calls.Implementations(method);
                if (implementations.Count != 1)
                {
                    return Node("unknown_call", invocation, symbol: id, detail: method.ToDisplayString(),
                        children: InvocationInputs(invocation).Select(o => Build(o, context)).ToList(),
                        facts: Facts(("dispatch", "ambiguous"), ("implementations", string.Join(";", implementations.Select(Symbols.Id))),
                            ("declared_in_source", "true")));
                }
                target = implementations[0];
            }
            var inlined = Inline(invocation, target, context);
            if (inlined is not null)
            {
                return inlined with
                {
                    Facts = Facts(("inlined", "true"), ("dispatch", dispatch == "direct" ? "direct" : "single_implementation")),
                };
            }
        }

        return Node("unknown_call", invocation, symbol: id, detail: method.ToDisplayString(),
            children: InvocationInputs(invocation).Select(o => Build(o, context)).ToList(),
            facts: Facts(("declared_in_source", Symbols.IsDeclaredInSource(method) ? "true" : "false"), ("dispatch", DispatchKind(method))));
    }

    private ValueNode? Inline(IInvocationOperation invocation, IMethodSymbol target, Context context)
    {
        var declaration = target.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
        var returns = ReturnExpressions(declaration);
        if (declaration is null || returns.Count == 0)
        {
            return null;
        }
        var targetId = Symbols.Id(target);
        if (context.Visiting.Contains(targetId))
        {
            return Node("call", invocation, symbol: targetId, detail: "recursive call not expanded");
        }

        var substitution = ImmutableDictionary<string, ValueNode>.Empty;
        foreach (var argument in invocation.Arguments)
        {
            if (argument.Parameter is null)
            {
                continue;
            }
            var parameter = target.Parameters.ElementAtOrDefault(argument.Parameter.Ordinal);
            if (parameter is not null)
            {
                substitution = substitution.SetItem(Symbols.Id(parameter), Build(argument.Value, context));
            }
        }

        var calleeContext = new Context(
            context.Visiting.Add(targetId),
            substitution,
            context.InlineDepth + 1,
            context.Depth);
        var model = _workspace.Model(declaration.SyntaxTree);
        var children = new List<ValueNode>();
        foreach (var expression in returns)
        {
            var operation = model.GetOperation(expression);
            children.Add(operation is null
                ? Node("unknown", expression, detail: "return expression not bound")
                : WithHopGuards(Build(operation, calleeContext), expression, operation, model));
        }
        return Node("call", invocation, symbol: targetId, detail: target.ToDisplayString(), children: children);
    }

    private ValueNode ExpandCreation(IObjectCreationOperation creation, Context context)
    {
        var type = Symbols.FullName(creation.Type);
        var inputs = creation.Arguments.Select(a => a.Value).ToList();
        if (type is "System.Text.StringBuilder" or "System.Uri" or "System.String" or "Microsoft.Extensions.Primitives.StringValues")
        {
            return Node("propagator", creation, detail: "new " + type, children: inputs.Select(o => Build(o, context)).ToList());
        }
        return Node("unknown_call", creation, symbol: creation.Constructor is null ? null : Symbols.Id(creation.Constructor),
            detail: "new " + type, children: inputs.Select(o => Build(o, context)).ToList(),
            facts: Facts(("declared_in_source", creation.Constructor is not null && Symbols.IsDeclaredInSource(creation.Constructor) ? "true" : "false")));
    }

    private List<ValueNode> MemberAssignments(ISymbol member, Context context)
    {
        var children = new List<ValueNode>();
        foreach (var reference in member.DeclaringSyntaxReferences)
        {
            var syntax = reference.GetSyntax();
            var model = _workspace.Model(syntax.SyntaxTree);
            // Field initializers are found by the type-wide scan below;
            // property initializers are not assignments, so add them here.
            if (syntax is PropertyDeclarationSyntax { Initializer: { } propertyInit }
                && model.GetOperation(propertyInit.Value) is { } initial)
            {
                children.Add(Build(initial, context));
            }
        }

        // Assignments anywhere in the declaring type, typically constructors.
        var type = member.ContainingType;
        foreach (var declaration in type.DeclaringSyntaxReferences.Select(r => r.GetSyntax()))
        {
            var model = _workspace.Model(declaration.SyntaxTree);
            foreach (var source in AssignedValues(member, declaration, model).Where(s => s.Kind is AssignmentKind.Value or AssignmentKind.Compound))
            {
                children.Add(WithHopGuards(Build(source.Operation, context), source.Operation.Syntax, source.Operation, model));
            }
        }
        if (children.Count == 0)
        {
            children.Add(new ValueNode("unknown", member.Name, Symbols.SpanOf(member.Locations.FirstOrDefault()),
                Detail: "no assignment found in declaring type"));
        }
        return children;
    }

    private enum AssignmentKind
    {
        Value,
        // x += y, x ??= y: adds to or may keep the previous value.
        Compound,
        OutArgument,
        Mutation,
    }

    private static IEnumerable<(AssignmentKind Kind, IOperation Operation)> AssignedValues(ISymbol symbol, SyntaxNode scope, SemanticModel model)
    {
        var target = symbol.OriginalDefinition;
        foreach (var node in scope.DescendantNodes())
        {
            switch (node)
            {
                case VariableDeclaratorSyntax { Initializer: { } init } declarator
                    when SymbolEqualityComparer.Default.Equals(model.GetDeclaredSymbol(declarator), target):
                    if (model.GetOperation(init.Value) is { } initOp)
                    {
                        yield return (AssignmentKind.Value, initOp);
                    }
                    break;

                case AssignmentExpressionSyntax assignment when Refers(model, assignment.Left, target):
                    if (model.GetOperation(assignment.Right) is { } right)
                    {
                        yield return (assignment.IsKind(SyntaxKind.SimpleAssignmentExpression) ? AssignmentKind.Value : AssignmentKind.Compound, right);
                    }
                    break;

                case ArgumentSyntax { RefKindKeyword.RawKind: (int)SyntaxKind.OutKeyword or (int)SyntaxKind.RefKeyword } argument
                    when ArgumentTargets(model, argument, target):
                    if (argument.Parent?.Parent is { } call && model.GetOperation(call) is { } callOp)
                    {
                        yield return (AssignmentKind.OutArgument, callOp);
                    }
                    break;

                case ForEachStatementSyntax forEach
                    when SymbolEqualityComparer.Default.Equals(model.GetDeclaredSymbol(forEach), target):
                    if (model.GetOperation(forEach.Expression) is { } collection)
                    {
                        yield return (AssignmentKind.Value, collection);
                    }
                    break;

                case DeclarationPatternSyntax { Designation: SingleVariableDesignationSyntax designation } pattern
                    when SymbolEqualityComparer.Default.Equals(model.GetDeclaredSymbol(designation), target):
                    if (pattern.Parent is IsPatternExpressionSyntax isPattern && model.GetOperation(isPattern.Expression) is { } tested)
                    {
                        yield return (AssignmentKind.Value, tested);
                    }
                    break;

                case InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax access } invocation
                    when Refers(model, access.Expression, target)
                        && model.GetOperation(invocation) is IInvocationOperation mutation
                        && Symbols.FullName(mutation.TargetMethod.ContainingType) == "System.Text.StringBuilder"
                        && mutation.TargetMethod.Name is "Append" or "AppendLine" or "AppendFormat" or "Insert" or "Replace" or "AppendJoin":
                    yield return (AssignmentKind.Mutation, mutation);
                    break;
            }
        }
    }

    private static bool Refers(SemanticModel model, ExpressionSyntax expression, ISymbol target)
    {
        var symbol = model.GetSymbolInfo(expression).Symbol;
        return symbol is not null && SymbolEqualityComparer.Default.Equals(symbol.OriginalDefinition, target);
    }

    private static bool ArgumentTargets(SemanticModel model, ArgumentSyntax argument, ISymbol target) => argument.Expression switch
    {
        DeclarationExpressionSyntax { Designation: SingleVariableDesignationSyntax designation } =>
            SymbolEqualityComparer.Default.Equals(model.GetDeclaredSymbol(designation), target),
        _ => Refers(model, argument.Expression, target),
    };

    private static IEnumerable<IOperation> InvocationInputs(IOperation call, bool includeReceiver = true)
    {
        switch (call)
        {
            case IInvocationOperation invocation:
                if (includeReceiver && invocation.Instance is not null)
                {
                    yield return invocation.Instance;
                }
                foreach (var argument in invocation.Arguments)
                {
                    if (argument.Parameter?.RefKind is RefKind.Out)
                    {
                        continue;
                    }
                    if (argument.ArgumentKind == ArgumentKind.ParamArray && argument.Value is IArrayCreationOperation { Initializer: { } init })
                    {
                        foreach (var element in init.ElementValues)
                        {
                            yield return element;
                        }
                        continue;
                    }
                    yield return argument.Value;
                }
                break;
            case IObjectCreationOperation creation:
                foreach (var argument in creation.Arguments)
                {
                    yield return argument.Value;
                }
                break;
        }
    }

    private static IEnumerable<IOperation> Flatten(IBinaryOperation binary)
    {
        foreach (var side in new[] { binary.LeftOperand, binary.RightOperand })
        {
            var unwrapped = side is IConversionOperation { IsImplicit: true } c && !Symbols.IsSafeType(c.Operand.Type) ? c.Operand : side;
            if (unwrapped is IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } nested && !nested.ConstantValue.HasValue)
            {
                foreach (var part in Flatten(nested))
                {
                    yield return part;
                }
            }
            else
            {
                yield return side;
            }
        }
    }

    // Every definition of a local or parameter, each annotated with how it
    // relates to the read being sliced, so the orchestrator can drop
    // definitions that cannot reach the read:
    //   def_kind      assign (replaces the value) or accumulate (+=, ??=, Append)
    //   def_order     before, after (cannot reach) or unordered (loop, lambda, goto)
    //   def_dominates true when it runs on every path to the read
    //   def_killed    true when a later statement in the same block replaces it
    //   def_position  source offset, to order definitions
    private List<ValueNode> Definitions(ISymbol symbol, SyntaxNode body, SemanticModel model, SyntaxNode read, Context context, bool includeMutations)
    {
        var children = new List<ValueNode>();
        var hasGoto = body.DescendantNodes().OfType<GotoStatementSyntax>().Any();
        foreach (var source in AssignedValues(symbol, body, model))
        {
            ValueNode node;
            switch (source.Kind)
            {
                case AssignmentKind.Value:
                    node = Build(source.Operation, context);
                    break;
                case AssignmentKind.Compound:
                    node = Node("propagator", source.Operation, detail: "compound " + Text(source.Operation), children: [Build(source.Operation, context)]);
                    break;
                case AssignmentKind.OutArgument:
                    node = Node("out_argument", source.Operation, detail: Text(source.Operation),
                        children: InvocationInputs(source.Operation).Select(o => Build(o, context)).ToList());
                    break;
                case AssignmentKind.Mutation when includeMutations:
                    node = Node("propagator", source.Operation, detail: "mutation " + Text(source.Operation),
                        children: InvocationInputs(source.Operation, includeReceiver: false).Select(o => Build(o, context)).ToList(),
                        facts: source.Operation is IInvocationOperation { TargetMethod.Name: "Replace" } ? Facts(("alters_content", "true")) : null);
                    break;
                default:
                    continue;
            }
            var definition = DefinitionSyntax(source.Operation.Syntax);
            var order = hasGoto ? "unordered" : Order(definition, read);
            var replaces = source.Kind is AssignmentKind.Value or AssignmentKind.OutArgument;
            var statement = definition.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
            var dominates = order == "before" && replaces && statement?.Parent is BlockSyntax block && read.Ancestors().Contains(block);
            var killed = order == "before" && statement?.Parent is BlockSyntax siblings
                && siblings.Statements.SkipWhile(st => st != statement).Skip(1)
                    .TakeWhile(st => st.Span.End <= read.SpanStart)
                    .Any(st => st is ExpressionStatementSyntax { Expression: AssignmentExpressionSyntax assign }
                        && assign.IsKind(SyntaxKind.SimpleAssignmentExpression) && Refers(model, assign.Left, symbol.OriginalDefinition));
            var facts = new Dictionary<string, string>(node.Facts ?? new Dictionary<string, string>(), StringComparer.Ordinal)
            {
                ["def_kind"] = replaces ? "assign" : "accumulate",
                ["def_order"] = order,
                ["def_dominates"] = dominates ? "true" : "false",
                ["def_killed"] = killed ? "true" : "false",
                ["def_position"] = definition.SpanStart.ToString(System.Globalization.CultureInfo.InvariantCulture),
            };
            children.Add(node with { Facts = facts });
        }
        return children;
    }

    // The statement-level node of a definition: a declarator, an assignment
    // or the call that writes an out argument.
    private static SyntaxNode DefinitionSyntax(SyntaxNode value) =>
        value.AncestorsAndSelf().FirstOrDefault(n => n is VariableDeclaratorSyntax or AssignmentExpressionSyntax
            or InvocationExpressionSyntax or ForEachStatementSyntax or IsPatternExpressionSyntax) ?? value;

    private static string Order(SyntaxNode definition, SyntaxNode read)
    {
        if (EnclosingFunction(definition) != EnclosingFunction(read))
        {
            return "unordered";
        }
        if (definition.Span.Contains(read.Span))
        {
            // x = F(x): the read happens before this definition completes.
            return "after";
        }
        if (definition.Span.End <= read.SpanStart)
        {
            return "before";
        }
        var sharedLoop = read.Ancestors().Any(a => a is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax or DoStatementSyntax
            && a.Span.Contains(definition.Span));
        return sharedLoop ? "unordered" : "after";
    }

    private static SyntaxNode? EnclosingFunction(SyntaxNode node) =>
        node.Ancestors().FirstOrDefault(a => a is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax);

    // Checks between a value and the point where it leaves a member (a
    // return of an inlined call, an assignment to a field) are attached so
    // validation in wrappers and constructors is not lost.
    private static ValueNode WithHopGuards(ValueNode node, SyntaxNode exit, IOperation value, SemanticModel model)
    {
        var guards = GuardFinder.Find(exit, value, model);
        if (guards.Count == 0)
        {
            return node;
        }
        var facts = new Dictionary<string, string>(node.Facts ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            ["hop_guards"] = System.Text.Json.JsonSerializer.Serialize(guards, Json.Options),
        };
        return node with { Facts = facts };
    }

    // "direct" when the call target is fixed at compile time.
    private static string DispatchKind(IMethodSymbol method)
    {
        if (method.ContainingType?.TypeKind == TypeKind.Interface)
        {
            return "interface";
        }
        if (method.IsAbstract || method.IsVirtual || method.IsOverride)
        {
            return "virtual";
        }
        return "direct";
    }

    private static List<ExpressionSyntax> ReturnExpressions(SyntaxNode? declaration)
    {
        var result = new List<ExpressionSyntax>();
        switch (declaration)
        {
            case MethodDeclarationSyntax { ExpressionBody: { } arrow }:
                result.Add(arrow.Expression);
                return result;
            case LocalFunctionStatementSyntax { ExpressionBody: { } localArrow }:
                result.Add(localArrow.Expression);
                return result;
            case MethodDeclarationSyntax { Body: { } body }:
                CollectReturns(body, result);
                return result;
            case LocalFunctionStatementSyntax { Body: { } localBody }:
                CollectReturns(localBody, result);
                return result;
            default:
                return result;
        }
    }

    private static void CollectReturns(SyntaxNode body, List<ExpressionSyntax> result)
    {
        foreach (var child in body.ChildNodes())
        {
            // Returns inside nested lambdas and local functions belong to them.
            if (child is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax)
            {
                continue;
            }
            if (child is ReturnStatementSyntax { Expression: { } expression })
            {
                result.Add(expression);
                continue;
            }
            CollectReturns(child, result);
        }
    }

    // The whole member that declares a local or parameter, including nested
    // lambdas, so assignments captured by closures are not missed.
    private static SyntaxNode? MemberBody(SyntaxNode declaration)
    {
        for (var current = declaration; current is not null; current = current.Parent)
        {
            if (current is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax or PropertyDeclarationSyntax
                or IndexerDeclarationSyntax or CompilationUnitSyntax)
            {
                return current;
            }
            if (current is LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax)
            {
                // Parameters of lambdas and local functions are scoped to them.
                if (declaration is ParameterSyntax)
                {
                    return current;
                }
            }
        }
        return null;
    }

    private static ValueNode Node(
        string kind,
        IOperation operation,
        string? symbol = null,
        string? detail = null,
        IReadOnlyList<ValueNode>? children = null,
        IReadOnlyDictionary<string, string>? facts = null) =>
        new(kind, Text(operation), Symbols.SpanOf(operation.Syntax), symbol, detail,
            children is { Count: > 0 } ? children : null, facts);

    private static ValueNode Node(string kind, SyntaxNode syntax, string? detail = null) =>
        new(kind, Truncate(syntax.ToString()), Symbols.SpanOf(syntax), Detail: detail);

    private static IReadOnlyDictionary<string, string> Facts(params (string Key, string Value)[] pairs) =>
        pairs.Where(p => p.Value.Length > 0).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);

    private static string Text(IOperation operation) => Truncate(operation.Syntax.ToString());

    private static string Location(IOperation operation)
    {
        var span = Symbols.SpanOf(operation.Syntax);
        return $"{span.Path}:{span.StartLine}";
    }

    private static string Truncate(string text)
    {
        var single = text.ReplaceLineEndings(" ");
        return single.Length <= MaxTextLength ? single : single[..(MaxTextLength - 3)] + "...";
    }

    private static string Preview(object? value) => value switch
    {
        null => "null",
        string s => Truncate("\"" + s + "\""),
        _ => Truncate(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? ""),
    };
}
