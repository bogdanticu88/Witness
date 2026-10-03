using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

// Finds conditions that structurally control whether a sink runs and that
// test a value flowing into it. The helper only reports what it sees:
// which predicate, on which variable, with what truth value at the sink, and
// whether the variable is reassigned in between. Whether a guard actually
// mitigates the vulnerability is decided by the orchestrator, per class.
//
// Recognized control shapes: the sink inside an if/else branch, a ternary
// branch, the right side of && or ||, and an earlier `if (cond) <exit>;`
// in an enclosing block. Loops, gotos, exceptions used for control flow and
// guards in callers are not modelled here.
internal static class GuardFinder
{
    private const int MaxSubjectExpansion = 6;

    public static List<GuardDto> Find(SyntaxNode sink, IOperation argument, SemanticModel model)
    {
        var subjects = CollectSubjects(argument, model);
        var guards = new List<GuardDto>();
        if (subjects.Count == 0)
        {
            return guards;
        }

        var body = Symbols.EnclosingBody(sink);
        var argumentSubject = ReferencedSymbol(Unwrap(argument));

        foreach (var (condition, truth) in ControllingConditions(sink, body))
        {
            foreach (var (leaf, holds) in Decompose(condition, truth))
            {
                var guard = Classify(leaf, model, subjects);
                if (guard is null)
                {
                    continue;
                }
                var subject = subjects[guard.Value.SubjectId];
                guards.Add(new GuardDto(
                    guard.Value.Kind,
                    guard.Value.SubjectId,
                    subject.Name,
                    holds,
                    ReassignedBetween(subject, condition.Span.End, sink.SpanStart, body, model),
                    argumentSubject is not null && Symbols.Id(argumentSubject) == guard.Value.SubjectId,
                    Symbols.SpanOf(leaf),
                    leaf.ToString().ReplaceLineEndings(" "),
                    guard.Value.Facts));
            }
        }
        return guards;
    }

    // Locals and parameters whose value reaches the sink argument within this
    // member, following local assignments a few steps back.
    private static Dictionary<string, ISymbol> CollectSubjects(IOperation argument, SemanticModel model)
    {
        var subjects = new Dictionary<string, ISymbol>(StringComparer.Ordinal);
        var pending = new Queue<(IOperation Operation, int Depth)>();
        pending.Enqueue((argument, 0));
        while (pending.Count > 0)
        {
            var (operation, depth) = pending.Dequeue();
            foreach (var node in operation.DescendantsAndSelf())
            {
                var symbol = ReferencedSymbol(node);
                if (symbol is null || !subjects.TryAdd(Symbols.Id(symbol), symbol) || depth >= MaxSubjectExpansion)
                {
                    continue;
                }
                if (symbol is ILocalSymbol local && local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is VariableDeclaratorSyntax { Initializer: { } init }
                    && model.SyntaxTree == init.SyntaxTree && model.GetOperation(init.Value) is { } initOp)
                {
                    pending.Enqueue((initOp, depth + 1));
                }
            }
        }
        return subjects;
    }

    private static IEnumerable<(ExpressionSyntax Condition, bool Truth)> ControllingConditions(SyntaxNode sink, SyntaxNode? body)
    {
        for (var node = sink; node.Parent is not null && node != body; node = node.Parent)
        {
            switch (node.Parent)
            {
                case IfStatementSyntax ifStatement when ifStatement.Statement == node:
                    yield return (ifStatement.Condition, true);
                    break;
                case ElseClauseSyntax { Parent: IfStatementSyntax owner } when node.Parent is ElseClauseSyntax:
                    yield return (owner.Condition, false);
                    break;
                case ConditionalExpressionSyntax conditional when conditional.WhenTrue == node:
                    yield return (conditional.Condition, true);
                    break;
                case ConditionalExpressionSyntax conditional when conditional.WhenFalse == node:
                    yield return (conditional.Condition, false);
                    break;
                case BinaryExpressionSyntax binary when binary.Right == node && binary.IsKind(SyntaxKind.LogicalAndExpression):
                    yield return (binary.Left, true);
                    break;
                case BinaryExpressionSyntax binary when binary.Right == node && binary.IsKind(SyntaxKind.LogicalOrExpression):
                    yield return (binary.Left, false);
                    break;
                case BlockSyntax block:
                    foreach (var statement in block.Statements.TakeWhile(s => s != node))
                    {
                        if (statement is IfStatementSyntax { Else: null } early && AlwaysExits(early.Statement))
                        {
                            yield return (early.Condition, false);
                        }
                    }
                    break;
                case SwitchSectionSyntax section:
                    foreach (var statement in section.Statements.TakeWhile(s => s != node))
                    {
                        if (statement is IfStatementSyntax { Else: null } early && AlwaysExits(early.Statement))
                        {
                            yield return (early.Condition, false);
                        }
                    }
                    break;
            }
            if (node is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax)
            {
                // Conditions outside a lambda do not control when it runs.
                yield break;
            }
        }
    }

    private static bool AlwaysExits(StatementSyntax statement) => statement switch
    {
        ReturnStatementSyntax or ThrowStatementSyntax or ContinueStatementSyntax or BreakStatementSyntax or GotoStatementSyntax => true,
        ExpressionStatementSyntax { Expression: ThrowExpressionSyntax } => true,
        BlockSyntax block => block.Statements.Count > 0 && AlwaysExits(block.Statements[^1]),
        IfStatementSyntax { Else: { } otherwise } nested => AlwaysExits(nested.Statement) && AlwaysExits(otherwise.Statement),
        _ => false,
    };

    // Splits a condition with a required truth value into leaf predicates.
    // "unknown" means the leaf may be either value when the sink runs.
    private static IEnumerable<(ExpressionSyntax Leaf, string Holds)> Decompose(ExpressionSyntax condition, bool truth)
    {
        return Walk(condition, truth ? "true" : "false");

        static IEnumerable<(ExpressionSyntax, string)> Walk(ExpressionSyntax expression, string required)
        {
            switch (expression)
            {
                case ParenthesizedExpressionSyntax parenthesized:
                    return Walk(parenthesized.Expression, required);
                case PrefixUnaryExpressionSyntax prefix when prefix.IsKind(SyntaxKind.LogicalNotExpression):
                    return Walk(prefix.Operand, Flip(required));
                case BinaryExpressionSyntax binary when binary.IsKind(SyntaxKind.LogicalAndExpression):
                    var andRequired = required == "true" ? "true" : "unknown";
                    return Walk(binary.Left, andRequired).Concat(Walk(binary.Right, andRequired));
                case BinaryExpressionSyntax binary when binary.IsKind(SyntaxKind.LogicalOrExpression):
                    var orRequired = required == "false" ? "false" : "unknown";
                    return Walk(binary.Left, orRequired).Concat(Walk(binary.Right, orRequired));
                case BinaryExpressionSyntax binary when binary.IsKind(SyntaxKind.EqualsExpression) && IsBoolLiteral(binary.Right, out var value):
                    return Walk(binary.Left, value ? required : Flip(required));
                case BinaryExpressionSyntax binary when binary.IsKind(SyntaxKind.NotEqualsExpression) && IsBoolLiteral(binary.Right, out var notValue):
                    return Walk(binary.Left, notValue ? Flip(required) : required);
                case IsPatternExpressionSyntax { Pattern: ConstantPatternSyntax { Expression: LiteralExpressionSyntax literal } } pattern
                    when literal.IsKind(SyntaxKind.TrueLiteralExpression) || literal.IsKind(SyntaxKind.FalseLiteralExpression):
                    return Walk(pattern.Expression, literal.IsKind(SyntaxKind.TrueLiteralExpression) ? required : Flip(required));
                default:
                    return [(expression, required)];
            }
        }

        static string Flip(string value) => value switch
        {
            "true" => "false",
            "false" => "true",
            _ => "unknown",
        };

        static bool IsBoolLiteral(ExpressionSyntax expression, out bool value)
        {
            value = expression.IsKind(SyntaxKind.TrueLiteralExpression);
            return value || expression.IsKind(SyntaxKind.FalseLiteralExpression);
        }
    }

    private readonly record struct Classified(string Kind, string SubjectId, IReadOnlyDictionary<string, string>? Facts);

    private static Classified? Classify(ExpressionSyntax leaf, SemanticModel model, Dictionary<string, ISymbol> subjects)
    {
        var operation = model.GetOperation(leaf);
        if (operation is IInvocationOperation invocation)
        {
            var method = invocation.TargetMethod.ReducedFrom ?? invocation.TargetMethod;
            var type = Symbols.FullName(method.ContainingType);
            var instance = invocation.Instance is null ? null : ReferencedSymbol(Unwrap(invocation.Instance));
            var arguments = invocation.Arguments.Select(a => ReferencedSymbol(Unwrap(a.Value))).ToList();

            if (method.Name == "IsLocalUrl"
                && (Symbols.Implements(method.ContainingType, "Microsoft.AspNetCore.Mvc.IUrlHelper")
                    || type is "Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult" or "Microsoft.AspNetCore.Mvc.UrlHelperExtensions"))
            {
                var argument = invocation.Arguments.FirstOrDefault(a => a.Parameter?.Type.SpecialType == SpecialType.System_String);
                var subject = argument is null ? null : ReferencedSymbol(Unwrap(argument.Value));
                return Subject(subject, subjects, "is_local_url", null);
            }

            if (type == "System.String" && instance is not null)
            {
                switch (method.Name)
                {
                    case "StartsWith":
                        return Subject(instance, subjects, "starts_with", StartsWithFacts(invocation, instance, model));
                    case "Contains" or "EndsWith" or "IndexOf" or "Equals":
                        return Subject(instance, subjects, "string_" + method.Name.ToLowerInvariant(),
                            Facts(("argument", invocation.Arguments.FirstOrDefault()?.Value.Syntax.ToString() ?? "")));
                }
            }
            if (type == "System.String" && method.Name is "IsNullOrEmpty" or "IsNullOrWhiteSpace")
            {
                return Subject(arguments.FirstOrDefault(), subjects, "null_or_empty_check", null);
            }
            if (type == "System.IO.Path" && method.Name is "IsPathRooted" or "IsPathFullyQualified")
            {
                return Subject(arguments.FirstOrDefault(), subjects, "rooted_check", null);
            }
            if (type == "System.Text.RegularExpressions.Regex" && method.Name == "IsMatch")
            {
                var subject = instance ?? arguments.FirstOrDefault();
                return Subject(subject, subjects, "regex_check", null);
            }

            // Any other predicate that takes a subject: a custom validator the
            // helper cannot interpret.
            foreach (var candidate in arguments.Append(instance))
            {
                if (candidate is not null && subjects.ContainsKey(Symbols.Id(candidate)))
                {
                    return new Classified("unknown_check", Symbols.Id(candidate), Facts(
                        ("callee", Symbols.Id(method)),
                        ("declared_in_source", Symbols.IsDeclaredInSource(method) ? "true" : "false")));
                }
            }
            return null;
        }

        if (operation is null)
        {
            return null;
        }
        foreach (var node in operation.DescendantsAndSelf())
        {
            var symbol = ReferencedSymbol(node);
            if (symbol is not null && subjects.ContainsKey(Symbols.Id(symbol)))
            {
                return new Classified("unknown_condition", Symbols.Id(symbol), null);
            }
        }
        return null;
    }

    private static Classified? Subject(ISymbol? subject, Dictionary<string, ISymbol> subjects, string kind, IReadOnlyDictionary<string, string>? facts) =>
        subject is not null && subjects.ContainsKey(Symbols.Id(subject))
            ? new Classified(kind, Symbols.Id(subject), facts)
            : null;

    private static IReadOnlyDictionary<string, string> StartsWithFacts(IInvocationOperation invocation, ISymbol subject, SemanticModel model)
    {
        var prefix = invocation.Arguments.FirstOrDefault(a => a.Parameter?.Ordinal == 0)?.Value;
        var comparison = invocation.Arguments.FirstOrDefault(a => Symbols.FullName(a.Parameter?.Type) == "System.StringComparison")?.Value;
        return Facts(
            ("prefix", prefix?.Syntax.ToString() ?? ""),
            ("prefix_ends_with_separator", prefix is null ? "unknown" : EndsWithSeparator(prefix, model, 0)),
            ("comparison", comparison?.Syntax.ToString() ?? "culture_sensitive_default"),
            ("subject_from_get_full_path", FromGetFullPath(subject, model)));
    }

    private static string EndsWithSeparator(IOperation operation, SemanticModel model, int depth)
    {
        operation = Unwrap(operation);
        if (operation.ConstantValue.HasValue)
        {
            var text = Convert.ToString(operation.ConstantValue.Value, System.Globalization.CultureInfo.InvariantCulture) ?? "";
            return text.EndsWith('/') || text.EndsWith('\\') ? "true" : "false";
        }
        switch (operation)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } binary:
                return EndsWithSeparator(binary.RightOperand, model, depth + 1);
            case IFieldReferenceOperation field when Symbols.FullName(field.Field.ContainingType) == "System.IO.Path"
                && field.Field.Name is "DirectorySeparatorChar" or "AltDirectorySeparatorChar":
                return "true";
            case IInterpolatedStringOperation interpolated when interpolated.Parts.LastOrDefault() is { } last:
                return last switch
                {
                    IInterpolatedStringTextOperation text => EndsWithSeparator(text.Text, model, depth + 1),
                    IInterpolationOperation hole => EndsWithSeparator(hole.Expression, model, depth + 1),
                    _ => "unknown",
                };
            case ILocalReferenceOperation local when depth < 3
                && local.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is VariableDeclaratorSyntax { Initializer: { } init }
                && init.SyntaxTree == model.SyntaxTree
                && !HasOtherAssignments(local.Local, model)
                && model.GetOperation(init.Value) is { } initOp:
                return EndsWithSeparator(initOp, model, depth + 1);
            default:
                return "unknown";
        }
    }

    private static string FromGetFullPath(ISymbol subject, SemanticModel model)
    {
        if (subject is not ILocalSymbol local
            || local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax { Initializer: { } init }
            || init.SyntaxTree != model.SyntaxTree)
        {
            return "unknown";
        }
        if (HasOtherAssignments(local, model))
        {
            return "reassigned";
        }
        return model.GetOperation(init.Value) is { } op && Unwrap(op) is IInvocationOperation call
            && Symbols.FullName(call.TargetMethod.ContainingType) == "System.IO.Path" && call.TargetMethod.Name == "GetFullPath"
            ? "true"
            : "false";
    }

    private static bool HasOtherAssignments(ILocalSymbol local, SemanticModel model)
    {
        var body = local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is { } declaration ? Symbols.EnclosingBody(declaration) : null;
        if (body is null)
        {
            return true;
        }
        return body.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Any(a => SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(a.Left).Symbol, local))
            || body.DescendantNodes().OfType<ArgumentSyntax>()
                .Any(a => !a.RefKindKeyword.IsKind(SyntaxKind.None) && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(a.Expression).Symbol, local));
    }

    private static bool ReassignedBetween(ISymbol subject, int afterPosition, int beforePosition, SyntaxNode? body, SemanticModel model)
    {
        if (body is null)
        {
            return true;
        }
        foreach (var node in body.DescendantNodes())
        {
            if (node.SpanStart <= afterPosition || node.SpanStart >= beforePosition)
            {
                continue;
            }
            var target = node switch
            {
                AssignmentExpressionSyntax assignment => assignment.Left,
                ArgumentSyntax argument when !argument.RefKindKeyword.IsKind(SyntaxKind.None) => argument.Expression,
                PrefixUnaryExpressionSyntax { RawKind: (int)SyntaxKind.PreIncrementExpression or (int)SyntaxKind.PreDecrementExpression } prefix => prefix.Operand,
                PostfixUnaryExpressionSyntax postfix => postfix.Operand,
                _ => null,
            };
            if (target is not null && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(target).Symbol?.OriginalDefinition, subject.OriginalDefinition))
            {
                return true;
            }
        }
        return false;
    }

    private static IOperation Unwrap(IOperation operation)
    {
        while (operation is IConversionOperation conversion)
        {
            operation = conversion.Operand;
        }
        return operation;
    }

    private static ISymbol? ReferencedSymbol(IOperation operation) => operation switch
    {
        ILocalReferenceOperation local => local.Local,
        IParameterReferenceOperation parameter => parameter.Parameter,
        _ => null,
    };

    private static IReadOnlyDictionary<string, string> Facts(params (string Key, string Value)[] pairs) =>
        pairs.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
}
