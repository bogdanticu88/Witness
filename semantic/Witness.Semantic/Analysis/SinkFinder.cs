using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

internal sealed record FoundSite(SiteDto Dto, SyntaxNode Node, IOperation? Argument, SemanticModel Model);

internal sealed record SafeApiHit(string Description, Span Location);

// Locates sink call sites. Site ids are stable across edits that do not
// change the containing member's signature, the sink, or the order of sink
// calls inside the member: sha256(containing id | sink id | ordinal).
internal static class SinkFinder
{
    public static List<FoundSite> Find(AnalysisWorkspace workspace, IReadOnlySet<string> classes, IReadOnlySet<string>? paths)
    {
        var found = new List<FoundSite>();
        foreach (var (path, project, tree) in workspace.Documents.OrderBy(d => d.Path, StringComparer.Ordinal))
        {
            if (paths is not null && !paths.Contains(path))
            {
                continue;
            }
            var model = project.Compilation.GetSemanticModel(tree);
            found.AddRange(FindInTree(tree, model, classes));
        }
        return found;
    }

    public static (List<FoundSite> Sites, List<SafeApiHit> SafeApis) FindAt(
        AnalysisWorkspace workspace, string path, int startLine, int endLine, IReadOnlySet<string> classes)
    {
        if (!workspace.TryGetDocument(path, out var project, out var tree))
        {
            throw new ProtocolException("unknown_document", $"{path} is not part of the loaded workspace");
        }
        var model = project.Compilation.GetSemanticModel(tree);
        var sites = FindInTree(tree, model, classes)
            .Where(s => Overlaps(Symbols.SpanOf(s.Node), startLine, endLine))
            .ToList();

        var safe = new List<SafeApiHit>();
        foreach (var node in tree.GetRoot().DescendantNodes())
        {
            if (node is not (InvocationExpressionSyntax or BaseObjectCreationExpressionSyntax) || !Overlaps(Symbols.SpanOf(node), startLine, endLine))
            {
                continue;
            }
            var method = model.GetOperation(node) switch
            {
                IInvocationOperation invocation => invocation.TargetMethod,
                IObjectCreationOperation creation => creation.Constructor,
                _ => null,
            };
            if (method is not null && Catalog.SafeApi(method) is { } description)
            {
                safe.Add(new SafeApiHit(description, Symbols.SpanOf(node)));
            }
        }
        return (sites, safe);
    }

    private static bool Overlaps(Span span, int startLine, int endLine) =>
        span.StartLine <= endLine && span.EndLine >= startLine;

    private static IEnumerable<FoundSite> FindInTree(SyntaxTree tree, SemanticModel model, IReadOnlySet<string> classes)
    {
        var raw = new List<(SyntaxNode Node, SinkMatch Match, string SinkId, string SinkDisplay, Resolution Resolution, IOperation? Argument)>();
        foreach (var node in tree.GetRoot().DescendantNodes())
        {
            switch (node)
            {
                case InvocationExpressionSyntax invocation:
                    Collect(invocation, model, raw);
                    break;
                case BaseObjectCreationExpressionSyntax creation:
                    Collect(creation, model, raw);
                    break;
                case AssignmentExpressionSyntax assignment:
                    CollectAssignment(assignment, model, raw);
                    break;
            }
        }

        // Number sites per (containing member, sink) in source order.
        var ordinals = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var item in raw.Where(r => classes.Contains(r.Match.VulnClass)).OrderBy(r => r.Node.SpanStart))
        {
            var containing = Symbols.EnclosingMember(model, item.Node);
            var containingId = containing is null ? tree.FilePath : Symbols.Id(containing);
            var key = containingId + "|" + item.SinkId;
            var ordinal = ordinals.GetValueOrDefault(key);
            ordinals[key] = ordinal + 1;

            var siteId = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{key}|{ordinal}")))[..16];
            var argumentSyntax = item.Argument?.Syntax ?? item.Node;
            yield return new FoundSite(
                new SiteDto(
                    siteId,
                    item.Match.VulnClass,
                    new SinkDto(item.SinkId, item.SinkDisplay, item.Resolution, item.Match.Role, item.Match.ParameterOrdinal, item.Match.Note),
                    Symbols.SpanOf(item.Node),
                    containing is null ? null : Symbols.Describe(containing),
                    ordinal,
                    argumentSyntax.ToString().ReplaceLineEndings(" ")),
                item.Node,
                item.Argument,
                model);
        }
    }

    private static void Collect(
        ExpressionSyntax node,
        SemanticModel model,
        List<(SyntaxNode, SinkMatch, string, string, Resolution, IOperation?)> raw)
    {
        var operation = model.GetOperation(node);
        IMethodSymbol? method = null;
        IReadOnlyList<IArgumentOperation> arguments = [];
        switch (operation)
        {
            case IInvocationOperation invocation:
                method = invocation.TargetMethod;
                arguments = invocation.Arguments;
                break;
            case IObjectCreationOperation { Constructor: { } ctor } creation:
                method = ctor;
                arguments = creation.Arguments;
                break;
        }

        if (method is not null)
        {
            var match = Catalog.MatchMethod(method);
            if (match is null)
            {
                return;
            }
            var argument = arguments.FirstOrDefault(a => a.Parameter?.Ordinal == match.ParameterOrdinal)?.Value;
            if (argument is null || argument.IsImplicit && argument is IDefaultValueOperation)
            {
                return;
            }
            var original = method.ReducedFrom ?? method;
            raw.Add((node, match, Symbols.Id(original), original.ToDisplayString(), Resolution.Resolved, argument));
            return;
        }

        // Roslyn could not bind the call, usually because a package is not
        // available. Report a candidate when the name matches, with the first
        // argument, and never claim it is the catalogued API.
        var (name, isConstruction, typeName, argumentList) = node switch
        {
            InvocationExpressionSyntax invocation => (
                invocation.Expression switch
                {
                    MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
                    SimpleNameSyntax simple => simple.Identifier.ValueText,
                    _ => null,
                },
                false,
                (string?)null,
                invocation.ArgumentList),
            ObjectCreationExpressionSyntax creation => (null, true, creation.Type.ToString(), creation.ArgumentList),
            _ => (null, false, null, null),
        };
        var candidate = Catalog.UnresolvedCandidateClass(name ?? "", isConstruction, typeName);
        if (candidate is null || argumentList is null || argumentList.Arguments.Count == 0)
        {
            return;
        }
        var first = model.GetOperation(argumentList.Arguments[0].Expression);
        raw.Add((
            node,
            new SinkMatch(candidate, "unresolved", 0, "symbol unresolved; matched by name only, first argument assumed"),
            "unresolved:" + (name ?? typeName),
            node.ToString().ReplaceLineEndings(" "),
            Resolution.UnresolvedCandidate,
            first));
    }

    private static void CollectAssignment(
        AssignmentExpressionSyntax assignment,
        SemanticModel model,
        List<(SyntaxNode, SinkMatch, string, string, Resolution, IOperation?)> raw)
    {
        if (model.GetOperation(assignment) is not IAssignmentOperation operation)
        {
            return;
        }
        if (operation.Target is IPropertyReferenceOperation property)
        {
            var index = property.Arguments.FirstOrDefault()?.Value.ConstantValue;
            var match = Catalog.MatchPropertySet(property.Property, index is { HasValue: true } ? index.Value.Value as string : null);
            if (match is not null)
            {
                raw.Add((assignment, match, Symbols.Id(property.Property.OriginalDefinition), property.Property.ToDisplayString(), Resolution.Resolved, operation.Value));
            }
            return;
        }
        if (operation.Target is IInvalidOperation && assignment.Left is MemberAccessExpressionSyntax { Name.Identifier.ValueText: "CommandText" })
        {
            raw.Add((
                assignment,
                new SinkMatch(VulnClasses.Sql, "unresolved", -1, "receiver type unresolved; matched by property name only"),
                "unresolved:CommandText",
                assignment.Left.ToString(),
                Resolution.UnresolvedCandidate,
                operation.Value));
        }
    }
}
