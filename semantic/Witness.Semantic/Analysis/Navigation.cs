using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

internal static class Navigation
{
    private const int MaxReferences = 500;

    public static ISymbol Resolve(AnalysisWorkspace workspace, string id)
    {
        if (id.StartsWith("lambda:", StringComparison.Ordinal) || id.StartsWith("local:", StringComparison.Ordinal))
        {
            return ResolveByLocation(workspace, id);
        }
        foreach (var project in workspace.Projects)
        {
            var symbol = DocumentationCommentId.GetFirstSymbolForDeclarationId(id, project.Compilation);
            if (symbol is not null && Symbols.IsDeclaredInSource(symbol))
            {
                return symbol;
            }
        }
        foreach (var project in workspace.Projects)
        {
            var symbol = DocumentationCommentId.GetFirstSymbolForDeclarationId(id, project.Compilation);
            if (symbol is not null)
            {
                return symbol;
            }
        }
        throw new ProtocolException("unknown_symbol", $"symbol not found: {id}");
    }

    // "lambda:path:line:col" ids point at the start of the declaration.
    private static ISymbol ResolveByLocation(AnalysisWorkspace workspace, string id)
    {
        var parts = id.Split(':');
        if (parts.Length < 4 || !int.TryParse(parts[^2], out var line) || !int.TryParse(parts[^1], out var column))
        {
            throw new ProtocolException("bad_symbol_id", $"malformed symbol id: {id}");
        }
        var path = string.Join(':', parts[1..^2]);
        if (!workspace.TryGetDocument(path, out _, out var tree))
        {
            throw new ProtocolException("unknown_document", $"{path} is not part of the loaded workspace");
        }
        var model = workspace.Model(tree);
        var position = tree.GetText().Lines[line - 1].Start + column - 1;
        foreach (var node in tree.GetRoot().FindToken(position).Parent!.AncestorsAndSelf())
        {
            var symbol = node switch
            {
                AnonymousFunctionExpressionSyntax lambda => model.GetSymbolInfo(lambda).Symbol,
                LocalFunctionStatementSyntax local => model.GetDeclaredSymbol(local),
                _ => null,
            };
            if (symbol is not null)
            {
                return symbol;
            }
        }
        throw new ProtocolException("unknown_symbol", $"symbol not found: {id}");
    }

    public static List<MemberDto> Members(AnalysisWorkspace workspace, string path)
    {
        if (!workspace.TryGetDocument(path, out _, out var tree))
        {
            throw new ProtocolException("unknown_document", $"{path} is not part of the loaded workspace");
        }
        var model = workspace.Model(tree);
        var members = new List<MemberDto>();
        foreach (var node in tree.GetRoot().DescendantNodes())
        {
            ISymbol? symbol = node switch
            {
                BaseTypeDeclarationSyntax type => model.GetDeclaredSymbol(type),
                BaseMethodDeclarationSyntax method => model.GetDeclaredSymbol(method),
                PropertyDeclarationSyntax property => model.GetDeclaredSymbol(property),
                IndexerDeclarationSyntax indexer => model.GetDeclaredSymbol(indexer),
                FieldDeclarationSyntax field => field.Declaration.Variables.Select(v => model.GetDeclaredSymbol(v)).FirstOrDefault(),
                EventDeclarationSyntax e => model.GetDeclaredSymbol(e),
                _ => null,
            };
            if (symbol is not null)
            {
                members.Add(new MemberDto(Symbols.Describe(symbol), Symbols.SpanOf(node)));
            }
        }
        if (tree.GetRoot() is CompilationUnitSyntax unit && unit.Members.OfType<GlobalStatementSyntax>().FirstOrDefault() is { } first
            && model.GetEnclosingSymbol(first.SpanStart) is { } main)
        {
            var statements = unit.Members.OfType<GlobalStatementSyntax>().ToList();
            var span = Symbols.SpanOf(first) with { EndLine = Symbols.SpanOf(statements[^1]).EndLine };
            members.Add(new MemberDto(Symbols.Describe(main), span));
        }
        return members;
    }

    public static MemberDto? SymbolAt(AnalysisWorkspace workspace, string path, int line)
    {
        return Members(workspace, path)
            .Where(m => m.Span.StartLine <= line && m.Span.EndLine >= line && m.Symbol.Kind != "NamedType")
            .OrderBy(m => m.Span.EndLine - m.Span.StartLine)
            .FirstOrDefault();
    }

    public static List<CalleeDto> Callees(AnalysisWorkspace workspace, ISymbol member)
    {
        var result = new List<CalleeDto>();
        foreach (var syntax in member.DeclaringSyntaxReferences.Select(r => r.GetSyntax()))
        {
            var model = workspace.Model(syntax.SyntaxTree);
            foreach (var node in syntax.DescendantNodes())
            {
                if (node is not (InvocationExpressionSyntax or BaseObjectCreationExpressionSyntax))
                {
                    continue;
                }
                var target = model.GetOperation(node) switch
                {
                    IInvocationOperation invocation => invocation.TargetMethod,
                    IObjectCreationOperation creation => creation.Constructor,
                    _ => null,
                };
                if (target is null)
                {
                    result.Add(new CalleeDto("unresolved:" + Truncate(node.ToString()), Truncate(node.ToString()), Resolution.UnresolvedCandidate, Symbols.SpanOf(node), null));
                    continue;
                }
                var original = target.ReducedFrom ?? target;
                result.Add(new CalleeDto(
                    Symbols.Id(original),
                    original.ToDisplayString(),
                    Resolution.Resolved,
                    Symbols.SpanOf(node),
                    Symbols.IsDeclaredInSource(original) ? Symbols.SpanOf(original.Locations.First())?.Path : null));
            }
        }
        return result;
    }

    // Files and source symbols a member's meaning depends on. Used by the
    // orchestrator to decide which edits invalidate a cached assessment.
    public static DependenciesDto Dependencies(AnalysisWorkspace workspace, ISymbol member)
    {
        var files = new SortedSet<string>(StringComparer.Ordinal);
        var symbols = new SortedSet<string>(StringComparer.Ordinal);
        var unresolved = 0;
        foreach (var syntax in member.DeclaringSyntaxReferences.Select(r => r.GetSyntax()))
        {
            files.Add(syntax.SyntaxTree.FilePath);
            var model = workspace.Model(syntax.SyntaxTree);
            foreach (var name in syntax.DescendantNodes().OfType<SimpleNameSyntax>())
            {
                var info = model.GetSymbolInfo(name);
                var symbol = info.Symbol ?? info.CandidateSymbols.FirstOrDefault();
                if (symbol is null)
                {
                    if (model.GetTypeInfo(name).Type is null or IErrorTypeSymbol)
                    {
                        unresolved++;
                    }
                    continue;
                }
                if (symbol is ILocalSymbol or IParameterSymbol or IRangeVariableSymbol or ILabelSymbol)
                {
                    continue;
                }
                var original = symbol.OriginalDefinition;
                if (!Symbols.IsDeclaredInSource(original))
                {
                    continue;
                }
                symbols.Add(Symbols.Id(original));
                foreach (var location in original.Locations.Where(l => l.IsInSource))
                {
                    files.Add(location.SourceTree!.FilePath);
                }
                // A type's members can change meaning (for example a new
                // overload), so depend on every file declaring the type too.
                foreach (var location in original.ContainingType?.Locations.Where(l => l.IsInSource) ?? [])
                {
                    files.Add(location.SourceTree!.FilePath);
                }
            }
        }
        return new DependenciesDto(Symbols.Id(member), files.ToList(), symbols.ToList(), unresolved);
    }

    public static List<Span> References(AnalysisWorkspace workspace, ISymbol target)
    {
        var id = Symbols.Id(target);
        var result = new List<Span>();
        foreach (var (_, project, tree) in workspace.Documents)
        {
            var model = project.Compilation.GetSemanticModel(tree);
            foreach (var name in tree.GetRoot().DescendantNodes().OfType<SimpleNameSyntax>())
            {
                if (name.Identifier.ValueText != target.Name)
                {
                    continue;
                }
                var symbol = model.GetSymbolInfo(name).Symbol;
                if (symbol is not null && Symbols.Id(symbol.OriginalDefinition) == id)
                {
                    result.Add(Symbols.SpanOf(name));
                    if (result.Count >= MaxReferences)
                    {
                        return result;
                    }
                }
            }
        }
        return result;
    }

    private static string Truncate(string text)
    {
        var single = text.ReplaceLineEndings(" ");
        return single.Length <= 120 ? single : single[..117] + "...";
    }
}
