using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Analysis;

internal static class Symbols
{
    private static readonly SymbolDisplayFormat QualifiedFormat = new(
        typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
        genericsOptions: SymbolDisplayGenericsOptions.None);

    // Types whose values cannot carry an injection payload into a string
    // context. char is deliberately excluded: a single quote is a char.
    private static readonly HashSet<SpecialType> SafeSpecialTypes =
    [
        SpecialType.System_Boolean, SpecialType.System_Byte, SpecialType.System_SByte,
        SpecialType.System_Int16, SpecialType.System_UInt16, SpecialType.System_Int32,
        SpecialType.System_UInt32, SpecialType.System_Int64, SpecialType.System_UInt64,
        SpecialType.System_Decimal, SpecialType.System_Single, SpecialType.System_Double,
        SpecialType.System_DateTime,
    ];

    private static readonly HashSet<string> SafeNamedTypes =
    [
        "System.Guid", "System.DateTimeOffset", "System.TimeSpan", "System.DateOnly", "System.TimeOnly",
        "System.Int128", "System.UInt128",
    ];

    public static string FullName(ITypeSymbol? type) =>
        type is null ? "" : type.OriginalDefinition.ToDisplayString(QualifiedFormat);

    public static string Id(ISymbol symbol)
    {
        var original = symbol.OriginalDefinition;
        if (original is IMethodSymbol { MethodKind: MethodKind.AnonymousFunction or MethodKind.LocalFunction } method)
        {
            var location = method.Locations.FirstOrDefault();
            var span = location?.GetLineSpan();
            var prefix = method.MethodKind == MethodKind.LocalFunction ? "local" : "lambda";
            return $"{prefix}:{span?.Path}:{(span?.StartLinePosition.Line ?? 0) + 1}:{(span?.StartLinePosition.Character ?? 0) + 1}";
        }
        if (original is ILocalSymbol or IParameterSymbol)
        {
            var location = original.Locations.FirstOrDefault()?.GetLineSpan();
            return $"{original.Kind.ToString().ToLowerInvariant()}:{original.Name}@{location?.Path}:{(location?.StartLinePosition.Line ?? 0) + 1}";
        }
        return original.GetDocumentationCommentId() ?? original.ToDisplayString();
    }

    public static bool IsSafeType(ITypeSymbol? type)
    {
        if (type is null)
        {
            return false;
        }
        if (type is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T } nullable)
        {
            type = nullable.TypeArguments[0];
        }
        return SafeSpecialTypes.Contains(type.SpecialType)
            || type.TypeKind == TypeKind.Enum
            || SafeNamedTypes.Contains(FullName(type));
    }

    public static bool InheritsFrom(ITypeSymbol? type, string fullName)
    {
        for (var t = type; t is not null; t = t.BaseType)
        {
            if (FullName(t) == fullName)
            {
                return true;
            }
        }
        return false;
    }

    public static bool Implements(ITypeSymbol? type, string interfaceName) =>
        type is not null
        && (FullName(type) == interfaceName || type.AllInterfaces.Any(i => FullName(i) == interfaceName));

    public static bool IsDeclaredInSource(ISymbol symbol) =>
        symbol.DeclaringSyntaxReferences.Length > 0 && symbol.Locations.Any(l => l.IsInSource);

    public static Span? SpanOf(Location? location)
    {
        if (location is null || !location.IsInSource)
        {
            return null;
        }
        var span = location.GetLineSpan();
        return new Span(
            span.Path,
            span.StartLinePosition.Line + 1,
            span.EndLinePosition.Line + 1,
            span.StartLinePosition.Character + 1,
            span.EndLinePosition.Character + 1);
    }

    public static Span SpanOf(SyntaxNode node) => SpanOf(node.GetLocation())!;

    public static SymbolInfoDto Describe(ISymbol symbol)
    {
        var syntax = symbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
        Span? span = syntax is not null ? SpanOf(syntax) : SpanOf(symbol.Locations.FirstOrDefault());
        return new SymbolInfoDto(
            Id(symbol),
            symbol.ToDisplayString(SymbolDisplayFormat.CSharpShortErrorMessageFormat),
            symbol.Kind == SymbolKind.Method ? ((IMethodSymbol)symbol).MethodKind.ToString() : symbol.Kind.ToString(),
            span,
            symbol.DeclaredAccessibility.ToString().ToLowerInvariant());
    }

    // The member (method, accessor, constructor, property) whose body holds
    // the node. Lambdas are skipped so callers see the enclosing member.
    public static ISymbol? EnclosingMember(SemanticModel model, SyntaxNode node)
    {
        for (var current = node; current is not null; current = current.Parent)
        {
            switch (current)
            {
                case BaseMethodDeclarationSyntax or LocalFunctionStatementSyntax or AccessorDeclarationSyntax
                    or PropertyDeclarationSyntax or IndexerDeclarationSyntax:
                    return model.GetDeclaredSymbol(current);
                case GlobalStatementSyntax global:
                    // Top-level statements: report the synthesized entry point
                    // rather than a lambda, so ids survive line shifts.
                    return model.GetEnclosingSymbol(global.SpanStart);
            }
        }
        return null;
    }

    public static SyntaxNode? EnclosingBody(SyntaxNode node)
    {
        for (var current = node; current is not null; current = current.Parent)
        {
            if (current is BaseMethodDeclarationSyntax or LocalFunctionStatementSyntax or AccessorDeclarationSyntax
                or AnonymousFunctionExpressionSyntax or PropertyDeclarationSyntax or CompilationUnitSyntax)
            {
                return current;
            }
        }
        return null;
    }
}
