using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;

namespace Witness.Semantic.Analysis;

// Model binding facts that can constrain a request value before the handler
// runs: validation attributes, custom binders and route constraints. The
// helper reports them; the orchestrator decides what they mean.
internal static partial class Binding
{
    public static IEnumerable<(string Key, string Value)> ParameterFacts(IParameterSymbol parameter, EndpointIndex endpoints)
    {
        var validation = new List<string>();
        var attributes = ValidationAttributes(parameter);
        if (attributes.Length > 0)
        {
            validation.Add(attributes);
        }
        if (Symbols.Implements(parameter.Type, "System.ComponentModel.DataAnnotations.IValidatableObject"))
        {
            validation.Add("IValidatableObject");
        }
        if (validation.Count > 0)
        {
            yield return ("validation", string.Join(",", validation));
        }
        var binder = parameter.GetAttributes().FirstOrDefault(a => a.AttributeClass?.Name is "ModelBinderAttribute");
        if (binder is not null)
        {
            yield return ("model_binder", binder.ConstructorArguments.FirstOrDefault().Value?.ToString() ?? "declared");
        }
        if (parameter.ContainingSymbol is IMethodSymbol method && endpoints.RouteOf(method) is { } route)
        {
            var constraints = RouteConstraints(route, parameter.Name);
            if (constraints.Length > 0)
            {
                yield return ("route_constraints", constraints);
            }
        }
    }

    // Names of attributes on the symbol that take part in model validation.
    // An attribute whose type did not resolve is reported as unresolved:
    // nothing is known about what it checks.
    public static string ValidationAttributes(ISymbol symbol)
    {
        var names = new List<string>();
        foreach (var attribute in symbol.GetAttributes())
        {
            var type = attribute.AttributeClass;
            if (type is null)
            {
                continue;
            }
            if (type.TypeKind == TypeKind.Error)
            {
                names.Add("unresolved:" + type.Name);
            }
            else if (Symbols.InheritsFrom(type, "System.ComponentModel.DataAnnotations.ValidationAttribute"))
            {
                names.Add(type.Name.EndsWith("Attribute", StringComparison.Ordinal) ? type.Name[..^"Attribute".Length] : type.Name);
            }
        }
        return string.Join(",", names);
    }

    // "{name:alpha:minlength(2)}" -> "alpha;minlength(2)".
    private static string RouteConstraints(string route, string parameter)
    {
        foreach (Match match in RouteParameter().Matches(route))
        {
            if (!string.Equals(match.Groups["name"].Value, parameter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            return string.Join(";", match.Groups["constraint"].Captures.Select(c => c.Value));
        }
        return "";
    }

    [GeneratedRegex(@"\{\*{0,2}(?<name>[A-Za-z_][A-Za-z0-9_]*)\??(?::(?<constraint>[^:}=?]+(?:\([^)]*\))?))*[^}]*\}")]
    private static partial Regex RouteParameter();
}
