using System.Text.Json;
using Witness.Semantic.Loading;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Tests;

// Loads the Shop sample once for all tests in the collection.
public sealed class ShopFixture
{
    public ShopFixture()
    {
        Root = Path.Combine(AppContext.BaseDirectory, "Samples", "Shop");
        Server = new Server(ReferenceResolver.DefaultRefPackDirectory());
        Load = (LoadResultDto)Call("load", new { root = Root })!;
        Sites = ((SitesDto)Call("find_sinks", new { })!).Sites.ToList();
    }

    public string Root { get; }
    internal Server Server { get; }
    internal LoadResultDto Load { get; }
    internal List<SiteDto> Sites { get; }

    internal object? Call(string method, object parameters)
    {
        var element = JsonSerializer.SerializeToElement(parameters, Json.Options);
        return Server.Handle(method, element);
    }

    internal SiteDto Site(string containingMember, string vulnClass, int ordinal = 0) =>
        Sites.Where(s => s.VulnClass == vulnClass && s.Containing is not null && Names(s.Containing.Id, containingMember))
            .OrderBy(s => s.Location.StartLine)
            .ElementAt(ordinal);

    // Documentation ids omit the parentheses for parameterless methods.
    private static bool Names(string id, string member) =>
        id.Contains("." + member + "(", StringComparison.Ordinal) || id.EndsWith("." + member, StringComparison.Ordinal);

    internal SiteAnalysisDto Analyze(SiteDto site) =>
        (SiteAnalysisDto)Call("analyze_site", new { site_id = site.SiteId })!;
}

[CollectionDefinition("shop")]
public sealed class ShopGroup : ICollectionFixture<ShopFixture>;

internal static class Trees
{
    public static IEnumerable<ValueNode> All(ValueNode node)
    {
        yield return node;
        foreach (var child in node.Children ?? [])
        {
            foreach (var descendant in All(child))
            {
                yield return descendant;
            }
        }
    }

    public static IEnumerable<ValueNode> Leaves(ValueNode node) =>
        All(node).Where(n => n.Children is null || n.Children.Count == 0);

    public static bool Has(ValueNode node, string kind) => All(node).Any(n => n.Kind == kind);
}
