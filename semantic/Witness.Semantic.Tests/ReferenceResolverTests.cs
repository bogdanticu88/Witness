using Witness.Semantic.Loading;

namespace Witness.Semantic.Tests;

public sealed class ReferenceResolverTests
{
    // The runtime lives at <root>/shared/Microsoft.NETCore.App/<version>/,
    // and the reference packs sit beside "shared" at <root>/packs.
    [Fact]
    public void Falls_back_to_packs_beside_the_running_runtime()
    {
        var root = Path.Combine(Path.GetTempPath(), "dotnet-root");
        var runtimeDir = Path.Combine(root, "shared", "Microsoft.NETCore.App", "10.0.12");
        Assert.Equal(Path.Combine(root, "packs"), ReferenceResolver.RefPackDirectory(null, null, runtimeDir));
    }

    [Fact]
    public void Dotnet_root_wins_over_the_runtime_location()
    {
        Assert.Equal(Path.Combine("/opt/dotnet", "packs"), ReferenceResolver.RefPackDirectory(null, "/opt/dotnet", "/elsewhere/shared/Microsoft.NETCore.App/10.0.12"));
    }

    [Fact]
    public void Explicit_directory_wins_over_everything()
    {
        Assert.Equal("/refs", ReferenceResolver.RefPackDirectory("/refs", "/opt/dotnet", "/elsewhere/shared/Microsoft.NETCore.App/10.0.12"));
    }
}
