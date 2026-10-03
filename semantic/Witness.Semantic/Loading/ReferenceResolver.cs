using Microsoft.CodeAnalysis;

namespace Witness.Semantic.Loading;

// Supplies metadata references without restoring anything. Framework
// assemblies come from the reference packs installed beside the helper.
// Packages resolve only when an operator-supplied directory with the NuGet
// global-packages layout already contains them.
internal sealed class ReferenceResolver
{
    // Preference order when a package ships several target frameworks.
    private static readonly string[] FrameworkPreference =
    [
        "net10.0", "net9.0", "net8.0", "net7.0", "net6.0", "net5.0",
        "netcoreapp3.1", "netstandard2.1", "netstandard2.0", "netstandard1.6", "netstandard1.3",
    ];

    private readonly string _refPackDirectory;
    private readonly string? _packageDirectory;
    private readonly Dictionary<string, List<MetadataReference>> _cache = new(StringComparer.OrdinalIgnoreCase);

    public ReferenceResolver(string refPackDirectory, string? packageDirectory)
    {
        _refPackDirectory = refPackDirectory;
        _packageDirectory = packageDirectory;
    }

    public static string DefaultRefPackDirectory() => RefPackDirectory(
        Environment.GetEnvironmentVariable("WITNESS_REF_PACKS"),
        Environment.GetEnvironmentVariable("DOTNET_ROOT"),
        Path.GetDirectoryName(typeof(object).Assembly.Location) ?? ".");

    // runtimeDirectory is <root>/shared/Microsoft.NETCore.App/<version>, so the
    // install root is three levels up from it.
    internal static string RefPackDirectory(string? explicitDir, string? dotnetRoot, string runtimeDirectory)
    {
        if (!string.IsNullOrEmpty(explicitDir))
        {
            return explicitDir;
        }
        if (string.IsNullOrEmpty(dotnetRoot))
        {
            dotnetRoot = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(runtimeDirectory)));
        }
        return Path.Combine(dotnetRoot ?? ".", "packs");
    }

    public IReadOnlyList<(string Name, string Version)> AvailablePacks()
    {
        var packs = new List<(string, string)>();
        foreach (var name in new[] { "Microsoft.NETCore.App.Ref", "Microsoft.AspNetCore.App.Ref" })
        {
            var version = LatestVersionDirectory(Path.Combine(_refPackDirectory, name));
            if (version is not null)
            {
                packs.Add((name, Path.GetFileName(version)));
            }
        }
        return packs;
    }

    public List<MetadataReference> FrameworkReferences(bool web, List<string> approximations)
    {
        var result = new List<MetadataReference>(Pack("Microsoft.NETCore.App.Ref", approximations));
        if (web)
        {
            result.AddRange(Pack("Microsoft.AspNetCore.App.Ref", approximations));
        }
        return result;
    }

    public List<MetadataReference> Package(string name, string? version)
    {
        if (_packageDirectory is null || string.IsNullOrWhiteSpace(version) || version.IndexOfAny(['*', '[', '(', '$']) >= 0)
        {
            return [];
        }
        var key = name + "/" + version;
        if (_cache.TryGetValue(key, out var cached))
        {
            return cached;
        }
        var packageRoot = Path.Combine(_packageDirectory, name.ToLowerInvariant(), version.ToLowerInvariant());
        var refs = new List<MetadataReference>();
        foreach (var kind in new[] { "ref", "lib" })
        {
            var dir = BestFrameworkDirectory(Path.Combine(packageRoot, kind));
            if (dir is null)
            {
                continue;
            }
            foreach (var dll in Directory.EnumerateFiles(dir, "*.dll").Order(StringComparer.Ordinal))
            {
                refs.Add(MetadataReference.CreateFromFile(dll));
            }
            break;
        }
        _cache[key] = refs;
        return refs;
    }

    private List<MetadataReference> Pack(string name, List<string> approximations)
    {
        if (_cache.TryGetValue(name, out var cached))
        {
            return cached;
        }
        var versionDir = LatestVersionDirectory(Path.Combine(_refPackDirectory, name));
        var refs = new List<MetadataReference>();
        if (versionDir is null)
        {
            approximations.Add($"reference pack {name} not found under {_refPackDirectory}; framework symbols unresolved");
            return refs;
        }
        var frameworkDir = BestFrameworkDirectory(Path.Combine(versionDir, "ref"));
        if (frameworkDir is not null)
        {
            foreach (var dll in Directory.EnumerateFiles(frameworkDir, "*.dll").Order(StringComparer.Ordinal))
            {
                refs.Add(MetadataReference.CreateFromFile(dll));
            }
        }
        _cache[name] = refs;
        return refs;
    }

    private static string? LatestVersionDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            return null;
        }
        return Directory.EnumerateDirectories(dir)
            .Select(d => (Dir: d, Parsed: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
            .Where(x => x.Parsed is not null)
            .OrderByDescending(x => x.Parsed)
            .Select(x => x.Dir)
            .FirstOrDefault();
    }

    private static string? BestFrameworkDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            return null;
        }
        foreach (var tfm in FrameworkPreference)
        {
            var candidate = Path.Combine(dir, tfm);
            if (Directory.Exists(candidate) && Directory.EnumerateFiles(candidate, "*.dll").Any())
            {
                return candidate;
            }
        }
        return null;
    }
}
