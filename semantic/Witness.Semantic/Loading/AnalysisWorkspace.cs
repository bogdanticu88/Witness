using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Witness.Semantic.Protocol;

namespace Witness.Semantic.Loading;

internal sealed record LoadOptions(
    string Root,
    string? PackageDirectory,
    string RefPackDirectory,
    int MaxFiles,
    long MaxFileBytes);

internal sealed class LoadedProject
{
    public required ProjectFile? File { get; init; }
    public required string Name { get; init; }
    public required CSharpCompilation Compilation { get; set; }
    public List<string> Documents { get; } = [];
    public List<PackageReferenceDto> Packages { get; } = [];
    public List<string> Approximations { get; } = [];
    public List<string> ProjectReferenceNames { get; } = [];
}

// Holds every compilation built from one repository snapshot. Paths exposed
// to the protocol are always relative to Root with forward slashes.
internal sealed class AnalysisWorkspace
{
    private static readonly string[] SkippedDirectories = [".git", "bin", "obj", "node_modules", ".vs", ".idea", "packages", ".witness"];

    private readonly Dictionary<string, (LoadedProject Project, SyntaxTree Tree)> _documents = new(StringComparer.Ordinal);

    private AnalysisWorkspace(string root)
    {
        Root = root;
    }

    public string Root { get; }
    public List<LoadedProject> Projects { get; } = [];
    public List<SkippedFileDto> Skipped { get; } = [];
    public long LoadMs { get; private set; }

    public IEnumerable<(string Path, LoadedProject Project, SyntaxTree Tree)> Documents =>
        _documents.Select(kv => (kv.Key, kv.Value.Project, kv.Value.Tree));

    public bool TryGetDocument(string relativePath, out LoadedProject project, out SyntaxTree tree)
    {
        if (_documents.TryGetValue(relativePath, out var entry))
        {
            project = entry.Project;
            tree = entry.Tree;
            return true;
        }
        project = null!;
        tree = null!;
        return false;
    }

    public string Relative(string fullPath) =>
        Path.GetRelativePath(Root, fullPath).Replace('\\', '/');

    public SemanticModel Model(SyntaxTree tree)
    {
        foreach (var project in Projects)
        {
            if (project.Compilation.ContainsSyntaxTree(tree))
            {
                return project.Compilation.GetSemanticModel(tree);
            }
        }
        throw new ProtocolException("internal", "syntax tree not part of any compilation");
    }

    public static AnalysisWorkspace Load(LoadOptions options)
    {
        var watch = Stopwatch.StartNew();
        var root = Path.GetFullPath(options.Root);
        if (!System.IO.Directory.Exists(root))
        {
            throw new ProtocolException("bad_root", $"repository root does not exist: {options.Root}");
        }

        var workspace = new AnalysisWorkspace(root);
        var files = workspace.Enumerate(root, options);
        var projectPaths = files.Where(f => f.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)).ToList();
        var sourcePaths = files.Where(f => f.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)).ToList();

        var refs = new ReferenceResolver(options.RefPackDirectory, options.PackageDirectory);
        var centralVersions = ReadCentralPackageVersions(root);

        var parsed = new Dictionary<string, ProjectFile>(StringComparer.Ordinal);
        foreach (var path in projectPaths)
        {
            try
            {
                parsed[path] = ProjectFile.Parse(path, File.ReadAllText(path));
            }
            catch (Exception ex) when (ex is System.Xml.XmlException or InvalidDataException)
            {
                workspace.Skipped.Add(new SkippedFileDto(workspace.Relative(path), $"project file unreadable: {ex.Message}"));
            }
        }

        var projectDirs = parsed.Values.Select(p => p.Directory).ToHashSet(StringComparer.Ordinal);
        var assigned = new HashSet<string>(StringComparer.Ordinal);

        // Build in reference order so project references become compilation references.
        var built = new Dictionary<string, LoadedProject>(StringComparer.Ordinal);
        var visiting = new HashSet<string>(StringComparer.Ordinal);

        LoadedProject? Build(string path)
        {
            if (built.TryGetValue(path, out var done))
            {
                return done;
            }
            if (!parsed.TryGetValue(path, out var file) || !visiting.Add(path))
            {
                return null;
            }

            var loaded = new LoadedProject
            {
                File = file,
                Name = file.Name,
                Compilation = null!,
            };
            loaded.Approximations.AddRange(file.Approximations.Distinct(StringComparer.Ordinal));
            loaded.Approximations.Add("MSBuild evaluation skipped; Debug configuration and default SDK items assumed");
            loaded.Approximations.Add("source generators (for example LoggerMessage, Regex, configuration binding) not run");
            foreach (var ancestorFile in AncestorBuildFiles(file.Directory, root))
            {
                loaded.Approximations.Add($"{workspace.Relative(ancestorFile)} not evaluated");
            }

            var references = new List<MetadataReference>();
            references.AddRange(refs.FrameworkReferences(file.IsWebSdk, loaded.Approximations));

            var lockFile = Path.Combine(file.Directory, "packages.lock.json");
            var transitive = File.Exists(lockFile) ? ReadLockFile(lockFile) : [];
            var direct = file.PackageReferences
                .Select(p => (p.Name, Version: p.Version ?? centralVersions.GetValueOrDefault(p.Name)))
                .ToList();
            foreach (var (name, version) in direct.Concat(transitive.Where(t => !direct.Any(d => d.Name.Equals(t.Name, StringComparison.OrdinalIgnoreCase)))))
            {
                var resolved = refs.Package(name, version);
                references.AddRange(resolved);
                loaded.Packages.Add(new PackageReferenceDto(
                    name,
                    version,
                    resolved.Count > 0,
                    resolved.Count > 0 ? "package_directory" : null));
            }

            foreach (var reference in file.ProjectReferences)
            {
                var target = Path.GetFullPath(Path.Combine(file.Directory, reference.Replace('\\', '/')));
                if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                {
                    loaded.Approximations.Add($"ProjectReference outside the repository ignored: {reference}");
                    continue;
                }
                var dependency = Build(target);
                if (dependency is null)
                {
                    loaded.Approximations.Add($"ProjectReference not loaded: {reference}");
                    continue;
                }
                references.Add(dependency.Compilation.ToMetadataReference());
                loaded.ProjectReferenceNames.Add(dependency.Name);
            }

            var parseOptions = ParseOptions(file);
            var trees = new List<SyntaxTree>();
            var implicitUsings = ImplicitUsings(file);
            if (implicitUsings is not null)
            {
                trees.Add(CSharpSyntaxTree.ParseText(implicitUsings, parseOptions, path: "<implicit-usings>"));
            }

            foreach (var source in ProjectSources(file, sourcePaths, projectDirs))
            {
                if (!assigned.Add(source))
                {
                    loaded.Approximations.Add($"{workspace.Relative(source)} belongs to more than one project; analyzed once");
                    continue;
                }
                var tree = workspace.Parse(source, parseOptions);
                if (tree is null)
                {
                    continue;
                }
                trees.Add(tree);
                loaded.Documents.Add(workspace.Relative(source));
                workspace._documents[workspace.Relative(source)] = (loaded, tree);
            }

            var outputKind = file.IsExecutable ? OutputKind.ConsoleApplication : OutputKind.DynamicallyLinkedLibrary;
            var nullable = string.Equals(file.Property("Nullable"), "enable", StringComparison.OrdinalIgnoreCase)
                ? NullableContextOptions.Enable
                : NullableContextOptions.Disable;
            loaded.Compilation = CSharpCompilation.Create(
                file.Property("AssemblyName") ?? file.Name,
                trees,
                references,
                new CSharpCompilationOptions(outputKind, nullableContextOptions: nullable, allowUnsafe: true));

            visiting.Remove(path);
            built[path] = loaded;
            workspace.Projects.Add(loaded);
            return loaded;
        }

        foreach (var path in parsed.Keys.Order(StringComparer.Ordinal))
        {
            Build(path);
        }

        // Source files that no project claims still get analyzed, with web
        // references, so findings in them are not silently dropped.
        var loose = sourcePaths.Where(s => !assigned.Contains(s)).ToList();
        if (loose.Count > 0)
        {
            var looseProject = new LoadedProject { File = null, Name = "(loose files)", Compilation = null! };
            looseProject.Approximations.Add("files not claimed by any .csproj; compiled together with ASP.NET Core references");
            var parseOptions = new CSharpParseOptions(LanguageVersion.Latest);
            var trees = new List<SyntaxTree>();
            foreach (var source in loose)
            {
                var tree = workspace.Parse(source, parseOptions);
                if (tree is null)
                {
                    continue;
                }
                trees.Add(tree);
                looseProject.Documents.Add(workspace.Relative(source));
                workspace._documents[workspace.Relative(source)] = (looseProject, tree);
            }
            looseProject.Compilation = CSharpCompilation.Create(
                "loose",
                trees,
                refs.FrameworkReferences(web: true, looseProject.Approximations),
                new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            workspace.Projects.Add(looseProject);
        }

        workspace.LoadMs = watch.ElapsedMilliseconds;
        return workspace;
    }

    private SyntaxTree? Parse(string fullPath, CSharpParseOptions options)
    {
        try
        {
            using var stream = File.OpenRead(fullPath);
            var text = SourceText.From(stream, Encoding.UTF8, SourceHashAlgorithm.Sha256);
            return CSharpSyntaxTree.ParseText(text, options, path: Relative(fullPath));
        }
        catch (IOException ex)
        {
            Skipped.Add(new SkippedFileDto(Relative(fullPath), $"unreadable: {ex.Message}"));
            return null;
        }
    }

    private List<string> Enumerate(string root, LoadOptions options)
    {
        var result = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            IEnumerable<string> entries;
            try
            {
                entries = System.IO.Directory.EnumerateFileSystemEntries(dir).Order(StringComparer.Ordinal).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Skipped.Add(new SkippedFileDto(Relative(dir), $"directory unreadable: {ex.Message}"));
                continue;
            }

            foreach (var entry in entries)
            {
                var info = new FileInfo(entry);
                var name = info.Name;
                var isDir = System.IO.Directory.Exists(entry);
                if (info.LinkTarget is not null)
                {
                    // Symlinks are never followed. A link inside the repository
                    // could point anywhere on the analysis host.
                    Skipped.Add(new SkippedFileDto(Relative(entry), "symbolic link not followed"));
                    continue;
                }
                if (isDir)
                {
                    if (!SkippedDirectories.Contains(name, StringComparer.OrdinalIgnoreCase))
                    {
                        pending.Push(entry);
                    }
                    continue;
                }
                if (!name.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                    && !name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (info.Length > options.MaxFileBytes)
                {
                    Skipped.Add(new SkippedFileDto(Relative(entry), $"larger than {options.MaxFileBytes} bytes"));
                    continue;
                }
                if (result.Count >= options.MaxFiles)
                {
                    Skipped.Add(new SkippedFileDto(Relative(entry), $"file limit {options.MaxFiles} reached"));
                    continue;
                }
                result.Add(entry);
            }
        }
        return result;
    }

    private static IEnumerable<string> ProjectSources(ProjectFile file, List<string> sources, HashSet<string> projectDirs)
    {
        var prefix = file.Directory + Path.DirectorySeparatorChar;
        var removes = file.CompileRemoves.Select(GlobToRegex).ToList();
        var defaults = !string.Equals(file.Property("EnableDefaultCompileItems"), "false", StringComparison.OrdinalIgnoreCase);
        var includes = file.CompileIncludes.Select(GlobToRegex).ToList();

        foreach (var source in sources)
        {
            var relative = Path.GetRelativePath(file.Directory, source).Replace('\\', '/');
            var underProject = source.StartsWith(prefix, StringComparison.Ordinal);
            var included = (defaults && underProject && !InNestedProject(source, file.Directory, projectDirs))
                || includes.Any(r => r.IsMatch(relative));
            if (included && !removes.Any(r => r.IsMatch(relative)))
            {
                yield return source;
            }
        }
    }

    private static bool InNestedProject(string source, string projectDir, HashSet<string> projectDirs)
    {
        for (var dir = Path.GetDirectoryName(source); dir is not null && dir.Length > projectDir.Length; dir = Path.GetDirectoryName(dir))
        {
            if (projectDirs.Contains(dir))
            {
                return true;
            }
        }
        return false;
    }

    private static Regex GlobToRegex(string glob)
    {
        var pattern = Regex.Escape(glob.Replace('\\', '/'))
            .Replace(@"\*\*/", "(.*/)?", StringComparison.Ordinal)
            .Replace(@"\*\*", ".*", StringComparison.Ordinal)
            .Replace(@"\*", "[^/]*", StringComparison.Ordinal)
            .Replace(@"\?", "[^/]", StringComparison.Ordinal);
        return new Regex("^" + pattern + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    }

    private static CSharpParseOptions ParseOptions(ProjectFile file)
    {
        var symbols = new List<string> { "DEBUG", "TRACE", "NET", "NETCOREAPP" };
        var defines = file.Property("DefineConstants");
        if (defines is not null)
        {
            symbols.AddRange(defines.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(s => !s.Contains('$', StringComparison.Ordinal)));
        }
        var version = LanguageVersion.Latest;
        var declared = file.Property("LangVersion");
        if (declared is not null && LanguageVersionFacts.TryParse(declared, out var parsedVersion))
        {
            version = parsedVersion;
        }
        return new CSharpParseOptions(version, preprocessorSymbols: symbols);
    }

    private static string? ImplicitUsings(ProjectFile file)
    {
        var builder = new StringBuilder();
        if (string.Equals(file.Property("ImplicitUsings"), "enable", StringComparison.OrdinalIgnoreCase)
            || string.Equals(file.Property("ImplicitUsings"), "true", StringComparison.OrdinalIgnoreCase))
        {
            // The SDK's documented default global usings.
            string[] common = ["System", "System.Collections.Generic", "System.IO", "System.Linq", "System.Net.Http", "System.Threading", "System.Threading.Tasks"];
            string[] web = ["System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Routing", "Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging"];
            foreach (var ns in file.IsWebSdk ? common.Concat(web) : common)
            {
                builder.Append("global using global::").Append(ns).AppendLine(";");
            }
        }
        foreach (var (name, isStatic, alias) in file.Usings)
        {
            builder.Append("global using ");
            if (isStatic)
            {
                builder.Append("static ");
            }
            if (alias is not null)
            {
                builder.Append(alias).Append(" = ");
            }
            builder.Append("global::").Append(name).AppendLine(";");
        }
        return builder.Length == 0 ? null : builder.ToString();
    }

    private static IEnumerable<string> AncestorBuildFiles(string directory, string root)
    {
        for (var dir = directory; dir is not null && dir.Length >= root.Length; dir = Path.GetDirectoryName(dir))
        {
            foreach (var name in new[] { "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props" })
            {
                var candidate = Path.Combine(dir, name);
                if (File.Exists(candidate) && new FileInfo(candidate).LinkTarget is null)
                {
                    yield return candidate;
                }
            }
        }
    }

    private static Dictionary<string, string> ReadCentralPackageVersions(string root)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(root, "Directory.Packages.props");
        if (!File.Exists(path) || new FileInfo(path).LinkTarget is not null)
        {
            return versions;
        }
        try
        {
            var doc = ProjectFile.LoadXml(File.ReadAllText(path));
            foreach (var item in doc.Descendants().Where(e => e.Name.LocalName == "PackageVersion"))
            {
                var name = (string?)item.Attribute("Include");
                var version = (string?)item.Attribute("Version");
                if (name is not null && version is not null)
                {
                    versions[name] = version;
                }
            }
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or InvalidDataException)
        {
            // An unreadable central file only means versions stay unknown.
        }
        return versions;
    }

    private static List<(string Name, string? Version)> ReadLockFile(string path)
    {
        var result = new List<(string, string?)>();
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path), new JsonDocumentOptions { MaxDepth = 32 });
            if (!doc.RootElement.TryGetProperty("dependencies", out var frameworks))
            {
                return result;
            }
            foreach (var framework in frameworks.EnumerateObject())
            {
                foreach (var package in framework.Value.EnumerateObject())
                {
                    if (package.Value.TryGetProperty("type", out var type) && type.GetString() == "Project")
                    {
                        continue;
                    }
                    var resolved = package.Value.TryGetProperty("resolved", out var r) ? r.GetString() : null;
                    result.Add((package.Name, resolved));
                }
                break;
            }
        }
        catch (JsonException)
        {
            // Treated as no lock file.
        }
        return result;
    }

    public static string Sha256(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
