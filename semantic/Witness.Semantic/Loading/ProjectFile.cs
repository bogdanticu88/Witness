using System.Xml;
using System.Xml.Linq;

namespace Witness.Semantic.Loading;

// A literal reading of a .csproj. Nothing here evaluates MSBuild: properties
// are taken as written, conditions are ignored, imports are not followed.
// Every shortcut is recorded in Approximations so callers can see how far the
// reconstruction may differ from a real build.
internal sealed class ProjectFile
{
    public required string FullPath { get; init; }
    public required string Directory { get; init; }
    public required string Sdk { get; init; }
    public Dictionary<string, string> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string Name, string? Version)> PackageReferences { get; } = [];
    public List<string> ProjectReferences { get; } = [];
    public List<string> FrameworkReferences { get; } = [];
    public List<string> CompileIncludes { get; } = [];
    public List<string> CompileRemoves { get; } = [];
    public List<(string Name, bool Static, string? Alias)> Usings { get; } = [];
    public List<string> Approximations { get; } = [];

    public string Name => Path.GetFileNameWithoutExtension(FullPath);

    public string? Property(string name) => Properties.TryGetValue(name, out var v) ? v : null;

    public bool IsWebSdk =>
        Sdk.StartsWith("Microsoft.NET.Sdk.Web", StringComparison.OrdinalIgnoreCase)
        || Sdk.StartsWith("Microsoft.NET.Sdk.Razor", StringComparison.OrdinalIgnoreCase)
        || FrameworkReferences.Any(f => f.Equals("Microsoft.AspNetCore.App", StringComparison.OrdinalIgnoreCase));

    public bool IsExecutable =>
        string.Equals(Property("OutputType"), "Exe", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Property("OutputType"), "WinExe", StringComparison.OrdinalIgnoreCase)
        || Sdk.StartsWith("Microsoft.NET.Sdk.Web", StringComparison.OrdinalIgnoreCase)
        || Sdk.StartsWith("Microsoft.NET.Sdk.Worker", StringComparison.OrdinalIgnoreCase);

    public static ProjectFile Parse(string fullPath, string text)
    {
        var doc = LoadXml(text);
        var root = doc.Root ?? throw new InvalidDataException("project file has no root element");
        var sdk = (string?)root.Attribute("Sdk")
            ?? root.Elements().FirstOrDefault(e => e.Name.LocalName == "Sdk")?.Attribute("Name")?.Value
            ?? "";

        var project = new ProjectFile
        {
            FullPath = fullPath,
            Directory = Path.GetDirectoryName(fullPath)!,
            Sdk = sdk,
        };

        if (sdk.Length == 0)
        {
            project.Approximations.Add("project has no SDK attribute; legacy or imported-SDK project read as SDK-style");
        }

        foreach (var element in root.Descendants())
        {
            var name = element.Name.LocalName;
            var condition = Condition(element);
            switch (name)
            {
                case "Import":
                    project.Approximations.Add($"Import '{(string?)element.Attribute("Project")}' not evaluated");
                    break;
                case "Target":
                    project.Approximations.Add($"Target '{(string?)element.Attribute("Name")}' not run");
                    break;
                case "Analyzer":
                    project.Approximations.Add($"Analyzer '{(string?)element.Attribute("Include")}' not loaded; generated code absent");
                    break;
            }

            if (element.Parent?.Name.LocalName == "PropertyGroup" && !element.HasElements)
            {
                if (condition is not null)
                {
                    project.Approximations.Add($"property {name} under condition {condition} ignored");
                    continue;
                }
                project.Properties.TryAdd(name, element.Value.Trim());
                continue;
            }

            if (element.Parent?.Name.LocalName != "ItemGroup")
            {
                continue;
            }

            if (condition is not null)
            {
                project.Approximations.Add($"{name} item under condition {condition} included unconditionally");
            }

            var include = (string?)element.Attribute("Include");
            switch (name)
            {
                case "PackageReference" when include is not null:
                    var version = (string?)element.Attribute("Version")
                        ?? element.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value;
                    project.PackageReferences.Add((include, version?.Trim()));
                    break;
                case "ProjectReference" when include is not null:
                    project.ProjectReferences.Add(include);
                    break;
                case "FrameworkReference" when include is not null:
                    project.FrameworkReferences.Add(include);
                    break;
                case "Compile":
                    if (include is not null)
                    {
                        project.CompileIncludes.Add(include);
                    }
                    var remove = (string?)element.Attribute("Remove");
                    if (remove is not null)
                    {
                        project.CompileRemoves.Add(remove);
                    }
                    break;
                case "Using" when include is not null:
                    project.Usings.Add((
                        include,
                        string.Equals((string?)element.Attribute("Static"), "true", StringComparison.OrdinalIgnoreCase),
                        (string?)element.Attribute("Alias")));
                    break;
            }
        }

        foreach (var value in project.Properties.Values)
        {
            if (value.Contains("$(", StringComparison.Ordinal))
            {
                project.Approximations.Add("property values contain MSBuild expressions that were not evaluated");
                break;
            }
        }

        return project;
    }

    // Project files are repository content: no DTDs, no external resolution.
    public static XDocument LoadXml(string text)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 4 * 1024 * 1024,
        };
        using var reader = XmlReader.Create(new StringReader(text), settings);
        return XDocument.Load(reader);
    }

    private static string? Condition(XElement element)
    {
        for (var e = element; e is not null; e = e.Parent)
        {
            var c = (string?)e.Attribute("Condition");
            if (c is not null)
            {
                return c;
            }
        }
        return null;
    }
}
