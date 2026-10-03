using Microsoft.CodeAnalysis;

namespace Witness.Semantic.Analysis;

internal static class VulnClasses
{
    public const string Sql = "sql_injection";
    public const string Redirect = "open_redirect";
    public const string Path = "path_traversal";
    public static readonly string[] All = [Sql, Redirect, Path];
}

internal sealed record SinkMatch(string VulnClass, string Role, int ParameterOrdinal, string? Note = null);

// What Witness knows about specific APIs. Matching is always on resolved
// symbols: containing type full name plus member name and parameter names.
// A method that merely shares a name with a catalogue entry is not a match.
internal static class Catalog
{
    private const string DbCommand = "System.Data.Common.DbCommand";
    private const string IDbCommand = "System.Data.IDbCommand";
    private const string DbDataAdapter = "System.Data.Common.DbDataAdapter";
    private const string ControllerBase = "Microsoft.AspNetCore.Mvc.ControllerBase";
    private const string HttpResponse = "Microsoft.AspNetCore.Http.HttpResponse";
    private const string HttpRequest = "Microsoft.AspNetCore.Http.HttpRequest";

    private static readonly HashSet<string> DapperSqlMethods =
    [
        "Query", "QueryAsync", "QueryFirst", "QueryFirstAsync", "QueryFirstOrDefault", "QueryFirstOrDefaultAsync",
        "QuerySingle", "QuerySingleAsync", "QuerySingleOrDefault", "QuerySingleOrDefaultAsync", "QueryMultiple",
        "QueryMultipleAsync", "QueryUnbufferedAsync", "Execute", "ExecuteAsync", "ExecuteScalar", "ExecuteScalarAsync",
        "ExecuteReader", "ExecuteReaderAsync",
    ];

    private static readonly HashSet<string> RedirectMethods =
        ["Redirect", "RedirectPermanent", "RedirectPreserveMethod", "RedirectPermanentPreserveMethod"];

    private static readonly HashSet<string> FileReadExistence = ["Exists", "GetAttributes", "GetCreationTime", "GetLastWriteTime", "GetLastAccessTime"];

    private static readonly HashSet<string> PathParameterNames =
        ["path", "sourceFileName", "destFileName", "destinationFileName", "destinationBackupFileName", "fileName", "sourceDirName", "destDirName", "physicalPath"];

    public static SinkMatch? MatchMethod(IMethodSymbol method)
    {
        method = method.ReducedFrom ?? method;
        var type = Symbols.FullName(method.ContainingType);
        var name = method.Name;

        // SQL
        if (type == "Dapper.SqlMapper" && DapperSqlMethods.Contains(name))
        {
            return ByParameter(method, VulnClasses.Sql, "sql", "sql");
        }
        if (type == "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions" && name == "FromSqlRaw"
            || type == "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions"
                && name is "ExecuteSqlRaw" or "ExecuteSqlRawAsync" or "SqlQueryRaw")
        {
            return ByParameter(method, VulnClasses.Sql, "sql", "sql");
        }
        if (method.MethodKind == MethodKind.Constructor
            && (Symbols.InheritsFrom(method.ContainingType, DbCommand) || Symbols.InheritsFrom(method.ContainingType, DbDataAdapter))
            && method.Parameters.Length > 0
            && method.Parameters[0].Type.SpecialType == SpecialType.System_String)
        {
            return new SinkMatch(VulnClasses.Sql, "sql", 0);
        }

        // Open redirect
        if (Symbols.InheritsFrom(method.ContainingType, ControllerBase) && RedirectMethods.Contains(name)
            && method.ContainingType.ToDisplayString().StartsWith("Microsoft.AspNetCore.Mvc", StringComparison.Ordinal))
        {
            return ByParameter(method, VulnClasses.Redirect, "url", "url");
        }
        if (type == HttpResponse && name == "Redirect")
        {
            return ByParameter(method, VulnClasses.Redirect, "location", "url");
        }
        if (type is "Microsoft.AspNetCore.Http.Results" or "Microsoft.AspNetCore.Http.TypedResults" && name == "Redirect")
        {
            return ByParameter(method, VulnClasses.Redirect, "url", "url");
        }
        if (method.MethodKind == MethodKind.Constructor && type == "Microsoft.AspNetCore.Mvc.RedirectResult")
        {
            return ByParameter(method, VulnClasses.Redirect, "url", "url");
        }

        // Path traversal
        if (type is "System.IO.File" or "System.IO.Directory" && !FileReadExistence.Contains(name))
        {
            var role = type == "System.IO.Directory" ? "directory_path" : "file_path";
            foreach (var parameter in method.Parameters)
            {
                if (parameter.Type.SpecialType == SpecialType.System_String && PathParameterNames.Contains(parameter.Name))
                {
                    return new SinkMatch(VulnClasses.Path, role, parameter.Ordinal);
                }
            }
        }
        if (method.MethodKind == MethodKind.Constructor
            && type is "System.IO.FileStream" or "System.IO.StreamReader" or "System.IO.StreamWriter" or "System.IO.FileInfo" or "System.IO.DirectoryInfo"
            && method.Parameters.Length > 0
            && method.Parameters[0].Type.SpecialType == SpecialType.System_String)
        {
            return new SinkMatch(VulnClasses.Path, type == "System.IO.DirectoryInfo" ? "directory_path" : "file_path", 0);
        }
        if (Symbols.InheritsFrom(method.ContainingType, ControllerBase) && name == "PhysicalFile")
        {
            return ByParameter(method, VulnClasses.Path, "physicalPath", "file_path");
        }
        if (type is "Microsoft.AspNetCore.Http.Results" or "Microsoft.AspNetCore.Http.TypedResults" && name == "PhysicalFile")
        {
            return ByParameter(method, VulnClasses.Path, "path", "file_path");
        }
        if (method.MethodKind == MethodKind.Constructor && type == "Microsoft.AspNetCore.Mvc.PhysicalFileResult")
        {
            return ByParameter(method, VulnClasses.Path, "fileName", "file_path");
        }
        return null;
    }

    // Property setters that act as sinks: DbCommand.CommandText and the
    // Location response header.
    public static SinkMatch? MatchPropertySet(IPropertySymbol property, string? constantIndex)
    {
        var owner = property.ContainingType;
        if (property.Name == "CommandText"
            && (Symbols.InheritsFrom(owner, DbCommand) || Symbols.Implements(owner, IDbCommand)))
        {
            return new SinkMatch(VulnClasses.Sql, "sql", -1);
        }
        if (property.Name == "Location" && Symbols.Implements(owner, "Microsoft.AspNetCore.Http.IHeaderDictionary"))
        {
            return new SinkMatch(VulnClasses.Redirect, "url", -1);
        }
        if (property.IsIndexer && Symbols.Implements(owner, "Microsoft.AspNetCore.Http.IHeaderDictionary")
            && string.Equals(constantIndex, "Location", StringComparison.OrdinalIgnoreCase))
        {
            return new SinkMatch(VulnClasses.Redirect, "url", -1);
        }
        return null;
    }

    // APIs that look like sinks but are safe by construction. Reported so a
    // scanner finding located on them can be explained.
    public static string? SafeApi(IMethodSymbol method)
    {
        method = method.ReducedFrom ?? method;
        var type = Symbols.FullName(method.ContainingType);
        var name = method.Name;
        if (type is "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions" or "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions"
            && name is "FromSqlInterpolated" or "FromSql" or "ExecuteSqlInterpolated" or "ExecuteSqlInterpolatedAsync" or "ExecuteSql" or "ExecuteSqlAsync" or "SqlQuery")
        {
            return $"{name} takes a FormattableString and sends interpolated values as parameters";
        }
        if (name.StartsWith("LocalRedirect", StringComparison.Ordinal)
            && (Symbols.InheritsFrom(method.ContainingType, ControllerBase)
                || type is "Microsoft.AspNetCore.Http.Results" or "Microsoft.AspNetCore.Http.TypedResults"))
        {
            return $"{name} rejects non-local URLs at runtime (throws InvalidOperationException)";
        }
        if (method.MethodKind == MethodKind.Constructor && type == "Microsoft.AspNetCore.Mvc.LocalRedirectResult")
        {
            return "LocalRedirectResult rejects non-local URLs at runtime";
        }
        return null;
    }

    // Names checked only when Roslyn could not resolve the call. A match is
    // reported as an unresolved candidate and never treated as a known sink.
    public static string? UnresolvedCandidateClass(string methodName, bool isConstruction, string? typeName)
    {
        if (!isConstruction && (DapperSqlMethods.Contains(methodName) || methodName is "FromSqlRaw" or "ExecuteSqlRaw" or "ExecuteSqlRawAsync" or "SqlQueryRaw"))
        {
            return VulnClasses.Sql;
        }
        if (isConstruction && typeName is not null && typeName.EndsWith("Command", StringComparison.Ordinal))
        {
            return VulnClasses.Sql;
        }
        if (!isConstruction && RedirectMethods.Contains(methodName))
        {
            return VulnClasses.Redirect;
        }
        if (!isConstruction && methodName == "PhysicalFile")
        {
            return VulnClasses.Path;
        }
        return null;
    }

    public enum SourceKind
    {
        None,
        Request,
        Configuration,
        Environment,
    }

    public static SourceKind PropertySource(IPropertySymbol property)
    {
        var type = Symbols.FullName(property.ContainingType);
        if (type == HttpRequest && property.Name is "Query" or "Form" or "Headers" or "Cookies" or "RouteValues"
            or "Path" or "PathBase" or "QueryString" or "Body" or "BodyReader" or "Host")
        {
            return SourceKind.Request;
        }
        if (Symbols.Implements(property.ContainingType, "Microsoft.AspNetCore.Http.IFormFile")
            && property.Name is "FileName" or "Name" or "ContentDisposition")
        {
            return SourceKind.Request;
        }
        if (Symbols.Implements(property.ContainingType, "Microsoft.Extensions.Configuration.IConfiguration") && property.IsIndexer)
        {
            return SourceKind.Configuration;
        }
        if (type == "Microsoft.Extensions.Options.IOptions" && property.Name == "Value"
            || type is "Microsoft.Extensions.Options.IOptionsSnapshot" or "Microsoft.Extensions.Options.IOptionsMonitor" && property.Name is "Value" or "CurrentValue")
        {
            return SourceKind.Configuration;
        }
        return SourceKind.None;
    }

    public static SourceKind MethodSource(IMethodSymbol method)
    {
        method = method.ReducedFrom ?? method;
        var type = Symbols.FullName(method.ContainingType);
        if (type == "System.Environment" && method.Name is "GetEnvironmentVariable" or "GetEnvironmentVariables" or "GetCommandLineArgs")
        {
            return SourceKind.Environment;
        }
        if (type is "Microsoft.Extensions.Configuration.ConfigurationBinder" or "Microsoft.Extensions.Configuration.ConfigurationExtensions"
            || Symbols.Implements(method.ContainingType, "Microsoft.Extensions.Configuration.IConfiguration"))
        {
            return SourceKind.Configuration;
        }
        if (type == HttpRequest && method.Name.StartsWith("Read", StringComparison.Ordinal)
            || type == "Microsoft.AspNetCore.Http.HttpRequestJsonExtensions")
        {
            return SourceKind.Request;
        }
        return SourceKind.None;
    }

    // Transformations with vulnerability-specific effect. The value says
    // what the transformation guarantees and for which sink roles.
    public static (string Name, string Effect)? Sanitizer(IMethodSymbol method)
    {
        var type = Symbols.FullName(method.ContainingType);
        if (type == "System.IO.Path" && method.Name is "GetFileName" or "GetFileNameWithoutExtension")
        {
            return ($"Path.{method.Name}", "strips_directory_components");
        }
        return null;
    }

    // Calls whose result carries the content of their receiver and string
    // arguments. Anything not listed and not in source is an unknown call.
    public static bool IsPropagator(IMethodSymbol method)
    {
        method = method.ReducedFrom ?? method;
        var type = Symbols.FullName(method.ContainingType);
        return type switch
        {
            "System.String" => true,
            "System.Text.StringBuilder" => true,
            "System.IO.Path" => method.Name is "Combine" or "Join" or "GetFullPath" or "GetDirectoryName" or "GetRelativePath" or "ChangeExtension",
            "System.Uri" => true,
            "System.Convert" => method.Name == "ToString",
            "System.Object" => method.Name == "ToString",
            "Microsoft.Extensions.Primitives.StringValues" => true,
            "System.Web.HttpUtility" or "System.Net.WebUtility" => true,
            "System.Text.RegularExpressions.Regex" => method.Name == "Replace",
            "System.Linq.Enumerable" => method.Name is "First" or "FirstOrDefault" or "Last" or "LastOrDefault" or "Single" or "SingleOrDefault" or "ElementAt",
            _ => method.Name == "ToString" && method.Parameters.Length == 0,
        };
    }

    // Propagators that can remove, replace or encode characters. Attacker
    // input still reaches the result, but its dangerous parts may not, so a
    // path through one of these cannot confirm a finding deterministically.
    public static bool AltersContent(IMethodSymbol method)
    {
        method = method.ReducedFrom ?? method;
        var type = Symbols.FullName(method.ContainingType);
        return type switch
        {
            "System.String" => method.Name is "Replace" or "Remove" or "ReplaceLineEndings",
            "System.Text.StringBuilder" => method.Name == "Replace",
            "System.Text.RegularExpressions.Regex" => method.Name == "Replace",
            "System.Web.HttpUtility" or "System.Net.WebUtility" => method.Name.Contains("Encode", StringComparison.Ordinal),
            "System.Uri" => method.Name is "EscapeDataString" or "EscapeUriString",
            _ => false,
        };
    }

    private static SinkMatch? ByParameter(IMethodSymbol method, string vulnClass, string parameterName, string role)
    {
        var parameter = method.Parameters.FirstOrDefault(p => p.Name == parameterName);
        return parameter is null ? null : new SinkMatch(vulnClass, role, parameter.Ordinal);
    }
}
