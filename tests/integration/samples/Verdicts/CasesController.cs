using System.ComponentModel.DataAnnotations;
using System.Data.Common;
using Microsoft.AspNetCore.Mvc;

namespace Verdicts;

[ApiController]
[Route("cases")]
public class CasesController : ControllerBase
{
    private readonly DbConnection _db;
    private readonly IWebHostEnvironment _env;
    private readonly Repository _repository;

    public CasesController(DbConnection db, IWebHostEnvironment env, Repository repository)
    {
        _db = db;
        _env = env;
        _repository = repository;
    }

    [HttpGet("v01")]
    public object? OtherValueValidated(string q, string other)
    {
        Rules.Check(other);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V01
        return command.ExecuteScalar();
    }

    [HttpGet("v02")]
    public object? ValidatedOnOneBranch(string q, bool strict)
    {
        if (strict)
        {
            Rules.Check(q);
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V02
        return command.ExecuteScalar();
    }

    [HttpGet("v03")]
    public object? FailureIgnored(string q)
    {
        try
        {
            Rules.Check(q);
        }
        catch (ArgumentException)
        {
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V03
        return command.ExecuteScalar();
    }

    [HttpGet("v04")]
    public object? FailureLeaves(string q)
    {
        try
        {
            Rules.Check(q);
        }
        catch (ArgumentException)
        {
            return null;
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V04
        return command.ExecuteScalar();
    }

    [HttpGet("v05")]
    public object? ReassignedAfterValidation(string q)
    {
        Rules.Check(q);
        q = Request.Query["raw"].ToString();
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V05
        return command.ExecuteScalar();
    }

    [HttpGet("v06")]
    public async Task<object?> AwaitedValidator(string q)
    {
        await Rules.CheckAsync(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V06
        return command.ExecuteScalar();
    }

    [HttpGet("v07")]
    public object? UnobservedValidator(string q)
    {
        _ = Rules.CheckAsync(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V07
        return command.ExecuteScalar();
    }

    [HttpGet("v08")]
    public object? ResultChecked(string q)
    {
        var ok = Rules.IsSafe(q);
        if (!ok)
        {
            return BadRequest();
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V08
        return command.ExecuteScalar();
    }

    [HttpGet("v09")]
    public object? ResultIgnored(string q)
    {
        var ok = Rules.IsSafe(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V09
        return command.ExecuteScalar() ?? ok;
    }

    [HttpGet("v10")]
    public object? CallerValidates(string q)
    {
        Rules.Check(q);
        return _repository.FindValidatedByCaller(q);
    }

    [HttpGet("v11")]
    public object? WrapperValidates(string q) => _repository.FindChecked(q);

    [HttpGet("v12")]
    public object? CleaningHelper(string q)
    {
        var clean = Rules.Clean(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + clean + "'"; // case: V12
        return command.ExecuteScalar();
    }

    [HttpGet("v13")]
    public object? ConstructorValidates(string q)
    {
        var search = new Search(q);
        using var command = _db.CreateCommand();
        command.CommandText = search.Sql(); // case: V13
        return command.ExecuteScalar();
    }

    [HttpGet("v14")]
    public object? RegexAttribute([FromQuery, RegularExpression("^[a-z]+$")] string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V14
        return command.ExecuteScalar();
    }

    [HttpGet("v15")]
    public object? LengthAttribute([FromQuery, StringLength(40)] string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V15
        return command.ExecuteScalar();
    }

    [HttpGet("v16/{name:alpha}")]
    public object? AlphaConstraint(string name)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + name + "'"; // case: V16
        return command.ExecuteScalar();
    }

    [HttpGet("v17/{name:minlength(2)}")]
    public object? LengthConstraint(string name)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + name + "'"; // case: V17
        return command.ExecuteScalar();
    }

    [HttpGet("v18")]
    [RejectQuotes]
    public object? RejectingFilter(string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V18
        return command.ExecuteScalar();
    }

    [HttpGet("v19")]
    [Timing]
    public object? TimingFilter(string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V19
        return command.ExecuteScalar();
    }

    [HttpGet("v20")]
    public IActionResult FixedRedirectPrefix(string q) => Redirect("/search?q=" + q); // case: V20

    [HttpGet("v21")]
    public IActionResult SlashRedirectPrefix(string q) => Redirect("/" + q); // case: V21

    [HttpGet("v22")]
    public IActionResult LocalUrlEmbedded(string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return BadRequest();
        }
        return Redirect("https:" + returnUrl); // case: V22
    }

    [HttpGet("v23")]
    public IActionResult FileNameAsDirectory(string name)
    {
        var text = System.IO.File.ReadAllText(Path.Combine(_env.ContentRootPath, Path.GetFileName(name), "index.txt")); // case: V23
        return Content(text);
    }

    [HttpGet("v24")]
    public IActionResult FileNameLast(string name)
    {
        var text = System.IO.File.ReadAllText(Path.Combine(_env.ContentRootPath, "docs", Path.GetFileName(name))); // case: V24
        return Content(text);
    }

    [HttpGet("v25")]
    public IActionResult IgnoreCasePrefix(string name)
    {
        var rootFull = Path.GetFullPath(_env.ContentRootPath);
        var full = Path.GetFullPath(Path.Combine(rootFull, name));
        if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full)); // case: V25
    }

    [HttpGet("v26")]
    public IActionResult CheckedOtherValue(string name)
    {
        var rootFull = Path.GetFullPath(_env.ContentRootPath);
        var full = Path.GetFullPath(Path.Combine(rootFull, name));
        if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(Path.Combine(rootFull, name))); // case: V26
    }

    [HttpGet("v27")]
    public IActionResult EarlyReadBeforeCheck(string name, bool fast)
    {
        var rootFull = Path.GetFullPath(_env.ContentRootPath);
        var full = Path.GetFullPath(Path.Combine(rootFull, name));
        if (fast)
        {
            return Content(System.IO.File.ReadAllText(full)); // case: V27a
        }
        if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full)); // case: V27b
    }

    [HttpGet("v28")]
    public object? Overwritten(string q)
    {
        var sql = "SELECT 1 FROM t WHERE a = '" + q + "'";
        sql = "SELECT 1";
        using var command = _db.CreateCommand();
        command.CommandText = sql; // case: V28
        return command.ExecuteScalar();
    }

    [HttpGet("v29")]
    public object? ParameterOverwritten(string q)
    {
        q = "fixed";
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: V29
        return command.ExecuteScalar();
    }

    [HttpGet("v30")]
    public object? HelperReadsRequest() => Lookup("east");

    private object? Lookup(string region)
    {
        region = Request.Query["region"].ToString();
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE region = '" + region + "'"; // case: V30
        return command.ExecuteScalar();
    }

    [HttpGet("v37")]
    public object? HelperSometimesReadsRequest(bool raw) => LookupMaybe("east", raw);

    private object? LookupMaybe(string region, bool raw)
    {
        if (raw)
        {
            region = Request.Query["region"].ToString();
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE region = '" + region + "'"; // case: V37
        return command.ExecuteScalar();
    }

    [HttpGet("v31")]
    public object? BranchAssigned(string q, bool flag)
    {
        string sql;
        if (flag)
        {
            sql = "SELECT 1 FROM t WHERE a = '" + q + "'";
        }
        else
        {
            sql = "SELECT 1";
        }
        using var command = _db.CreateCommand();
        command.CommandText = sql; // case: V31
        return command.ExecuteScalar();
    }

    [HttpGet("v32")]
    public object? IntList([FromQuery] int[] ids)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE id IN (" + string.Join(",", ids) + ")"; // case: V32
        return command.ExecuteScalar();
    }

    [HttpGet("v34")]
    public object? Appended(string q)
    {
        var sql = "SELECT 1 FROM t WHERE a = '";
        sql += q;
        using var command = _db.CreateCommand();
        command.CommandText = sql; // case: V34
        return command.ExecuteScalar();
    }

    [HttpGet("v35")]
    public object? WrittenAfterUse(string q)
    {
        var sql = "SELECT 1";
        using var command = _db.CreateCommand();
        command.CommandText = sql; // case: V35
        sql = q;
        return command.ExecuteScalar() ?? sql;
    }

    [HttpGet("v36")]
    public object? ThroughDelegate(string q)
    {
        Func<string, object?> run = Filtered;
        return run(q);
    }

    private object? Filtered(string filter)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE " + filter; // case: V36
        return command.ExecuteScalar();
    }
}

public class Repository(DbConnection db)
{
    public object? FindValidatedByCaller(string name)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE name = '" + name + "'"; // case: V10
        return command.ExecuteScalar();
    }

    public object? FindChecked(string name)
    {
        Rules.Check(name);
        return FindUnchecked(name);
    }

    private object? FindUnchecked(string name)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE name = '" + name + "'"; // case: V11
        return command.ExecuteScalar();
    }
}

public class Search
{
    private readonly string _term;

    public Search(string term)
    {
        Rules.Check(term);
        _term = term;
    }

    public string Sql() => "SELECT 1 FROM t WHERE a = '" + _term + "'";
}

public class Reports(IHttpContextAccessor accessor, DbConnection db)
{
    public object? Run()
    {
        var region = accessor.HttpContext!.Request.Query["region"].ToString();
        using var command = db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE region = '" + region + "'"; // case: V33
        return command.ExecuteScalar();
    }
}

public static class Rules
{
    public static void Check(string value)
    {
        if (value.Contains('\''))
        {
            throw new ArgumentException("quote", nameof(value));
        }
    }

    public static async Task CheckAsync(string value)
    {
        await Task.Yield();
        Check(value);
    }

    public static bool IsSafe(string value) => !value.Contains('\'');

    public static string Clean(string value)
    {
        if (!IsSafe(value))
        {
            throw new ArgumentException("quote", nameof(value));
        }
        return value;
    }
}
