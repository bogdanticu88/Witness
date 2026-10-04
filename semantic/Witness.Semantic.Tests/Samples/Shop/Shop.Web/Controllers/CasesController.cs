using System.Data.Common;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Shop.Data;

namespace Shop.Web.Controllers;

[ApiController]
[Route("cases")]
public class CasesController : ControllerBase
{
    private readonly DbConnection _db;
    private readonly ProductRepository _repository;
    private readonly IProductFinder _finder;
    private readonly IConfiguration _configuration;

    public CasesController(DbConnection db, ProductRepository repository, IProductFinder finder, IConfiguration configuration)
    {
        _db = db;
        _repository = repository;
        _finder = finder;
        _configuration = configuration;
    }

    [HttpGet("concat")]
    public object? Concat(string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + q + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("constant")]
    public object? Constant()
    {
        using var command = _db.CreateCommand();
        command.CommandText = string.Concat("SELECT * FROM t ", "WHERE a = 1");
        return command.ExecuteScalar();
    }

    [HttpGet("typed/{id}")]
    public object? Typed(int id)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE id = " + id;
        return command.ExecuteScalar();
    }

    [HttpGet("cross")]
    public object? Cross(string name) => _repository.FindByName(name);

    [HttpGet("helper")]
    public object? Helper(string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = BuildQuery(q);
        return command.ExecuteScalar();
    }

    private static string BuildQuery(string value) => "SELECT * FROM t WHERE a = '" + value + "'";

    [HttpGet("escaped")]
    public object? Escaped(string q)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + Escape(q) + "'";
        return command.ExecuteScalar();
    }

    private static string Escape(string value) => value.Replace("'", "''");

    [HttpGet("dispatch")]
    public object? Dispatch(string term) => _finder.Find(term);

    [HttpGet("dapper")]
    public object Dapper(string q) => _db.Query<int>("SELECT id FROM t WHERE a = '" + q + "'");

    [HttpGet("builder")]
    public object? Builder(string q)
    {
        var sql = new StringBuilder("SELECT * FROM t WHERE a = '");
        sql.Append(q);
        sql.Append('\'');
        using var command = _db.CreateCommand();
        command.CommandText = sql.ToString();
        return command.ExecuteScalar();
    }

    [HttpGet("tryget")]
    public object? TryGet()
    {
        Request.Query.TryGetValue("q", out var value);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + value + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("branch")]
    public object? Branch(string q, bool exact)
    {
        using var command = _db.CreateCommand();
        command.CommandText = exact ? "SELECT * FROM t WHERE a = @q" : "SELECT * FROM t WHERE a LIKE '" + q + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("go")]
    public IActionResult Go(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return Redirect("/");
    }

    [HttpGet("go-other")]
    public IActionResult GoOther(string returnUrl, string next)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return BadRequest();
        }
        return Redirect(next);
    }

    [HttpGet("go-reassigned")]
    public IActionResult GoReassigned(string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return BadRequest();
        }
        returnUrl = Request.Query["fallback"].ToString();
        return Redirect(returnUrl);
    }

    [HttpGet("go-local")]
    public IActionResult GoLocal(string returnUrl) => LocalRedirect(returnUrl);

    [HttpGet("file-naive")]
    public IActionResult FileNaive(string name)
    {
        var path = Path.Combine("/srv/docs", name);
        if (!path.StartsWith("/srv/docs"))
        {
            return BadRequest();
        }
        return PhysicalFile(path, "application/octet-stream");
    }

    [HttpGet("file-name")]
    public IActionResult FileName(string name)
    {
        var text = System.IO.File.ReadAllText(Path.Combine("/srv/docs", Path.GetFileName(name)));
        return Content(text);
    }

    [HttpGet("file-config")]
    public IActionResult FileConfig()
    {
        var text = System.IO.File.ReadAllText(_configuration["Reports:Path"]!);
        return Content(text);
    }

    [HttpGet("validated")]
    public object? Validated(string q)
    {
        Rules.Check(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + q + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("validated-async")]
    public async Task<object?> ValidatedAsync(string q)
    {
        await Rules.CheckAsync(q);
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + q + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("ids")]
    public object? Ids([FromQuery] int[] ids)
    {
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE id IN (" + string.Join(",", ids) + ")";
        return command.ExecuteScalar();
    }

    [HttpGet("overwritten")]
    public object? Overwritten(string q)
    {
        var sql = "SELECT * FROM t WHERE a = '" + q + "'";
        sql = "SELECT 1";
        using var command = _db.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    [HttpGet("swallowed")]
    public object? Swallowed(string q)
    {
        try
        {
            Rules.Check(q);
        }
        catch (ArgumentException)
        {
        }
        using var command = _db.CreateCommand();
        command.CommandText = "SELECT * FROM t WHERE a = '" + q + "'";
        return command.ExecuteScalar();
    }

    [HttpGet("file-checked")]
    public IActionResult FileChecked(string name)
    {
        var rootFull = Path.GetFullPath("/srv/docs");
        var full = Path.GetFullPath(Path.Combine(rootFull, name));
        if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full));
    }

    [HttpGet("self-trimmed")]
    public object? SelfTrimmed(string q)
    {
        var sql = "SELECT * FROM t WHERE a = '" + q + "'";
        sql = sql.Trim();
        using var command = _db.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    [HttpGet("loop-trimmed")]
    public object? LoopTrimmed(string q, int passes)
    {
        var sql = "SELECT * FROM t WHERE a = '" + q + "'";
        for (var i = 0; i < passes; i++)
        {
            sql = sql.Trim();
        }
        using var command = _db.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    [HttpGet("constant-root")]
    public IActionResult ConstantRoot(string name)
    {
        var full = Path.GetFullPath(Path.Combine("/srv/docs", name));
        if (!full.StartsWith("/srv/docs/", StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full));
    }

    private static readonly string[] Roots = ["/srv/docs"];

    [HttpGet("array-root")]
    public IActionResult ArrayRoot(string name)
    {
        var full = Path.GetFullPath(Path.Combine("/srv/docs", name));
        if (!full.StartsWith(Roots[0] + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full));
    }

    [HttpGet("computed-root")]
    public IActionResult ComputedRoot(string name)
    {
        var full = Path.GetFullPath(Path.Combine("/srv/docs", name));
        if (!full.StartsWith(Path.GetFullPath("/srv/docs") + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full));
    }
}

internal static class Rules
{
    public static Task CheckAsync(string value)
    {
        Check(value);
        return Task.CompletedTask;
    }

    public static void Check(string value)
    {
        if (value.Length > 64)
        {
            throw new ArgumentException("too long", nameof(value));
        }
    }
}
