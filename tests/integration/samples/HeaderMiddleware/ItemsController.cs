using System.Data.Common;
using Microsoft.AspNetCore.Mvc;

namespace Sample;

[ApiController]
[Route("items")]
public class ItemsController(DbConnection db) : ControllerBase
{
    [HttpGet]
    public object? Find(string q)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT 1 FROM t WHERE a = '" + q + "'"; // case: M01
        return command.ExecuteScalar();
    }
}
