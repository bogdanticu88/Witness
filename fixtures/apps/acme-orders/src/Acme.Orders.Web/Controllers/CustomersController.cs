using Acme.Orders.Data;
using Acme.Orders.Web.Validation;
using Dapper;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Orders.Web.Controllers;

[ApiController]
[Route("api/customers")]
public class CustomersController : ControllerBase
{
    private readonly CustomerRepository _customers;
    private readonly IOrderSearch _search;
    private readonly Database _database;

    public CustomersController(CustomerRepository customers, IOrderSearch search, Database database)
    {
        _customers = customers;
        _search = search;
        _database = database;
    }

    [HttpGet("by-name")]
    public IActionResult ByName([FromQuery] string name) => Ok(_customers.FindByName(name));

    [HttpGet("by-email")]
    public IActionResult ByEmail([FromQuery] string email) => Ok(_customers.FindByEmail(email));

    [HttpGet("orders")]
    public IActionResult Orders([FromQuery] string reference) => Ok(_search.ByReference(reference));

    [HttpGet("regions")]
    public IActionResult Regions() => Ok(new { east = _customers.CountEast(), west = _customers.CountWest() });

    [HttpGet("emails")]
    public IActionResult Emails([FromQuery] string region)
    {
        using var connection = _database.Open();
        var emails = connection.Query<string>("SELECT email FROM customers WHERE region = '" + region + "'");
        return Ok(emails);
    }

    [HttpGet("by-region")]
    public IActionResult ByRegion([FromQuery] string region)
    {
        InputRules.EnsureSqlSafe(region);
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, name FROM customers WHERE region = '" + region + "'";
        return Ok(command.ReadAll());
    }
}
