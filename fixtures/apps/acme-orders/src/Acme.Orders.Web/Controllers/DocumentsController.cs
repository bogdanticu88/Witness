using Acme.Orders.Web.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Orders.Web.Controllers;

[ApiController]
[Route("api/documents")]
public class DocumentsController : ControllerBase
{
    private readonly string _root;
    private readonly FileStore _store;

    public DocumentsController(IWebHostEnvironment environment, FileStore store)
    {
        _root = Path.Combine(environment.ContentRootPath, "documents");
        _store = store;
    }

    [HttpGet("raw")]
    public IActionResult Raw([FromQuery] string name)
    {
        var text = System.IO.File.ReadAllText(Path.Combine(_root, name));
        return Content(text, "text/plain");
    }

    [HttpGet("preview")]
    public IActionResult Preview([FromQuery] string name)
    {
        var safeName = Path.GetFileName(name);
        var text = System.IO.File.ReadAllText(Path.Combine(_root, safeName));
        return Content(text, "text/plain");
    }

    [HttpGet("view")]
    public IActionResult View([FromQuery] string name)
    {
        var rootFull = Path.GetFullPath(_root);
        var full = Path.GetFullPath(Path.Combine(rootFull, name));
        if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(full), "text/plain");
    }

    [HttpGet("legacy")]
    public IActionResult Legacy([FromQuery] string name)
    {
        var path = Path.Combine(_root, name);
        if (!path.StartsWith(_root, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return Content(System.IO.File.ReadAllText(path), "text/plain");
    }

    [HttpGet("download")]
    public IActionResult Download([FromQuery] string name)
    {
        return PhysicalFile(Path.Combine(_root, name), "application/octet-stream");
    }

    [HttpGet("open")]
    public IActionResult Open([FromQuery] string name)
    {
        using var stream = _store.OpenDocument(name);
        using var reader = new StreamReader(stream);
        return Content(reader.ReadToEnd(), "text/plain");
    }
}
