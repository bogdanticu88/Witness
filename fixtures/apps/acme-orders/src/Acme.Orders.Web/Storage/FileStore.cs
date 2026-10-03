namespace Acme.Orders.Web.Storage;

public sealed class FileStore
{
    private readonly string _root;

    public FileStore(IWebHostEnvironment environment)
    {
        _root = Path.Combine(environment.ContentRootPath, "documents");
    }

    public Stream OpenDocument(string name)
    {
        var path = Path.Combine(_root, name);
        return File.OpenRead(path);
    }
}
