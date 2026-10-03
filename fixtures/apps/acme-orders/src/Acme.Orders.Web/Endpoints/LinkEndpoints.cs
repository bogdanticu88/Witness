using Acme.Orders.Web.Services;

namespace Acme.Orders.Web.Endpoints;

public static class LinkEndpoints
{
    public static void MapLinkEndpoints(this WebApplication app)
    {
        var links = app.MapGroup("/links");
        links.MapGet("/out", (string next) => Results.Redirect(next));
        links.MapPost("/import", async (HttpRequest request, OrderExport export) =>
        {
            using var reader = new StreamReader(request.Body);
            var rows = export.Parse(await reader.ReadToEndAsync());
            return Results.Ok(new { imported = rows.Count });
        });
    }
}
