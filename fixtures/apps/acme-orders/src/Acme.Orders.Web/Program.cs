using Acme.Orders.Data;
using Acme.Orders.Web.Endpoints;
using Acme.Orders.Web.Services;
using Acme.Orders.Web.Storage;

var builder = WebApplication.CreateBuilder(args);

var databasePath = builder.Configuration["Database:Path"] ?? Path.Combine(Path.GetTempPath(), "acme-orders.db");
builder.Services.AddSingleton(new Database(databasePath));
builder.Services.AddScoped<CustomerRepository>();
builder.Services.AddSingleton<FileStore>();
builder.Services.AddSingleton<OrderExport>();
builder.Services.AddHostedService<ExportCleanupService>();

if (string.Equals(builder.Configuration["Search:Mode"], "legacy", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddScoped<IOrderSearch, LegacyOrderSearch>();
}
else
{
    builder.Services.AddScoped<IOrderSearch, ParameterizedOrderSearch>();
}

builder.Services.AddControllers();

var app = builder.Build();
app.Services.GetRequiredService<Database>().EnsureSeeded();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapLinkEndpoints();
app.MapControllers();

app.Run();
