using System.Data.Common;
using Verdicts;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddScoped<Repository>();
builder.Services.AddScoped<Reports>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<DbConnection>(_ => throw new NotSupportedException("no database in the sample"));
var app = builder.Build();
app.MapControllers();
app.MapGet("/v38", (HttpContext context, DbConnection db) =>
{
    using var command = db.CreateCommand();
    command.CommandText = "SELECT 1 FROM t WHERE a = '" + context.Request.Query["q"] + "'"; // case: V38
    return command.ExecuteScalar();
});
app.Run();
