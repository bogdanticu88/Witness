using System.Data.Common;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddScoped<DbConnection>(_ => throw new NotSupportedException("no database in the sample"));
var app = builder.Build();
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});
app.MapControllers();
app.Run();
