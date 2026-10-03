using Shop.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddScoped<ProductRepository>();
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddScoped<IProductFinder, ConcatenatingFinder>();
}
else
{
    builder.Services.AddScoped<IProductFinder, ParameterizedFinder>();
}

var app = builder.Build();
var api = app.MapGroup("/api");
api.MapGet("/next", (string next) => Results.Redirect(next));
api.MapGet("/count", (string category, ProductRepository repository) => repository.CountByCategory(category));
app.MapControllers();
app.Run();
