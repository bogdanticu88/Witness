using System.Data.Common;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var databasePath = app.Configuration["Database:Path"] ?? Path.Combine(Path.GetTempPath(), "acme-billing.db");
var connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
InvoiceStore.Seed(connectionString);

app.MapGet("/invoices", (string customer) =>
{
    var rows = InvoiceStore.ForCustomer(connectionString, customer);
    return Results.Content(JsonConvert.SerializeObject(rows), "application/json");
});

app.Run();

static class InvoiceStore
{
    public static void Seed(string connectionString)
    {
        using var connection = Open(connectionString);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY, customer TEXT NOT NULL, amount REAL NOT NULL);
            DELETE FROM invoices;
            INSERT INTO invoices (id, customer, amount) VALUES (1, 'ana', 120.0), (2, 'ben', 75.5);
            """;
        command.ExecuteNonQuery();
    }

    public static List<object[]> ForCustomer(string connectionString, string customer)
    {
        using var connection = Open(connectionString);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, amount FROM invoices WHERE customer = '" + customer + "'";
        var rows = new List<object[]>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add([reader.GetInt64(0), reader.GetDouble(1)]);
        }
        return rows;
    }

    private static DbConnection Open(string connectionString)
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }
}
