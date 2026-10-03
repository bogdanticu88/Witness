using System.Data.Common;
using Microsoft.Data.Sqlite;

namespace Acme.Orders.Data;

public sealed class Database
{
    private readonly string _connectionString;

    public Database(string path)
    {
        _connectionString = new SqliteConnectionStringBuilder { DataSource = path }.ToString();
    }

    public DbConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public void EnsureSeeded()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, region TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, status TEXT NOT NULL, total REAL NOT NULL, reference TEXT NOT NULL);
            DELETE FROM orders;
            DELETE FROM customers;
            INSERT INTO customers (id, name, email, region) VALUES
                (1, 'Ana Popescu', 'ana@example.test', 'east'),
                (2, 'Ben Carter', 'ben@example.test', 'west'),
                (3, 'Chloe Martin', 'chloe@example.test', 'east');
            INSERT INTO orders (id, customer_id, status, total, reference) VALUES
                (100, 1, 'shipped', 42.50, 'AC-100'),
                (101, 1, 'pending', 12.00, 'AC-101'),
                (102, 2, 'cancelled', 99.99, 'AC-102'),
                (103, 3, 'shipped', 7.25, 'AC-103');
            """;
        command.ExecuteNonQuery();
    }
}

public static class CommandExtensions
{
    public static void AddParameter(this DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    public static List<Dictionary<string, object?>> ReadAll(this DbCommand command)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var row = new Dictionary<string, object?>();
            for (var i = 0; i < reader.FieldCount; i++)
            {
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            }
            rows.Add(row);
        }
        return rows;
    }
}
