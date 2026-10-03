namespace Acme.Orders.Data;

public sealed class CustomerRepository
{
    private readonly Database _database;

    public CustomerRepository(Database database)
    {
        _database = database;
    }

    public List<Dictionary<string, object?>> FindByName(string name)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, name, email FROM customers WHERE name = '" + name + "'";
        return command.ReadAll();
    }

    public List<Dictionary<string, object?>> FindByEmail(string email)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, name, email FROM customers WHERE email = '" + SqlText.Escape(email) + "'";
        return command.ReadAll();
    }

    public long CountEast() => CountWhere("region = 'east'");

    public long CountWest() => CountWhere("region = 'west'");

    private long CountWhere(string filter)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM customers WHERE " + filter;
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }
}
