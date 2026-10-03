namespace Acme.Orders.Data;

public interface IOrderSearch
{
    List<Dictionary<string, object?>> ByReference(string reference);
}

public sealed class ParameterizedOrderSearch : IOrderSearch
{
    private readonly Database _database;

    public ParameterizedOrderSearch(Database database) => _database = database;

    public List<Dictionary<string, object?>> ByReference(string reference)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, status, total FROM orders WHERE reference = @reference";
        command.AddParameter("@reference", reference);
        return command.ReadAll();
    }
}

// Kept for the reporting replica, which does not support parameters on the
// old driver. Selected with Search:Mode=legacy.
public sealed class LegacyOrderSearch : IOrderSearch
{
    private readonly Database _database;

    public LegacyOrderSearch(Database database) => _database = database;

    public List<Dictionary<string, object?>> ByReference(string reference)
    {
        using var connection = _database.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, status, total FROM orders WHERE reference LIKE '" + reference + "%'";
        return command.ReadAll();
    }
}
