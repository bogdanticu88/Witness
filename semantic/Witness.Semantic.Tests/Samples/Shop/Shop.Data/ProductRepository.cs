using System.Data.Common;

namespace Shop.Data;

public class ProductRepository
{
    private readonly DbConnection _connection;

    public ProductRepository(DbConnection connection)
    {
        _connection = connection;
    }

    public object? FindByName(string name)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT id FROM products WHERE name = '" + name + "'";
        return command.ExecuteScalar();
    }

    public object? CountByCategory(string category) => Count("category = '" + category + "'");

    public object? CountAll() => Count("1 = 1");

    private object? Count(string where)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM products WHERE " + where;
        return command.ExecuteScalar();
    }

    public object? CountActive() => CountWhere("active = 1");

    public object? CountDiscontinued() => CountWhere("discontinued = 1");

    private object? CountWhere(string where)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM products WHERE " + where;
        return command.ExecuteScalar();
    }
}

public interface IProductFinder
{
    object? Find(string term);
}

public class ParameterizedFinder : IProductFinder
{
    private readonly DbConnection _connection;

    public ParameterizedFinder(DbConnection connection) => _connection = connection;

    public object? Find(string term)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT id FROM products WHERE name = @term";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "@term";
        parameter.Value = term;
        command.Parameters.Add(parameter);
        return command.ExecuteScalar();
    }
}

public class ConcatenatingFinder : IProductFinder
{
    private readonly DbConnection _connection;

    public ConcatenatingFinder(DbConnection connection) => _connection = connection;

    public object? Find(string term)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT id FROM products WHERE name LIKE '%" + term + "%'";
        return command.ExecuteScalar();
    }
}
