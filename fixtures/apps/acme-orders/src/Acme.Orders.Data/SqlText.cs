namespace Acme.Orders.Data;

public static class SqlText
{
    // Escapes a value for use inside a single-quoted SQLite string literal.
    public static string Escape(string value) => value.Replace("'", "''");
}
