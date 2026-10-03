namespace Acme.Orders.Web.Validation;

public static class InputRules
{
    public static void EnsureSqlSafe(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 64)
        {
            throw new ArgumentException("value is empty or too long", nameof(value));
        }
    }
}
