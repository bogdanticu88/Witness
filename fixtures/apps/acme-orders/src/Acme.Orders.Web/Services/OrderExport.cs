using Newtonsoft.Json;

namespace Acme.Orders.Web.Services;

public sealed class OrderExport
{
    public string Serialize(IEnumerable<Dictionary<string, object?>> rows) =>
        JsonConvert.SerializeObject(rows, Formatting.Indented);

    public List<Dictionary<string, object?>> Parse(string json) =>
        JsonConvert.DeserializeObject<List<Dictionary<string, object?>>>(json) ?? [];
}
