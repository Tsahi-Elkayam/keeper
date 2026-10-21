using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keeper.Runners;

/// <summary>Turning what systems return into row values: text, numbers, booleans, ISO dates.</summary>
public static class RowValues
{
    public static JsonNode? From(object? value) => value switch
    {
        null or DBNull => null,
        string s => JsonValue.Create(s),
        bool b => JsonValue.Create(b),
        byte or sbyte or short or ushort or int or uint or long => JsonValue.Create(Convert.ToInt64(value, CultureInfo.InvariantCulture)),
        ulong u => JsonValue.Create(u.ToString(CultureInfo.InvariantCulture)),
        float or double or decimal => JsonValue.Create(Convert.ToDouble(value, CultureInfo.InvariantCulture)),
        DateTime dt => JsonValue.Create(Iso(new DateTimeOffset(dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt))),
        DateTimeOffset dto => JsonValue.Create(Iso(dto)),
        TimeSpan ts => JsonValue.Create(ts.TotalSeconds),
        Guid g => JsonValue.Create(g.ToString()),
        byte[] bytes => JsonValue.Create(Convert.ToBase64String(bytes)),
        Array array => new JsonArray(array.Cast<object?>().Select(From).ToArray()),
        _ => JsonValue.Create(Convert.ToString(value, CultureInfo.InvariantCulture)),
    };

    public static string Iso(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>JSON from an HTTP body, as rows: the array at <paramref name="items"/>, or OData "value", or the root.</summary>
    public static IReadOnlyList<JsonObject> ItemsOf(JsonNode? body, string? items)
    {
        JsonNode? node = body;
        if (!string.IsNullOrEmpty(items))
            node = Keeper.Rules.FieldPath.First(body, items);
        else if (body is JsonObject o && o["value"] is JsonArray odata)
            node = odata;

        // A list of plain values ("GREEN", or ["ntp1", "ntp2"]) becomes one row per value as { value: ... },
        // so a count over it is a real count - dropped, it would always look like a pass.
        return node switch
        {
            JsonArray array => array.Where(e => e is not null)
                .Select(e => e is JsonObject o ? Detach(o) : new JsonObject { ["value"] = e!.DeepClone() }).ToList(),
            JsonObject single => [Detach(single)],
            JsonValue scalar => [new JsonObject { ["value"] = scalar.DeepClone() }],
            _ => [],
        };
    }

    /// <summary>A row of its own, with every secret property masked (<see cref="SecretProperties"/>).</summary>
    public static JsonObject Detach(JsonObject node)
    {
        var row = (JsonObject)JsonNode.Parse(node.ToJsonString())!;
        SecretProperties.Mask(row);
        return row;
    }

    public static JsonNode? Parse(string text)
    {
        try
        {
            return JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
