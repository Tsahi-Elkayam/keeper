using System.Text.Json;

namespace Keeper.Queue;

/// <summary>Reads payload fields. A missing or invalid required field is a RequestException.</summary>
public static class Payload
{
    public static string? Text(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static string Required(JsonElement payload, string name) =>
        Text(payload, name) is { Length: > 0 } value ? value : throw new RequestException($"payload.{name} is required.");

    public static string OneOf(JsonElement payload, string name, params string[] allowed)
    {
        var value = Required(payload, name);
        return allowed.Contains(value, StringComparer.Ordinal)
            ? value
            : throw new RequestException($"payload.{name} must be one of: {string.Join(", ", allowed)}.");
    }
}
