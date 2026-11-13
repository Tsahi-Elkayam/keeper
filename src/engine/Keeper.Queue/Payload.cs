using System.Globalization;
using System.Text.Json;
using Keeper.Common;

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

    public static bool? Bool(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : null;

    public static int? Int(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : null;

    public static double? Number(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetDouble() : null;

    /// <summary>A yyyy-MM-dd date, or null when the field is absent. Anything else is refused.</summary>
    public static string? Date(JsonElement payload, string name)
    {
        var text = Text(payload, name);
        if (text is null)
            return null;
        return DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)
            ? text
            : throw new RequestException($"payload.{name} must be a date (yyyy-MM-dd).");
    }

    public static IReadOnlyList<string> List(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
            : [];

    /// <summary>
    /// A file a request points at: { "file": "&lt;path under the data folder&gt;", "sha256": "..." }.
    /// The path must stay inside the data folder and the file must still have the hash it was
    /// submitted with - so nothing can swap the file between submit and apply.
    /// </summary>
    public static string VerifiedFile(RequestContext context, string fileField = "file", string hashField = "sha256")
    {
        var relative = Required(context.Request.Payload, fileField);
        var expected = Required(context.Request.Payload, hashField);
        string full;
        try
        {
            full = PathGuard.Resolve(context.DataDir, relative);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new RequestException(ex.Message);
        }
        if (!File.Exists(full))
            throw new RequestException($"payload.{fileField}: {relative} does not exist.");
        if (!string.Equals(Hashing.Sha256File(full), expected, StringComparison.OrdinalIgnoreCase))
            throw new RequestException($"payload.{fileField}: {relative} changed after it was submitted.");
        return full;
    }
}
