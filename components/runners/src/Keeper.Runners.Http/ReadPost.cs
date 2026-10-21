using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;

namespace Keeper.Runners.Http;

/// <summary>
/// POSTs that only read. An API that takes its read queries as POSTs (Check Point's show- commands, Azure
/// Resource Graph) is only ever POSTed on the paths its integration type lists; any other path is refused
/// before anything is sent. The body is the rule's own fixed text - never something a tenant types.
/// </summary>
public static class ReadPost
{
    /// <summary>
    /// The path (its query string ignored) matches one of the patterns exactly, case included: '*' stands for
    /// one path segment's plain characters, never a '/', '%' or '..' that could walk elsewhere.
    /// </summary>
    public static bool Allow(IReadOnlyList<string> patterns, string path)
    {
        var bare = path.Split('?')[0];
        // Within a segment: letters, digits, _ ~ - and single dots (v1.8), never two dots in a row.
        return patterns.Any(p => Regex.IsMatch(bare, @"\A" + Regex.Escape(p).Replace(@"\*", @"(?:[A-Za-z0-9_~-]|\.(?!\.))*", StringComparison.Ordinal) + @"\z",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
    }

    /// <summary>
    /// Why a POST body may not be sent to an API that runs named commands, or null when it may: the body must
    /// name one command, a plain name ('*' in a pattern stands for letters and digits) that one of the type's
    /// patterns matches exactly, case included - Get-Mailbox, never Set-Mailbox or "Get-X; Remove-Y".
    /// </summary>
    public static string? CommandProblem(ReadCommand? command, JsonObject? body)
    {
        if (command is null)
            return null;
        if (!Single(body, command.Field, out var node))
            return $"the body names {command.Field} more than once";
        if (node is not JsonValue || Values.Text(node) is not { Length: > 0 } name)
            return $"the body must name its command in {command.Field}";
        var allowed = command.Allowed.Any(p => Regex.IsMatch(name, @"\A" + Regex.Escape(p).Replace(@"\*", "[A-Za-z0-9]*", StringComparison.Ordinal) + @"\z",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
        if (!allowed)
            return $"the command {HttpEngine.Truncate(name, 60)} is not one the integration type runs ({string.Join(", ", command.Allowed)})";
        if (command.ParametersField is { } parametersField)
        {
            if (!Single(body, parametersField, out var parameters))
                return $"the body names {parametersField} more than once";
            if (parameters is not (null or JsonObject))
                return $"{parametersField} must be a mapping of parameter names";
            if (parameters is JsonObject given && given.Select(p => p.Key).FirstOrDefault(k => command.DeniedParameters.Contains(k, StringComparer.OrdinalIgnoreCase)) is { } denied)
                return $"the parameter {denied} makes {name} do more than read";
        }
        return null;
    }

    /// <summary>
    /// The node at a dotted path, found by any case - and false when a step has two fields that differ only in
    /// case: a server that binds names case-insensitively must not find a second one beside the one checked.
    /// </summary>
    private static bool Single(JsonObject? body, string path, out JsonNode? node)
    {
        node = body;
        foreach (var part in path.Split('.'))
        {
            var matches = node is JsonObject obj ? obj.Where(p => string.Equals(p.Key, part, StringComparison.OrdinalIgnoreCase)).ToList() : [];
            if (matches.Count > 1)
                return false;
            node = matches.Count == 1 ? matches[0].Value : null;
        }
        return true;
    }

    /// <summary>Sets a value at a dotted path in a request body, creating the objects on the way ("options.$skipToken").</summary>
    public static void Set(JsonObject body, string dotted, JsonNode? value)
    {
        var parts = dotted.Split('.');
        var node = body;
        foreach (var part in parts[..^1])
        {
            if (node[part] is not JsonObject child)
                node[part] = child = [];
            node = child;
        }
        node[parts[^1]] = value;
    }

    /// <summary><see cref="Set(JsonObject, string, JsonNode?)"/>, then the same request again: the next page of a body-paged read.</summary>
    public static Uri Set(JsonObject body, string dotted, JsonNode? value, Uri same)
    {
        Set(body, dotted, value);
        return same;
    }
}
