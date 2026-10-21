using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

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
