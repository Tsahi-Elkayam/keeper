using System.Text;
using System.Text.Json;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Keeper.Integrations;

/// <summary>
/// Which Microsoft Graph application permissions a Graph request path needs (graph-permissions.yaml, built in), and
/// what an access token grants. Lets 'keeper connect' say, before any scan, which rules a tenant's consent leaves
/// unable to run - instead of the first scan finding out one 403 at a time.
/// </summary>
public static class GraphPermissions
{
    /// <summary>One line of the map: a path prefix, an optional field the rule must select, the permissions of which one is enough.</summary>
    public sealed record Entry(string Path, string? Select, IReadOnlyList<string> Any, bool Confirm);

    /// <summary>A rule's need: one of <see cref="Any"/>. A rule may have several needs, all required.</summary>
    public sealed record Need(IReadOnlyList<string> Any, bool Confirm)
    {
        public bool MetBy(IReadOnlySet<string> granted) => Any.Any(granted.Contains);

        /// <summary>How the need reads to a person: the first permission, and the others that would also do.</summary>
        public string Text => Any.Count == 1 ? Any[0] : $"{Any[0]} (or {string.Join(", ", Any.Skip(1))})";
    }

    private sealed class EntryDto
    {
        public string? Path { get; set; }
        public string? Select { get; set; }
        public List<string>? Any { get; set; }
        public bool Confirm { get; set; }
    }

    private static readonly Lazy<IReadOnlyList<Entry>> BuiltInMap = new(() =>
    {
        using var stream = typeof(GraphPermissions).Assembly.GetManifestResourceStream("integrations/graph-permissions.yaml")
            ?? throw new InvalidOperationException("The Graph permission map is missing from Keeper.Integrations.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    });

    public static IReadOnlyList<Entry> Map => BuiltInMap.Value;

    public static IReadOnlyList<Entry> Parse(string yaml)
    {
        List<EntryDto> dtos;
        try
        {
            dtos = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build()
                .Deserialize<List<EntryDto>>(yaml) ?? [];
        }
        catch (YamlException ex)
        {
            throw new InvalidOperationException($"graph-permissions.yaml, line {ex.Start.Line}: {(ex.InnerException ?? ex).Message}", ex);
        }
        return dtos.Select((d, i) => d.Path is { Length: > 1 } path && path[0] == '/' && d.Any is { Count: > 0 } any
                ? new Entry(path.TrimEnd('/'), d.Select, any, d.Confirm)
                : throw new InvalidOperationException($"graph-permissions.yaml entry {i + 1}: needs a path starting with / and at least one permission in any."))
            .ToList();
    }

    /// <summary>
    /// What a request needs: the entries of the longest path that matches (a '*' segment matches one segment), those
    /// with a select only when the request selects that field. Null when no entry matches: the map does not know it.
    /// </summary>
    public static IReadOnlyList<Need>? Needs(string path, IEnumerable<string> select, IReadOnlyList<Entry>? map = null)
    {
        map ??= Map;
        var request = Segments(path);
        var selected = select.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var matching = map.Where(e => Matches(Segments(e.Path), request)).ToList();
        if (matching.Count == 0)
            return null;
        var longest = matching.Max(e => Segments(e.Path).Count);
        return matching.Where(e => Segments(e.Path).Count == longest && (e.Select is null || selected.Contains(e.Select)))
            .Select(e => new Need(e.Any, e.Confirm))
            .ToList();
    }

    /// <summary>The path's segments without its query and without the key or function arguments after a '('.</summary>
    private static List<string> Segments(string path)
    {
        var bare = path.Split('?')[0].Trim();
        return bare.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.IndexOf('(', StringComparison.Ordinal) is var i and > 0 ? s[..i] : s)
            .Select(s => s.StartsWith('{') ? "*" : s)
            .ToList();
    }

    private static bool Matches(List<string> prefix, List<string> request) =>
        prefix.Count <= request.Count
        && prefix.Select((s, i) => s == "*" || request[i] == "*" || string.Equals(s, request[i], StringComparison.OrdinalIgnoreCase)).All(x => x);

    /// <summary>
    /// The permissions an access token carries: application permissions ('roles'), and delegated ones ('scp') when
    /// someone signed in. Read from the token's payload only; the signature is the issuer's business, not checked here.
    /// </summary>
    public static IReadOnlySet<string> Granted(string accessToken)
    {
        var parts = accessToken.Split('.');
        if (parts.Length < 2)
            throw new ArgumentException("not a JSON web token");
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var json = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
        var granted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (json.RootElement.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
            granted.UnionWith(roles.EnumerateArray().Select(r => r.GetString()).OfType<string>());
        if (json.RootElement.TryGetProperty("scp", out var scp) && scp.ValueKind == JsonValueKind.String)
            granted.UnionWith(scp.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries));
        return granted;
    }

    /// <summary>The token's audience and expiry, for the line that says who Keeper signed in as and until when.</summary>
    public static (string? Audience, DateTimeOffset? Expires, string? AppName) Describe(string accessToken)
    {
        var parts = accessToken.Split('.');
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var json = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
        var root = json.RootElement;
        return (root.TryGetProperty("aud", out var aud) ? aud.GetString() : null,
                root.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var seconds) ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null,
                root.TryGetProperty("app_displayname", out var name) ? name.GetString() : null);
    }

    /// <summary>Every permission the map can ask for, the first of each 'any' (the one the setup guide grants).</summary>
    public static IReadOnlyList<string> Recommended(IReadOnlyList<Entry>? map = null) =>
        [.. (map ?? Map).Select(e => e.Any[0]).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)];
}
