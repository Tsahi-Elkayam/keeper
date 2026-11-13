using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using Keeper.Runners.Host;

namespace Keeper.Scan;

/// <summary>
/// Scan targets taken from what discovery found: the answering devices of the kinds an integration names (targetsFrom
/// discovery, targetsKind printer), kept to the integration's own scope. The list is only as good as the inventory, so
/// a missing, degraded or old one is said, and the scan that used it is partial rather than quietly short.
/// </summary>
public static class DiscoveryTargets
{
    public const int StaleAfterDays = 14;

    public static (IReadOnlyList<string> Targets, string? Problem) Read(string importsDir, string kinds, string? scope, string integrationType, DateTimeOffset now)
    {
        var path = Path.Combine(importsDir, "discovery", "inventory.json");
        if (!File.Exists(path))
            return ([], $"there is no discovery inventory ({path}): run 'keeper discover' first");

        JsonNode? inventory;
        try
        {
            inventory = JsonNode.Parse(File.ReadAllText(path));
        }
        catch (JsonException)
        {
            return ([], $"the discovery inventory ({path}) is not readable: run 'keeper discover' again");
        }

        var wanted = kinds.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(k => k.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        var targets = new List<string>();
        foreach (var asset in inventory?["assets"] as JsonArray ?? [])
        {
            if (asset is not JsonObject a || !string.Equals(a["state"]?.ToString(), "answering", StringComparison.Ordinal)
                || a["kind"]?.ToString()?.ToLowerInvariant() is not { } kind || !wanted.Contains(kind))
                continue;
            var addresses = (a["addresses"] as JsonArray ?? []).Select(n => n?.ToString()).OfType<string>().ToList();
            var names = (a["names"] as JsonArray ?? []).Select(n => n?.ToString()).OfType<string>().ToList();
            // An IPv4 address is the most reliable way to reach it; failing that any address, failing that its name.
            var target = addresses.FirstOrDefault(x => System.Net.IPAddress.TryParse(x, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?? addresses.FirstOrDefault() ?? names.FirstOrDefault();
            if (target is null)
                continue;
            // Integrations whose endpoint is a scope only ever talk inside it: others would just be refused one by one.
            if (integrationType is "ssh" or "printer" && !string.IsNullOrWhiteSpace(scope) && !SshScope.Allows(target, scope))
                continue;
            if (!targets.Contains(target, StringComparer.Ordinal))
                targets.Add(target);
        }

        var problems = new List<string>();
        var health = inventory?["scanHealth"]?.ToString();
        if (health is not null and not "ok")
            problems.Add($"the discovery inventory's own scan was {health}, so devices may be missing from the list");
        var age = now - File.GetLastWriteTimeUtc(path);
        if (age.TotalDays > StaleAfterDays)
            problems.Add($"the discovery inventory is {(int)age.TotalDays} days old, so new devices may be missing");
        if (targets.Count == 0)
            problems.Add($"discovery found no answering device of kind {string.Join(", ", wanted)}{(string.IsNullOrWhiteSpace(scope) ? "" : $" inside {scope}")}");
        return (targets, problems.Count == 0 ? null : string.Join("; ", problems));
    }
}
