using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// Operational and Scan Coverage Report ("מה נבדק לעומת מה שקיים"):
/// 1. Estate &amp; discovery inventory coverage: answering vs not-answering vs likely-gone vs unresolved,
///    device kinds, management protocol reachability (SSH, WinRM, HTTPS, SNMP), unlisted machines,
///    and deep host inspection vs surface/directory-only visibility.
/// 2. System scan &amp; rule catalogue coverage: per (system, instance) standing (correct, should-configure,
///    broken, not-checked, not-run) and judged percentage.
/// 3. Operational blind spots: failed or partial query/target reads and unjudged checks.
/// 4. Unscanned catalogue rule packs: packs loaded in the catalogue that have never been scanned.
/// </summary>
public static class CoverageReport
{
    public static Document Build(SqliteConnection connection, DateTimeOffset now)
    {
        var estateSection = BuildEstateCoverageSection(connection);
        var systemSection = BuildSystemStandingSection(connection);
        var blindSpotSection = BuildBlindSpotsSection(connection);
        var unscannedSection = BuildUnscannedPacksSection(connection);

        return new Document(
            "Operational and scan coverage",
            $"What Keeper sees across the estate, how deeply it inspects each machine and system, and where blind spots remain. Generated {Iso.Utc(now)}.",
            [
                estateSection,
                systemSection,
                blindSpotSection,
                unscannedSection,
            ]);
    }

    private static Section BuildEstateCoverageSection(SqliteConnection connection)
    {
        var seenRows = Sql.Rows(connection,
            """
            SELECT r.system, r.instance, rs.entity_type, rs.entity_key, rs.entity_name, rs.attrs
            FROM row_seen rs
            JOIN latest_run r ON r.run_id = rs.run_id
            WHERE rs.entity_type IN ('computer', 'host')
            ORDER BY r.system, rs.entity_key;
            """);

        if (seenRows.Count == 0)
        {
            return new Section(
                "Estate and discovery inventory coverage",
                [],
                "No computer or network discovery rows are in the store yet. Run 'keeper discover' or scan a directory first.");
        }

        // Collect all entity_keys that have host-level result rows outside directory/network discovery
        var deepInspectedKeys = Sql.Rows(connection,
            """
            SELECT DISTINCT lower(res.entity_key) AS k
            FROM result res
            LEFT JOIN rule ru ON ru.rule_id = res.rule_id
            WHERE COALESCE(ru.system, res.instance) NOT IN ('network', 'active-directory', 'entra', 'hybrid-identity');
            """)
            .Select(r => r["k"] as string)
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .ToHashSet(StringComparer.OrdinalIgnoreCase)!;

        var assets = new Dictionary<string, AssetNode>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in seenRows)
        {
            var sys = (string)row["system"]!;
            var key = (string)row["entity_key"]!;
            var name = row["entity_name"] as string;
            var attrsJson = row["attrs"] as string;
            var attrs = attrsJson is not null ? JsonNode.Parse(attrsJson) as JsonObject : null;

            var canonical = CanonicalKey(key, name, attrs);
            if (!assets.TryGetValue(canonical, out var node))
            {
                node = new AssetNode(canonical);
                assets[canonical] = node;
            }

            node.Aliases.Add(key);
            if (key.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
                node.Aliases.Add(key[3..]);
            if (!string.IsNullOrWhiteSpace(name))
                node.Aliases.Add(name);

            if (sys == "network" && attrs is not null)
            {
                node.InNetwork = true;
                node.State = attrs["state"]?.GetValue<string>() ?? node.State;
                node.DeviceKind = attrs["kind"]?.GetValue<string>() ?? node.DeviceKind;

                if (attrs["sources"] is JsonArray sources)
                {
                    foreach (var s in sources)
                    {
                        var srcKind = s is JsonObject o ? o["kind"]?.GetValue<string>() : s?.GetValue<string>();
                        if (srcKind is "ad" or "directory")
                            node.InDirectory = true;
                    }
                }

                if (attrs["answered"] is JsonArray answered)
                {
                    foreach (var proto in answered.Select(x => x?.GetValue<string>()?.ToLowerInvariant()))
                    {
                        switch (proto)
                        {
                            case "ssh": node.HasSsh = true; break;
                            case "winrm": node.HasWinRm = true; break;
                            case "https": node.HasHttps = true; break;
                            case "snmp": node.HasSnmp = true; break;
                        }
                    }
                }

                if (attrs["snmp"] is not null)
                    node.HasSnmp = true;

                if (attrs["addresses"] is JsonArray addrs)
                {
                    foreach (var a in addrs.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)))
                        node.Aliases.Add(a!);
                }
            }
            else
            {
                node.InDirectory = true;
                if (attrs?["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
                    node.Aliases.Add(dns);
                if (attrs?["sAMAccountName"]?.GetValue<string>() is { Length: > 0 } sam)
                    node.Aliases.Add(sam.TrimEnd('$'));
                node.DeviceKind ??= "directory-computer";
            }
        }

        foreach (var node in assets.Values)
        {
            if (node.Aliases.Any(a => deepInspectedKeys.Contains(a)))
                node.DeepInspected = true;
        }

        var total = assets.Count;
        var inNetwork = assets.Values.Count(a => a.InNetwork);
        var inDirectory = assets.Values.Count(a => a.InDirectory);
        var answering = assets.Values.Count(a => a.State == "answering");
        var notAnswering = assets.Values.Count(a => a.State == "not-answering");
        var likelyGone = assets.Values.Count(a => a.State == "likely-gone");
        var unresolved = assets.Values.Count(a => a.State == "unresolved");
        var excluded = assets.Values.Count(a => a.State == "excluded");
        var mgmtReachable = assets.Values.Count(a => a.HasMgmt);
        var sshCount = assets.Values.Count(a => a.HasSsh);
        var winrmCount = assets.Values.Count(a => a.HasWinRm);
        var httpsCount = assets.Values.Count(a => a.HasHttps);
        var snmpCount = assets.Values.Count(a => a.HasSnmp);
        var unlisted = assets.Values.Count(a => a.InNetwork && !a.InDirectory && a.State == "answering");
        var deepInspected = assets.Values.Count(a => a.DeepInspected);
        var surfaceOnly = total - deepInspected;

        var lines = new List<string>
        {
            string.Create(CultureInfo.InvariantCulture,
                $"Known machines/devices: {total} ({inNetwork} in network discovery, {inDirectory} in directory)."),
            string.Create(CultureInfo.InvariantCulture,
                $"Network reachability: {answering} answering, {notAnswering} not-answering, {likelyGone} likely-gone, {unresolved} unresolved DNS, {excluded} excluded."),
            string.Create(CultureInfo.InvariantCulture,
                $"Management protocol reachability: {mgmtReachable} reachable via at least one management channel (SSH: {sshCount}, WinRM: {winrmCount}, HTTPS: {httpsCount}, SNMP: {snmpCount})."),
            string.Create(CultureInfo.InvariantCulture,
                $"Unlisted / dark machines (answering on the network but absent from directory): {unlisted}."),
            string.Create(CultureInfo.InvariantCulture,
                $"Inspection depth: {deepInspected} with deep host-level checks (OS/services/SMB/TLS/events), {surfaceOnly} with surface or directory-only visibility."),
        };

        var byKind = assets.Values
            .GroupBy(a => a.DeviceKind ?? "unknown", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase);

        foreach (var g in byKind)
        {
            var kTotal = g.Count();
            var kAns = g.Count(a => a.State == "answering");
            var kMgmt = g.Count(a => a.HasMgmt);
            var kDeep = g.Count(a => a.DeepInspected);
            lines.Add(string.Create(CultureInfo.InvariantCulture,
                $"Kind '{g.Key}': {kTotal} total ({kAns} answering, {kMgmt} with management protocol, {kDeep} deeply inspected)"));
        }

        return new Section("Estate and discovery inventory coverage", lines);
    }

    private static Section BuildSystemStandingSection(SqliteConnection connection)
    {
        var systems = Sql.Rows(connection,
            """
            SELECT st.system, st.instance,
                   (SELECT lr.status FROM latest_run lr WHERE lr.system = st.system AND lr.instance = st.instance LIMIT 1) AS run_status,
                   COUNT(*) AS checks_in_standing,
                   SUM(st.standing = 'correct') AS correct_count,
                   SUM(st.standing = 'should-configure') AS should_count,
                   SUM(st.standing = 'broken') AS broken_count,
                   SUM(st.standing = 'not-checked') AS unchecked_count,
                   (SELECT COUNT(*) FROM rule r WHERE r.system = st.system) AS catalogue_rules,
                   substr(MAX(st.tested_at), 1, 10) AS scanned_on
            FROM rule_standing st
            GROUP BY st.system, st.instance
            ORDER BY st.system, st.instance;
            """);

        if (systems.Count == 0)
        {
            return new Section(
                "System scan and rule coverage",
                [],
                "No scanned systems have rule standings yet. Run 'keeper rules load' and 'keeper qm run'.");
        }

        var lines = systems.Select(s =>
        {
            var sys = (string)s["system"]!;
            var inst = (string)s["instance"]!;
            var status = s["run_status"] as string ?? "ok";
            var scanned = s["scanned_on"] as string ?? "-";
            var inStanding = s["checks_in_standing"] as long? ?? 0;
            var catalogue = s["catalogue_rules"] as long? ?? inStanding;
            var totalRules = Math.Max(inStanding, catalogue);
            var notRun = Math.Max(0, totalRules - inStanding);
            var correct = s["correct_count"] as long? ?? 0;
            var should = s["should_count"] as long? ?? 0;
            var broken = s["broken_count"] as long? ?? 0;
            var uncheckedCount = s["unchecked_count"] as long? ?? 0;
            var judged = correct + should + broken;
            var pct = totalRules > 0 ? (int)Math.Round(100.0 * judged / totalRules) : 0;

            return string.Create(CultureInfo.InvariantCulture,
                $"{sys} ({inst}, status={status}, scanned {scanned}): {judged}/{totalRules} rules judged ({pct}%) - {correct} correct, {should} should-configure, {broken} broken, {uncheckedCount} not-checked, {notRun} not-run");
        }).ToList();

        return new Section("System scan and rule coverage", lines)
        {
            Intro = "Rule catalogue coverage per scanned (system, instance). Judged % = (correct + should-configure + broken) / total rules in pack.",
        };
    }

    private static Section BuildBlindSpotsSection(SqliteConnection connection)
    {
        var lines = Sql.Rows(connection,
            """
            SELECT system, instance, detail, ord FROM (
                SELECT r.system AS system, r.instance AS instance,
                       c.scope || ' ' || c.item || ' was ' || c.state || COALESCE(': ' || c.reason, '') AS detail,
                       0 AS ord
                FROM coverage c
                JOIN latest_run r ON r.run_id = c.run_id
                WHERE c.scope IN ('query', 'target') AND c.state IN ('failed', 'partial')
                UNION ALL
                SELECT system, instance,
                       COUNT(*) || ' check(s) not-checked: ' || COALESCE(why_not_correct, 'no data'),
                       1 AS ord
                FROM rule_standing
                WHERE standing = 'not-checked'
                GROUP BY system, instance, why_not_correct
            )
            ORDER BY system, instance, ord;
            """)
            .Select(r => $"{r["system"]} ({r["instance"]}): {r["detail"]}")
            .ToList();

        return new Section(
            "Operational blind spots (failed and partial reads)",
            lines,
            "Every query, target, and rule check that ran could read its data.");
    }

    private static Section BuildUnscannedPacksSection(SqliteConnection connection)
    {
        var unscanned = Sql.Rows(connection,
            """
            SELECT r.system, COUNT(*) AS rule_count
            FROM rule r
            WHERE NOT EXISTS (
                SELECT 1 FROM latest_run lr WHERE lr.system = r.system
            )
            GROUP BY r.system
            ORDER BY r.system;
            """)
            .Select(r => string.Create(CultureInfo.InvariantCulture,
                $"{r["system"]}: {r["rule_count"]} rule(s) in catalogue, 0 scans recorded"))
            .ToList();

        return new Section(
            "Unscanned catalogue rule packs",
            unscanned,
            "Every rule pack loaded in the catalogue has at least one scan run.");
    }

    private static string CanonicalKey(string entityKey, string? entityName, JsonObject? attrs)
    {
        if (attrs?["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
            return dns.Trim().TrimEnd('.').ToLowerInvariant();

        if (attrs?["names"] is JsonArray names)
        {
            var firstDns = names.Select(x => x?.GetValue<string>()).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
            if (!string.IsNullOrWhiteSpace(firstDns))
                return firstDns.Trim().TrimEnd('.').ToLowerInvariant();
        }

        if (!string.IsNullOrWhiteSpace(entityName) && !entityName.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
            return entityName.Trim().TrimEnd('.', '$').ToLowerInvariant();

        var cleaned = entityKey.StartsWith("ip:", StringComparison.OrdinalIgnoreCase) ? entityKey[3..] : entityKey;
        return cleaned.Trim().TrimEnd('.', '$').ToLowerInvariant();
    }

    private sealed class AssetNode(string key)
    {
        public string Key { get; } = key;
        public HashSet<string> Aliases { get; } = new(StringComparer.OrdinalIgnoreCase) { key };
        public bool InNetwork { get; set; }
        public bool InDirectory { get; set; }
        public string? State { get; set; }
        public string? DeviceKind { get; set; }
        public bool HasSsh { get; set; }
        public bool HasWinRm { get; set; }
        public bool HasHttps { get; set; }
        public bool HasSnmp { get; set; }
        public bool HasMgmt => HasSsh || HasWinRm || HasHttps || HasSnmp;
        public bool DeepInspected { get; set; }
    }
}
