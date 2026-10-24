using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// keeper ui: the whole picture as one interactive page - no server, no port, nothing fetched from anywhere. The
/// store's answers are embedded as JSON and drawn by the page's own script. Everything that came from a scanned
/// system is written as text (textContent), never as markup, and the JSON escapes '&lt;' so it cannot close its
/// script element.
/// </summary>
public static class Ui
{
    public static string Build(SqliteConnection connection, DateTimeOffset now, string? tenant)
    {
        var gpoNames = Reports.GpoNames(connection);
        string? Named(object? value) => value is string text ? Reports.Named(text, gpoNames) : null;

        var systems = Rows(connection,
            """
            SELECT st.system, st.instance, COUNT(*) AS checks,
                   SUM(st.standing = 'correct') AS correct, SUM(st.standing = 'should-configure') AS should,
                   SUM(st.standing = 'broken') AS broken, SUM(st.standing = 'not-checked') AS unchecked,
                   (SELECT COUNT(*) FROM rule r WHERE r.system = st.system) - COUNT(*) AS norun,
                   MAX(st.tested_at) AS scanned
            FROM rule_standing st GROUP BY st.system, st.instance ORDER BY st.system, st.instance;
            """);

        // Open findings, one entry per check, with every object it was found on.
        var objects = new Dictionary<string, JsonArray>(StringComparer.Ordinal);
        foreach (var r in Sql.Rows(connection,
                     "SELECT check_id, target, COALESCE(entity_name, target) AS name, evidence FROM active_finding ORDER BY check_id, name;"))
        {
            var id = (string)r["check_id"]!;
            if (!objects.TryGetValue(id, out var list))
                objects[id] = list = [];
            list.Add(new JsonArray(Named(r["name"]), Named(r["evidence"]), r["target"] as string));
        }

        var checks = new JsonArray();
        foreach (var r in Sql.Rows(connection,
                     """
                     SELECT check_id, MIN(severity_rank) AS rank, severity, kind, title, why, fix, refs, system, category, security,
                            COUNT(*) AS n, COUNT(DISTINCT system_id) AS sys_count, MIN(first_seen) AS first_seen
                     FROM active_finding GROUP BY check_id ORDER BY rank, n DESC, title;
                     """))
        {
            var id = (string)r["check_id"]!;
            checks.Add(new JsonObject
            {
                ["id"] = id,
                ["severity"] = (string?)r["severity"],
                ["kind"] = (string?)r["kind"],
                ["title"] = (string?)r["title"],
                ["why"] = (string?)r["why"],
                ["fix"] = (string?)r["fix"],
                ["system"] = (string?)r["system"],
                ["category"] = (string?)r["category"],
                ["security"] = r["security"] is 1L,
                ["count"] = (long)r["n"]!,
                ["sysCount"] = (long)r["sys_count"]!,
                ["firstSeen"] = (string?)r["first_seen"],
                ["refs"] = r["refs"] is string refs && JsonNode.Parse(refs) is JsonArray parsed ? parsed : new JsonArray(),
                ["objects"] = objects.TryGetValue(id, out var list) ? list : new JsonArray(),
            });
        }

        // Cross-cutting categories
        var categories = Rows(connection,
            """
            SELECT c.code, c.name, c.security,
                   COUNT(f.finding_key) AS open,
                   SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN f.kind = 'broken' THEN 1 ELSE 0 END) AS broken,
                   SUM(CASE WHEN f.kind IN ('misconfigured', 'missing') THEN 1 ELSE 0 END) AS config,
                   COUNT(DISTINCT f.system_id) AS systems,
                   COUNT(DISTINCT f.target) AS targets,
                   (SELECT COUNT(*) FROM rule_standing st JOIN rule r ON r.rule_id = st.rule_id WHERE r.category = c.code AND st.standing = 'correct') AS correct,
                   (SELECT COUNT(*) FROM rule_standing st JOIN rule r ON r.rule_id = st.rule_id WHERE r.category = c.code) AS ran
            FROM category c
            LEFT JOIN active_finding f ON f.category = c.code
            GROUP BY c.code, c.name, c.security
            HAVING open > 0 OR ran > 0
            ORDER BY critical DESC, high DESC, open DESC, c.code;
            """);

        // Operations vs security split per business system
        var systemSplit = Rows(connection,
            """
            SELECT f.system_id AS id, COALESCE(s.name, f.system_id) AS name,
                   COUNT(*) AS open,
                   SUM(f.severity IN ('critical', 'high')) AS serious,
                   SUM(f.kind = 'broken') AS broken,
                   SUM(f.kind IN ('misconfigured', 'missing')) AS config,
                   SUM(f.security = 0) AS maintenance,
                   SUM(f.security = 1) AS security
            FROM active_finding f
            LEFT JOIN system s ON s.system_id = f.system_id
            GROUP BY f.system_id
            ORDER BY serious DESC, open DESC, f.system_id;
            """);

        var (entities, estateCoverage) = BuildEntitiesAndEstate(connection, gpoNames);

        var data = new JsonObject
        {
            ["generated"] = now.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture),
            ["tenant"] = tenant,
            ["systems"] = systems,
            ["checks"] = checks,
            ["categories"] = categories,
            ["systemSplit"] = systemSplit,
            ["entities"] = entities,
            ["estate"] = estateCoverage,
            ["passed"] = Rows(connection,
                """
                SELECT st.system, st.rule_id AS id, st.title, st.severity, st.passed, st.threshold_override AS override
                FROM rule_standing st JOIN severity s ON s.code = st.severity
                WHERE st.standing = 'correct' ORDER BY st.system, s.rank, st.rule_id;
                """),
            ["unchecked"] = Rows(connection,
                "SELECT system, rule_id AS id, title, severity, why_not_correct AS why FROM rule_standing WHERE standing = 'not-checked' ORDER BY system, rule_id;"),
            ["coverage"] = Rows(connection,
                """
                SELECT r.system, c.scope, c.item, c.state, c.reason, COUNT(*) AS n
                FROM coverage c JOIN latest_run r ON r.run_id = c.run_id
                WHERE c.scope IN ('query', 'target') AND c.state IN ('failed', 'partial')
                GROUP BY r.system, c.scope, c.item, c.state, c.reason ORDER BY r.system, c.scope;
                """),
            ["neverScanned"] = Rows(connection,
                "SELECT system, COUNT(*) AS rules FROM rule WHERE system NOT IN (SELECT DISTINCT system FROM rule_standing) GROUP BY system ORDER BY rules DESC;"),
        };

        // The default encoder escapes < > & ' " and every non-ASCII character, so the JSON is inert inside the page.
        return Page.Replace("/*KEEPER-DATA*/", data.ToJsonString(), StringComparison.Ordinal);
    }

    private static (JsonArray Entities, JsonObject Estate) BuildEntitiesAndEstate(
        SqliteConnection connection,
        IReadOnlyDictionary<string, string> gpoNames)
    {
        var nodes = new Dictionary<string, EntityNode>(StringComparer.OrdinalIgnoreCase);
        var aliasMap = new Dictionary<string, EntityNode>(StringComparer.OrdinalIgnoreCase);

        void RegisterAlias(EntityNode node, string? alias)
        {
            if (string.IsNullOrWhiteSpace(alias) || alias == "-")
                return;
            var trimmed = alias.Trim();
            node.Aliases.Add(trimmed);
            aliasMap.TryAdd(trimmed, node);
            if (trimmed.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
            {
                var bareIp = trimmed[3..];
                node.Aliases.Add(bareIp);
                aliasMap.TryAdd(bareIp, node);
            }
        }

        EntityNode? ResolveNode(string? key, string? name)
        {
            foreach (var candidate in new[] { key, name })
            {
                if (string.IsNullOrWhiteSpace(candidate) || candidate == "-")
                    continue;
                if (aliasMap.TryGetValue(candidate, out var found))
                    return found;
                var slash = candidate.IndexOf('/', StringComparison.Ordinal);
                if (slash >= 0 && aliasMap.TryGetValue(candidate[(slash + 1)..], out found))
                    return found;
                var pipe = candidate.IndexOf('|', StringComparison.Ordinal);
                if (pipe >= 0 && aliasMap.TryGetValue(candidate[..pipe], out found))
                    return found;
            }
            return null;
        }

        // 1. Read row_seen from newest runs
        var seenRows = Sql.Rows(connection,
            """
            SELECT r.system, r.instance, rs.entity_type, rs.entity_key, rs.entity_name, rs.attrs, rs.observed_at
            FROM row_seen rs
            JOIN latest_run r ON r.run_id = rs.run_id
            ORDER BY r.system, rs.entity_type, rs.entity_key;
            """);

        foreach (var row in seenRows)
        {
            var sys = (string)row["system"]!;
            var inst = (string)row["instance"]!;
            var type = (string)row["entity_type"]!;
            var key = (string)row["entity_key"]!;
            var name = row["entity_name"] as string;
            var observed = row["observed_at"] as string ?? "";
            var attrsText = row["attrs"] as string;
            var attrs = attrsText is not null ? JsonNode.Parse(attrsText) as JsonObject : null;

            var node = ResolveNode(key, name);
            if (node is null)
            {
                var canonical = CanonicalEntityKey(key, name, attrs);
                if (!nodes.TryGetValue(canonical, out node))
                {
                    var display = Reports.Named(name ?? key, gpoNames);
                    node = new EntityNode(canonical, display, type);
                    nodes[canonical] = node;
                }
            }

            RegisterAlias(node, key);
            RegisterAlias(node, name);
            node.Systems.Add(sys);

            if (type is "computer" or "host")
                node.EntityType = "computer";

            if (sys == "network" && attrs is not null)
            {
                node.InNetwork = true;
                node.NetworkState = attrs["state"]?.GetValue<string>() ?? node.NetworkState;
                node.DeviceKind = attrs["kind"]?.GetValue<string>() ?? node.DeviceKind;
                node.KindWhy = attrs["kindWhy"]?.GetValue<string>() ?? node.KindWhy;

                if (attrs["addresses"] is JsonArray addrs)
                {
                    foreach (var a in addrs.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)))
                    {
                        node.Addresses.Add(a!);
                        RegisterAlias(node, a!);
                    }
                }
                if (attrs["names"] is JsonArray names)
                {
                    foreach (var n in names.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)))
                        RegisterAlias(node, n!);
                }
                if (attrs["sources"] is JsonArray sources)
                {
                    foreach (var s in sources)
                    {
                        var srcKind = s is JsonObject o ? o["kind"]?.GetValue<string>() : s?.GetValue<string>();
                        if (!string.IsNullOrWhiteSpace(srcKind))
                        {
                            node.Sources.Add(srcKind!);
                            if (srcKind is "ad" or "directory")
                                node.InDirectory = true;
                        }
                    }
                }
                if (attrs["answered"] is JsonArray answered)
                {
                    foreach (var proto in answered.Select(x => x?.GetValue<string>()?.ToLowerInvariant()).Where(x => !string.IsNullOrWhiteSpace(x)))
                    {
                        node.Protocols.Add(proto!);
                        switch (proto)
                        {
                            case "ssh": node.HasSsh = true; break;
                            case "winrm": node.HasWinRm = true; break;
                            case "https": node.HasHttps = true; break;
                            case "snmp": node.HasSnmp = true; break;
                        }
                    }
                }
                if (attrs["services"] is JsonArray svcs)
                {
                    foreach (var s in svcs.OfType<JsonObject>())
                        node.Services.Add($"{s["port"]}/{s["transport"] ?? "tcp"} {s["service"]}");
                }
                if (attrs["snmp"] is JsonObject snmp)
                {
                    node.HasSnmp = true;
                    node.Protocols.Add("snmp");
                    node.SnmpSummary = $"SNMP {snmp["version"]?.GetValue<string>()}: {snmp["sysName"]?.GetValue<string>() ?? "-"} ({snmp["sysDescr"]?.GetValue<string>() ?? "-"})";
                }
                node.SourcesSummary.Add($"network ({inst}, {observed[..Math.Min(10, observed.Length)]})");
            }
            else
            {
                if (type is "computer" or "host")
                {
                    node.InDirectory = true;
                    node.DeviceKind ??= "directory-computer";
                }
                if (attrs is not null)
                {
                    if (attrs["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
                        RegisterAlias(node, dns);
                    if (attrs["sAMAccountName"]?.GetValue<string>() is { Length: > 0 } sam)
                        RegisterAlias(node, sam.TrimEnd('$'));
                    if (attrs["operatingSystem"]?.GetValue<string>() is { Length: > 0 } os)
                        node.OperatingSystem = os;
                }
                node.SourcesSummary.Add($"{sys} ({inst}, {observed[..Math.Min(10, observed.Length)]})");
            }
        }

        // 2. Open findings per entity
        var findingRows = Sql.Rows(connection,
            """
            SELECT check_id, system, system_id, entity_type, target, entity_name, kind, category,
                   severity, severity_rank, security, title, evidence, why, fix, first_seen, snoozed_until, delegated_to
            FROM active_finding
            WHERE target <> '-'
            ORDER BY severity_rank, check_id;
            """);

        foreach (var f in findingRows)
        {
            var target = (string)f["target"]!;
            var entityName = f["entity_name"] as string;
            var type = (string)f["entity_type"]!;
            var node = ResolveNode(target, entityName);
            if (node is null)
            {
                var display = Reports.Named(entityName ?? target, gpoNames);
                node = new EntityNode(target, display, type);
                nodes[target] = node;
                RegisterAlias(node, target);
                RegisterAlias(node, entityName);
            }

            var sev = (string)f["severity"]!;
            var kind = (string)f["kind"]!;
            var sec = f["security"] is 1L;
            node.Systems.Add((string)f["system"]!);
            node.OpenCount++;
            if (sev == "critical") node.CriticalCount++;
            else if (sev == "high") node.HighCount++;
            if (kind == "broken") node.BrokenCount++;
            else node.ConfigCount++;
            if (sec) node.SecurityCount++;

            node.Findings.Add(new JsonObject
            {
                ["id"] = (string)f["check_id"]!,
                ["system"] = (string)f["system"]!,
                ["category"] = (string)f["category"]!,
                ["severity"] = sev,
                ["kind"] = kind,
                ["security"] = sec,
                ["title"] = (string)f["title"]!,
                ["evidence"] = Reports.Named(f["evidence"] as string ?? target, gpoNames),
                ["why"] = f["why"] as string,
                ["fix"] = f["fix"] as string,
            });

            if (f["snoozed_until"] is string until)
                node.Decisions.Add($"[{sev}] {f["title"]} ({f["check_id"]}): snoozed until {until}");
            else if (f["delegated_to"] is string to)
                node.Decisions.Add($"[{sev}] {f["title"]} ({f["check_id"]}): delegated to {to}");
        }

        // 3. Results (pass / unknown / deep host inspection)
        var resultRows = Sql.Rows(connection,
            """
            SELECT res.instance, res.rule_id, res.entity_key, res.state, res.why,
                   COALESCE(ru.system, res.instance) AS system, COALESCE(ru.title, res.rule_id) AS title
            FROM result res
            LEFT JOIN rule ru ON ru.rule_id = res.rule_id
            WHERE res.entity_key <> '-'
            ORDER BY system, res.rule_id;
            """);

        foreach (var r in resultRows)
        {
            var ek = (string)r["entity_key"]!;
            var node = ResolveNode(ek, null);
            if (node is null)
                continue;

            var sys = (string)r["system"]!;
            var state = (string)r["state"]!;
            if (sys is not ("network" or "active-directory" or "entra" or "hybrid-identity"))
                node.DeepInspected = true;

            if (state == "pass")
            {
                node.PassedCount++;
                if (node.PassedChecks.Count < 60)
                    node.PassedChecks.Add($"[{sys}] {r["title"]} ({r["rule_id"]})");
            }
            else if (state == "unknown")
            {
                node.BlindSpots.Add($"{sys} ({r["instance"]}): {r["title"]} ({r["rule_id"]}) could not be checked{(r["why"] is string w ? $" - {w}" : "")}");
            }
        }

        // Target-scope failed/partial reads
        foreach (var tc in Sql.Rows(connection,
                     """
                     SELECT r.system, r.instance, c.item, c.state, c.reason
                     FROM coverage c JOIN latest_run r ON r.run_id = c.run_id
                     WHERE c.scope = 'target' AND c.state IN ('failed', 'partial');
                     """))
        {
            var item = tc["item"] as string ?? "";
            var at = item.LastIndexOf('@');
            if (at < 0) continue;
            var node = ResolveNode(item[(at + 1)..], null);
            node?.BlindSpots.Add($"{tc["system"]} ({tc["instance"]}): target read {item} was {tc["state"]}{(tc["reason"] is string rsn ? $" - {rsn}" : "")}");
        }

        // Compute estate summary across computer/host entities
        var computers = nodes.Values.Where(n => n.EntityType is "computer" or "host" || n.InNetwork).ToList();
        var byKind = computers
            .GroupBy(c => c.DeviceKind ?? "unknown", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => (JsonNode)new JsonObject
            {
                ["kind"] = g.Key,
                ["total"] = g.Count(),
                ["answering"] = g.Count(c => c.NetworkState == "answering"),
                ["mgmt"] = g.Count(c => c.HasMgmt),
                ["unlisted"] = g.Count(c => c.InNetwork && !c.InDirectory && c.NetworkState == "answering"),
                ["deep"] = g.Count(c => c.DeepInspected),
            })
            .ToArray();

        var estate = new JsonObject
        {
            ["total"] = computers.Count,
            ["inNetwork"] = computers.Count(c => c.InNetwork),
            ["inDirectory"] = computers.Count(c => c.InDirectory),
            ["answering"] = computers.Count(c => c.NetworkState == "answering"),
            ["notAnswering"] = computers.Count(c => c.NetworkState == "not-answering"),
            ["likelyGone"] = computers.Count(c => c.NetworkState == "likely-gone"),
            ["unresolved"] = computers.Count(c => c.NetworkState == "unresolved"),
            ["excluded"] = computers.Count(c => c.NetworkState == "excluded"),
            ["mgmt"] = computers.Count(c => c.HasMgmt),
            ["ssh"] = computers.Count(c => c.HasSsh),
            ["winrm"] = computers.Count(c => c.HasWinRm),
            ["https"] = computers.Count(c => c.HasHttps),
            ["snmp"] = computers.Count(c => c.HasSnmp),
            ["unlisted"] = computers.Count(c => c.InNetwork && !c.InDirectory && c.NetworkState == "answering"),
            ["deep"] = computers.Count(c => c.DeepInspected),
            ["surfaceOnly"] = computers.Count(c => !c.DeepInspected),
            ["byKind"] = new JsonArray(byKind),
        };

        var entityArray = new JsonArray();
        foreach (var n in nodes.Values
                     .OrderByDescending(n => n.CriticalCount)
                     .ThenByDescending(n => n.HighCount)
                     .ThenByDescending(n => n.OpenCount)
                     .ThenBy(n => n.Name, StringComparer.OrdinalIgnoreCase))
        {
            var isComputer = n.EntityType is "computer" or "host" || n.InNetwork;
            if (isComputer && !n.DeepInspected)
            {
                if (n.NetworkState == "answering" && !n.HasMgmt)
                    n.BlindSpots.Add("Operational gap: answers on the network but exposes no management protocol (WinRM, SSH, HTTPS, or SNMP).");
                else
                    n.BlindSpots.Add("Operational gap: only directory/network surface data is present; no host-level pack has inspected inside this machine yet.");
            }

            entityArray.Add(new JsonObject
            {
                ["key"] = n.Key,
                ["name"] = n.Name,
                ["type"] = n.EntityType,
                ["kind"] = n.DeviceKind,
                ["kindWhy"] = n.KindWhy,
                ["state"] = n.NetworkState,
                ["os"] = n.OperatingSystem,
                ["inNetwork"] = n.InNetwork,
                ["inDirectory"] = n.InDirectory,
                ["unlisted"] = n.InNetwork && !n.InDirectory && n.NetworkState == "answering",
                ["hasMgmt"] = n.HasMgmt,
                ["deep"] = n.DeepInspected,
                ["addresses"] = new JsonArray(n.Addresses.Select(a => (JsonNode)a).ToArray()),
                ["protocols"] = new JsonArray(n.Protocols.Select(p => (JsonNode)p).ToArray()),
                ["services"] = new JsonArray(n.Services.Select(s => (JsonNode)s).ToArray()),
                ["snmp"] = n.SnmpSummary,
                ["sources"] = new JsonArray(n.SourcesSummary.Select(s => (JsonNode)s).ToArray()),
                ["systems"] = new JsonArray(n.Systems.OrderBy(s => s).Select(s => (JsonNode)s).ToArray()),
                ["open"] = n.OpenCount,
                ["critical"] = n.CriticalCount,
                ["high"] = n.HighCount,
                ["broken"] = n.BrokenCount,
                ["config"] = n.ConfigCount,
                ["security"] = n.SecurityCount,
                ["passedCount"] = n.PassedCount,
                ["passed"] = new JsonArray(n.PassedChecks.Select(p => (JsonNode)p).ToArray()),
                ["blindSpots"] = new JsonArray(n.BlindSpots.Select(b => (JsonNode)b).ToArray()),
                ["decisions"] = new JsonArray(n.Decisions.Select(d => (JsonNode)d).ToArray()),
                ["findings"] = n.Findings,
            });
        }

        return (entityArray, estate);
    }

    private static string CanonicalEntityKey(string entityKey, string? entityName, JsonObject? attrs)
    {
        if (attrs?["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
            return dns.Trim().TrimEnd('.').ToLowerInvariant();
        if (attrs?["names"] is JsonArray names)
        {
            var first = names.Select(x => x?.GetValue<string>()).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
            if (!string.IsNullOrWhiteSpace(first))
                return first.Trim().TrimEnd('.').ToLowerInvariant();
        }
        if (!string.IsNullOrWhiteSpace(entityName) && !entityName.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
            return entityName.Trim().TrimEnd('.', '$').ToLowerInvariant();
        var cleaned = entityKey.StartsWith("ip:", StringComparison.OrdinalIgnoreCase) ? entityKey[3..] : entityKey;
        return cleaned.Trim().TrimEnd('.', '$').ToLowerInvariant();
    }

    private sealed class EntityNode(string key, string name, string entityType)
    {
        public string Key { get; } = key;
        public string Name { get; } = name;
        public string EntityType { get; set; } = entityType;
        public HashSet<string> Aliases { get; } = new(StringComparer.OrdinalIgnoreCase) { key, name };
        public HashSet<string> Systems { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Addresses { get; } = [];
        public HashSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> SourcesSummary { get; } = [];
        public HashSet<string> Protocols { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Services { get; } = [];
        public string? SnmpSummary { get; set; }
        public string? OperatingSystem { get; set; }
        public bool InNetwork { get; set; }
        public bool InDirectory { get; set; }
        public string? NetworkState { get; set; }
        public string? DeviceKind { get; set; }
        public string? KindWhy { get; set; }
        public bool HasSsh { get; set; }
        public bool HasWinRm { get; set; }
        public bool HasHttps { get; set; }
        public bool HasSnmp { get; set; }
        public bool HasMgmt => HasSsh || HasWinRm || HasHttps || HasSnmp;
        public bool DeepInspected { get; set; }
        public int OpenCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int BrokenCount { get; set; }
        public int ConfigCount { get; set; }
        public int SecurityCount { get; set; }
        public int PassedCount { get; set; }
        public List<string> PassedChecks { get; } = [];
        public List<string> BlindSpots { get; } = [];
        public List<string> Decisions { get; } = [];
        public JsonArray Findings { get; } = [];
    }

    private static JsonArray Rows(SqliteConnection connection, string sql)
    {
        var array = new JsonArray();
        foreach (var row in Sql.Rows(connection, sql))
        {
            var obj = new JsonObject();
            foreach (var (key, value) in row)
                obj[key] = value switch { null => null, long n => n, double d => d, string s => s, _ => value.ToString() };
            array.Add(obj);
        }
        return array;
    }

    private const string Page = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Keeper</title>
<style>
:root { color-scheme: light;
  --page:#f9f9f7; --surface:#fcfcfb; --raise:#ffffff; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7;
  --border:rgba(11,11,11,.10); --accent:#2a78d6; --accent-wash:rgba(42,120,214,.10);
  --good:#0ca30c; --warning:#fab219; --serious:#ec835a; --critical:#d03b3b; --unchecked:#898781; --norun:#d9d8d1;
  --shadow:0 1px 2px rgba(0,0,0,.04), 0 4px 16px rgba(0,0,0,.05); }
@media (prefers-color-scheme: dark) { :root:where(:not([data-theme="light"])) { color-scheme: dark;
  --page:#0d0d0d; --surface:#1a1a19; --raise:#202020; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --border:rgba(255,255,255,.10); --accent:#3987e5; --accent-wash:rgba(57,135,229,.16); --norun:#383835; --shadow:none; } }
:root[data-theme="dark"] { color-scheme: dark;
  --page:#0d0d0d; --surface:#1a1a19; --raise:#202020; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --border:rgba(255,255,255,.10); --accent:#3987e5; --accent-wash:rgba(57,135,229,.16); --norun:#383835; --shadow:none; }
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
button, input, select { font: inherit; color: inherit; }
a { color: var(--accent); }
header { position: sticky; top: 0; z-index: 5; background: color-mix(in srgb, var(--page) 88%, transparent); backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border); }
.bar { max-width: 1280px; margin: 0 auto; padding: 10px 24px; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; letter-spacing: -.01em; }
.brand .mark { width: 26px; height: 26px; border-radius: 7px; background: linear-gradient(135deg, var(--accent), #6250d6); display: grid; place-items: center; color: #fff; font-size: 14px; }
.brand small { font-weight: 400; color: var(--muted); font-size: 12px; }
nav { display: flex; gap: 4px; flex-wrap: wrap; }
nav button { border: 0; background: none; padding: 6px 12px; border-radius: 8px; cursor: pointer; color: var(--ink2); }
nav button[aria-current="page"] { background: var(--accent-wash); color: var(--accent); font-weight: 600; }
nav button:hover { background: var(--accent-wash); }
.spacer { flex: 1; }
.search { position: relative; }
.search input { width: 260px; max-width: 60vw; padding: 7px 10px 7px 30px; border: 1px solid var(--border); border-radius: 9px; background: var(--surface); }
.search::before { content: "\2315"; position: absolute; left: 10px; top: 6px; color: var(--muted); }
.icon-btn { border: 1px solid var(--border); background: var(--surface); border-radius: 9px; padding: 6px 10px; cursor: pointer; }
main { max-width: 1280px; margin: 0 auto; padding: 24px; }
h1 { font-size: 26px; letter-spacing: -.02em; margin: 4px 0 6px; } h2 { font-size: 15px; margin: 0 0 12px; }
.lede { color: var(--ink2); font-size: 15px; margin: 0 0 20px; max-width: 900px; }
.grid { display: grid; gap: 16px; }
.tiles { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); margin-bottom: 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; box-shadow: var(--shadow); }
.tile { cursor: pointer; transition: transform .12s ease, border-color .12s ease; position: relative; overflow: hidden; }
.tile:hover, .tile:focus-visible { transform: translateY(-2px); border-color: var(--accent); outline: none; }
.tile .label { display: flex; align-items: center; gap: 8px; color: var(--ink2); font-weight: 600; }
.tile .value { font-size: 36px; font-weight: 700; letter-spacing: -.03em; line-height: 1.1; margin-top: 6px; }
.tile .note { color: var(--muted); font-size: 12px; margin-top: 4px; }
.tile .stripe { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
.dot { width: 18px; height: 18px; border-radius: 50%; display: inline-grid; place-items: center; color: #fff; font-size: 11px; font-weight: 700; flex: none; }
.two { grid-template-columns: 1.15fr .85fr; } @media (max-width: 900px) { .two { grid-template-columns: 1fr; } }
.sys { padding: 14px 0; border-top: 1px solid var(--grid); cursor: pointer; } .sys:first-of-type { border-top: 0; }
.sys:hover .sysname { color: var(--accent); }
.sysrow { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.sysname { font-weight: 600; } .meta { color: var(--muted); font-size: 12px; }
.stack { display: flex; gap: 2px; height: 14px; border-radius: 4px; overflow: hidden; background: var(--surface); }
.stack span { display: block; height: 100%; min-width: 2px; }
.stack span:first-child { border-radius: 4px 0 0 4px; } .stack span:last-child { border-radius: 0 4px 4px 0; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 8px; font-size: 12px; color: var(--ink2); }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.legend b { color: var(--ink); font-weight: 600; margin-right: 3px; }
.row { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 10px; cursor: pointer; }
.row:hover, .row:focus-visible { background: var(--accent-wash); outline: none; }
.row .t { flex: 1; min-width: 0; } .row .t div:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pill { font-size: 12px; font-weight: 600; padding: 1px 8px; border-radius: 99px; background: var(--grid); color: var(--ink); white-space: nowrap; font-variant-numeric: tabular-nums; }
.sev { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; color: var(--ink2); white-space: nowrap; }
.sev::before { content: ""; width: 8px; height: 8px; border-radius: 2px; background: var(--c); }
.hbar { display: grid; grid-template-columns: 92px 1fr auto; gap: 10px; align-items: center; margin: 8px 0; font-size: 13px; }
.hbar .track { height: 12px; background: var(--grid); border-radius: 4px; overflow: hidden; }
.hbar .fill { height: 100%; border-radius: 0 4px 4px 0; }
.hbar .num { color: var(--ink2); font-variant-numeric: tabular-nums; white-space: nowrap; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { border: 1px solid var(--border); background: var(--surface); padding: 4px 10px; border-radius: 99px; cursor: pointer; font-size: 12px; }
.chip[aria-pressed="true"] { background: var(--accent-wash); border-color: var(--accent); color: var(--accent); font-weight: 600; }
.filters { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.split { display: grid; grid-template-columns: minmax(320px, 440px) 1fr; gap: 16px; align-items: start; }
@media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
.list { max-height: calc(100vh - 230px); overflow: auto; padding: 6px; }
.list .row[aria-selected="true"] { background: var(--accent-wash); box-shadow: inset 3px 0 0 var(--accent); }
.detail { position: sticky; top: 76px; max-height: calc(100vh - 100px); overflow: auto; }
.detail h3 { font-size: 20px; letter-spacing: -.01em; margin: 8px 0 10px; }
.kv { display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.block { margin: 14px 0; } .block .h { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: 4px; }
.fix { border-left: 3px solid var(--good); padding: 8px 12px; background: color-mix(in srgb, var(--good) 8%, transparent); border-radius: 0 8px 8px 0; }
.warnbox { border-left: 3px solid var(--warning); padding: 8px 12px; background: color-mix(in srgb, var(--warning) 8%, transparent); border-radius: 0 8px 8px 0; margin-top: 6px; font-size: 13px; }
.objs { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.objs .tools { display: flex; gap: 8px; padding: 8px; border-bottom: 1px solid var(--border); background: var(--raise); }
.objs .tools input { flex: 1; padding: 5px 8px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface); }
.obj { padding: 7px 12px; border-top: 1px solid var(--grid); font-size: 13px; display: flex; justify-content: space-between; align-items: center; gap: 8px; } .obj:first-child { border-top: 0; }
.obj b { font-weight: 600; } .obj span { color: var(--ink2); }
.empty { color: var(--muted); padding: 24px; text-align: center; }
.ok { display: flex; gap: 10px; align-items: flex-start; padding: 8px 4px; border-top: 1px solid var(--grid); }
.ok:first-child { border-top: 0; }
.group { margin-bottom: 18px; } .group > .h { font-weight: 700; margin: 0 0 6px; display: flex; gap: 8px; align-items: center; }
#tip { position: fixed; pointer-events: none; z-index: 20; background: var(--raise); border: 1px solid var(--border); border-radius: 8px;
  padding: 6px 10px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,.18); display: none; }
.kbd { font-size: 11px; border: 1px solid var(--border); border-bottom-width: 2px; border-radius: 5px; padding: 0 5px; color: var(--muted); }
table.data { width: 100%; border-collapse: collapse; font-size: 13px; } table.data th, table.data td { text-align: left; padding: 7px 8px; border-top: 1px solid var(--grid); }
table.data th { color: var(--muted); font-weight: 600; } table.data td.n, table.data th.n { text-align: right; font-variant-numeric: tabular-nums; }
table.data tr.click { cursor: pointer; } table.data tr.click:hover { background: var(--accent-wash); }
details summary { cursor: pointer; color: var(--muted); font-size: 12px; margin-top: 10px; }
.foot { color: var(--muted); font-size: 12px; text-align: center; padding: 24px 0 8px; }
</style></head>
<body>
<header><div class="bar">
  <div class="brand"><div class="mark" aria-hidden="true">K</div><div>Keeper <small id="sub"></small></div></div>
  <nav id="nav"></nav><div class="spacer"></div>
  <label class="search"><input id="q" type="search" placeholder="Search findings, objects, rules" aria-label="Search"></label>
  <button class="icon-btn" id="theme" title="Light / dark">&#9681;</button>
</div></header>
<main id="main"></main>
<div id="tip" role="tooltip"></div>
<script type="application/json" id="keeper-data">/*KEEPER-DATA*/</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("keeper-data").textContent);
const SEV = { critical: "var(--critical)", high: "var(--serious)", medium: "var(--warning)", low: "var(--accent)", info: "var(--muted)" };
const SEVORDER = ["critical", "high", "medium", "low", "info"];
const ST = [
  { key: "correct", label: "Correct", icon: "✓", color: "var(--good)", note: "configured as it should be" },
  { key: "should", label: "Should configure", icon: "!", color: "var(--warning)", note: "missing or against best practice" },
  { key: "broken", label: "Broken", icon: "✕", color: "var(--critical)", note: "configured but not working" },
  { key: "unchecked", label: "Couldn't check", icon: "?", color: "var(--unchecked)", note: "data could not be fully read" },
  { key: "norun", label: "No result", icon: "–", color: "var(--norun)", note: "checks that produced nothing" },
];
const fmt = n => Number(n || 0).toLocaleString("en-US");
const pct = (a, b) => b ? Math.round(100 * a / b) + "%" : "0%";
const KIND = { missing: "Should configure", misconfigured: "Should configure", broken: "Broken" };

// Every value from a scanned system goes in as text, never as markup.
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v; else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
}
const sevBadge = s => h("span", { class: "sev", style: `--c:${SEV[s] || "var(--muted)"}` }, s || "");
const statusDot = s => h("span", { class: "dot", style: `background:${s.color}`, "aria-hidden": "true" }, s.icon);

const totals = D.systems.reduce((t, s) => { for (const k of ["checks", "correct", "should", "broken", "unchecked", "norun"]) t[k] = (t[k] || 0) + (s[k] || 0); return t; }, {});
const openObjects = D.checks.reduce((n, c) => n + c.count, 0);
const state = {
  tab: "overview",
  q: "",
  sev: new Set(),
  kind: "all",
  system: "all",
  category: "all",
  selected: null,
  objq: "",
  objAll: false,
  entFilter: "all",
  selectedEntity: null
};

const tip = document.getElementById("tip");
function tipOn(el, text) {
  el.addEventListener("mousemove", ev => { tip.textContent = text; tip.style.display = "block"; tip.style.left = (ev.clientX + 12) + "px"; tip.style.top = (ev.clientY + 12) + "px"; });
  el.addEventListener("mouseleave", () => tip.style.display = "none");
}

function stackBar(s) {
  const total = ST.reduce((n, x) => n + (s[x.key] || 0), 0);
  const bar = h("div", { class: "stack", role: "img", "aria-label": ST.map(x => `${x.label} ${s[x.key] || 0}`).join(", ") });
  for (const x of ST) {
    const v = s[x.key] || 0; if (!v) continue;
    const seg = h("span", { style: `flex:${v};background:${x.color}` });
    tipOn(seg, `${x.label}: ${fmt(v)} checks (${pct(v, total)})`);
    bar.append(seg);
  }
  return bar;
}
function legend(s) {
  return h("div", { class: "legend" }, ST.map(x => h("span", {}, h("i", { style: `background:${x.color}` }), h("b", {}, fmt(s[x.key] || 0)), x.label.toLowerCase())));
}

function openFinding(id) {
  state.selected = id; state.kind = "all"; state.sev.clear(); state.system = "all"; state.category = "all"; state.objq = "";
  show("findings");
}

function openEntity(targetOrName) {
  if (!targetOrName) return;
  const q = String(targetOrName).toLowerCase();
  const found = (D.entities || []).find(e =>
    e.key.toLowerCase() === q ||
    e.name.toLowerCase() === q ||
    (e.addresses || []).some(a => a.toLowerCase() === q));
  state.selectedEntity = found ? found.key : targetOrName;
  state.entFilter = "all";
  show("objects");
}

const views = {
  overview() {
    const intro = D.systems.length
      ? `Keeper ran ${fmt(totals.checks)} checks on ${D.systems.length} system${D.systems.length === 1 ? "" : "s"}. ${fmt(totals.correct)} found the configuration correct, ${fmt(totals.should)} found something to configure, ${fmt(totals.broken)} found something broken, and ${fmt(totals.unchecked)} could not check. Behind them: ${fmt(openObjects)} open findings across ${fmt(D.checks.length)} checks.`
      : "No scan has results yet. Run 'keeper run' to scan, then build this page again.";
    const tiles = h("div", { class: "grid tiles" }, ST.slice(0, 4).map(x => {
      const go = () => { if (x.key === "correct") show("passed"); else if (x.key === "unchecked") show("coverage"); else { state.kind = x.key === "broken" ? "broken" : "should"; show("findings"); } };
      return h("div", { class: "card tile", tabindex: "0", role: "button", onclick: go, onkeydown: e => { if (e.key === "Enter") go(); } },
        h("div", { class: "stripe", style: `background:${x.color}` }),
        h("div", { class: "label" }, statusDot(x), x.label),
        h("div", { class: "value" }, fmt(totals[x.key])),
        h("div", { class: "note" }, `${pct(totals[x.key], totals.checks)} of checks · ${x.note}`));
    }));

    const systems = h("div", { class: "card" }, h("h2", {}, "Systems"),
      D.systems.length ? D.systems.map(s => h("div", { class: "sys", tabindex: "0", onclick: () => { state.system = s.system; show("findings"); } },
        h("div", { class: "sysrow" }, h("span", { class: "sysname" }, s.system), h("span", { class: "meta" }, `${s.instance} · scanned ${(s.scanned || "").slice(0, 10)} · ${fmt(s.checks)} checks`)),
        stackBar(s), legend(s))) : h("div", { class: "empty" }, "Nothing scanned yet."),
      D.neverScanned.length ? h("details", {}, h("summary", {}, `${D.neverScanned.length} more systems have rules but were never scanned`),
        h("div", { class: "chips", style: "margin-top:8px" }, D.neverScanned.map(n => h("span", { class: "chip" }, `${n.system} · ${n.rules}`)))) : null);

    const urgent = D.checks.filter(c => c.severity === "critical" || c.severity === "high").slice(0, 8);
    const fixFirst = h("div", { class: "card" }, h("h2", {}, "Fix first"),
      urgent.length ? urgent.map(c => h("div", { class: "row", tabindex: "0", onclick: () => openFinding(c.id), onkeydown: e => { if (e.key === "Enter") openFinding(c.id); } },
        sevBadge(c.severity), h("div", { class: "t" }, h("div", {}, c.title), h("div", { class: "meta" }, `${KIND[c.kind] || c.kind} · ${c.system}`)),
        h("span", { class: "pill" }, fmt(c.count)))) : h("div", { class: "empty" }, "Nothing critical or high is open."));

    const bySev = SEVORDER.map(s => ({ s, checks: D.checks.filter(c => c.severity === s).length, objects: D.checks.filter(c => c.severity === s).reduce((n, c) => n + c.count, 0) })).filter(x => x.checks);
    const max = Math.max(1, ...bySev.map(x => x.objects));
    const sevCard = h("div", { class: "card" }, h("h2", {}, "Open findings by severity"),
      bySev.map(x => {
        const row = h("div", { class: "hbar" }, sevBadge(x.s), h("div", { class: "track" }, h("div", { class: "fill", style: `width:${Math.max(1.5, 100 * x.objects / max)}%;background:${SEV[x.s]}` })),
          h("span", { class: "num" }, `${fmt(x.objects)} objects · ${x.checks} checks`));
        tipOn(row, `${x.s}: ${fmt(x.objects)} affected objects in ${x.checks} checks`);
        return row;
      }),
      h("details", {}, h("summary", {}, "Table view"), h("table", { class: "data" }, h("tr", {}, h("th", {}, "Severity"), h("th", {}, "Checks"), h("th", {}, "Objects")),
        bySev.map(x => h("tr", {}, h("td", {}, x.s), h("td", { class: "n" }, x.checks), h("td", { class: "n" }, fmt(x.objects)))))));

    return [h("h1", {}, "Configuration posture"), h("p", { class: "lede" }, intro), tiles,
      h("div", { class: "grid two" }, h("div", { class: "grid" }, systems), h("div", { class: "grid" }, fixFirst, sevCard))];
  },

  findings() {
    const q = state.q.toLowerCase();
    const list = D.checks.filter(c =>
      (state.kind === "all" || (state.kind === "broken" ? c.kind === "broken" : c.kind !== "broken")) &&
      (state.system === "all" || c.system === state.system) &&
      (state.category === "all" || c.category === state.category) &&
      (!state.sev.size || state.sev.has(c.severity)) &&
      (!q || (c.title + " " + c.id + " " + (c.why || "") + " " + c.objects.map(o => o.join(" ")).join(" ")).toLowerCase().includes(q)));
    if (state.selected && !list.some(c => c.id === state.selected)) state.selected = null;
    if (!state.selected && list.length) state.selected = list[0].id;

    const kindChips = h("div", { class: "chips" }, [["all", "All"], ["should", "Should configure"], ["broken", "Broken"]].map(([k, l]) =>
      h("button", { class: "chip", "aria-pressed": String(state.kind === k), onclick: () => { state.kind = k; render(); } }, l)));
    const sevChips = h("div", { class: "chips" }, SEVORDER.filter(s => D.checks.some(c => c.severity === s)).map(s =>
      h("button", { class: "chip", "aria-pressed": String(state.sev.has(s)), onclick: () => { state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s); render(); } }, s)));
    const sysSel = h("select", { class: "chip", onchange: e => { state.system = e.target.value; render(); } },
      h("option", { value: "all" }, "All systems"), [...new Set(D.checks.map(c => c.system))].sort().map(s => h("option", { value: s, selected: state.system === s }, s)));
    const catSel = h("select", { class: "chip", onchange: e => { state.category = e.target.value; render(); } },
      h("option", { value: "all" }, "All categories"), [...new Set(D.checks.map(c => c.category).filter(Boolean))].sort().map(cat => h("option", { value: cat, selected: state.category === cat }, cat)));

    const rows = h("div", { class: "card list", role: "listbox", "aria-label": "Findings" },
      list.length ? list.map(c => h("div", { class: "row", role: "option", tabindex: "0", "aria-selected": String(c.id === state.selected), "data-id": c.id,
        onclick: () => { state.selected = c.id; state.objq = ""; state.objAll = false; location.hash = "findings/" + encodeURIComponent(c.id); render(); } },
        sevBadge(c.severity), h("div", { class: "t" }, h("div", {}, c.title), h("div", { class: "meta" }, `${KIND[c.kind] || c.kind} · ${c.system} · ${c.category || ""}`)),
        h("span", { class: "pill" }, fmt(c.count)))) : h("div", { class: "empty" }, "No finding matches."));

    const c = D.checks.find(x => x.id === state.selected);
    return [h("h1", {}, "Findings"), h("p", { class: "lede" }, `${fmt(list.length)} checks with open findings · ${fmt(list.reduce((n, x) => n + x.count, 0))} affected objects. Press `, h("span", { class: "kbd" }, "/"), " to search, ", h("span", { class: "kbd" }, "j"), " ", h("span", { class: "kbd" }, "k"), " to move."),
      h("div", { class: "filters" }, kindChips, sevChips, sysSel, catSel),
      h("div", { class: "split" }, rows, c ? detail(c) : h("div", { class: "card empty" }, "Choose a finding."))];
  },

  objects() {
    const q = state.q.toLowerCase();
    const all = D.entities || [];
    const list = all.filter(e => {
      if (state.entFilter === "problems" && !e.open) return false;
      if (state.entFilter === "broken" && !e.broken) return false;
      if (state.entFilter === "answering" && e.state !== "answering") return false;
      if (state.entFilter === "unlisted" && !e.unlisted) return false;
      if (state.entFilter === "surface" && (e.deep || (e.type !== "computer" && e.type !== "host" && !e.inNetwork))) return false;
      if (!q) return true;
      const hay = [e.name, e.key, e.kind, e.state, e.os, ...(e.addresses || []), ...(e.protocols || []), ...(e.systems || [])].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });

    if (state.selectedEntity && !list.some(e => e.key === state.selectedEntity)) state.selectedEntity = null;
    if (!state.selectedEntity && list.length) state.selectedEntity = list[0].key;

    const filterChips = h("div", { class: "chips" }, [
      ["all", `All (${fmt(all.length)})`],
      ["problems", `With open findings (${fmt(all.filter(e => e.open > 0).length)})`],
      ["broken", `Broken (${fmt(all.filter(e => e.broken > 0).length)})`],
      ["answering", `Answering on network (${fmt(all.filter(e => e.state === "answering").length)})`],
      ["unlisted", `Unlisted / dark (${fmt(all.filter(e => e.unlisted).length)})`],
      ["surface", `Surface-only (${fmt(all.filter(e => !e.deep && (e.type === "computer" || e.type === "host" || e.inNetwork)).length)})`],
    ].map(([k, l]) => h("button", { class: "chip", "aria-pressed": String(state.entFilter === k), onclick: () => { state.entFilter = k; render(); } }, l)));

    const rows = h("div", { class: "card list", role: "listbox", "aria-label": "Objects" },
      list.length ? list.map(e => {
        const sub = [e.kind || e.type, e.state ? `state:${e.state}` : null, (e.addresses || [])[0]].filter(Boolean).join(" · ");
        const worst = e.critical ? "critical" : e.high ? "high" : e.open ? "medium" : "info";
        return h("div", { class: "row", role: "option", tabindex: "0", "aria-selected": String(e.key === state.selectedEntity), "data-id": e.key,
          onclick: () => { state.selectedEntity = e.key; location.hash = "objects/" + encodeURIComponent(e.key); render(); } },
          e.open ? sevBadge(worst) : statusDot(ST[0]),
          h("div", { class: "t" }, h("div", {}, e.name), h("div", { class: "meta" }, sub)),
          h("span", { class: "pill" }, e.open ? `${fmt(e.open)} open` : `${fmt(e.passedCount)} ok`));
      }) : h("div", { class: "empty" }, "No object matches."));

    const ent = all.find(e => e.key === state.selectedEntity);
    return [
      h("h1", {}, "Object dossier"),
      h("p", { class: "lede" }, "Point-in-time dossier for any individual server, workstation, network device, account, or GPO: identity, open broken and configuration problems, decisions, passed checks, and blind spots."),
      h("div", { class: "filters" }, filterChips),
      h("div", { class: "split" }, rows, ent ? entityDetail(ent) : h("div", { class: "card empty" }, "Choose an object to inspect its dossier."))
    ];
  },

  matrix() {
    const cats = D.categories || [];
    const widespread = D.checks.filter(c => c.count > 1).slice(0, 25);
    const hotspots = (D.entities || []).filter(e => e.open > 0).slice(0, 20);
    const sysSplit = D.systemSplit || [];

    const catTable = h("div", { class: "card group" },
      h("h2", {}, "By operational and security category"),
      cats.length ? h("table", { class: "data" },
        h("tr", {},
          h("th", {}, "Category"),
          h("th", {}, "Tier"),
          h("th", { class: "n" }, "Open"),
          h("th", { class: "n" }, "Critical"),
          h("th", { class: "n" }, "High"),
          h("th", { class: "n" }, "Broken"),
          h("th", { class: "n" }, "Config / Missing"),
          h("th", { class: "n" }, "Systems"),
          h("th", { class: "n" }, "Objects"),
          h("th", { class: "n" }, "Checks Correct")),
        cats.map(c => h("tr", { class: "click", onclick: () => { state.category = c.code; show("findings"); } },
          h("td", {}, h("b", {}, c.code), " — ", c.name),
          h("td", {}, c.security ? "security" : "operations"),
          h("td", { class: "n" }, fmt(c.open)),
          h("td", { class: "n" }, fmt(c.critical)),
          h("td", { class: "n" }, fmt(c.high)),
          h("td", { class: "n" }, fmt(c.broken)),
          h("td", { class: "n" }, fmt(c.config)),
          h("td", { class: "n" }, fmt(c.systems)),
          h("td", { class: "n" }, fmt(c.targets)),
          h("td", { class: "n" }, c.ran ? `${fmt(c.correct)} / ${fmt(c.ran)}` : "—"))))
      : h("div", { class: "empty" }, "No findings or evaluated rules in any category yet."));

    const wideCard = h("div", { class: "card" },
      h("h2", {}, "Widespread systemic issues (failing on multiple objects)"),
      widespread.length ? widespread.map(c => h("div", { class: "row", tabindex: "0", onclick: () => openFinding(c.id) },
        sevBadge(c.severity),
        h("div", { class: "t" },
          h("div", {}, c.title),
          h("div", { class: "meta" }, `${c.category || ""} · ${KIND[c.kind] || c.kind} · ${c.system} (${fmt(c.sysCount || 1)} system${(c.sysCount || 1) === 1 ? "" : "s"})`)),
        h("span", { class: "pill" }, `${fmt(c.count)} objects`)))
      : h("div", { class: "empty" }, "No check currently fails on more than one object."));

    const hotCard = h("div", { class: "card" },
      h("h2", {}, "Object hotspots (most problems on a single target)"),
      hotspots.length ? hotspots.map(e => h("div", { class: "row", tabindex: "0", onclick: () => openEntity(e.key) },
        sevBadge(e.critical ? "critical" : e.high ? "high" : "medium"),
        h("div", { class: "t" },
          h("div", {}, e.name),
          h("div", { class: "meta" }, `${e.kind || e.type} · ${(e.systems || []).join(", ")} · ${fmt(e.broken)} broken, ${fmt(e.config)} config`)),
        h("span", { class: "pill" }, `${fmt(e.open)} open`)))
      : h("div", { class: "empty" }, "No individual target has open findings."));

    const splitCard = sysSplit.length ? h("div", { class: "card group", style: "margin-top:16px" },
      h("h2", {}, "Operations vs security balance by system"),
      h("table", { class: "data" },
        h("tr", {},
          h("th", {}, "System"),
          h("th", { class: "n" }, "Total Open"),
          h("th", { class: "n" }, "Critical / High"),
          h("th", { class: "n" }, "Operations / Maintenance"),
          h("th", { class: "n" }, "Security Tier"),
          h("th", { class: "n" }, "Broken"),
          h("th", { class: "n" }, "Misconfigured / Missing")),
        sysSplit.map(s => h("tr", {},
          h("td", {}, h("b", {}, s.id), s.name && s.name !== s.id ? ` (${s.name})` : ""),
          h("td", { class: "n" }, fmt(s.open)),
          h("td", { class: "n" }, fmt(s.serious)),
          h("td", { class: "n" }, fmt(s.maintenance)),
          h("td", { class: "n" }, fmt(s.security)),
          h("td", { class: "n" }, fmt(s.broken)),
          h("td", { class: "n" }, fmt(s.config)))))) : null;

    return [
      h("h1", {}, "Cross-cutting estate matrix"),
      h("p", { class: "lede" }, "Horizontal view across Keeper's 12 operational and security categories, systemic checks affecting many objects, and multi-finding object hotspots."),
      catTable,
      h("div", { class: "grid two" }, wideCard, hotCard),
      splitCard
    ];
  },

  coverage() {
    const est = D.estate || {};
    const byKind = est.byKind || [];
    const q = state.q.toLowerCase();
    const items = D.unchecked.filter(u => (state.system === "all" || u.system === state.system) && (!q || (u.title + " " + u.id + " " + (u.why || "")).toLowerCase().includes(q)));

    const estateTiles = h("div", { class: "grid tiles" }, [
      { label: "Known Machines", val: fmt(est.total), note: `${fmt(est.inNetwork)} in network discovery · ${fmt(est.inDirectory)} in directory`, color: "var(--accent)", filter: "all" },
      { label: "Answering on Network", val: fmt(est.answering), note: `${fmt(est.notAnswering)} not-answering · ${fmt(est.likelyGone)} likely-gone`, color: "var(--good)", filter: "answering" },
      { label: "Mgmt Protocol Reachable", val: fmt(est.mgmt), note: `SSH ${fmt(est.ssh)} · WinRM ${fmt(est.winrm)} · HTTPS ${fmt(est.https)} · SNMP ${fmt(est.snmp)}`, color: "var(--accent)", filter: "answering" },
      { label: "Unlisted / Dark Assets", val: fmt(est.unlisted), note: `${fmt(est.unresolved)} unresolved DNS`, color: "var(--serious)", filter: "unlisted" },
      { label: "Deep Host Inspection", val: fmt(est.deep), note: `${fmt(est.surfaceOnly)} surface/directory-only`, color: "var(--warning)", filter: "surface" },
    ].map(t => h("div", { class: "card tile", tabindex: "0", role: "button", onclick: () => { state.entFilter = t.filter; show("objects"); } },
      h("div", { class: "stripe", style: `background:${t.color}` }),
      h("div", { class: "label" }, t.label),
      h("div", { class: "value" }, t.val),
      h("div", { class: "note" }, t.note))));

    const kindCard = h("div", { class: "card group" },
      h("h2", {}, "Estate & discovery coverage by device kind"),
      byKind.length ? h("table", { class: "data" },
        h("tr", {},
          h("th", {}, "Device Kind"),
          h("th", { class: "n" }, "Total"),
          h("th", { class: "n" }, "Answering"),
          h("th", { class: "n" }, "Mgmt Protocol"),
          h("th", { class: "n" }, "Unlisted"),
          h("th", { class: "n" }, "Deep Inspected")),
        byKind.map(k => h("tr", {},
          h("td", {}, h("b", {}, k.kind)),
          h("td", { class: "n" }, fmt(k.total)),
          h("td", { class: "n" }, fmt(k.answering)),
          h("td", { class: "n" }, fmt(k.mgmt)),
          h("td", { class: "n" }, fmt(k.unlisted)),
          h("td", { class: "n" }, fmt(k.deep)))))
      : h("div", { class: "empty" }, "No computer or network discovery rows are in the store yet."));

    const sysCoverage = h("div", { class: "card group" },
      h("h2", {}, "System scan & rule catalogue coverage"),
      D.systems.length ? h("table", { class: "data" },
        h("tr", {},
          h("th", {}, "System"),
          h("th", {}, "Instance"),
          h("th", {}, "Scanned"),
          h("th", { class: "n" }, "Correct"),
          h("th", { class: "n" }, "Should Configure"),
          h("th", { class: "n" }, "Broken"),
          h("th", { class: "n" }, "Couldn't Check"),
          h("th", { class: "n" }, "No Result"),
          h("th", { class: "n" }, "Judged %")),
        D.systems.map(s => {
          const judged = (s.correct || 0) + (s.should || 0) + (s.broken || 0);
          const total = (s.checks || 0) + (s.norun || 0);
          return h("tr", {},
            h("td", {}, h("b", {}, s.system)),
            h("td", {}, s.instance),
            h("td", {}, (s.scanned || "").slice(0, 10)),
            h("td", { class: "n" }, fmt(s.correct)),
            h("td", { class: "n" }, fmt(s.should)),
            h("td", { class: "n" }, fmt(s.broken)),
            h("td", { class: "n" }, fmt(s.unchecked)),
            h("td", { class: "n" }, fmt(s.norun)),
            h("td", { class: "n" }, pct(judged, total)));
        }))
      : h("div", { class: "empty" }, "No scanned systems recorded yet."));

    return [
      h("h1", {}, "Operational and scan coverage"),
      h("p", { class: "lede" }, "What Keeper sees across the estate, which machines are reachable or inspected deeply, rule standing per system, and operational blind spots."),
      estateTiles,
      kindCard,
      sysCoverage,
      D.coverage.length ? h("div", { class: "card group" }, h("div", { class: "h" }, "Operational blind spots (failed or partial reads)"),
        D.coverage.map(c => h("div", { class: "ok" }, statusDot(ST[3]), h("div", { style: "flex:1" }, h("div", {}, `${c.system}: ${c.scope || "read"} ${c.item || ""} (${c.state})`), h("div", { class: "meta" }, c.reason || ""))))) : null,
      h("div", { class: "card group" }, h("div", { class: "h" }, `Checks without an answer (${fmt(items.length)})`),
        items.length ? items.map(u => h("div", { class: "ok" }, sevBadge(u.severity), h("div", { style: "flex:1" }, h("div", {}, u.title), h("div", { class: "meta" }, `${u.system} · ${u.id} · ${u.why || ""}`)))) :
          h("div", { class: "empty" }, "Every check that ran could see its data.")),
      D.neverScanned.length ? h("div", { class: "card group" }, h("div", { class: "h" }, "Unscanned catalogue rule packs"),
        h("div", { class: "chips" }, D.neverScanned.map(n => h("span", { class: "chip" }, `${n.system} · ${n.rules} rules`)))) : null
    ];
  },

  passed() {
    const q = state.q.toLowerCase();
    const items = D.passed.filter(p => (state.system === "all" || p.system === state.system) && (!q || (p.title + " " + p.id).toLowerCase().includes(q)));
    const groups = [...new Set(items.map(p => p.system))];
    return [h("h1", {}, "Configured correctly"),
      h("p", { class: "lede" }, `Each line is a problem Keeper looked for and did not find anywhere it looked - in a complete, fresh read. ${fmt(items.length)} checks.`),
      groups.length ? groups.map(g => h("div", { class: "card group" }, h("div", { class: "h" }, statusDot(ST[0]), g),
        items.filter(p => p.system === g).map(p => h("div", { class: "ok" }, sevBadge(p.severity),
          h("div", { style: "flex:1" }, h("div", {}, p.title), h("div", { class: "meta" }, `${p.id} · none found in ${fmt(p.passed)} checked${p.override ? " · threshold changed by " + p.override : ""}`)))))) :
        h("div", { class: "card empty" }, "Nothing passes yet: a check counts only when it passed everywhere in a clean, fresh read.")];
  },
};

function entityDetail(e) {
  const brokenList = (e.findings || []).filter(f => f.kind === "broken");
  const configList = (e.findings || []).filter(f => f.kind !== "broken");

  const idBadges = [
    e.type ? `type: ${e.type}` : null,
    e.kind ? `kind: ${e.kind}${e.kindWhy ? " (" + e.kindWhy + ")" : ""}` : null,
    e.state ? `network: ${e.state}` : null,
    e.os ? `os: ${e.os}` : null,
    e.unlisted ? "unlisted in directory" : null,
    e.deep ? "deep host inspection" : null
  ].filter(Boolean);

  return h("div", { class: "card detail" },
    h("div", { style: "display:flex;gap:10px;align-items:center;flex-wrap:wrap" },
      e.open ? sevBadge(e.critical ? "critical" : e.high ? "high" : "medium") : statusDot(ST[0]),
      h("span", { class: "meta" }, (e.systems || []).join(", ") || e.type)),
    h("h3", {}, e.name),
    h("div", { class: "kv" }, idBadges.map(b => h("span", { class: "chip" }, b))),
    (e.addresses && e.addresses.length) ? h("div", { class: "block" }, h("div", { class: "h" }, "Addresses & Sources"),
      h("div", {}, `Addresses: ${e.addresses.join(", ")}${e.sources && e.sources.length ? " · Seen in: " + e.sources.join(", ") : ""}`)) : null,
    (e.services && e.services.length) ? h("div", { class: "block" }, h("div", { class: "h" }, "Open Network Services"),
      h("div", { class: "chips" }, e.services.map(s => h("span", { class: "chip" }, s)))) : null,
    e.snmp ? h("div", { class: "block" }, h("div", { class: "h" }, "SNMP Identity"), h("div", {}, e.snmp)) : null,

    h("div", { class: "block" },
      h("div", { class: "h" }, `What is broken on this object (${fmt(brokenList.length)})`),
      brokenList.length ? brokenList.map(f => h("div", { class: "ok", style: "cursor:pointer", onclick: () => openFinding(f.id) },
        sevBadge(f.severity),
        h("div", { style: "flex:1" },
          h("div", {}, h("b", {}, f.title), ` [${f.system} / ${f.category} / ${f.id}]`),
          h("div", { class: "meta" }, f.evidence || ""),
          f.fix ? h("div", { class: "fix", style: "margin-top:4px" }, f.fix) : null)))
      : h("div", { class: "meta" }, "Nothing is currently reported broken on this object.")),

    h("div", { class: "block" },
      h("div", { class: "h" }, `What should be configured on this object (${fmt(configList.length)})`),
      configList.length ? configList.map(f => h("div", { class: "ok", style: "cursor:pointer", onclick: () => openFinding(f.id) },
        sevBadge(f.severity),
        h("div", { style: "flex:1" },
          h("div", {}, h("b", {}, f.title), ` [${f.system} / ${f.category} / ${f.id}]`),
          h("div", { class: "meta" }, f.evidence || ""),
          f.fix ? h("div", { class: "fix", style: "margin-top:4px" }, f.fix) : null)))
      : h("div", { class: "meta" }, "No misconfigurations or missing controls reported on this object.")),

    (e.decisions && e.decisions.length) ? h("div", { class: "block" },
      h("div", { class: "h" }, "Active Decisions & Exceptions"),
      e.decisions.map(d => h("div", { class: "ok" }, d))) : null,

    (e.blindSpots && e.blindSpots.length) ? h("div", { class: "block" },
      h("div", { class: "h" }, "Operational Blind Spots on this Object"),
      e.blindSpots.map(b => h("div", { class: "warnbox" }, b))) : null,

    h("div", { class: "block" },
      h("div", { class: "h" }, `Passed Checks on this Object (${fmt(e.passedCount)})`),
      (e.passed && e.passed.length)
        ? h("div", { class: "chips" }, e.passed.map(p => h("span", { class: "chip" }, p)))
        : h("div", { class: "meta" }, "No individual passing checks recorded for this object yet."))
  );
}

function detail(c) {
  const q = state.objq.toLowerCase();
  const objs = c.objects.filter(o => !q || o.join(" ").toLowerCase().includes(q));
  const shown = state.objAll ? objs : objs.slice(0, 300);
  const objList = h("div", {}, shown.map(([name, ev, rawKey]) => h("div", { class: "obj" },
    h("div", {}, ev ? (name && name !== "-" && !ev.toLowerCase().includes(String(name).toLowerCase()) ? [h("b", {}, name), h("span", {}, " — " + ev)] : h("span", {}, ev)) : h("b", {}, name || "")),
    (rawKey && rawKey !== "-") ? h("button", { class: "chip", onclick: () => openEntity(rawKey) }, "Dossier") : null)),
    objs.length > shown.length ? h("div", { class: "obj" }, h("button", { class: "chip", onclick: () => { state.objAll = true; render(); } }, `Show all ${fmt(objs.length)}`)) : null,
    !objs.length ? h("div", { class: "empty" }, "No object matches.") : null);
  const text = () => objs.map(([n, e]) => e || n).join("\n");
  const csv = () => "name,evidence\n" + objs.map(([n, e]) => [n, e].map(v => '"' + String(v ?? "").replace(/"/g, '""') + '"').join(",")).join("\n");
  const download = () => { const a = h("a", { href: URL.createObjectURL(new Blob([csv()], { type: "text/csv" })), download: c.id + ".csv" }); document.body.append(a); a.click(); a.remove(); };
  const filter = h("input", { type: "search", placeholder: `Filter ${fmt(c.count)} objects`, value: state.objq,
    oninput: e => { state.objq = e.target.value; const pos = e.target.selectionStart; render(); const f = document.querySelector(".objs input"); if (f) { f.focus(); f.setSelectionRange(pos, pos); } } });
  return h("div", { class: "card detail" },
    h("div", { style: "display:flex;gap:10px;align-items:center" }, sevBadge(c.severity), h("span", { class: "meta" }, KIND[c.kind] || c.kind)),
    h("h3", {}, c.title),
    h("div", { class: "kv" }, h("span", {}, `Found on ${fmt(c.count)}`), h("span", {}, c.system), c.category ? h("span", {}, c.category) : null, h("span", {}, c.id), c.firstSeen ? h("span", {}, `first seen ${c.firstSeen.slice(0, 10)}`) : null, c.security ? h("span", {}, "security") : null),
    c.why ? h("div", { class: "block" }, h("div", { class: "h" }, "Why it matters"), h("div", {}, c.why)) : null,
    c.fix ? h("div", { class: "block" }, h("div", { class: "h" }, "What to do"), h("div", { class: "fix" }, c.fix)) : null,
    c.refs && c.refs.length ? h("div", { class: "block" }, h("div", { class: "h" }, "References"), h("div", { class: "chips" }, c.refs.map(r => h("span", { class: "chip" }, r)))) : null,
    h("div", { class: "block" }, h("div", { class: "h" }, "Where"),
      h("div", { class: "objs" }, h("div", { class: "tools" }, filter,
        h("button", { class: "chip", onclick: e => { navigator.clipboard && navigator.clipboard.writeText(text()); e.target.textContent = "Copied"; } }, "Copy"),
        h("button", { class: "chip", onclick: download }, "CSV")), objList)));
}

function show(tab) {
  state.tab = tab;
  if (tab === "findings" && state.selected) location.hash = "findings/" + encodeURIComponent(state.selected);
  else if (tab === "objects" && state.selectedEntity) location.hash = "objects/" + encodeURIComponent(state.selectedEntity);
  else location.hash = tab;
  render();
  window.scrollTo(0, 0);
}

const TABS = [
  ["overview", "Overview"],
  ["findings", "Findings"],
  ["objects", "Objects"],
  ["matrix", "Matrix"],
  ["coverage", "Coverage"],
  ["passed", "Correct"]
];

function render() {
  const nav = document.getElementById("nav"); nav.replaceChildren(...TABS.map(([k, l]) => h("button", { "aria-current": state.tab === k ? "page" : null, onclick: () => show(k) }, l)));
  document.getElementById("main").replaceChildren(...views[state.tab](), h("div", { class: "foot" }, `Generated ${D.generated} by keeper · read-only · nothing in this page was fetched from anywhere`));
}

document.getElementById("sub").textContent = [D.tenant, D.generated].filter(Boolean).join(" · ");
const qInput = document.getElementById("q");
qInput.addEventListener("input", () => { state.q = qInput.value; if (state.tab === "overview" && state.q) state.tab = "findings"; render(); });
document.getElementById("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("keeper-theme", document.documentElement.dataset.theme); } catch { }
});
try { const t = localStorage.getItem("keeper-theme"); if (t) document.documentElement.dataset.theme = t; } catch { }
document.addEventListener("keydown", e => {
  if (e.target.matches("input, select")) { if (e.key === "Escape") e.target.blur(); return; }
  if (e.key === "/") { e.preventDefault(); qInput.focus(); }
  if ((state.tab === "findings" || state.tab === "objects") && (e.key === "j" || e.key === "k")) {
    const ids = [...document.querySelectorAll(".list .row")].map(r => r.dataset.id);
    const cur = state.tab === "findings" ? state.selected : state.selectedEntity;
    const i = ids.indexOf(cur);
    const next = ids[Math.min(ids.length - 1, Math.max(0, i + (e.key === "j" ? 1 : -1)))];
    if (next) {
      if (state.tab === "findings") { state.selected = next; state.objq = ""; state.objAll = false; }
      else { state.selectedEntity = next; }
      render();
      document.querySelector('.list .row[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
    }
  }
});
const m = location.hash.slice(1).split("/");
if (m[0] === "unchecked") state.tab = "coverage";
else if (TABS.some(([k]) => k === m[0])) state.tab = m[0];
if (m[0] === "findings" && m[1]) state.selected = decodeURIComponent(m[1]);
if (m[0] === "objects" && m[1]) state.selectedEntity = decodeURIComponent(m[1]);
render();
</script>
</body></html>
""";
}
