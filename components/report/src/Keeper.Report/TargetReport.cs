using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// Point-in-time dossier for one specific object (server, computer, account, endpoint, GPO, or entity key):
/// 1. Identity &amp; discovered state across every scan that saw it (AD, network discovery inventory, cloud, etc.).
/// 2. Open findings on this object (broken vs misconfigured/missing), with evidence, why, and fix.
/// 3. Active decisions on this object (snoozed, delegated, accepted risk).
/// 4. Coverage on this object: which checks passed, which checks could not run (unknown / failed target reads),
///    and whether an answering machine is only seen on the network without deep host inspection.
/// </summary>
public static class TargetReport
{
    public static Document Build(SqliteConnection connection, string targetQuery, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(targetQuery))
            throw new ArgumentException("Target report requires an object name, IP address, or key (e.g. 'keeper report target dc01.example.com').");

        var needle = targetQuery.Trim();
        var lower = needle.ToLowerInvariant();
        var gpoNames = Reports.GpoNames(connection);

        // 1. Find matching inventory rows in row_seen from the newest run of each (instance, system)
        var seenRows = Sql.Rows(connection,
            """
            SELECT r.system, r.instance, rs.entity_type, rs.entity_key, rs.entity_name, rs.attrs, rs.observed_at
            FROM row_seen rs
            JOIN latest_run r ON r.run_id = rs.run_id
            WHERE lower(rs.entity_key) = :q
               OR lower(rs.entity_name) = :q
               OR lower(rs.entity_key) = 'ip:' || :q
               OR lower(COALESCE(json_extract(rs.attrs, '$.dNSHostName'), '')) = :q
               OR lower(COALESCE(json_extract(rs.attrs, '$.sAMAccountName'), '')) = :q
               OR lower(COALESCE(json_extract(rs.attrs, '$.userPrincipalName'), '')) = :q
               OR EXISTS (
                   SELECT 1 FROM json_each(CASE WHEN json_type(rs.attrs, '$.addresses') = 'array' THEN json_extract(rs.attrs, '$.addresses') ELSE '[]' END) a
                   WHERE lower(a.value) = :q
               )
               OR EXISTS (
                   SELECT 1 FROM json_each(CASE WHEN json_type(rs.attrs, '$.names') = 'array' THEN json_extract(rs.attrs, '$.names') ELSE '[]' END) n
                   WHERE lower(n.value) = :q
               )
            ORDER BY r.system, r.instance, rs.entity_type;
            """,
            null, (":q", lower));

        // Collect all known keys/names for this object so we match findings and results whether keyed by hostname, IP, or samAccountName
        var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { needle, $"ip:{needle}" };
        foreach (var row in seenRows)
        {
            if (row["entity_key"] is string ek && ek.Length > 0)
            {
                aliases.Add(ek);
                if (ek.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
                    aliases.Add(ek[3..]);
            }
            if (row["entity_name"] is string en && en.Length > 0)
                aliases.Add(en);
            if (row["attrs"] is string attrsJson && JsonNode.Parse(attrsJson) is JsonObject attrs)
            {
                if (attrs["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
                    aliases.Add(dns);
                if (attrs["sAMAccountName"]?.GetValue<string>() is { Length: > 0 } sam)
                    aliases.Add(sam.TrimEnd('$'));
                if (attrs["addresses"] is JsonArray addrs)
                {
                    foreach (var a in addrs.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)))
                        aliases.Add(a!);
                }
                if (attrs["names"] is JsonArray names)
                {
                    foreach (var n in names.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)))
                        aliases.Add(n!);
                }
            }
        }

        bool MatchesTarget(string? entityKey, string? entityName)
        {
            foreach (var candidate in new[] { entityKey, entityName })
            {
                if (string.IsNullOrWhiteSpace(candidate))
                    continue;
                if (aliases.Contains(candidate))
                    return true;
                // target in findings can be "instance/key" or "key|subkey"
                var slash = candidate.IndexOf('/', StringComparison.Ordinal);
                if (slash >= 0 && aliases.Contains(candidate[(slash + 1)..]))
                    return true;
                var pipe = candidate.IndexOf('|', StringComparison.Ordinal);
                if (pipe >= 0 && aliases.Contains(candidate[..pipe]))
                    return true;
            }
            return false;
        }

        var identityLines = FormatIdentityLines(seenRows, out var networkState, out var hasManagementProto);

        // 2. Open findings on this object
        var allOpenFindings = Sql.Rows(connection,
            """
            SELECT check_id, rule_id, system, system_id, instance, entity_type, target, entity_name,
                   kind, lens, category, severity, severity_rank, security, title, evidence, why, fix,
                   first_seen, deadline, days_left, snoozed_until, delegated_to
            FROM active_finding
            ORDER BY severity_rank, kind, check_id;
            """)
            .Where(r => MatchesTarget(r["target"] as string, r["entity_name"] as string))
            .ToList();

        var brokenCards = BuildObjectCards(allOpenFindings.Where(f => (string)f["kind"]! == "broken").ToList(), gpoNames);
        var configCards = BuildObjectCards(allOpenFindings.Where(f => (string)f["kind"]! != "broken").ToList(), gpoNames);

        var openSummaryLines = new List<string>();
        if (allOpenFindings.Count > 0)
        {
            var crit = allOpenFindings.Count(f => (string)f["severity"]! == "critical");
            var high = allOpenFindings.Count(f => (string)f["severity"]! == "high");
            var med = allOpenFindings.Count(f => (string)f["severity"]! == "medium");
            var low = allOpenFindings.Count(f => (string)f["severity"]! is "low" or "info");
            var brokenCount = allOpenFindings.Count(f => (string)f["kind"]! == "broken");
            var secCount = allOpenFindings.Count(f => f["security"] is 1L);
            var maintCount = allOpenFindings.Count - secCount;
            openSummaryLines.Add(string.Create(CultureInfo.InvariantCulture,
                $"Total open on {needle}: {allOpenFindings.Count} ({crit} critical, {high} high, {med} medium, {low} low/info; {brokenCount} broken, {allOpenFindings.Count - brokenCount} misconfigured/missing; {maintCount} maintenance, {secCount} security)."));
        }

        // 3. Decisions (snoozed, delegated, accepted risk / disabled on this object)
        var decisionLines = new List<string>();
        foreach (var f in allOpenFindings.Where(f => f["snoozed_until"] is string || f["delegated_to"] is string))
        {
            var statusNote = f["snoozed_until"] is string until ? $"snoozed until {until}" : $"delegated to {f["delegated_to"]}";
            decisionLines.Add($"[{f["severity"]}] {f["title"]} ({f["check_id"]}): {statusNote}");
        }
        var acceptedRows = Sql.Rows(connection,
            """
            SELECT check_id, severity, title, status, target, entity_name
            FROM finding
            WHERE status IN ('exception', 'disabled')
            ORDER BY check_id;
            """)
            .Where(r => MatchesTarget(r["target"] as string, r["entity_name"] as string));
        foreach (var r in acceptedRows)
            decisionLines.Add($"[{r["severity"]}] {r["title"]} ({r["check_id"]}): {r["status"]}");

        // 4. Coverage on this object (passed rules, unknown rules, per-target failed reads, and inspection depth)
        var allResults = Sql.Rows(connection,
            """
            SELECT res.instance, res.rule_id, res.entity_type, res.entity_key, res.state, res.why, res.at,
                   COALESCE(ru.system, res.instance) AS system, COALESCE(ru.title, res.rule_id) AS title,
                   COALESCE(ru.severity, 'info') AS severity, COALESCE(ru.category, 'CFG') AS category
            FROM result res
            LEFT JOIN rule ru ON ru.rule_id = res.rule_id
            ORDER BY system, res.rule_id;
            """)
            .Where(r => MatchesTarget(r["entity_key"] as string, null))
            .ToList();

        var passedResults = allResults.Where(r => (string)r["state"]! == "pass").ToList();
        var unknownResults = allResults.Where(r => (string)r["state"]! == "unknown").ToList();
        var failedResults = allResults.Where(r => (string)r["state"]! == "fail").ToList();

        var targetCoverageFailures = Sql.Rows(connection,
            """
            SELECT r.system, r.instance, c.item, c.state, c.reason
            FROM coverage c
            JOIN latest_run r ON r.run_id = c.run_id
            WHERE c.scope = 'target' AND c.state IN ('failed', 'partial')
            ORDER BY r.system, c.item;
            """)
            .Where(r =>
            {
                var item = r["item"] as string ?? "";
                var atIdx = item.LastIndexOf('@');
                return atIdx >= 0 && aliases.Contains(item[(atIdx + 1)..]);
            })
            .ToList();

        var blindSpotLines = new List<string>();
        foreach (var tc in targetCoverageFailures)
            blindSpotLines.Add($"{tc["system"]} ({tc["instance"]}): target read {tc["item"]} was {tc["state"]}{(tc["reason"] is string rsn ? $" - {rsn}" : "")}");
        foreach (var u in unknownResults)
            blindSpotLines.Add($"{u["system"]} ({u["instance"]}): {u["title"]} ({u["rule_id"]}) could not be checked{(u["why"] is string w ? $" - {w}" : "")}");

        // Check operational depth: if seen as an answering machine on the network or AD computer, do we have host-level checks?
        var inspectedSystems = allResults.Select(r => (string)r["system"]!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var hasDeepHostScan = inspectedSystems.Any(s => s is not ("network" or "active-directory" or "entra" or "hybrid-identity"));
        var isComputer = seenRows.Any(r => (string)r["entity_type"]! is "computer" or "host");
        if (isComputer && !hasDeepHostScan)
        {
            if (networkState == "answering" && hasManagementProto == false)
                blindSpotLines.Add("Operational gap: machine answers on the network but exposes no management protocol (WinRM, SSH, HTTPS, or SNMP), so Keeper cannot inspect inside the host.");
            else
                blindSpotLines.Add("Operational gap: Keeper only has directory/network surface data for this computer; no host-level pack (OS, services, registry, event logs, SMB, or TLS) has scanned inside it yet.");
        }

        var passedLines = passedResults
            .Select(r => $"[{r["system"]}] {r["title"]} ({r["rule_id"]}) - passed")
            .ToList();

        var totalJudgedOnObject = passedResults.Count + failedResults.Count;
        var coverageIntro = totalJudgedOnObject == 0 && unknownResults.Count == 0
            ? "No rule has recorded an individual pass, fail, or unknown result for this object yet."
            : string.Create(CultureInfo.InvariantCulture,
                $"Keeper evaluated {totalJudgedOnObject + unknownResults.Count} check(s) directly on {needle} across {inspectedSystems.Count} system(s): {passedResults.Count} passed, {failedResults.Count} failed, and {unknownResults.Count} could not be checked.");

        return new Document(
            $"Object dossier: {needle}",
            $"Everything Keeper knows about {needle}: identity, open problems, decisions, and check coverage. Generated {Iso.Utc(now)}.",
            [
                new Section("Identity and inventory state", identityLines, $"No inventory row in row_seen matched '{needle}'.")
                {
                    Intro = seenRows.Count == 0 ? null : string.Create(CultureInfo.InvariantCulture, $"Seen in {seenRows.Count} inventory source(s)."),
                },
                new Section("What is broken on this object", openSummaryLines, "Nothing is currently reported broken on this object.")
                {
                    Intro = brokenCards.Count == 0 ? null : string.Create(CultureInfo.InvariantCulture, $"{brokenCards.Count} broken check(s) on {needle}: services, reachability, or expiring items that need operational attention."),
                    Cards = brokenCards,
                },
                new Section("What should be configured on this object", [], "No misconfigurations or missing controls reported on this object.")
                {
                    Intro = configCards.Count == 0 ? null : string.Create(CultureInfo.InvariantCulture, $"{configCards.Count} configuration or security check(s) failing on {needle}."),
                    Cards = configCards,
                },
                new Section("Decisions and exceptions on this object", decisionLines, "No active snoozes, delegations, or accepted risks on this object."),
                new Section("What passed on this object", passedLines, "No passing checks recorded on this object yet.")
                {
                    Intro = coverageIntro,
                },
                new Section("What Keeper could not check on this object", blindSpotLines, "Every check targeted at this object could read its data."),
            ]);
    }

    private static List<string> FormatIdentityLines(
        List<Dictionary<string, object?>> seenRows,
        out string? networkState,
        out bool? hasManagementProto)
    {
        networkState = null;
        hasManagementProto = null;
        var lines = new List<string>();

        foreach (var row in seenRows)
        {
            var sys = (string)row["system"]!;
            var inst = (string)row["instance"]!;
            var type = (string)row["entity_type"]!;
            var key = (string)row["entity_key"]!;
            var observed = (string)row["observed_at"]!;
            var attrsText = row["attrs"] as string;
            var attrs = attrsText is not null ? JsonNode.Parse(attrsText) as JsonObject : null;

            if (sys == "network" && attrs is not null)
            {
                var state = attrs["state"]?.GetValue<string>() ?? "unknown";
                var kind = attrs["kind"]?.GetValue<string>() ?? "unknown";
                var kindWhy = attrs["kindWhy"]?.GetValue<string>();
                networkState = state;
                var addrs = attrs["addresses"] is JsonArray a ? string.Join(", ", a.Select(x => x?.GetValue<string>())) : "";
                var sources = attrs["sources"] is JsonArray srcArr
                    ? string.Join(", ", srcArr.Select(s => s is JsonObject o ? o["kind"]?.GetValue<string>() : s?.GetValue<string>()).Where(s => s is not null))
                    : "";
                var answered = attrs["answered"] is JsonArray ansArr
                    ? ansArr.Select(x => x?.GetValue<string>() ?? "").Where(x => x.Length > 0).ToList()
                    : [];
                hasManagementProto = answered.Any(p => p is "ssh" or "winrm" or "https" or "snmp") || attrs["snmp"] is not null;

                lines.Add($"Network discovery ({inst}, {observed}): state={state}, kind={kind}{(kindWhy is not null ? $" ({kindWhy})" : "")}" +
                          $"{(addrs.Length > 0 ? $", addresses=[{addrs}]" : "")}{(sources.Length > 0 ? $", sources=[{sources}]" : "")}");

                if (attrs["services"] is JsonArray svcs && svcs.Count > 0)
                {
                    var svcDescriptions = svcs.OfType<JsonObject>()
                        .Select(s => $"{s["port"]}/{s["transport"] ?? "tcp"} {s["service"]}")
                        .ToList();
                    lines.Add($"  Open services: {string.Join(", ", svcDescriptions)}");
                }
                if (attrs["snmp"] is JsonObject snmp)
                {
                    lines.Add($"  SNMP: version={snmp["version"]?.GetValue<string>()}, sysName={snmp["sysName"]?.GetValue<string>() ?? "-"}, sysDescr={snmp["sysDescr"]?.GetValue<string>() ?? "-"}");
                }
            }
            else if (attrs is not null)
            {
                var details = new List<string>();
                if (attrs["operatingSystem"]?.GetValue<string>() is { Length: > 0 } os)
                    details.Add($"os={os}");
                if (attrs["dNSHostName"]?.GetValue<string>() is { Length: > 0 } dns)
                    details.Add($"dns={dns}");
                if (attrs["distinguishedName"]?.GetValue<string>() is { Length: > 0 } dn)
                    details.Add($"dn={dn}");
                var suffix = details.Count > 0 ? $": {string.Join(", ", details)}" : "";
                lines.Add($"{sys} ({inst}, {type} '{key}', seen {observed}){suffix}");
            }
            else
            {
                lines.Add($"{sys} ({inst}, {type} '{key}', seen {observed})");
            }
        }

        return lines;
    }

    private static List<Card> BuildObjectCards(List<Dictionary<string, object?>> findings, IReadOnlyDictionary<string, string> gpoNames) =>
        findings.Select(f =>
        {
            var sev = (string)f["severity"]!;
            var title = (string)f["title"]!;
            var sys = (string)f["system"]!;
            var cat = (string)f["category"]!;
            var checkId = (string)f["check_id"]!;
            var evidence = Reports.Named(f["evidence"] as string ?? (string)f["target"]!, gpoNames);
            var deadline = f["deadline"] is string d ? $" (deadline {d}, {f["days_left"]} days left)" : "";
            return new Card(
                sev,
                $"{title} [{sys} / {cat} / {checkId}]{deadline}",
                f["why"] as string,
                f["fix"] as string,
                [$"{evidence} (first seen {f["first_seen"]})"],
                1);
        }).ToList();
}
