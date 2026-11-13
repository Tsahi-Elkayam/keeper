using System.Globalization;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// Horizontal, cross-cutting view of the estate ("חתך רוחבי"):
/// 1. By operational &amp; security category (HLT, AVL, BCK, MON, LCM, CFG, HYG, IAM, AUT, PKI, LOG, CST).
/// 2. Widespread systemic checks failing across multiple objects and systems.
/// 3. Multi-finding object hotspots: individual servers/accounts/endpoints accumulating multiple distinct problems.
/// 4. Maintenance/operations vs security balance across systems.
/// </summary>
public static class CrossCutting
{
    public static Document Build(SqliteConnection connection, DateTimeOffset now)
    {
        var gpoNames = Reports.GpoNames(connection);

        // 1. Cross-cutting by category
        var categoryRows = Sql.Rows(connection,
            """
            SELECT c.code, c.name, c.security,
                   COUNT(f.finding_key) AS open_count,
                   SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                   SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count,
                   SUM(CASE WHEN f.kind = 'broken' THEN 1 ELSE 0 END) AS broken_count,
                   SUM(CASE WHEN f.kind IN ('misconfigured', 'missing') THEN 1 ELSE 0 END) AS config_count,
                   COUNT(DISTINCT f.system_id) AS systems_affected,
                   COUNT(DISTINCT f.target) AS targets_affected,
                   (SELECT COUNT(*) FROM rule_standing st JOIN rule r ON r.rule_id = st.rule_id WHERE r.category = c.code AND st.standing = 'correct') AS checks_correct,
                   (SELECT COUNT(*) FROM rule_standing st JOIN rule r ON r.rule_id = st.rule_id WHERE r.category = c.code) AS checks_ran
            FROM category c
            LEFT JOIN active_finding f ON f.category = c.code
            GROUP BY c.code, c.name, c.security
            HAVING open_count > 0 OR checks_ran > 0
            ORDER BY critical_count DESC, high_count DESC, open_count DESC, c.code;
            """);

        var categoryLines = categoryRows.Select(r =>
        {
            var code = (string)r["code"]!;
            var name = (string)r["name"]!;
            var tier = r["security"] is 1L ? "security" : "operations";
            var open = r["open_count"] as long? ?? 0;
            var crit = r["critical_count"] as long? ?? 0;
            var high = r["high_count"] as long? ?? 0;
            var broken = r["broken_count"] as long? ?? 0;
            var cfg = r["config_count"] as long? ?? 0;
            var sysCount = r["systems_affected"] as long? ?? 0;
            var tgtCount = r["targets_affected"] as long? ?? 0;
            var correct = r["checks_correct"] as long? ?? 0;
            var ran = r["checks_ran"] as long? ?? 0;
            var checkPart = ran > 0
                ? string.Create(CultureInfo.InvariantCulture, $"; {correct}/{ran} checks correct")
                : "";
            return string.Create(CultureInfo.InvariantCulture,
                $"[{code}] {name} ({tier}): {open} open ({crit} critical, {high} high; {broken} broken, {cfg} config/missing) across {sysCount} system(s) and {tgtCount} object(s){checkPart}");
        }).ToList();

        // 2. Widespread systemic checks (failing on > 1 target or across multiple systems)
        var widespreadCards = Sql.Rows(connection,
            """
            SELECT check_id, MIN(severity_rank) AS rank, severity, kind, category, title, why, fix,
                   COUNT(*) AS n, COUNT(DISTINCT system_id) AS systems_count,
                   GROUP_CONCAT(DISTINCT system_id) AS system_list
            FROM active_finding
            GROUP BY check_id
            HAVING COUNT(*) > 1
            ORDER BY rank, n DESC, systems_count DESC, title
            LIMIT 40;
            """)
            .Select(c =>
            {
                var total = (int)(long)c["n"]!;
                var sysCount = (long)c["systems_count"]!;
                var items = Sql.Rows(connection,
                        """
                        SELECT system_id, COALESCE(entity_name, target) AS name, target, evidence
                        FROM active_finding
                        WHERE check_id = :check
                        ORDER BY system_id, name
                        LIMIT :max;
                        """,
                        null, (":check", c["check_id"]), (":max", Reports.CardItems))
                    .Select(r =>
                    {
                        var name = r["name"] as string ?? "";
                        var ev = r["evidence"] as string ?? "";
                        var line = ev.Length == 0 ? name : (name == "-" || ev.Contains(name, StringComparison.OrdinalIgnoreCase) ? ev : $"{name}: {ev}");
                        return $"[{r["system_id"]}] {Reports.Named(line, gpoNames)}";
                    })
                    .ToList();

                var headline = string.Create(CultureInfo.InvariantCulture,
                    $"Found on {total} objects across {sysCount} system(s): {c["title"]} [{c["category"]} / {c["check_id"]}]");
                return new Card(
                    (string)c["severity"]!,
                    headline,
                    c["why"] as string,
                    c["fix"] as string,
                    items,
                    total);
            })
            .ToList();

        // 3. Multi-finding object hotspots (objects with multiple open findings)
        var hotspotRows = Sql.Rows(connection,
            """
            SELECT COALESCE(entity_name, target) AS object_name,
                   entity_type,
                   COUNT(*) AS open_count,
                   COUNT(DISTINCT check_id) AS checks_count,
                   COUNT(DISTINCT system) AS systems_count,
                   SUM(severity = 'critical') AS crit,
                   SUM(severity = 'high') AS high,
                   SUM(kind = 'broken') AS broken,
                   SUM(security = 1) AS sec,
                   GROUP_CONCAT(DISTINCT system) AS systems,
                   GROUP_CONCAT(DISTINCT check_id) AS checks
            FROM active_finding
            WHERE target <> '-'
            GROUP BY COALESCE(entity_name, target), entity_type
            ORDER BY crit DESC, high DESC, open_count DESC, object_name
            LIMIT 30;
            """);

        var hotspotLines = hotspotRows.Select(r =>
        {
            var objName = Reports.Named((string)r["object_name"]!, gpoNames);
            var type = (string)r["entity_type"]!;
            var open = (long)r["open_count"]!;
            var crit = r["crit"] as long? ?? 0;
            var high = r["high"] as long? ?? 0;
            var broken = r["broken"] as long? ?? 0;
            var sec = r["sec"] as long? ?? 0;
            var systems = r["systems"] as string ?? "";
            var checks = r["checks"] as string ?? "";
            return string.Create(CultureInfo.InvariantCulture,
                $"{objName} ({type}, in {systems}): {open} open ({crit} critical, {high} high; {broken} broken, {sec} security) - checks: {checks}");
        }).ToList();

        // 4. Operations vs security split by system
        var systemSplitLines = Sql.Rows(connection,
            """
            SELECT f.system_id, COALESCE(s.name, f.system_id) AS sys_name,
                   COUNT(*) AS total,
                   SUM(f.kind = 'broken') AS broken,
                   SUM(f.kind = 'misconfigured') AS misconfigured,
                   SUM(f.kind = 'missing') AS missing,
                   SUM(f.security = 0) AS maintenance_tier,
                   SUM(f.security = 1) AS security_tier,
                   SUM(f.severity IN ('critical', 'high')) AS serious
            FROM active_finding f
            LEFT JOIN system s ON s.system_id = f.system_id
            GROUP BY f.system_id
            ORDER BY serious DESC, total DESC, f.system_id;
            """)
            .Select(r =>
            {
                var id = (string)r["system_id"]!;
                var name = (string)r["sys_name"]!;
                var label = id.Equals(name, StringComparison.OrdinalIgnoreCase) ? id : $"{id} ({name})";
                return string.Create(CultureInfo.InvariantCulture,
                    $"{label}: {r["total"]} open ({r["serious"]} critical/high) - operations/maintenance: {r["maintenance_tier"]}, security: {r["security_tier"]} | broken: {r["broken"]}, misconfigured: {r["misconfigured"]}, missing: {r["missing"]}");
            })
            .ToList();

        return new Document(
            "Cross-cutting estate matrix",
            $"Horizontal view across categories, systemic checks, multi-finding object hotspots, and systems. Generated {Iso.Utc(now)}.",
            [
                new Section("By operational and security category", categoryLines, "No findings or evaluated rules in any category yet.")
                {
                    Intro = "How open problems and passing checks distribute across Keeper's 12 operational and security categories.",
                },
                new Section("Widespread systemic issues", [], "No check currently fails on more than one object.")
                {
                    Intro = widespreadCards.Count == 0
                        ? null
                        : string.Create(CultureInfo.InvariantCulture, $"{widespreadCards.Count} check(s) fail across multiple objects: fixing the root cause (GPO, template, script, or standard) resolves all of them together."),
                    Cards = widespreadCards,
                },
                new Section("Object hotspots (most problems on a single target)", hotspotLines, "No individual target has open findings.")
                {
                    Intro = "Individual machines, accounts, or objects accumulating the highest number of open findings across all checks. Inspect any target in full with 'keeper report target <name>'.",
                },
                new Section("Operations vs security balance by system", systemSplitLines, "No systems have open findings."),
            ]);
    }
}
