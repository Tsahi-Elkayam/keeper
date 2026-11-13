using Keeper.Common;
using Keeper.Contracts;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>Reports for people who read rather than act: the state of the estate, security, what expires, what changed.</summary>
public static class Reports
{
    public static readonly IReadOnlyList<string> Names = ["posture", "summary", "security", "expiring", "changes", "trends", "finance", "matrix", "coverage", "assets"];

    public static Document Build(string name, SqliteConnection connection, DateTimeOffset now, string? since, int days = 90, string? target = null) => name switch
    {
        "posture" => Posture(connection, now),
        "summary" => Summary(connection, now),
        "security" => Security(connection, now),
        "expiring" => Expiring(connection, now),
        "changes" => Changes(connection, since ?? Iso.Date(now.AddDays(-30))),
        "trends" => Trends.Build(connection, now, days),
        "finance" => Finance.Build(connection, now, days),
        "matrix" or "cross-cutting" => CrossCutting.Build(connection, now),
        "coverage" => CoverageReport.Build(connection, now),
        "assets" or "inventory" => Assets.Build(connection, now),
        "target" or "object" => TargetReport.Build(connection, target ?? "", now),
        _ => throw new ArgumentException($"Reports: {string.Join(", ", Names)}, target <name>, evidence."),
    };

    private static List<string> Lines(SqliteConnection connection, string sql, Func<Dictionary<string, object?>, string> line,
        params (string, object?)[] parameters) =>
        Sql.Rows(connection, sql, null, parameters).Select(line).ToList();

    private static Document Summary(SqliteConnection connection, DateTimeOffset now) => new(
        "Estate summary",
        $"Generated {Iso.Utc(now)}.",
        [
            new Section("Open findings by kind and severity", Lines(connection,
                """
                SELECT kind, severity, COUNT(*) AS n FROM active_finding f JOIN severity s ON s.code = f.severity
                GROUP BY kind, severity ORDER BY kind, MIN(s.rank);
                """, r => $"{r["kind"]} / {r["severity"]}: {r["n"]}"), "No open findings."),
            Widespread(connection, security: false),
            new Section("Systems with the most serious open findings", Lines(connection,
                """
                SELECT system_id, COUNT(*) AS n, SUM(severity = 'critical') AS c, SUM(severity = 'high') AS h
                FROM active_finding GROUP BY system_id ORDER BY c DESC, h DESC, n DESC LIMIT 15;
                """, r => $"{r["system_id"]}: {r["n"]} open ({r["c"]} critical, {r["h"]} high)"), "No systems with findings."),
            new Section("Last 30 days", Lines(connection,
                "SELECT event, COUNT(*) AS n FROM finding_event WHERE julianday('now') - julianday(at) <= 30 GROUP BY event ORDER BY n DESC;",
                r => $"{r["event"]}: {r["n"]}"), "No changes."),
            new Section("Coverage", Lines(connection,
                """
                SELECT (SELECT COUNT(*) FROM rule) AS rules,
                       (SELECT COUNT(DISTINCT rule_id) FROM result) AS ran,
                       (SELECT COUNT(DISTINCT rule_id) FROM result WHERE state = 'unknown') AS unknown,
                       (SELECT COUNT(*) FROM latest_run WHERE status <> 'ok') AS imperfect_scans;
                """, r => $"{r["ran"]} of {r["rules"]} rules have results; {r["unknown"]} rules could not see their data; {r["imperfect_scans"]} newest scans were partial or failed.")),
        ]);

    /// <summary>The objects a posture card lists in full; the rest are one question away.</summary>
    public const int CardItems = 200;

    /// <summary>
    /// The three questions told as an audit: what Keeper found (each finding with the objects it was found on,
    /// what was seen on each, why it matters and what to do), what is configured correctly, and what it could
    /// not check - which bounds that answer. Counts are checks (rules) on each instance's newest scan.
    /// </summary>
    private static Document Posture(SqliteConnection connection, DateTimeOffset now)
    {
        var systems = Sql.Rows(connection,
            """
            SELECT st.system, st.instance, COUNT(*) AS checks,
                   SUM(st.standing = 'correct') AS correct, SUM(st.standing = 'should-configure') AS should,
                   SUM(st.standing = 'broken') AS broken, SUM(st.standing = 'not-checked') AS unchecked,
                   (SELECT COUNT(*) FROM rule r WHERE r.system = st.system) - COUNT(*) AS not_run,
                   substr(MAX(st.tested_at), 1, 10) AS scanned
            FROM rule_standing st GROUP BY st.system, st.instance ORDER BY st.system, st.instance;
            """);
        long Sum(string column) => systems.Sum(s => s[column] is long n ? n : 0);
        var gpoNames = GpoNames(connection);
        var shouldCards = Cards(connection, "kind IN ('missing', 'misconfigured')", gpoNames);
        var brokenCards = Cards(connection, "kind = 'broken'", gpoNames);
        var open = Sql.Scalar(connection, "SELECT COUNT(*) FROM active_finding;") is long o ? o : 0;

        // Standings are read through the rule catalogue: scans loaded without 'keeper rules load' show nothing.
        var nothing = Sql.Scalar(connection, "SELECT EXISTS (SELECT 1 FROM result) AND NOT EXISTS (SELECT 1 FROM rule);") is 1L
            ? "Scans have results, but the rule catalogue is not loaded: run 'keeper rules load' then 'keeper qm run' ('keeper run' does both)."
            : "No scan has results yet: nothing is known to be correct, wrong or broken.";
        var intro = systems.Count == 0 ? null
            : $"Keeper ran {Sum("checks")} checks on {systems.Count} system(s). {Sum("correct")} found the configuration correct, " +
              $"{Sum("should")} found something that should be configured, {Sum("broken")} found something broken, and " +
              $"{Sum("unchecked")} could not check because the data could not be fully read. Behind them are {open} open findings. " +
              $"{Sum("not_run")} further checks for these systems produced no result in this scan.";

        var fixFirst = shouldCards.Concat(brokenCards)
            .Where(c => c.Severity is "critical" or "high")
            .OrderBy(c => Vocabulary.SeverityRank(c.Severity)).ThenByDescending(c => c.Total)
            .Take(5)
            .Select(c => $"[{c.Severity}] {c.Headline}")
            .ToList();

        return new Document(
            "Configuration posture",
            $"What Keeper found: what should be configured, what is broken, what is configured correctly - and what it could not check. Generated {Iso.Utc(now)}.",
            [
                new Section("Summary",
                    [.. systems.Select(s => $"{s["system"]} ({s["instance"]}, scanned {s["scanned"]}): {s["correct"]} correct, {s["should"]} should be configured, " +
                                            $"{s["broken"]} broken, {s["unchecked"]} could not check, {s["not_run"]} no result"),
                     .. fixFirst.Count == 0 ? Array.Empty<string>() : ["", "Fix first:", .. fixFirst]],
                    nothing) { Intro = intro },
                new Section("What should be configured", [], "Nothing found to configure.")
                {
                    Intro = shouldCards.Count == 0 ? null : $"{shouldCards.Count} checks found something missing or set against best practice, on {shouldCards.Sum(c => c.Total)} objects in all.",
                    Cards = shouldCards,
                },
                new Section("What is configured but broken", [], "Nothing found broken.")
                {
                    Intro = brokenCards.Count == 0 ? null : $"{brokenCards.Count} checks found something that does not work, or has stopped working, on {brokenCards.Sum(c => c.Total)} objects in all.",
                    Cards = brokenCards,
                },
                new Section("What is configured correctly", Lines(connection,
                    """
                    SELECT st.system, st.title, st.passed, st.threshold_override
                    FROM rule_standing st JOIN severity s ON s.code = st.severity
                    WHERE st.standing = 'correct' ORDER BY st.system, s.rank, st.rule_id;
                    """,
                    r => $"{r["system"]}: checked {r["passed"]}, none found - {r["title"]}" +
                         (r["threshold_override"] is string ov ? $" (against a threshold changed by {ov})" : "")),
                    "Nothing yet: a check counts as correct only when it passed everywhere in a clean, fresh read.")
                {
                    Intro = "Each line is a problem Keeper looked for and did not find anywhere it looked.",
                },
                new Section("What Keeper could not check", Lines(connection,
                    """
                    SELECT system, why, n, ord FROM (
                        SELECT r.system AS system, c.state || COALESCE(': ' || c.reason, '') AS why, 1 AS n, 0 AS ord
                        FROM coverage c JOIN latest_run r ON r.run_id = c.run_id
                        WHERE c.scope IN ('query', 'target') AND c.state IN ('failed', 'partial')
                        GROUP BY r.system, c.reason
                        UNION ALL
                        SELECT system, why_not_correct, COUNT(*), 1 FROM rule_standing WHERE standing = 'not-checked'
                        GROUP BY system, why_not_correct)
                    ORDER BY system, ord, n DESC;
                    """,
                    // A read that came back failed or partial, then the checks it (or anything else) left unjudged.
                    r => r["ord"] is 0L
                        ? $"{r["system"]}: the read was {Short(r["why"] as string ?? "", 300)}"
                        : $"{r["system"]}: {r["n"]} check(s) - {Short(r["why"] as string ?? "", 300)}"),
                    "Every check that ran could see its data.")
                {
                    Intro = "A check here is neither correct nor a finding: Keeper did not see enough to say. Fix the access or the setting named, and scan again.",
                },
            ]);
    }

    /// <summary>One card per check with open findings of the kinds given: worst severity first, then the widest.</summary>
    private static List<Card> Cards(SqliteConnection connection, string where, IReadOnlyDictionary<string, string> gpoNames) =>
        Sql.Rows(connection,
            $"""
            SELECT check_id, MIN(severity_rank) AS rank, severity, kind, title, why, fix, system, COUNT(*) AS n
            FROM active_finding WHERE {where}
            GROUP BY check_id ORDER BY rank, n DESC, title;
            """)
        .Select(c =>
        {
            var total = (int)(long)c["n"]!;
            var items = Sql.Rows(connection,
                    "SELECT COALESCE(entity_name, target) AS name, target, evidence FROM active_finding WHERE check_id = :check ORDER BY name LIMIT :max;",
                    null, (":check", c["check_id"]), (":max", CardItems))
                .Select(r => Named(Item(r), gpoNames))
                .ToList();
            var headline = total == 1 && items.Count == 1
                ? $"Found: {c["title"]} - {Short(items[0], 140)}"
                : $"Found on {total}: {c["title"]}";
            return new Card((string)c["severity"]!, $"{headline} [{c["system"]}]", c["why"] as string, c["fix"] as string, items, total,
                $"'keeper {c["kind"]} --system {c["system"]}' lists every one");
        })
        .ToList();

    /// <summary>One affected object: its evidence when that names it, else the name and the evidence.</summary>
    private static string Item(Dictionary<string, object?> r)
    {
        var name = r["name"] as string ?? "";
        return r["evidence"] is not string evidence || evidence.Length == 0 ? name
            : name == "-" || evidence.Contains(name, StringComparison.OrdinalIgnoreCase) ? evidence
            : $"{name}: {evidence}";
    }

    /// <summary>GPO GUIDs to their display names, from the newest directory read: SYSVOL knows a GPO only by its GUID.</summary>
    internal static Dictionary<string, string> GpoNames(SqliteConnection connection) =>
        Sql.Rows(connection,
            """
            SELECT json_extract(attrs, '$.cn') AS cn, json_extract(attrs, '$.displayName') AS name, MAX(observed_at) AS at
            FROM row_seen WHERE entity_type = 'gpo' AND json_extract(attrs, '$.displayName') IS NOT NULL
            GROUP BY json_extract(attrs, '$.cn');
            """)
            .Where(r => r["cn"] is string && r["name"] is string)
            .ToDictionary(r => ((string)r["cn"]!).ToUpperInvariant(), r => (string)r["name"]!);

    internal static string Named(string text, IReadOnlyDictionary<string, string> gpoNames) =>
        gpoNames.Count == 0 ? text
            : System.Text.RegularExpressions.Regex.Replace(text, @"\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                m => gpoNames.TryGetValue(m.Value.ToUpperInvariant(), out var name) ? $"\"{name}\" {m.Value}" : m.Value,
                System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static string Short(string text, int max) => text.Length <= max ? text : text[..max] + "...";

    private static Document Security(SqliteConnection connection, DateTimeOffset now) => new(
        "Security findings",
        $"Open findings in the security tier. Generated {Iso.Utc(now)}.",
        [
            new Section("By severity", Lines(connection,
                "SELECT severity, COUNT(*) AS n FROM active_finding WHERE security = 1 GROUP BY severity ORDER BY MIN(severity_rank);",
                r => $"{r["severity"]}: {r["n"]}"), "No open security findings."),
            new Section("Most serious", Lines(connection,
                """
                -- SQLite takes bare columns from the row MIN() picked: the most severe finding of each check.
                SELECT MIN(severity_rank) AS rank, severity, title, system_id, target, COUNT(*) AS n, first_seen
                FROM active_finding WHERE security = 1
                GROUP BY check_id ORDER BY rank, n DESC, first_seen LIMIT 40;
                """,
                r => $"[{r["severity"]}] {r["title"]} - {Where(r)} (since {r["first_seen"]})")),
            Widespread(connection, security: true),
        ]);

    /// <summary>One check failing on many targets: seen once, it was likely to be everywhere, and here is how far.</summary>
    private static Section Widespread(SqliteConnection connection, bool security) => new(
        "Most widespread",
        Lines(connection,
            $"""
            SELECT MIN(severity_rank) AS rank, severity, title, check_id, COUNT(*) AS n, COUNT(DISTINCT system_id) AS systems
            FROM active_finding {(security ? "WHERE security = 1" : "")}
            GROUP BY check_id HAVING COUNT(*) > 1 ORDER BY n DESC LIMIT 15;
            """,
            r => $"{r["n"]} x [{r["severity"]}] {r["title"]} ({r["check_id"]}) on {r["systems"]} system(s)"),
        "No check fails on more than one target.");

    private static string Where(Dictionary<string, object?> r) =>
        r["n"] is long n && n > 1 ? $"{n} targets, e.g. {r["system_id"]} / {r["target"]}" : $"{r["system_id"]} / {r["target"]}";

    private static Document Expiring(SqliteConnection connection, DateTimeOffset now) => new(
        "What expires in the next 90 days",
        $"Licences, contracts, key dates and every finding with a deadline. Generated {Iso.Utc(now)}.",
        [
            new Section("Licences", Lines(connection,
                """
                SELECT product, expires_on, notice_days, CAST(julianday(expires_on) - julianday(date('now')) AS INTEGER) AS left
                FROM licence WHERE expires_on IS NOT NULL AND julianday(expires_on) - julianday('now') <= 90 ORDER BY expires_on;
                """, r => $"{r["product"]}: {r["expires_on"]} ({r["left"]} days; start the renewal {r["notice_days"]} days before)"), "None."),
            new Section("Contracts", Lines(connection,
                """
                SELECT title, end_on, COALESCE(decision, 'no decision') AS decision FROM contract
                WHERE end_on IS NOT NULL AND julianday(end_on) - julianday('now') <= 90 ORDER BY end_on;
                """, r => $"{r["title"]}: ends {r["end_on"]} - {r["decision"]}"), "None."),
            new Section("Certificates, credentials and other deadlines", Lines(connection,
                "SELECT title, system_id, target, deadline, days_left FROM active_finding WHERE deadline IS NOT NULL AND days_left <= 90 ORDER BY deadline;",
                r => $"{r["title"]} - {r["system_id"]} / {r["target"]}: {r["deadline"]} ({r["days_left"]} days)"), "None."),
            new Section("Key dates", Lines(connection,
                "SELECT kind, title, due_on FROM key_date WHERE julianday(due_on) - julianday('now') <= 90 ORDER BY due_on;",
                r => $"{r["kind"]}: {r["title"]} - {r["due_on"]}"), "None."),
        ]);

    private static Document Changes(SqliteConnection connection, string since) => new(
        $"What changed since {since}",
        "Finding events, newest first.",
        [
            new Section("Events", Lines(connection,
                """
                SELECT e.at, e.event, f.severity, f.title, f.system_id, f.target, e.actor FROM finding_event e
                JOIN finding f ON f.finding_key = e.finding_key WHERE julianday(e.at) >= julianday(:since) ORDER BY e.at DESC LIMIT 500;
                """, r => $"{r["at"]} {r["event"]}: [{r["severity"]}] {r["title"]} - {r["system_id"]} / {r["target"]}{(r["actor"] is string a ? " by " + a : "")}",
                (":since", since)), "No changes."),
        ]);
}
