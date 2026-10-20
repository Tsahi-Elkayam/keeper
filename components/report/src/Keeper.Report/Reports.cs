using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>Reports for people who read rather than act: the state of the estate, security, what expires, what changed.</summary>
public static class Reports
{
    public static readonly IReadOnlyList<string> Names = ["summary", "security", "expiring", "changes", "trends"];

    public static Document Build(string name, SqliteConnection connection, DateTimeOffset now, string? since, int days = 90) => name switch
    {
        "summary" => Summary(connection, now),
        "security" => Security(connection, now),
        "expiring" => Expiring(connection, now),
        "changes" => Changes(connection, since ?? Iso.Date(now.AddDays(-30))),
        "trends" => Trends.Build(connection, now, days),
        _ => throw new ArgumentException($"Reports: {string.Join(", ", Names)}, evidence."),
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
