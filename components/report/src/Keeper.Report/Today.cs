using System.Globalization;
using System.Text.Json;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

public sealed record TodayItem(long Position, string Severity, string Title, string SystemId, string Target, string? Deadline,
    long? DaysLeft, long Minutes, IReadOnlyList<string> Reasons, string? Fix, string FindingKey);

public sealed record WaitingItem(string Owner, string Severity, string Title, string SystemId, long DaysWaiting, string FindingKey);

public sealed record BlindSpot(string Instance, string System, string Item, string State, string? Why, string At);

public sealed record DueItem(string What, string Id, string Title, string DueOn, long DaysLeft);

public sealed record TodayReport(
    string GeneratedAt,
    string? RankedAt,
    long BudgetMinutes,
    IReadOnlyList<TodayItem> Today,
    IReadOnlyList<WaitingItem> Waiting,
    long NewSinceYesterday,
    IReadOnlyList<string> NewTitles,
    IReadOnlyList<BlindSpot> BlindSpots,
    IReadOnlyList<string> StaleScans,
    IReadOnlyList<DueItem> DueSoon);

/// <summary>Builds today's page from the store (read-only): the ranked list and what the ranking cannot show.</summary>
public static class TodayBuilder
{
    public static TodayReport Build(SqliteConnection connection, DateTimeOffset now)
    {
        var settings = Sql.Rows(connection, "SELECT key, value FROM setting WHERE key IN ('rank.daily-minutes', 'report.stale-scan-days', 'report.due-soon-days');")
            .ToDictionary(r => (string)r["key"]!, r => (string)r["value"]!);
        long Setting(string key, long fallback) =>
            settings.TryGetValue(key, out var v) && long.TryParse(v, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : fallback;

        var today = Sql.Rows(connection,
            """
            SELECT r.position, f.severity, f.title, f.system_id, f.target, f.deadline, f.days_left, r.minutes, r.reasons, f.fix, f.finding_key
            FROM latest_ranking r JOIN active_finding f ON f.finding_key = r.finding_key
            WHERE r.list = 'today' ORDER BY r.position;
            """)
            .Select(r => new TodayItem((long)r["position"]!, (string)r["severity"]!, (string)r["title"]!, (string)r["system_id"]!,
                (string)r["target"]!, r["deadline"] as string, r["days_left"] as long?, (long)r["minutes"]!,
                JsonSerializer.Deserialize<List<string>>((string)r["reasons"]!) ?? [], r["fix"] as string, (string)r["finding_key"]!))
            .ToList();

        var waiting = Sql.Rows(connection,
            """
            SELECT f.delegated_to, f.severity, f.title, f.system_id, CAST(julianday('now') - julianday(lt.at) AS INTEGER) AS days, f.finding_key
            FROM active_finding f JOIN latest_triage lt ON lt.finding_key = f.finding_key AND lt.decision = 'delegate'
            ORDER BY lt.at;
            """)
            .Select(r => new WaitingItem((string)r["delegated_to"]!, (string)r["severity"]!, (string)r["title"]!, (string)r["system_id"]!,
                (long)r["days"]!, (string)r["finding_key"]!))
            .ToList();

        var since = Iso.Utc(now.AddDays(-1));
        var fresh = Sql.Rows(connection,
            """
            SELECT f.title FROM finding_event e JOIN finding f ON f.finding_key = e.finding_key
            WHERE e.event IN ('new', 'reopened') AND e.at >= :since ORDER BY e.at DESC;
            """, null, (":since", since));

        var blind = Sql.Rows(connection,
            """
            SELECT r.instance, r.system, c.item, c.state, c.reason, r.started_at
            FROM coverage c JOIN latest_run r ON r.run_id = c.run_id
            WHERE c.state IN ('failed', 'partial') AND c.scope IN ('query', 'target')
            ORDER BY r.instance, c.item;
            """)
            .Select(r => new BlindSpot((string)r["instance"]!, (string)r["system"]!, (string)r["item"]!, (string)r["state"]!,
                r["reason"] as string, (string)r["started_at"]!))
            .ToList();

        var staleDays = Setting("report.stale-scan-days", 7);
        var stale = Sql.Rows(connection,
            "SELECT instance, system, started_at FROM latest_run WHERE julianday('now') - julianday(started_at) > :days ORDER BY started_at;",
            null, (":days", staleDays))
            .Select(r => $"{r["system"]} via {r["instance"]}: last scanned {r["started_at"]}")
            .ToList();

        var dueDays = Setting("report.due-soon-days", 14);
        var inToday = today.Select(t => t.FindingKey).ToHashSet(StringComparer.Ordinal);
        var due = Sql.Rows(connection,
            """
            SELECT 'licence' AS what, licence_id AS id, product AS title, expires_on AS due_on FROM licence WHERE expires_on IS NOT NULL
            UNION ALL SELECT 'contract', contract_id, title, end_on FROM contract WHERE end_on IS NOT NULL
            UNION ALL SELECT kind, key_date_id, title, due_on FROM key_date
            UNION ALL SELECT 'finding', finding_key, title, deadline FROM active_finding WHERE deadline IS NOT NULL;
            """)
            .Select(r => (What: (string)r["what"]!, Id: (string)r["id"]!, Title: (string)r["title"]!, Due: (string)r["due_on"]!))
            .Select(r => (r.What, r.Id, r.Title, r.Due,
                Left: DateOnly.TryParse(r.Due, CultureInfo.InvariantCulture, out var d) ? d.DayNumber - DateOnly.FromDateTime(now.UtcDateTime).DayNumber : long.MaxValue))
            .Where(r => r.Left <= dueDays && !inToday.Contains(r.Id))
            .OrderBy(r => r.Left)
            .Select(r => new DueItem(r.What, r.Id, r.Title, r.Due, r.Left))
            .ToList();

        var rankedAt = Sql.Scalar(connection, "SELECT at FROM rank_build ORDER BY build_id DESC LIMIT 1;") as string;
        return new TodayReport(Iso.Utc(now), rankedAt, Setting("rank.daily-minutes", 120), today, waiting, fresh.Count,
            fresh.Take(5).Select(f => (string)f["title"]!).ToList(), blind, stale, due);
    }
}
