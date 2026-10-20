using System.Globalization;
using System.Text.Json;
using Keeper.Common;
using Keeper.Query;
using Keeper.Queue;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Rank;

public sealed record RankedItem(string FindingKey, string List, int Position, double Score, int Minutes, IReadOnlyList<string> Reasons);

public sealed record RankingFile(string BuildId, string At, int BudgetMinutes, IReadOnlyList<RankedItem> Items);

/// <summary>
/// Orders the open findings into what to do today. Severity first; then deadline pressure, a reopened or new
/// problem, the security tier, the system's criticality and how many targets share the problem. Findings of
/// one check are one task. Delegated findings wait on someone else; snoozed ones stay out until their date.
/// Today's list is cut to the time budget (setting rank.daily-minutes).
/// </summary>
public sealed class Ranker(SqliteConnection connection, TimeProvider? clock = null)
{
    public const int DefaultBudgetMinutes = 120;
    public const int DefaultMaxItems = 10;

    private static readonly Dictionary<string, int> DefaultMinutes = new()
    {
        ["critical"] = 60, ["high"] = 45, ["medium"] = 30, ["low"] = 15, ["info"] = 10,
    };

    private static readonly Dictionary<string, double> SeverityWeight = new()
    {
        ["critical"] = 100, ["high"] = 60, ["medium"] = 30, ["low"] = 10, ["info"] = 0,
    };

    public static MigrationSet Schema { get; } = MigrationSet.FromResources("rank", typeof(Ranker).Assembly, "rank/", "review");

    public static QueryPack Questions { get; } = new("rank", typeof(Ranker).Assembly, "rank-questions/");

    public RankingFile Rank(string buildId)
    {
        var now = (clock ?? TimeProvider.System).GetUtcNow();
        var settings = Sql.Rows(connection, "SELECT key, value FROM setting WHERE key LIKE 'rank.%';")
            .ToDictionary(r => (string)r["key"]!, r => (string)r["value"]!, StringComparer.Ordinal);
        int Setting(string key, int fallback) =>
            settings.TryGetValue(key, out var v) && int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0 ? n : fallback;
        var budget = Setting("rank.daily-minutes", DefaultBudgetMinutes);
        var maxItems = Setting("rank.max-items", DefaultMaxItems);

        var rows = Sql.Rows(connection,
            """
            SELECT f.finding_key, f.check_id, f.severity, f.security, f.lifecycle, f.deadline, f.days_left, f.first_seen,
                   f.snoozed_until, f.delegated_to, s.criticality
            FROM active_finding f
            LEFT JOIN system s ON s.system_id = f.system_id;
            """);

        var scored = rows.Select(r => Score(r, now, Setting)).ToList();
        var items = new List<RankedItem>();
        var used = 0;
        var tasks = 0;
        var position = 0;

        // One check failing on many targets is one task with a wide reach, not many tasks: it is ranked
        // once, by its worst instance plus its spread, and its time counts against the budget once.
        var groups = scored.Where(s => s.List == "open")
            .GroupBy(s => s.Check, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var members = g.OrderByDescending(m => m.Score).ThenBy(m => m.Key, StringComparer.Ordinal).ToList();
                return (Members: members, Score: Math.Round(members[0].Score + Spread(members.Count), 1));
            })
            .OrderByDescending(g => g.Score).ThenBy(g => g.Members[0].Key, StringComparer.Ordinal);
        foreach (var (members, score) in groups)
        {
            var minutes = members[0].Minutes;
            var fits = tasks < maxItems && (used + minutes <= budget || tasks == 0);
            if (fits)
            {
                used += minutes;
                tasks++;
            }
            var lead = members[0];
            var reasons = members.Count > 1 ? [.. lead.Reasons, $"{members.Count} targets"] : lead.Reasons;
            items.Add(new RankedItem(lead.Key, fits ? "today" : "later", ++position, score, minutes, reasons));
            var leadPosition = position;
            foreach (var member in members.Skip(1))
                items.Add(new RankedItem(member.Key, fits ? "today" : "later", ++position, member.Score, 0, [.. member.Reasons, $"same check as #{leadPosition}"]));
        }
        foreach (var item in scored.Where(s => s.List is "waiting" or "snoozed").OrderByDescending(s => s.Score))
            items.Add(new RankedItem(item.Key, item.List, ++position, item.Score, item.Minutes, item.Reasons));

        return new RankingFile(buildId, Iso.Utc(now), budget, items);
    }

    private sealed record Scored(string Key, string Check, string List, double Score, int Minutes, List<string> Reasons);

    /// <summary>How much a problem's reach adds: 10 targets +15, 100 targets +30 (the most).</summary>
    public static double Spread(int targets) => targets <= 1 ? 0 : Math.Min(30, 15 * Math.Log10(targets));

    private static Scored Score(Dictionary<string, object?> r, DateTimeOffset now, Func<string, int, int> setting)
    {
        var severity = (string)r["severity"]!;
        var reasons = new List<string> { severity };
        var score = SeverityWeight.GetValueOrDefault(severity);

        if (r["days_left"] is long daysLeft)
        {
            (double Boost, string? Reason) deadline = daysLeft switch
            {
                <= 0 => (120.0, daysLeft == 0 ? "due today" : $"overdue by {-daysLeft} days"),
                <= 3 => (80, $"due in {daysLeft} days"),
                <= 7 => (60, $"due in {daysLeft} days"),
                <= 14 => (40, $"due in {daysLeft} days"),
                <= 30 => (20, $"due in {daysLeft} days"),
                _ => (0, null),
            };
            score += deadline.Boost;
            if (deadline.Reason is not null)
                reasons.Add(deadline.Reason);
        }

        switch ((string)r["lifecycle"]!)
        {
            case "reopened":
                score += 25;
                reasons.Add("came back after being fixed");
                break;
            case "new":
                score += 15;
                reasons.Add("new");
                break;
            case "stale":
                score -= 10;
                reasons.Add("not re-checked recently");
                break;
        }

        if (r["security"] is long security && security == 1)
        {
            score += 10;
            reasons.Add("security");
        }
        if (r["criticality"] is long criticality)
        {
            score += criticality switch { 1 => 30, 2 => 15, _ => 0 };
            if (criticality <= 2)
                reasons.Add($"system criticality {criticality}");
        }
        if (DateTimeOffset.TryParse((string)r["first_seen"]!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var firstSeen)
            && (now - firstSeen).TotalDays > 30)
        {
            score += 5;
            reasons.Add($"open {(int)(now - firstSeen).TotalDays} days");
        }

        var minutes = setting($"rank.minutes.{severity}", DefaultMinutes.GetValueOrDefault(severity, 30));
        var list = "open";
        if (r["snoozed_until"] is string until)
        {
            list = "snoozed";
            reasons.Add($"snoozed until {until}");
        }
        else if (r["delegated_to"] is string owner)
        {
            list = "waiting";
            reasons.Add($"with {owner}");
        }
        return new Scored((string)r["finding_key"]!, (string)r["check_id"]!, list, Math.Round(score, 1), minutes, reasons);
    }
}

/// <summary>rank.register: { "file": "builds/&lt;id&gt;/ranking.json", "sha256" } - one ranking; the newest 30 are kept.</summary>
public sealed class RankRegisterHandler : IRequestHandler
{
    public string Kind => "rank.register";

    public void Apply(RequestContext context)
    {
        var file = Payload.VerifiedFile(context);
        RankingFile ranking;
        try
        {
            ranking = JsonSerializer.Deserialize<RankingFile>(File.ReadAllText(file), JsonLines.Options)
                ?? throw new RequestException("Empty ranking file.");
        }
        catch (JsonException ex)
        {
            throw new RequestException($"Ranking file is not valid: {ex.Message}");
        }

        context.Execute("DELETE FROM ranking WHERE build_id = :b;", (":b", ranking.BuildId));
        foreach (var item in ranking.Items)
        {
            context.Execute(
                """
                INSERT INTO ranking (build_id, finding_key, list, position, score, minutes, reasons, at)
                VALUES (:b, :k, :list, :pos, :score, :min, :reasons, :at);
                """,
                (":b", ranking.BuildId), (":k", item.FindingKey), (":list", item.List), (":pos", item.Position), (":score", item.Score),
                (":min", item.Minutes), (":reasons", JsonSerializer.Serialize(item.Reasons, JsonLines.Options)), (":at", ranking.At));
        }
        context.Execute(
            """
            INSERT INTO rank_build (build_id, at, items, budget_minutes) VALUES (:b, :at, :n, :budget)
            ON CONFLICT (build_id) DO UPDATE SET at = excluded.at, items = excluded.items, budget_minutes = excluded.budget_minutes;
            """,
            (":b", ranking.BuildId), (":at", ranking.At), (":n", ranking.Items.Count), (":budget", ranking.BudgetMinutes));
        context.Execute("DELETE FROM rank_build WHERE build_id NOT IN (SELECT build_id FROM rank_build ORDER BY build_id DESC LIMIT 30);");
        context.Execute("DELETE FROM ranking WHERE build_id NOT IN (SELECT build_id FROM rank_build);");
    }
}
