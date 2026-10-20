using System.Globalization;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// Progress for people who manage rather than fix: per system, where it stands now against 30 and 90 days
/// ago, what was fixed and what came in, and a sparkline of open serious findings. Read from system_trend,
/// the snapshot each run keeps - what was true on each day, not a reconstruction.
/// </summary>
public static class Trends
{
    private sealed record Day(string Date, long Open, long Critical, long High, long Security, long Overdue, long Accepted,
        long Opened, long Resolved, long Passing, long Judged)
    {
        public long Serious => Critical + High;
        public double? PassRate => Judged == 0 ? null : 100.0 * Passing / Judged;
    }

    public static Document Build(SqliteConnection connection, DateTimeOffset now, int days)
    {
        var from = Iso.Date(now.AddDays(-days));
        var history = Sql.Rows(connection, "SELECT * FROM system_trend WHERE day >= :from ORDER BY day;", null, (":from", from))
            .GroupBy(r => (string)r["system_id"]!)
            .ToDictionary(g => g.Key, g => g.Select(r => new Day((string)r["day"]!, L(r, "open"), L(r, "critical"), L(r, "high"),
                L(r, "security"), L(r, "overdue"), L(r, "accepted"), L(r, "opened"), L(r, "resolved"),
                L(r, "checks_passing"), L(r, "checks_judged"))).ToList());
        var names = Sql.Rows(connection, "SELECT system_id, name FROM system;")
            .ToDictionary(r => (string)r["system_id"]!, r => (string)r["name"]!, StringComparer.OrdinalIgnoreCase);

        if (!history.TryGetValue("*", out var estate) || estate.Count == 0)
        {
            return new Document("Progress by system", $"Generated {Iso.Utc(now)}.",
                [new Section("Nothing recorded yet", [], "Keeper records each system's standing every run; the first trend appears after the first 'keeper run'.")]);
        }

        var first = estate[0].Date;
        var fixTimes = Sql.Rows(connection,
                "SELECT julianday(resolved_at) - julianday(first_seen) AS d FROM finding WHERE resolved_at IS NOT NULL AND resolved_at >= :from;",
                null, (":from", from))
            .Select(r => Convert.ToDouble(r["d"], CultureInfo.InvariantCulture)).Order().ToList();

        var sections = new List<Section>
        {
            new("Whole estate", EstateLines(estate, now, fixTimes)),
        };

        var systems = history.Where(h => h.Key != "*" && h.Value.Any(d => d.Open > 0 || d.Resolved > 0))
            .Select(h => (Id: h.Key, Days: h.Value, Now: h.Value[^1], Then: At(h.Value, now.AddDays(-30))))
            .ToList();
        sections.Add(new Section("By system - most serious first",
            systems.OrderByDescending(s => s.Now.Serious).ThenByDescending(s => s.Now.Open)
                .Select(s => SystemLine(s.Id, names.GetValueOrDefault(s.Id), s.Days, now)).ToList(),
            "No system has had open findings in this period."));

        var moved = systems.Where(s => s.Then is not null).Select(s => (s.Id, Change: s.Now.Open - s.Then!.Open, s.Now, s.Then)).ToList();
        sections.Add(new Section("Most improved (last 30 days)",
            moved.Where(m => m.Change < 0).OrderBy(m => m.Change).Take(5)
                .Select(m => $"{Label(m.Id, names)}: {m.Then!.Open} -> {m.Now.Open} open ({m.Change}), serious {m.Then.Serious} -> {m.Now.Serious}").ToList(),
            "No system has fewer open findings than 30 days ago."));
        sections.Add(new Section("Getting worse (last 30 days)",
            moved.Where(m => m.Change > 0).OrderByDescending(m => m.Change).Take(5)
                .Select(m => $"{Label(m.Id, names)}: {m.Then!.Open} -> {m.Now.Open} open (+{m.Change}), serious {m.Then.Serious} -> {m.Now.Serious}").ToList(),
            "No system has more open findings than 30 days ago."));
        sections.Add(new Section("How to read this",
        [
            $"Each run records every system's standing; the record starts {first}, so earlier comparisons say \"since {first}\".",
            "Serious = critical + high. The line after each count is its daily trend, oldest left (each mark is a day or a group of days).",
            "Checks passing = results that passed out of those that could be judged on the system's own entities.",
            "A drop can mean fixed or accepted as a risk: accepted risks are counted apart, never as fixed.",
        ]));

        return new Document("Progress by system", $"The last {days} days, generated {Iso.Utc(now)}.", sections);
    }

    private static List<string> EstateLines(List<Day> estate, DateTimeOffset now, List<double> fixTimes)
    {
        var today = estate[^1];
        var month = At(estate, now.AddDays(-30));
        var quarter = At(estate, now.AddDays(-90));
        var recent = estate.Where(d => string.CompareOrdinal(d.Date, Iso.Date(now.AddDays(-30))) > 0).ToList();
        var lines = new List<string>
        {
            $"Open findings: {today.Open} now{Compare(today.Open, month, "30 days ago", d => d.Open)}{Compare(today.Open, quarter, "90 days ago", d => d.Open)}{Line(estate.Select(d => d.Open))}",
            $"Critical and high: {today.Serious} now{Compare(today.Serious, month, "30 days ago", d => d.Serious)}{Line(estate.Select(d => d.Serious))}",
            $"Last 30 days: {recent.Sum(d => d.Resolved)} resolved, {recent.Sum(d => d.Opened)} new or reopened.",
            $"Security tier: {today.Security} open. Overdue: {today.Overdue}. Accepted risks in force: {today.Accepted}.",
        };
        if (today.PassRate is { } rate)
            lines.Add($"Checks passing: {rate:0}% now{(month?.PassRate is { } was ? $", {was:0}% 30 days ago" : "")}.");
        if (fixTimes.Count > 0)
            lines.Add($"Median time to fix: {fixTimes[fixTimes.Count / 2]:0} days ({fixTimes.Count} findings resolved in this period).");
        return lines;
    }

    private static string SystemLine(string id, string? name, List<Day> days, DateTimeOffset now)
    {
        var today = days[^1];
        var month = At(days, now.AddDays(-30));
        var recent = days.Where(d => string.CompareOrdinal(d.Date, Iso.Date(now.AddDays(-30))) > 0).ToList();
        var pass = today.PassRate is { } rate ? $", checks passing {rate:0}%{(month?.PassRate is { } was ? $" (was {was:0}%)" : "")}" : "";
        return $"{(name is null || name == id ? id : $"{id} - {name}")}: open {today.Open}{Compare(today.Open, month, "30 d", d => d.Open)}, " +
               $"serious {today.Serious}{Compare(today.Serious, month, "30 d", d => d.Serious)}{Line(days.Select(d => d.Serious))}; " +
               $"last 30 days {recent.Sum(d => d.Resolved)} fixed, {recent.Sum(d => d.Opened)} new{pass}";
    }

    /// <summary>The snapshot on or just before the day, or the first one when the record starts later.</summary>
    private static Day? At(List<Day> days, DateTimeOffset when)
    {
        var day = Iso.Date(when);
        var before = days.LastOrDefault(d => string.CompareOrdinal(d.Date, day) <= 0);
        return before ?? (days.Count > 1 ? days[0] : null);
    }

    private static string Compare(long now, Day? then, string label, Func<Day, long> value)
    {
        if (then is null)
            return "";
        var change = now - value(then);
        return $", {value(then)} {label} ({(change > 0 ? "+" : "")}{change})";
    }

    /// <summary>Up to 16 marks, oldest left: ▁ is the period's lowest value, █ its highest.</summary>
    public static string Spark(IEnumerable<long> values)
    {
        var list = values.ToList();
        if (list.Count < 2)
            return "";
        const string marks = "▁▂▃▄▅▆▇█";
        var points = Enumerable.Range(0, Math.Min(16, list.Count))
            .Select(i => list[(int)Math.Round(i * (list.Count - 1) / (double)(Math.Min(16, list.Count) - 1))])
            .ToList();
        var (low, high) = (points.Min(), points.Max());
        return string.Concat(points.Select(p => high == low ? marks[3] : marks[(int)Math.Round((p - low) * 7.0 / (high - low))]));
    }

    private static string Line(IEnumerable<long> values) => Spark(values) is { Length: > 0 } spark ? "  " + spark : "";

    private static string Label(string id, Dictionary<string, string> names) =>
        names.TryGetValue(id, out var name) && name != id ? $"{id} - {name}" : id;

    private static long L(Dictionary<string, object?> row, string column) => row[column] as long? ?? 0;
}
