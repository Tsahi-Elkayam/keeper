using System.Globalization;
using System.Text.Json.Nodes;

namespace Keeper.Runners;

/// <summary>
/// When an integration may be read: integration option <c>window</c> (<c>20:00-06:00</c>; a window that ends at or
/// before its start runs past midnight; <c>00:00-24:00</c> is the whole day), optionally only on some days
/// (<c>window.days</c>: <c>Sun-Thu</c>, <c>Sat,Sun</c>; the day the window opens), in the Keeper machine's time zone
/// or <c>window.timeZone</c> (<c>Asia/Jerusalem</c>). A scan does not start outside its window, and stops reading when
/// the window closes: what was not read by then is a failed read, never an empty one.
/// </summary>
public sealed record ScanWindow(TimeSpan Start, TimeSpan End, IReadOnlySet<DayOfWeek> Days, TimeZoneInfo Zone, string Text)
{
    private static readonly DayOfWeek[] Week =
        [DayOfWeek.Sunday, DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday];

    /// <summary>The window an integration's options set, or null when they set none.</summary>
    public static ScanWindow? From(JsonObject options, TimeZoneInfo? localZone = null)
    {
        var text = options["window"]?.ToString();
        var daysText = options["window.days"]?.ToString();
        var zoneText = options["window.timeZone"]?.ToString();
        if (string.IsNullOrWhiteSpace(text))
        {
            if (!string.IsNullOrWhiteSpace(daysText) || !string.IsNullOrWhiteSpace(zoneText))
                throw new ArgumentException("window.days and window.timeZone need the option window (for example window=20:00-06:00).");
            return null;
        }
        var parts = text.Split('-', StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || Clock(parts[0]) is not { } start || Clock(parts[1]) is not { } end || start == TimeSpan.FromHours(24))
            throw new ArgumentException($"window must be HH:MM-HH:MM (for example 20:00-06:00), not '{text}'.");
        TimeZoneInfo zone;
        try
        {
            zone = string.IsNullOrWhiteSpace(zoneText) ? localZone ?? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(zoneText);
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            throw new ArgumentException($"window.timeZone '{zoneText}' is not a time zone this machine knows (for example Asia/Jerusalem).", ex);
        }
        var days = string.IsNullOrWhiteSpace(daysText) ? Week.ToHashSet() : Parse(daysText);
        if (days.Count == 0)
            throw new ArgumentException($"window.days names no day: '{daysText}'.");
        var shown = text.Trim() + (string.IsNullOrWhiteSpace(daysText) ? "" : $" {daysText.Trim()}") + (string.IsNullOrWhiteSpace(zoneText) ? "" : $" ({zoneText.Trim()})");
        return new ScanWindow(start, end, days, zone, shown);
    }

    /// <summary>
    /// When the window that is open at <paramref name="now"/> closes, or null when it is not open. Windows that meet
    /// (00:00-24:00 on Fri,Sat; 20:00-20:00) are one: a scan is not stopped at the instant the next one opens. A window
    /// that never closes (00:00-24:00 every day) is given a close a week on.
    /// </summary>
    public DateTimeOffset? ClosesAt(DateTimeOffset now)
    {
        // The window open now opened today or, running past midnight, yesterday (local days).
        var local = TimeZoneInfo.ConvertTime(now, Zone);
        for (var back = 0; back <= 1; back++)
        {
            var day = local.Date.AddDays(-back);
            if (!Days.Contains(day.DayOfWeek))
                continue;
            var (opens, closes) = Interval(day);
            if (now < opens || now >= closes)
                continue;
            for (var next = day.AddDays(1); next <= day.AddDays(7); next = next.AddDays(1))
            {
                if (!Days.Contains(next.DayOfWeek) || Interval(next).Opens > closes)
                    break;
                closes = Interval(next).Closes;
            }
            return closes;
        }
        return null;
    }

    /// <summary>An instant as the window's own wall clock, for messages ("opens 2026-11-15 20:00 Asia/Jerusalem").</summary>
    public string Local(DateTimeOffset instant) =>
        $"{TimeZoneInfo.ConvertTime(instant, Zone):yyyy-MM-dd HH:mm} {(Zone == TimeZoneInfo.Local ? "" : Zone.Id)}".TrimEnd();

    /// <summary>When the window next opens after <paramref name="now"/> (now itself when it is open).</summary>
    public DateTimeOffset NextOpen(DateTimeOffset now)
    {
        if (ClosesAt(now) is not null)
            return now;
        var local = TimeZoneInfo.ConvertTime(now, Zone);
        for (var ahead = 0; ahead <= 8; ahead++)
        {
            var day = local.Date.AddDays(ahead);
            if (Days.Contains(day.DayOfWeek) && Interval(day).Opens > now)
                return Interval(day).Opens;
        }
        throw new InvalidOperationException("a window with days opens within a week");
    }

    public override string ToString() => Text;

    /// <summary>The instants a window opening on local <paramref name="day"/> opens and closes.</summary>
    private (DateTimeOffset Opens, DateTimeOffset Closes) Interval(DateTime day)
    {
        var opens = At(day + Start);
        var closes = At(End > Start ? day + End : day.AddDays(1) + End);
        return (opens, closes);
    }

    /// <summary>A local wall-clock time as an instant; a time skipped by a clock change counts as the hour after it.</summary>
    private DateTimeOffset At(DateTime local)
    {
        var unspecified = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        if (Zone.IsInvalidTime(unspecified))
            unspecified = unspecified.AddHours(1);
        return new DateTimeOffset(unspecified, Zone.GetUtcOffset(unspecified));
    }

    private static TimeSpan? Clock(string text)
    {
        if (text == "24:00")
            return TimeSpan.FromHours(24);
        return TimeSpan.TryParseExact(text, ["hh\\:mm", "h\\:mm"], CultureInfo.InvariantCulture, out var time) && time < TimeSpan.FromHours(24)
            ? time
            : null;
    }

    private static HashSet<DayOfWeek> Parse(string text)
    {
        var days = new HashSet<DayOfWeek>();
        foreach (var part in text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var range = part.Split('-', StringSplitOptions.TrimEntries);
            if (range.Length is < 1 or > 2 || Day(range[0]) is not { } from || Day(range[^1]) is not { } to)
                throw new ArgumentException($"window.days must name days like Sun-Thu or Sat,Sun, not '{text}'.");
            for (var d = (int)from; ; d = (d + 1) % 7)
            {
                days.Add((DayOfWeek)d);
                if (d == (int)to)
                    break;
            }
        }
        return days;
    }

    private static DayOfWeek? Day(string text) =>
        text.Length >= 3 ? Week.Cast<DayOfWeek?>().FirstOrDefault(d => d.ToString()!.StartsWith(text[..3], StringComparison.OrdinalIgnoreCase)
                                                                    && d.ToString()!.StartsWith(text, StringComparison.OrdinalIgnoreCase)) : null;
}
