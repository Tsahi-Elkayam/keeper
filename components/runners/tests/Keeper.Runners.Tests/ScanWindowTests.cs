using System.Text.Json.Nodes;
using Keeper.Runners;

namespace Keeper.Runners.Tests;

/// <summary>When an integration may be read: a night window, work days, the whole day, and what is not a window.</summary>
public sealed class ScanWindowTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;

    private static ScanWindow Window(string window, string? days = null, string? zone = null)
    {
        var options = new JsonObject { ["window"] = window };
        if (days is not null)
            options["window.days"] = days;
        if (zone is not null)
            options["window.timeZone"] = zone;
        return ScanWindow.From(options, Utc)!;
    }

    // 2026-11-12 is a Thursday.
    private static DateTimeOffset At(int day, int hour, int minute = 0) => new(2026, 11, day, hour, minute, 0, TimeSpan.Zero);

    [Fact]
    public void A_night_window_runs_past_midnight()
    {
        var night = Window("20:00-06:00");

        Assert.Null(night.ClosesAt(At(12, 19, 59)));
        Assert.Equal(At(13, 6), night.ClosesAt(At(12, 20)));
        Assert.Equal(At(13, 6), night.ClosesAt(At(13, 5, 59)));   // opened yesterday
        Assert.Null(night.ClosesAt(At(13, 6)));
        Assert.Equal(At(13, 20), night.NextOpen(At(13, 12)));
    }

    [Fact]
    public void Days_are_the_days_the_window_opens()
    {
        var workNights = Window("20:00-06:00", days: "Sun-Thu");

        Assert.Equal(At(13, 6), workNights.ClosesAt(At(13, 3)));    // Thursday night runs into Friday
        Assert.Null(workNights.ClosesAt(At(13, 21)));                // Friday night is not a work night
        Assert.Equal(At(15, 20), workNights.NextOpen(At(13, 21)));   // Sunday evening
    }

    [Fact]
    public void A_day_list_and_the_whole_day()
    {
        var weekend = Window("00:00-24:00", days: "Fri,Saturday");

        Assert.Null(weekend.ClosesAt(At(12, 23)));
        Assert.Equal(At(15, 0), weekend.ClosesAt(At(13, 0)));       // Friday and Saturday meet: one window to Sunday
        Assert.Equal(At(15, 0), weekend.ClosesAt(At(14, 23, 59)));
    }

    [Fact]
    public void Windows_that_meet_are_one()
    {
        Assert.Equal(At(13, 23) + TimeSpan.FromDays(7) + TimeSpan.FromHours(1),
            Window("00:00-24:00").ClosesAt(At(13, 23)));                 // every day, all day: not cut at midnight
        Assert.Equal(At(13, 20) + TimeSpan.FromDays(7),
            Window("20:00-20:00").ClosesAt(At(12, 21)));
        Assert.Equal(At(13, 6), Window("20:00-06:00", days: "Thu,Fri").ClosesAt(At(12, 21)));   // a gap in the day: no join
    }

    [Fact]
    public void A_time_is_said_on_the_window_s_own_clock()
    {
        var night = Window("20:00-06:00", zone: "Asia/Jerusalem");

        Assert.Equal("2026-11-12 20:00 Asia/Jerusalem", night.Local(At(12, 18)));
    }

    [Fact]
    public void A_time_zone_is_the_estate_s_wall_clock()
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("Asia/Jerusalem");
        var night = Window("20:00-06:00", zone: "Asia/Jerusalem");
        var opens = night.NextOpen(At(12, 12));

        Assert.Equal(20, TimeZoneInfo.ConvertTime(opens, zone).Hour);
        Assert.Equal(TimeSpan.FromHours(2), zone.GetUtcOffset(opens));   // winter: 18:00 UTC
        Assert.Equal(At(12, 18), opens);
    }

    [Fact]
    public void No_window_is_any_time()
    {
        Assert.Null(ScanWindow.From([], Utc));
    }

    [Theory]
    [InlineData("20:00", null, null)]
    [InlineData("8pm-6am", null, null)]
    [InlineData("24:00-06:00", null, null)]
    [InlineData("20:00-25:00", null, null)]
    [InlineData("20:00-06:00", "Weekdays", null)]
    [InlineData("20:00-06:00", "Th", null)]
    [InlineData("20:00-06:00", null, "Mars/Olympus")]
    [InlineData("20:00-06:00", ",", null)]
    public void What_is_not_a_window_is_said(string window, string? days, string? zone)
    {
        var options = new JsonObject { ["window"] = window, ["window.days"] = days, ["window.timeZone"] = zone };

        Assert.Throws<ArgumentException>(() => ScanWindow.From(options, Utc));
    }

    [Fact]
    public void Days_without_a_window_are_said()
    {
        Assert.Throws<ArgumentException>(() => ScanWindow.From(new JsonObject { ["window.days"] = "Sun-Thu" }, Utc));
    }

    [Fact]
    public void Every_host_stops_when_the_window_closes()
    {
        var clock = new Settable { Now = At(13, 5, 59) };
        var pacer = new Pacer(PaceProfile.Unlimited, clock) { Until = At(13, 6) };

        Assert.Null(pacer.Stopped("pc01"));
        clock.Now = At(13, 6);

        Assert.Contains("scan window closed", pacer.Stopped("pc01"), StringComparison.Ordinal);
        Assert.True(pacer.WindowClosed);
        Assert.Empty(pacer.PushedBack());   // the window is not the host's doing
    }

    private sealed class Settable : TimeProvider
    {
        public DateTimeOffset Now { get; set; }

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
