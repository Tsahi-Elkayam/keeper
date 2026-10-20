namespace Keeper.Report.Tests;

public sealed class RenderTests
{
    private static TodayReport Report(string title) => new(
        "2026-10-20T06:00:00Z", "2026-10-20T06:00:00Z", 120,
        [new TodayItem(1, "high", title, "SYS1", "host1.example.org", "2026-10-25", 5, 45, ["high", "due in 5 days"], "Renew it & restart", "0123456789abcdef")],
        [new WaitingItem("network team", "medium", "Waiting item", "SYS1", 3, "fedcba9876543210")],
        1, [title], [], [], [new DueItem("licence", "backup-suite", "Backup suite", "2026-10-30", 10)]);

    [Fact]
    public void Html_encodes_everything_that_came_from_a_scan()
    {
        var html = Render.As(TodayDocument.From(Report("<script>alert(1)</script> & \"quoted\"")), "html");

        Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("Renew it &amp; restart", html, StringComparison.Ordinal);
        Assert.StartsWith("<!doctype html>", html.TrimStart(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("text")]
    [InlineData("markdown")]
    [InlineData("html")]
    public void Every_format_shows_todays_items_what_waits_and_what_falls_due(string format)
    {
        var text = Render.As(TodayDocument.From(Report("Certificate expires soon")), format);

        Assert.Contains("Certificate expires soon", text, StringComparison.Ordinal);
        Assert.Contains("network team", text, StringComparison.Ordinal);
        Assert.Contains("Backup suite", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_check_on_many_targets_is_one_line_with_its_reach()
    {
        var report = Report("x") with
        {
            Today = [new TodayItem(1, "high", "Unexpected local administrators", "WORKSTATIONS", "pc01.example.org", null, null, 45,
                ["high", "91 targets"], null, "0123456789abcdef", Targets: 91, Systems: 1, Examples: ["pc01", "pc02", "pc03"])],
        };

        var text = Render.As(TodayDocument.From(report), "text");

        Assert.Contains("Unexpected local administrators - 91 targets on WORKSTATIONS, e.g. pc01, pc02, pc03", text, StringComparison.Ordinal);
        Assert.Contains("1 tasks covering 91 findings", text, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_format_is_refused()
    {
        Assert.Throws<ArgumentException>(() => Render.As(TodayDocument.From(Report("x")), "pdf"));
    }
}
