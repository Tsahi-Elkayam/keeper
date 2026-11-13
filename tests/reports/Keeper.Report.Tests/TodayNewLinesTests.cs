namespace Keeper.Report.Tests;

public sealed class TodayNewLinesTests
{
    private static Dictionary<string, object?> Row(string title, string? about) => new() { ["title"] = title, ["about"] = about };

    [Fact]
    public void Findings_of_one_check_read_as_one_line_naming_what_they_are_about()
    {
        var lines = TodayBuilder.NewLines(
        [
            Row("A system's newest scan failed", "entra"), Row("A system's newest scan failed", "intune"),
            Row("Certificate expired", "web01"), Row("A system's newest scan failed", "entra"),
        ]);

        Assert.Equal(["A system's newest scan failed: entra, intune", "Certificate expired: web01"], lines);
    }

    [Fact]
    public void A_long_list_is_cut_and_counted_and_only_five_checks_are_shown()
    {
        var many = TodayBuilder.NewLines([.. Enumerable.Range(1, 6).Select(i => Row("Weak cipher", $"host{i}"))]);
        var checks = TodayBuilder.NewLines([.. Enumerable.Range(1, 7).Select(i => Row($"Check {i}", null))]);

        Assert.Equal("Weak cipher: host1, host2, host3 and 3 more", Assert.Single(many));
        Assert.Equal(5, checks.Count);
        Assert.Equal("Check 1", checks[0]);
    }
}

public sealed class NotCoveredLinesTests
{
    [Fact]
    public void A_few_unreached_system_types_are_named_and_many_are_counted()
    {
        var few = TodayDocument.NotCoveredLines([("aws", 341), ("gcp", 167)]);
        var many = TodayDocument.NotCoveredLines([.. Enumerable.Range(1, 30).Select(i => ($"system{i}", 100L))]);

        Assert.Contains("aws (341 rules), gcp (167 rules)", Assert.Single(few), StringComparison.Ordinal);
        Assert.StartsWith("Not covered - 30 system types (3,000 rules)", Assert.Single(many), StringComparison.Ordinal);
        Assert.Contains("keeper report coverage", many[0], StringComparison.Ordinal);
        Assert.Empty(TodayDocument.NotCoveredLines([]));
    }
}
