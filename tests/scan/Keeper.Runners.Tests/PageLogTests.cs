using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class PageLogTests
{
    private const string Log = """
        Reception_Laser alice 17 [24/Oct/2026:09:01:12 +0000] 1 1 - 192.0.2.77 Quarterly report - FINAL (v2).docx na_letter_8.5x11in one-sided
        Reception_Laser alice 17 [24/Oct/2026:09:01:14 +0000] 2 1 - 192.0.2.77 Quarterly report - FINAL (v2).docx na_letter_8.5x11in one-sided
        Reception_Laser bob 18 [24/Oct/2026:10:30:00 +0000] 1 3 - 192.0.2.78 Invoice 4471 iso_a4_210x297mm two-sided-long-edge
        Reception_Laser bob 19 [25/Oct/2026:08:00:00 +0000] total 12 - 192.0.2.78 Contract draft iso_a4_210x297mm one-sided
        Warehouse_Label carol 20 [23/Oct/2026:16:45:10 +0000] 1 1 - 192.0.2.80 label.pdf label one-sided
        not a log line at all
        """;

    private static FakeSession Host(string? text) => new("print01", text is null ? [] : new() { ["/var/log/cups/page_log"] = text });

    private static QuerySpec Q(params (string Name, JsonNode? Value)[] more) =>
        Context.Query("host", "name", [("read", "cups"), ("what", "pages"), .. more]);

    private static Task<RunnerResult> Run(IHostSession session, QuerySpec query) =>
        new HostRunner(_ => session).RunAsync(query, Context.For(new SshFakeConnection(), "print01"), CancellationToken.None);

    [Fact]
    public async Task Pages_are_totalled_per_printer_counting_copies_and_a_jobs_total_line_once()
    {
        var result = await Run(Host(Log), Q());

        Assert.Equal("ok", result.State);
        var reception = result.Rows.Single(r => r["name"]!.ToString() == "Reception_Laser");
        Assert.Equal(2L + 3 + 12, (long)reception["pages"]!);          // two single pages, three copies of one, a 12-page total
        Assert.Equal(3, (int)reception["jobs"]!);
        Assert.Equal(2, (int)reception["users"]!);
        Assert.Equal("2026-10-24T09:01:12Z", reception["firstPrinted"]!.ToString());
        Assert.Equal("2026-10-25T08:00:00Z", reception["lastPrinted"]!.ToString());
        Assert.Equal(1L, (long)result.Rows.Single(r => r["name"]!.ToString() == "Warehouse_Label")["pages"]!);
        Assert.All(result.Rows, r => Assert.Equal("print01", r["host"]!.ToString()));
    }

    [Fact]
    public async Task No_user_name_job_name_or_address_leaves_the_log()
    {
        var result = await Run(Host(Log), Q());

        var text = string.Join("\n", result.Rows.Select(r => r.ToJsonString()));
        foreach (var private_ in new[] { "alice", "bob", "carol", "Quarterly", "Invoice", "Contract", "label.pdf", "192.0.2" })
            Assert.DoesNotContain(private_, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_log_is_a_failed_read_that_says_why_unless_the_rule_says_it_may_be_absent()
    {
        var strict = await Run(Host(null), Q());
        var optional = await Run(Host(null), Q(("optional", true)));

        Assert.Equal("failed", strict.State);
        Assert.Contains("page log", strict.Reason!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("ok", optional.State);
        Assert.Empty(optional.Rows);
    }

    [Fact]
    public async Task A_log_with_no_pages_in_it_is_an_empty_answer()
    {
        var result = await Run(Host("nothing printed yet\n"), Q());

        Assert.Equal("ok", result.State);
        Assert.Empty(result.Rows);
    }

    [Fact]
    public async Task The_path_of_the_log_can_be_named_but_not_to_a_secret()
    {
        var runner = new HostRunner();

        Assert.Empty(runner.Validate(Q(("path", "/var/log/cups/page_log.1"))));
        Assert.NotEmpty(runner.Validate(Q(("path", "relative/page_log"))));
        Assert.NotEmpty(runner.Validate(Q(("path", "/etc/shadow"))));
        await Task.CompletedTask;
    }
}
