using System.Text.Json.Nodes;

namespace Keeper.Contracts.Tests;

public sealed class RunFolderTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 6, 0, 0, TimeSpan.Zero);

    private readonly string _runs = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_runs, recursive: true);

    private static FindingRecord Finding(string kind = "misconfigured") => new()
    {
        FindingKey = FindingKey.For("ad-main", "AD-USER-PWD-NEVER-EXPIRES", "svc1"),
        Instance = "ad-main",
        System = "active-directory",
        RuleId = "AD-USER-PWD-NEVER-EXPIRES",
        CheckId = "AD-USER-PWD-NEVER-EXPIRES",
        EntityType = "user",
        Target = "svc1",
        Kind = kind,
        Lens = "security",
        Category = "IAM",
        Severity = "medium",
        Title = "Password never expires",
        ObservedAt = "2026-10-20T06:00:00Z",
    };

    private RunManifest WriteRun(FindingRecord finding)
    {
        using var run = new RunWriter(_runs, "ad-main", "active-directory", Now);
        run.Row(new RowRecord
        {
            Instance = "ad-main", System = "active-directory", Query = "q1", EntityType = "user", EntityKey = "svc1",
            Attrs = new JsonObject { ["userAccountControl"] = 66048 }, ObservedAt = "2026-10-20T06:00:00Z",
        });
        run.Finding(finding);
        run.Coverage(new CoverageRecord
        {
            Instance = "ad-main", System = "active-directory", Scope = "query", Item = "q1", State = "ok", Count = 1,
            ObservedAt = "2026-10-20T06:00:00Z",
        });
        return run.Complete("ok", Now.AddMinutes(1), "EXAMPLE\\keeper-reader", []);
    }

    [Fact]
    public void A_complete_run_verifies()
    {
        var manifest = WriteRun(Finding());
        var folder = Path.Combine(_runs, manifest.RunId);

        Assert.True(RunFolder.IsComplete(folder));
        Assert.Equal(manifest.RunId, RunFolder.Verify(folder).RunId);
        Assert.Equal(3, manifest.Files.Count);
        Assert.False(Directory.Exists(folder + ".tmp"));
    }

    [Fact]
    public void A_changed_file_fails_its_hash()
    {
        var manifest = WriteRun(Finding());
        var folder = Path.Combine(_runs, manifest.RunId);
        File.AppendAllText(Path.Combine(folder, RunFolder.Findings), "\n");

        var ex = Assert.Throws<ContractException>(() => RunFolder.Verify(folder));
        Assert.Contains("hash", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_record_outside_the_vocabulary_is_refused()
    {
        var manifest = WriteRun(Finding(kind: "on-fire"));

        var ex = Assert.Throws<ContractException>(() => RunFolder.Verify(Path.Combine(_runs, manifest.RunId)));
        Assert.Contains("kind", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_finding_whose_key_does_not_match_is_refused()
    {
        var manifest = WriteRun(Finding() with { Target = "someone-else" });

        Assert.Throws<ContractException>(() => RunFolder.Verify(Path.Combine(_runs, manifest.RunId)));
    }

    [Fact]
    public void Runs_started_in_the_same_second_get_their_own_folders()
    {
        // Keeper's own systems all scan through the one "keeper" instance, often within the same second.
        using var registers = new RunWriter(_runs, "keeper", "registers", Now);
        using var obligations = new RunWriter(_runs, "keeper", "obligations", Now);
        using var again = new RunWriter(_runs, "keeper", "registers", Now);
        using var plain = new RunWriter(_runs, "keeper", "keeper", Now);

        Assert.Equal(4, new[] { registers.RunId, obligations.RunId, again.RunId, plain.RunId }.Distinct().Count());
        Assert.EndsWith("-keeper-registers", registers.RunId, StringComparison.Ordinal);
        Assert.EndsWith("-keeper-registers-2", again.RunId, StringComparison.Ordinal);
        Assert.EndsWith("-keeper", plain.RunId, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unfinished_run_is_not_complete()
    {
        using var run = new RunWriter(_runs, "ad-main", "active-directory", Now);

        Assert.False(RunFolder.IsComplete(run.Folder));
    }
}
