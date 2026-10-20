using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Queue;
using Keeper.Review.Load;
using Keeper.Review.Track;

namespace Keeper.Review.Tests;

/// <summary>Scan folder -> load -> track -> register, through the real queue manager.</summary>
public sealed class PipelineTests : IDisposable
{
    private const string Instance = "ex-main";
    private const string Rule = "EX-USER-STALE";

    private readonly TempStore _store = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 20, 6, 0, 0, TimeSpan.Zero));

    public void Dispose() => _store.Dispose();

    /// <summary>One scan: u1 fails the rule or passes it; u2 always passes.</summary>
    private void Scan(bool u1Fails, bool includeU1 = true, bool ruleRan = true)
    {
        var at = Iso.Utc(_clock.Now);
        using var run = new RunWriter(_store.Runs, Instance, "example", _clock.Now);
        foreach (var user in includeU1 ? new[] { "u1", "u2" } : ["u2"])
        {
            run.Row(new RowRecord
            {
                Instance = Instance, System = "example", Query = "q1", EntityType = "user", EntityKey = user,
                EntityName = user.ToUpperInvariant(), Attrs = new JsonObject { ["enabled"] = true }, ObservedAt = at,
            });
            if (!ruleRan)
                continue;
            var fails = user == "u1" && u1Fails;
            run.Result(new ResultRecord
            {
                Instance = Instance, System = "example", RuleId = Rule, EntityType = "user", EntityKey = user,
                State = fails ? "fail" : "pass", TtlMinutes = 3 * 1440, At = at,
            });
            if (fails)
                run.Finding(Finding("u1", at));
        }
        if (ruleRan)
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "rule", Item = Rule, State = "ok", ObservedAt = at });
        run.Complete("ok", _clock.Now, null, []);
    }

    private static FindingRecord Finding(string user, string at) => new()
    {
        FindingKey = FindingKey.For(Instance, Rule, user),
        Instance = Instance, System = "example", RuleId = Rule, CheckId = Rule, EntityType = "user", Target = user,
        Kind = "misconfigured", Lens = "security", Category = "IAM", Severity = "medium",
        Title = "Enabled account not used for 180 days", ObservedAt = at,
    };

    /// <summary>keeper-load, the queue manager, keeper-track and the queue manager again.</summary>
    private RegisterFile Cycle()
    {
        var writer = new RequestWriter(_store.Spool, _clock);
        using (var connection = _store.Db.OpenReadOnly())
        {
            foreach (var candidate in RunLoader.Pending(connection, _store.Runs, _store.DataDir))
            {
                Assert.Null(candidate.Problem);
                RunLoader.Submit(writer, candidate);
            }
        }
        Assert.Equal(0, _store.Manager(_clock).DrainOnce().Failed);

        RegisterFile register;
        using (var connection = _store.Db.OpenReadOnly())
            register = new Tracker(connection, _clock).Build(Iso.Stamp(_clock.Now));

        var file = Path.Combine(_store.Builds, register.BuildId, "register.json");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(register, JsonLines.Options));
        writer.Submit("review.register", "test", new
        {
            file = Path.GetRelativePath(_store.DataDir, file).Replace('\\', '/'),
            sha256 = Hashing.Sha256File(file),
        });
        Assert.Equal(1, _store.Manager(_clock).DrainOnce().Done);
        _clock.Now = _clock.Now.AddHours(1);
        return register;
    }

    private Dictionary<string, object?> U1() =>
        Assert.Single(_store.Rows($"SELECT * FROM finding WHERE target = 'u1'"));

    private List<string?> Events() =>
        _store.Rows("SELECT event FROM finding_event ORDER BY event_id").Select(r => r["event"] as string).ToList();

    [Fact]
    public void A_failing_rule_becomes_a_new_finding_and_the_entities_are_inventoried()
    {
        Scan(u1Fails: true);
        Cycle();

        var u1 = U1();
        Assert.Equal("open", u1["status"]);
        Assert.Equal("new", u1["lifecycle"]);
        Assert.Equal("UNMAPPED", u1["system_id"]);
        Assert.Equal(new[] { "new" }, Events());
        Assert.Equal(2L, _store.Scalar("SELECT COUNT(*) FROM entity"));
    }

    [Fact]
    public void It_resolves_only_when_the_rule_passes_and_reopens_when_it_fails_again()
    {
        Scan(u1Fails: true);
        Cycle();
        Scan(u1Fails: false);
        Cycle();
        Assert.Equal("resolved", U1()["status"]);

        Scan(u1Fails: true);
        Cycle();

        Assert.Equal("reopened", U1()["lifecycle"]);
        Assert.Equal(new[] { "new", "resolved", "reopened" }, Events());
    }

    [Fact]
    public void A_scan_that_did_not_run_the_rule_never_resolves_but_goes_stale()
    {
        Scan(u1Fails: true);
        Cycle();
        _clock.Now = _clock.Now.AddDays(4);   // beyond the 3-day TTL
        Scan(u1Fails: false, ruleRan: false);
        Cycle();

        var u1 = U1();
        Assert.Equal("open", u1["status"]);
        Assert.Equal("stale", u1["lifecycle"]);
    }

    [Fact]
    public void A_gone_entity_resolves_when_the_rule_ran_cleanly()
    {
        Scan(u1Fails: true);
        Cycle();
        Scan(u1Fails: false, includeU1: false);
        Cycle();

        Assert.Equal("resolved", U1()["status"]);
        Assert.NotNull(_store.Scalar("SELECT gone_since FROM entity WHERE entity_key = 'u1'"));
    }

    [Fact]
    public void A_system_rule_maps_entities_and_their_findings()
    {
        _store.Submit("review.system", """{ "op": "upsert", "systemId": "HR", "name": "HR" }""");
        _store.Submit("review.system-rule", """{ "op": "upsert", "ruleId": "hr-users", "field": "key", "pattern": "^u1$", "systemId": "HR" }""");
        Assert.Equal(2, _store.Manager().DrainOnce().Done);

        Scan(u1Fails: true);
        Cycle();

        Assert.Equal("HR", U1()["system_id"]);
        Assert.Equal("rule:hr-users", _store.Scalar("SELECT mapped_by FROM entity WHERE entity_key = 'u1'"));
    }

    /// <summary>One complete scan of rule system <paramref name="system"/> through <paramref name="instance"/>, returning these rows.</summary>
    private void ScanAs(string instance, string system, params (string Key, JsonObject Attrs)[] rows) => ScanAs("ok", instance, system, rows);

    private void ScanAs(string status, string instance, string system, params (string Key, JsonObject Attrs)[] rows)
    {
        var at = Iso.Utc(_clock.Now);
        using var run = new RunWriter(_store.Runs, instance, system, _clock.Now);
        foreach (var (key, attrs) in rows)
            run.Row(new RowRecord { Instance = instance, System = system, Query = "q1", EntityType = "item", EntityKey = key, Attrs = attrs, ObservedAt = at });
        run.Complete(status, _clock.Now, null, []);
    }

    [Fact]
    public void A_scan_of_one_rule_system_never_marks_another_systems_entities_gone()
    {
        // Two rule files reading through one integration, e.g. Entra and Intune through one Graph integration.
        ScanAs(Instance, "alpha", ("a1", []));
        ScanAs(Instance, "beta", ("b1", []));
        Cycle();

        // alpha's newest scan fails, so only beta's complete scan is usable: it must not call a1 gone.
        ScanAs("failed", Instance, "alpha");
        ScanAs(Instance, "beta", ("b1", []));
        Cycle();

        Assert.Null(_store.Scalar("SELECT gone_since FROM entity WHERE entity_key = 'a1'"));
        Assert.Equal("alpha", _store.Scalar("SELECT seen_by FROM entity WHERE entity_key = 'a1'"));

        ScanAs(Instance, "alpha");   // a complete alpha scan that no longer returns a1
        Cycle();

        Assert.NotNull(_store.Scalar("SELECT gone_since FROM entity WHERE entity_key = 'a1'"));
        Assert.Null(_store.Scalar("SELECT gone_since FROM entity WHERE entity_key = 'b1'"));
    }

    [Fact]
    public void Register_rows_belong_to_the_system_they_name_or_else_to_the_organisation()
    {
        _store.Submit("review.system", """{ "op": "upsert", "systemId": "HR", "name": "HR" }""");
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        ScanAs("keeper", "registers", ("lic-hr", new JsonObject { ["system_id"] = "HR" }), ("lic-none", []), ("lic-typo", new JsonObject { ["system_id"] = "NOPE" }));
        ScanAs("keeper", "keeper", ("integration-x", []));
        Cycle();

        Assert.Equal("HR", _store.Scalar("SELECT system_id FROM entity WHERE entity_key = 'lic-hr'"));
        Assert.Equal("ORG", _store.Scalar("SELECT system_id FROM entity WHERE entity_key = 'lic-none'"));
        Assert.Equal("ORG", _store.Scalar("SELECT system_id FROM entity WHERE entity_key = 'lic-typo'"));
        Assert.Equal("KEEPER", _store.Scalar("SELECT system_id FROM entity WHERE entity_key = 'integration-x'"));
    }

    [Fact]
    public void A_disabled_rule_keeps_its_findings_as_disabled_not_resolved()
    {
        _store.Submit("review.override", $$"""{ "op": "add", "checkId": "{{Rule}}", "decision": "disable" }""");
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        Scan(u1Fails: true);
        Cycle();

        Assert.Equal("disabled", U1()["status"]);
        Assert.Equal(0L, _store.Scalar("SELECT COUNT(*) FROM active_finding"));
    }

    [Fact]
    public void A_tampered_run_folder_is_refused_by_the_loader()
    {
        Scan(u1Fails: true);
        var folder = Directory.GetDirectories(_store.Runs).Single();
        File.AppendAllText(Path.Combine(folder, RunFolder.Findings), "\n");

        using var connection = _store.Db.OpenReadOnly();
        var candidate = Assert.Single(RunLoader.Pending(connection, _store.Runs, _store.DataDir));
        Assert.NotNull(candidate.Problem);
    }

    [Fact]
    public void Loading_the_same_run_twice_is_a_no_op()
    {
        Scan(u1Fails: true);
        Cycle();
        var folder = Directory.GetDirectories(_store.Runs).Single();
        RunLoader.Submit(new RequestWriter(_store.Spool), new LoadCandidate(Path.GetFileName(folder), folder,
            Path.GetRelativePath(_store.DataDir, folder).Replace('\\', '/'), null));

        Assert.Equal(1, _store.Manager().DrainOnce().Done);
        Assert.Equal(1L, _store.Scalar("SELECT COUNT(*) FROM run"));
    }
}
