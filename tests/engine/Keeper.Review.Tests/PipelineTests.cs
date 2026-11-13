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
        // A real scan writes a coverage record for every read it made; the tracker trusts nothing else.
        run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "query", Item = "q1", State = "ok", Count = includeU1 ? 2 : 1, ObservedAt = at });
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
        run.Coverage(new CoverageRecord { Instance = instance, System = system, Scope = "query", Item = "q1", State = status, Count = rows.Length, ObservedAt = at });
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

    private sealed record Read(string Query, string? Host, string State, params string[] Keys);

    /// <summary>One scan of rule system "example" made of these reads: each writes its rows and its coverage, as a real scan does.</summary>
    private void ScanReads(params Read[] reads)
    {
        var at = Iso.Utc(_clock.Now);
        using var run = new RunWriter(_store.Runs, Instance, "example", _clock.Now);
        foreach (var read in reads)
        {
            foreach (var key in read.Keys)
                run.Row(new RowRecord
                {
                    Instance = Instance, System = "example", Query = read.Query, EntityType = "item", EntityKey = key, Target = read.Host,
                    Attrs = [], ObservedAt = at,
                });
            run.Coverage(new CoverageRecord
            {
                Instance = Instance, System = "example", Scope = read.Host is null ? "query" : "target",
                Item = RunFolder.CoverageItem(read.Query, read.Host), State = read.State, Count = read.Keys.Length, ObservedAt = at,
            });
        }
        var states = reads.Select(r => r.State).ToList();
        run.Complete(states.All(s => s == "ok") ? "ok" : states.Any(s => s is "ok" or "partial") ? "partial" : "failed", _clock.Now, null, []);
    }

    private object? GoneSince(string key) => _store.Scalar($"SELECT gone_since FROM entity WHERE entity_key = '{key}'");

    [Fact]
    public void A_failed_read_hides_only_its_own_entities_not_every_other_reads()
    {
        ScanReads(new Read("q1", null, "ok", "a1", "a2"), new Read("q2", null, "ok", "b1"));
        Cycle();

        // q1 read cleanly without a2; q2 failed, so b1 is merely unseen.
        ScanReads(new Read("q1", null, "ok", "a1"), new Read("q2", null, "failed"));
        Cycle();

        Assert.NotNull(GoneSince("a2"));
        Assert.Null(GoneSince("b1"));
        Assert.Null(GoneSince("a1"));
    }

    [Fact]
    public void A_host_that_read_badly_keeps_its_entities_while_the_other_hosts_are_judged()
    {
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|admin-x"), new Read("q1", "pc02.example.org", "ok", "pc02|admin-y"));
        Cycle();

        // Both entities are missing now, but pc02's read was partial (it suddenly returned nothing).
        ScanReads(new Read("q1", "pc01.example.org", "ok"), new Read("q1", "pc02.example.org", "partial"));
        Cycle();

        Assert.NotNull(GoneSince("pc01|admin-x"));
        Assert.Null(GoneSince("pc02|admin-y"));
    }

    [Fact]
    public void An_entity_returned_by_two_reads_is_gone_only_when_both_read_cleanly_without_it()
    {
        ScanReads(new Read("q1", null, "ok", "u1"), new Read("q2", null, "ok", "u1"));
        Cycle();
        ScanReads(new Read("q1", null, "ok"), new Read("q2", null, "partial"));
        Cycle();
        Assert.Null(GoneSince("u1"));

        ScanReads(new Read("q1", null, "ok"), new Read("q2", null, "ok"));
        Cycle();
        Assert.NotNull(GoneSince("u1"));
    }

    [Fact]
    public void A_host_no_longer_read_at_all_is_retired_while_a_host_that_failed_keeps_its_entities()
    {
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|x"), new Read("q1", "pc02.example.org", "ok", "pc02|y"),
            new Read("q1", "pc03.example.org", "ok", "pc03|z"));
        Cycle();

        // pc02 was decommissioned (no longer a target at all); pc03 was offline.
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|x"), new Read("q1", "pc03.example.org", "failed"));
        Cycle();

        Assert.NotNull(GoneSince("pc02|y"));
        Assert.Null(GoneSince("pc03|z"));
        Assert.Null(GoneSince("pc01|x"));
    }

    [Fact]
    public void A_host_is_not_retired_when_no_host_of_its_query_read_cleanly()
    {
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|x"), new Read("q1", "pc02.example.org", "ok", "pc02|y"));
        Cycle();

        // pc02 is gone from a static list, but pc01 failed too (WinRM blocked): nothing proves the scan worked.
        ScanReads(new Read("q1", "pc01.example.org", "failed"), new Read("q2", null, "ok", "other"));
        Cycle();

        Assert.Null(GoneSince("pc02|y"));
    }

    /// <summary>The catalogue, as keeper rules load writes it: EX-ADMINS-MANY reads query q1.</summary>
    private void LoadCatalogue()
    {
        var file = Path.Combine(_store.Builds, "rules.json");
        Directory.CreateDirectory(_store.Builds);
        File.WriteAllText(file, JsonSerializer.Serialize(new[]
        {
            new Keeper.Review.Handlers.RulesLoadHandler.RuleRow("EX-ADMINS-MANY", "example", "Too many administrators", "misconfigured", "security",
                "IAM", "high", "member", "cim", 1440, null, null, [], "test") { QueryId = "q1" },
        }, JsonLines.Options));
        new RequestWriter(_store.Spool, _clock).Submit("review.rules-load", "test", new
        {
            file = Path.GetRelativePath(_store.DataDir, file).Replace('\\', '/'), sha256 = Hashing.Sha256File(file),
        });
        Assert.Equal(1, _store.Manager(_clock).DrainOnce().Done);
    }

    /// <summary>A per-host count finding (target = the host) on pc02, from the rule over q1; q2 reads pc03 only.</summary>
    private void ScanHostCount(bool pc02Listed, string? listRecord = null)
    {
        var at = Iso.Utc(_clock.Now);
        using var run = new RunWriter(_store.Runs, Instance, "example", _clock.Now);
        foreach (var host in pc02Listed ? new[] { "pc01.example.org", "pc02.example.org" } : ["pc01.example.org"])
        {
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "target", Item = $"q1@{host}", State = "ok", Count = 0, ObservedAt = at });
            var fails = host == "pc02.example.org";
            run.Result(new ResultRecord { Instance = Instance, System = "example", RuleId = "EX-ADMINS-MANY", EntityType = "member", EntityKey = host, State = fails ? "fail" : "pass", TtlMinutes = 1440, At = at });
            if (fails)
                run.Finding(new FindingRecord
                {
                    FindingKey = FindingKey.For(Instance, "EX-ADMINS-MANY", host), Instance = Instance, System = "example", RuleId = "EX-ADMINS-MANY",
                    CheckId = "EX-ADMINS-MANY", EntityType = "member", Target = host, Kind = "misconfigured", Lens = "security", Category = "IAM",
                    Severity = "high", Title = "Too many administrators", ObservedAt = at,
                });
        }
        if (listRecord is not null)
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "query", Item = "q1", State = listRecord, Count = 0, ObservedAt = at });
        run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "rule", Item = "EX-ADMINS-MANY", State = listRecord is null ? "ok" : "partial", ObservedAt = at });
        run.Complete(listRecord is null ? "ok" : "partial", _clock.Now, null, []);
    }

    [Theory]
    [InlineData(null, "resolved")]        // pc02 left the host list: its finding about pc02 is moot
    [InlineData("partial", "open")]       // the list itself may miss hosts: pc02 may simply be missing from it
    public void A_count_finding_on_a_host_no_longer_scanned_closes_only_when_the_host_list_is_trusted(string? listRecord, string status)
    {
        LoadCatalogue();
        ScanHostCount(pc02Listed: true);
        Cycle();
        ScanHostCount(pc02Listed: false, listRecord);
        Cycle();

        Assert.Equal(status, _store.Scalar("SELECT status FROM finding WHERE target = 'pc02.example.org'"));
    }

    [Fact]
    public void A_host_finding_stays_open_when_only_another_query_stopped_reading_the_host()
    {
        LoadCatalogue();
        ScanHostCount(pc02Listed: true);
        Cycle();

        // The rule's own query q1 is not run at all now (its rules were disabled); only q2 reads, cleanly.
        var at = Iso.Utc(_clock.Now);
        using (var run = new RunWriter(_store.Runs, Instance, "example", _clock.Now))
        {
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "target", Item = "q2@pc01.example.org", State = "ok", Count = 1, ObservedAt = at });
            run.Complete("ok", _clock.Now, null, []);
        }
        Cycle();

        Assert.Equal("open", _store.Scalar("SELECT status FROM finding WHERE target = 'pc02.example.org'"));
    }

    [Fact]
    public void A_host_missing_from_a_host_list_that_may_be_incomplete_is_not_retired()
    {
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|x"), new Read("q1", "pc02.example.org", "ok", "pc02|y"));
        Cycle();

        // pc02 is not in the list, but the scan says the list came from a read that was not clean.
        ScanReads(new Read("q1", "pc01.example.org", "ok", "pc01|x"), new Read("q1", null, "partial"));
        Cycle();

        Assert.Null(GoneSince("pc02|y"));
    }

    [Theory]
    [InlineData("ok", true)]        // the rules changed and every other read was clean
    [InlineData("partial", false)]  // something else in that scan did not read cleanly: say nothing
    public void A_query_the_newest_scan_no_longer_runs_counts_only_when_that_scan_was_clean(string otherRead, bool gone)
    {
        ScanReads(new Read("q-old", null, "ok", "u1"), new Read("q2", null, "ok", "u2"));
        Cycle();
        ScanReads(new Read("q2", null, otherRead, "u2"));
        Cycle();

        Assert.Equal(gone, GoneSince("u1") is not null);
    }

    [Fact]
    public void Two_runs_of_one_system_in_the_same_second_are_tracked_as_the_later_one()
    {
        ScanReads(new Read("q1", null, "ok", "a1", "a2"));
        Cycle();
        // The same clock for both: the second run gets the -2 id, and both are "newest".
        ScanReads(new Read("q1", null, "ok", "a1"));
        ScanReads(new Read("q1", null, "ok", "a1", "a2"));

        Cycle();

        Assert.Null(GoneSince("a2"));
        Assert.Equal(2L, _store.Scalar("SELECT COUNT(*) FROM latest_run"));
    }

    [Fact]
    public void A_finding_whose_entity_is_missing_from_a_partial_read_stays_open()
    {
        Scan(u1Fails: true);
        Cycle();

        // The same query, now partial (for example: it returned far fewer rows than last time), without u1.
        var at = Iso.Utc(_clock.Now);
        using (var run = new RunWriter(_store.Runs, Instance, "example", _clock.Now))
        {
            run.Row(new RowRecord { Instance = Instance, System = "example", Query = "q1", EntityType = "user", EntityKey = "u2", Attrs = [], ObservedAt = at });
            run.Result(new ResultRecord { Instance = Instance, System = "example", RuleId = Rule, EntityType = "user", EntityKey = "u2", State = "pass", TtlMinutes = 3 * 1440, At = at });
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "query", Item = "q1", State = "partial", Count = 1, ObservedAt = at });
            run.Coverage(new CoverageRecord { Instance = Instance, System = "example", Scope = "rule", Item = Rule, State = "partial", ObservedAt = at });
            run.Complete("partial", _clock.Now, null, []);
        }
        Cycle();

        Assert.Equal("open", U1()["status"]);
        Assert.Null(GoneSince("u1"));
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
    public void An_exception_lapses_after_its_until_day_and_the_finding_comes_back_saying_so()
    {
        _store.Submit("review.override", $$"""{ "op": "add", "checkId": "{{Rule}}", "decision": "exception", "entity": "u1", "until": "2026-10-25" }""");
        Assert.Equal(1, _store.Manager(_clock).DrainOnce().Done);

        Scan(u1Fails: true);
        Cycle();
        Assert.Equal("exception", U1()["status"]);

        _clock.Now = new DateTimeOffset(2026, 10, 25, 23, 0, 0, TimeSpan.Zero);   // the last day it holds
        Scan(u1Fails: true);
        Cycle();
        Assert.Equal("exception", U1()["status"]);

        _clock.Now = new DateTimeOffset(2026, 10, 26, 6, 0, 0, TimeSpan.Zero);
        Scan(u1Fails: true);
        Cycle();
        Assert.Equal("open", U1()["status"]);
        Assert.Equal("the exception ended on 2026-10-25", _store.Scalar("SELECT note FROM finding_event WHERE event = 'reopened'"));
    }

    [Fact]
    public void A_lapsed_exception_gives_its_finding_back_even_when_nothing_scans_it_again()
    {
        _store.Submit("review.override", $$"""{ "op": "add", "checkId": "{{Rule}}", "decision": "exception", "entity": "u1", "until": "2026-10-25" }""");
        Assert.Equal(1, _store.Manager(_clock).DrainOnce().Done);
        Scan(u1Fails: true);
        Cycle();
        Scan(u1Fails: true, ruleRan: false);   // the newest scan does not report it: the rule did not run
        Cycle();
        Assert.Equal("exception", U1()["status"]);

        _clock.Now = new DateTimeOffset(2026, 10, 26, 6, 0, 0, TimeSpan.Zero);
        Cycle();   // no scan since

        Assert.Equal(("open", "reopened"), ((string)U1()["status"]!, (string)U1()["lifecycle"]!));
        Assert.StartsWith("the exception ended on 2026-10-25; not scanned since", (string)_store.Scalar("SELECT note FROM finding_event WHERE event = 'reopened'")!, StringComparison.Ordinal);
    }

    [Fact]
    public void An_override_cannot_end_before_it_is_made()
    {
        _store.Submit("review.override", $$"""{ "op": "add", "checkId": "{{Rule}}", "decision": "disable", "until": "2026-10-19" }""");

        Assert.Equal(1, _store.Manager(_clock).DrainOnce().Failed);
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
