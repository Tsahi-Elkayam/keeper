using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Store;

namespace Keeper.Scan.Tests;

/// <summary>What a scan reads from the store before it starts, against a real store built from every schema.</summary>
public sealed class StoreInputsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public StoreInputsTests()
    {
        using var connection = Store.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Composition.Composition.Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Store => new(Path.Combine(_dir, "keeper.db"));

    private void Run(string id, string instance, string system, string startedAt, params (string Scope, string Item, string State, int Count)[] coverage)
    {
        using var connection = Store.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES (:id, :i, :s, :at, :at, 'ok', :id, '{}', :at);
            """,
            null, (":id", id), (":i", instance), (":s", system), (":at", startedAt));
        foreach (var (scope, item, state, count) in coverage)
            Sql.Execute(connection,
                "INSERT INTO coverage (run_id, scope, item, state, count, observed_at) VALUES (:id, :scope, :item, :state, :count, :at);",
                null, (":id", id), (":scope", scope), (":item", item), (":state", state), (":count", count), (":at", startedAt));
    }

    private void Row(string runId, string query, string type, string key, string attrs, string? target = null)
    {
        using var connection = Store.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO row_seen (run_id, query, entity_type, entity_key, target, attrs, observed_at)
            VALUES (:run, :q, :t, :k, :target, :attrs, '2026-10-20T06:00:00Z');
            """,
            null, (":run", runId), (":q", query), (":t", type), (":k", key), (":target", target), (":attrs", attrs));
    }

    private const string DomainQuery = "q-domain";

    private void Policies(string runId, string at, int domainThreshold, params (string Cn, int Threshold)[] fineGrained)
    {
        Run(runId, "ad-main", "active-directory", at, ("query", DomainQuery, "ok", 1), ("query", "q-pso", "ok", fineGrained.Length));
        Row(runId, DomainQuery, "domain", "DC=example,DC=org",
            $$"""{ "distinguishedName": "DC=example,DC=org", "name": "example", "lockoutThreshold": "{{domainThreshold}}" }""");
        foreach (var (cn, threshold) in fineGrained)
            Row(runId, "q-pso", "policy", cn,
                $$"""{ "distinguishedName": "CN={{cn}},CN=Password Settings Container,CN=System,DC=example,DC=org", "cn": "{{cn}}", "msDS-LockoutThreshold": ["{{threshold}}"] }""");
    }

    [Theory]
    [InlineData("EXAMPLE\\reader")]
    [InlineData("reader@example.org")]
    [InlineData("reader")]                 // one domain known: that one
    public void The_lockout_threshold_comes_from_the_newest_ad_read(string identity)
    {
        Policies("ad1", "2026-10-20T06:00:00Z", domainThreshold: 3);
        Policies("ad2", "2026-10-21T06:00:00Z", domainThreshold: 5);

        using var connection = Store.OpenReadOnly();
        var known = StoreInputs.LockoutFor(identity, new StoreInputs(connection).LockoutPolicies());

        Assert.NotNull(known);
        Assert.Equal(5, known.Threshold);
        Assert.Equal(4, known.DeniedSignInsAllowed);
        Assert.Equal("example", known.Domain);
    }

    [Fact]
    public void The_strictest_fine_grained_policy_counts_and_a_deleted_one_is_gone()
    {
        Policies("ad1", "2026-10-20T06:00:00Z", domainThreshold: 10, ("Old-Strict", 1), ("Admins", 0));
        Policies("ad2", "2026-10-21T06:00:00Z", domainThreshold: 10, ("Service-Accounts", 2), ("Admins", 0));

        using var connection = Store.OpenReadOnly();
        var known = StoreInputs.LockoutFor("EXAMPLE\\svc-keeper", new StoreInputs(connection).LockoutPolicies())!;

        Assert.Equal(2, known.Threshold);         // Old-Strict was deleted since; 0 never locks
        Assert.True(known.FineGrained);
        Assert.Equal(1, known.DeniedSignInsAllowed);
    }

    [Fact]
    public void A_failed_read_keeps_the_last_clean_policy_and_an_empty_clean_one_drops_it()
    {
        Policies("ad1", "2026-10-20T06:00:00Z", domainThreshold: 10, ("Strict", 2));
        Run("ad2", "ad-main", "active-directory", "2026-10-21T06:00:00Z", ("query", DomainQuery, "failed", 0), ("query", "q-pso", "failed", 0));

        using (var connection = Store.OpenReadOnly())
            Assert.Equal(2, StoreInputs.LockoutFor("EXAMPLE\\reader", new StoreInputs(connection).LockoutPolicies())!.Threshold);

        Policies("ad3", "2026-10-22T06:00:00Z", domainThreshold: 10);   // the fine-grained policy was deleted

        using (var connection = Store.OpenReadOnly())
            Assert.Equal(10, StoreInputs.LockoutFor("EXAMPLE\\reader", new StoreInputs(connection).LockoutPolicies())!.Threshold);
    }

    [Fact]
    public void A_domain_that_never_locks_and_one_that_is_not_known()
    {
        Policies("ad1", "2026-10-20T06:00:00Z", domainThreshold: 0);

        using var connection = Store.OpenReadOnly();
        var policies = new StoreInputs(connection).LockoutPolicies();

        Assert.Equal(0, StoreInputs.LockoutFor("EXAMPLE\\reader", policies)!.Threshold);
        Assert.Equal(int.MaxValue, StoreInputs.LockoutFor("EXAMPLE\\reader", policies)!.DeniedSignInsAllowed);
        Assert.Null(StoreInputs.LockoutFor("EXAMPLE\\reader", []));
    }

    [Fact]
    public void Two_domains_and_an_identity_that_names_neither_is_not_guessed()
    {
        Policies("ad1", "2026-10-20T06:00:00Z", domainThreshold: 3);
        Run("ad9", "ad-other", "active-directory", "2026-10-20T06:00:00Z", ("query", DomainQuery, "ok", 1));
        Row("ad9", DomainQuery, "domain", "DC=other,DC=net", """{ "name": "other", "lockoutThreshold": 1 }""");

        using var connection = Store.OpenReadOnly();
        var policies = new StoreInputs(connection).LockoutPolicies();

        Assert.Equal(1, StoreInputs.LockoutFor("OTHER\\reader", policies)!.Threshold);
        Assert.Equal(3, StoreInputs.LockoutFor("reader@example.org", policies)!.Threshold);
        Assert.False(StoreInputs.LockoutFor("reader@example.org", policies)!.Guessed);
        // Not matched (a UPN suffix that is not the DNS name, two domains and none named): the strictest, said to be a guess.
        foreach (var unmatched in new[] { "reader", "THIRD\\reader", "reader@corp.example.com" })
        {
            var guess = StoreInputs.LockoutFor(unmatched, policies)!;
            Assert.Equal(1, guess.Threshold);
            Assert.True(guess.Guessed);
        }
    }

    [Theory]
    [InlineData("ok", false)]
    [InlineData("partial", true)]   // the computers read was cut short: a missing PC may just be missing from the list
    public void A_host_list_from_a_read_that_was_not_clean_says_so(string computersRead, bool incomplete)
    {
        Run("ad1", "ad-main", "active-directory", "2026-10-20T06:00:00Z", ("query", "q-computers", computersRead, 2));
        Row("ad1", "q-computers", "computer", "PC01", """{ "dNSHostName": "pc01.example.org" }""");
        Row("ad1", "q-computers", "computer", "PC02", """{ "dNSHostName": "pc02.example.org" }""");
        // A per-host read of the same entity type is judged by its own host's record.
        Run("ws1", "cim-main", "workstations", "2026-10-20T07:00:00Z", ("target", "q-os@pc01.example.org", "ok", 1));
        Row("ws1", "q-os", "computer", "pc01.example.org", "{}", "pc01.example.org");

        using var connection = Store.OpenReadOnly();
        var inputs = new StoreInputs(connection);
        var spec = new TargetSpec("computer", null, "dNSHostName", []);

        Assert.Equal(new[] { "pc01.example.org", "pc02.example.org" }, inputs.Targets(spec, DateTimeOffset.UtcNow));
        Assert.Equal(incomplete, inputs.TargetsIncomplete(spec) is not null);
    }

    [Fact]
    public void Threshold_overrides_come_most_specific_first()
    {
        using (var connection = Store.OpenReadWrite())
        {
            void Add(string id, string check, string entity, string value, string at) => Sql.Execute(connection,
                "INSERT INTO override (override_id, check_id, decision, entity, value, actor, at, why) VALUES (:id, :c, 'threshold', :e, :v, 'test', :at, 'test');",
                null, (":id", id), (":c", check), (":e", entity), (":v", value), (":at", at));
            Add("OVR-0001", "AD-*", "", "prefix", "2026-11-01T00:00:00Z");
            Add("OVR-0002", "AD-STALE-*", "", "longer prefix", "2026-10-01T00:00:00Z");
            Add("OVR-0003", "AD-STALE-USER", "", "exact, older", "2026-09-01T00:00:00Z");
            Add("OVR-0004", "AD-STALE-USER", "", "exact, newer", "2026-10-15T00:00:00Z");
            Add("OVR-0005", "AD-STALE-USER", "alice", "for alice", "2026-08-01T00:00:00Z");
        }
        using var read = Store.OpenReadOnly();
        var inputs = new StoreInputs(read, "2026-11-13");

        Assert.Equal(["for alice", "exact, newer", "exact, older", "longer prefix", "prefix"], inputs.OverrideThresholds("AD-STALE-USER", "alice"));
        Assert.Equal(["exact, newer", "exact, older", "longer prefix", "prefix"], inputs.OverrideThresholds("AD-STALE-USER", "bob"));
    }

    [Fact]
    public void A_host_the_where_cannot_judge_is_not_dropped_silently()
    {
        Run("ad1", "ad-main", "active-directory", "2026-10-20T06:00:00Z", ("query", "q-computers", "ok", 3));
        Row("ad1", "q-computers", "computer", "PC01", """{ "dNSHostName": "pc01.example.org", "operatingSystem": "Windows 11 Pro" }""");
        Row("ad1", "q-computers", "computer", "PC02", """{ "dNSHostName": "pc02.example.org", "operatingSystem": "Ubuntu" }""");
        Row("ad1", "q-computers", "computer", "PC03", """{ "dNSHostName": "pc03.example.org" }""");   // no operatingSystem read

        using var connection = Store.OpenReadOnly();
        var inputs = new StoreInputs(connection);
        var spec = new TargetSpec("computer", new LeafCondition("operatingSystem", "match", JsonValue.Create("^Windows"), null), "dNSHostName", []);

        Assert.Equal(new[] { "pc01.example.org" }, inputs.Targets(spec, DateTimeOffset.UtcNow));
        var why = inputs.TargetsUnjudged(spec, DateTimeOffset.UtcNow);
        Assert.Contains("1 computer host(s) are not read", why, StringComparison.Ordinal);
        Assert.Contains("pc03.example.org", why, StringComparison.Ordinal);
        Assert.Null(inputs.TargetsIncomplete(spec));       // a note, not an incomplete list: findings can still be resolved
    }

    [Fact]
    public void A_host_list_is_incomplete_when_a_system_that_supplied_hosts_before_failed_its_newest_scan()
    {
        // Two systems list computers. The second one's newest scan failed: its hosts vanished from the list.
        Run("ad1", "ad-main", "active-directory", "2026-10-20T06:00:00Z", ("query", "q-computers", "ok", 1));
        Row("ad1", "q-computers", "computer", "PC01", """{ "dNSHostName": "pc01.example.org" }""");
        Run("cm1", "cm-main", "sccm", "2026-10-19T06:00:00Z", ("query", "q-devices", "ok", 1));
        Row("cm1", "q-devices", "computer", "PC09", """{ "dNSHostName": "pc09.example.org" }""");
        using (var connection = Store.OpenReadWrite())
            Sql.Execute(connection,
                "INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at) VALUES ('cm2', 'cm-main', 'sccm', '2026-10-20T06:00:00Z', '2026-10-20T06:00:00Z', 'failed', 'cm2', '{}', '2026-10-20T06:00:00Z');");

        using var read = Store.OpenReadOnly();
        var inputs = new StoreInputs(read);
        var spec = new TargetSpec("computer", null, "dNSHostName", []);

        Assert.Equal(new[] { "pc01.example.org" }, inputs.Targets(spec, DateTimeOffset.UtcNow));
        Assert.Contains("sccm", inputs.TargetsIncomplete(spec), StringComparison.Ordinal);
    }

    [Fact]
    public void A_reads_history_is_its_newest_clean_read_of_this_system_through_this_integration_and_the_partial_reads_since()
    {
        Run("r0", "ad-main", "active-directory", "2026-10-17T06:00:00Z", ("query", "q-users", "ok", 2900), ("target", "q-admins@pc02", "partial", 1));
        Run("r1", "ad-main", "active-directory", "2026-10-18T06:00:00Z", ("query", "q-users", "ok", 3000), ("target", "q-admins@pc01", "ok", 4));
        Run("r2", "ad-main", "active-directory", "2026-10-19T06:00:00Z", ("query", "q-users", "partial", 1200));
        Run("r3", "ad-main", "active-directory", "2026-10-20T06:00:00Z", ("query", "q-users", "failed", 0), ("query", "q-x", "partial", 7));  // failed: no read at all
        Run("r4", "ad-other", "active-directory", "2026-10-21T06:00:00Z", ("query", "q-users", "ok", 10));     // another integration
        Run("r5", "ad-main", "hybrid-identity", "2026-10-21T06:00:00Z", ("query", "q-users", "ok", 20));      // another rule system

        using var connection = Store.OpenReadOnly();
        var previous = new StoreInputs(connection).PreviousRows("ad-main", "active-directory");

        Assert.Equal(3000, previous["q-users"].Clean);
        Assert.Equal(new[] { 1200 }, previous["q-users"].PartialSince.Select(p => p.Count));
        Assert.False(previous["q-users"].PartialSince[0].Low);   // partial, but not held back by the drop guard
        Assert.Equal(4, previous["q-admins@pc01"].Clean);   // per host
        Assert.False(previous.ContainsKey("q-admins@pc02"));  // never read cleanly: nothing to compare with
        Assert.False(previous.ContainsKey("q-x"));
        Assert.Equal(2, previous.Count);
    }

    [Fact]
    public void The_last_clean_rows_are_each_reads_own_newest_clean_read()
    {
        Run("r1", "ad-main", "active-directory", "2026-10-18T06:00:00Z", ("query", "q-groups", "ok", 1), ("target", "q-admins@pc01", "ok", 1));
        Row("r1", "q-groups", "group", "admins", """{ "members": ["a", "b"] }""");
        Row("r1", "q-admins", "member", "pc01|x", "{}", "pc01");
        Run("r2", "ad-main", "active-directory", "2026-10-19T06:00:00Z", ("query", "q-groups", "partial", 1), ("target", "q-admins@pc01", "ok", 0));
        Row("r2", "q-groups", "group", "admins", """{ "members": ["a"] }""");        // partial: not compared with
        Run("r3", "ad-main", "active-directory", "2026-10-20T06:00:00Z", ("query", "q-groups-other", "ok", 1));
        Run("r4", "ad-other", "active-directory", "2026-10-21T06:00:00Z", ("query", "q-groups", "ok", 1));
        Row("r4", "q-groups", "group", "admins", """{ "members": [] }""");          // another integration

        using var connection = Store.OpenReadOnly();
        var inputs = new StoreInputs(connection);
        var groups = inputs.LastCleanRows("ad-main", "active-directory", "q-groups");
        var admins = inputs.LastCleanRows("ad-main", "active-directory", "q-admins");

        var read = Assert.Single(groups);
        Assert.Equal(("q-groups", "2026-10-18T06:00:00Z"), (read.Key, read.Value.At));
        Assert.Equal("""["a","b"]""", read.Value.Rows["admins"]["members"]!.ToJsonString());
        Assert.Empty(admins["q-admins@pc01"].Rows);   // the newest clean read of pc01 found no one: still a read
        Assert.Empty(inputs.LastCleanRows("ad-main", "active-directory", "q-group"));   // a prefix of another query is not it
    }
}
