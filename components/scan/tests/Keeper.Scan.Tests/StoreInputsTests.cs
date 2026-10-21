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
}
