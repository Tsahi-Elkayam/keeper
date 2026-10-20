using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Testing;

namespace Keeper.Queue.Tests;

public sealed class QueueManagerTests : IDisposable
{
    private const string AddDisable = """{ "op": "add", "checkId": "AD-001", "decision": "disable" }""";

    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    private QueueManager Manager() => new(_store.Db, _store.Spool, QueueManager.BuiltInHandlers());

    private string Submit(string kind, string payloadJson, string reason = "test")
    {
        using var payload = JsonDocument.Parse(payloadJson);
        return new RequestWriter(_store.Spool).Submit(kind, reason, payload.RootElement.Clone(), @"TEST\user");
    }

    private string[] Files(string folder) => Directory.GetFiles(Path.Combine(_store.Spool, folder));

    [Fact]
    public void Queued_override_is_applied_and_audited()
    {
        var id = Submit("override", AddDisable);

        var report = Manager().DrainOnce();

        Assert.Equal(new QueueReport(1, 0, 0), report);
        Assert.Equal("OVR-0001", _store.Scalar("SELECT override_id FROM override WHERE check_id = 'AD-001' AND active = 1"));
        Assert.Equal("done", _store.Scalar($"SELECT state FROM request WHERE request_id = '{id}'"));
        Assert.Single(Files(Spool.Done));
        Assert.Empty(Files(Spool.Queue));
        Assert.Empty(Files(Spool.Work));
    }

    [Fact]
    public void Invalid_payload_goes_to_failed_with_the_reason()
    {
        var id = Submit("override", """{ "op": "add", "decision": "disable" }""");

        var report = Manager().DrainOnce();

        Assert.Equal(1, report.Failed);
        Assert.Equal(0L, _store.Scalar("SELECT COUNT(*) FROM override"));
        Assert.Contains("checkId", File.ReadAllText(Assert.Single(Files(Spool.Failed))), StringComparison.Ordinal);
        Assert.Equal("failed", _store.Scalar($"SELECT state FROM request WHERE request_id = '{id}'"));
    }

    [Fact]
    public void Unknown_kind_fails()
    {
        Submit("drop-everything", "{}");

        Assert.Equal(1, Manager().DrainOnce().Failed);
    }

    [Fact]
    public void A_request_is_never_applied_twice()
    {
        Submit("override", AddDisable);
        Manager().DrainOnce();

        // Put the request back in work\, as a crash between commit and move would leave it.
        var done = Assert.Single(Files(Spool.Done));
        var original = JsonNode.Parse(File.ReadAllText(done))!["request"]!.ToJsonString();
        File.WriteAllText(Path.Combine(_store.Spool, Spool.Work, Path.GetFileName(done)), original);

        var report = Manager().DrainOnce();

        Assert.Equal(new QueueReport(0, 0, 1), report);
        Assert.Equal(1L, _store.Scalar("SELECT COUNT(*) FROM override"));
    }

    [Fact]
    public void Second_writer_is_refused_while_the_lock_is_held()
    {
        Spool.EnsureFolders(_store.Spool);
        using var held = new FileStream(Path.Combine(_store.Spool, "writer.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        Assert.Throws<QueueBusyException>(() => Manager().DrainOnce());
    }

    [Fact]
    public void Removing_an_override_keeps_the_record()
    {
        Submit("override", AddDisable);
        Manager().DrainOnce();
        Submit("override", """{ "op": "remove", "overrideId": "OVR-0001" }""", "check re-enabled");

        Manager().DrainOnce();

        Assert.Equal(0L, _store.Scalar("SELECT active FROM override WHERE override_id = 'OVR-0001'"));
        Assert.Equal("check re-enabled", _store.Scalar("SELECT removed_why FROM override WHERE override_id = 'OVR-0001'"));
    }

    [Fact]
    public void Attestation_needs_exactly_one_target()
    {
        Submit("attestation", """{ "state": "yes", "evidence": "restore test log" }""");

        Assert.Equal(1, Manager().DrainOnce().Failed);
    }

    [Fact]
    public void Snoozing_a_finding_records_an_event_and_shows_in_the_view()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"));
        Submit("triage", """{ "findingKey": "k1", "decision": "snooze", "until": "2999-01-01" }""", "waiting for the vendor");

        Assert.Equal(1, Manager().DrainOnce().Done);
        Assert.Equal("snoozed", _store.Scalar("SELECT event FROM finding_event WHERE finding_key = 'k1'"));
        Assert.Equal("2999-01-01", _store.Scalar("SELECT snoozed_until FROM active_finding WHERE finding_key = 'k1'"));
    }

    [Fact]
    public void Missing_reason_is_refused()
    {
        Submit("override", AddDisable, reason: "");

        Assert.Equal(1, Manager().DrainOnce().Failed);
        Assert.Equal(0L, _store.Scalar("SELECT COUNT(*) FROM override"));
    }
}
