namespace Keeper.Review.Tests;

public sealed class HandlerTests : IDisposable
{
    private const string AddDisable = """{ "op": "add", "checkId": "AD-001", "decision": "disable" }""";

    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    private int Done() => _store.Manager().DrainOnce().Done;

    private int Failed() => _store.Manager().DrainOnce().Failed;

    [Fact]
    public void An_override_is_added_and_removed_keeping_the_record()
    {
        _store.Submit("review.override", AddDisable);
        Assert.Equal(1, Done());
        _store.Submit("review.override", """{ "op": "remove", "overrideId": "OVR-0001" }""", "rule re-enabled");
        Assert.Equal(1, Done());

        var row = Assert.Single(_store.Rows("SELECT active, removed_why FROM override"));
        Assert.Equal(0L, row["active"]);
        Assert.Equal("rule re-enabled", row["removed_why"]);
    }

    [Fact]
    public void An_exception_needs_an_entity()
    {
        _store.Submit("review.override", """{ "op": "add", "checkId": "AD-001", "decision": "exception" }""");

        Assert.Equal(1, Failed());
    }

    [Fact]
    public void A_snooze_records_an_event_and_shows_in_the_view()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"));
        _store.Submit("review.triage", """{ "findingKey": "k1", "decision": "snooze", "until": "2999-01-01" }""", "waiting for the vendor");

        Assert.Equal(1, Done());
        Assert.Equal("snoozed", _store.Scalar("SELECT event FROM finding_event WHERE finding_key = 'k1'"));
        Assert.Equal("2999-01-01", _store.Scalar("SELECT snoozed_until FROM active_finding WHERE finding_key = 'k1'"));
    }

    [Fact]
    public void A_snooze_needs_a_real_date()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"));
        _store.Submit("review.triage", """{ "findingKey": "k1", "decision": "snooze", "until": "next week" }""");

        Assert.Equal(1, Failed());
    }

    [Fact]
    public void An_attestation_is_recorded_and_a_bad_obligation_id_refused()
    {
        _store.Submit("review.attestation", """{ "obligation": "backup.restore-test", "state": "yes", "doneOn": "2026-10-01", "evidence": "restore log" }""");
        _store.Submit("review.attestation", """{ "obligation": "Backup Restore", "state": "yes", "evidence": "x" }""");

        var report = _store.Manager().DrainOnce();

        Assert.Equal(1, report.Done);
        Assert.Equal(1, report.Failed);
        Assert.Equal("backup.restore-test", _store.Scalar("SELECT obligation FROM latest_attestation"));
    }

    [Fact]
    public void A_setting_is_set_changed_and_removed()
    {
        _store.Submit("review.setting", """{ "key": "threshold.ad.stale-user-days", "value": "90" }""");
        _store.Submit("review.setting", """{ "key": "threshold.ad.stale-user-days", "value": "120" }""");
        Assert.Equal(2, Done());
        Assert.Equal("120", _store.Scalar("SELECT value FROM setting"));

        _store.Submit("review.setting", """{ "key": "threshold.ad.stale-user-days", "remove": true }""");
        Assert.Equal(1, Done());
        Assert.Equal(0L, _store.Scalar("SELECT COUNT(*) FROM setting"));
    }

    [Fact]
    public void A_system_is_upserted_but_a_built_in_one_is_protected()
    {
        _store.Submit("review.system", """{ "op": "upsert", "systemId": "MAIL", "name": "Mail", "criticality": 1 }""");
        _store.Submit("review.system", """{ "op": "upsert", "systemId": "KEEPER", "name": "Mine now" }""");

        var report = _store.Manager().DrainOnce();

        Assert.Equal(1, report.Done);
        Assert.Equal(1, report.Failed);
        Assert.Equal(1L, _store.Scalar("SELECT criticality FROM system WHERE system_id = 'MAIL'"));
    }

    [Fact]
    public void A_system_with_open_findings_cannot_be_removed()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"));
        _store.Submit("review.system", """{ "op": "remove", "systemId": "SYS1" }""");

        Assert.Equal(1, Failed());
    }

    [Fact]
    public void A_system_rule_with_a_bad_pattern_is_refused()
    {
        _store.Submit("review.system", """{ "op": "upsert", "systemId": "MAIL", "name": "Mail" }""");
        _store.Submit("review.system-rule", """{ "op": "upsert", "ruleId": "mail-hosts", "field": "key", "pattern": "^mx[", "systemId": "MAIL" }""");

        var report = _store.Manager().DrainOnce();

        Assert.Equal(1, report.Done);
        Assert.Equal(1, report.Failed);
    }

    [Fact]
    public void A_licence_is_registered_with_its_notice_period()
    {
        _store.Submit("review.licence", """
            { "op": "upsert", "licenceId": "backup-suite", "product": "Backup suite", "expiresOn": "2026-12-31",
              "noticeDays": 90, "seats": 100, "seatsUsed": 95, "autoRenews": false }
            """);

        Assert.Equal(1, Done());
        var row = Assert.Single(_store.Rows("SELECT * FROM licence"));
        Assert.Equal("2026-12-31", row["expires_on"]);
        Assert.Equal(90L, row["notice_days"]);
        Assert.Equal(0L, row["auto_renews"]);
    }

    [Theory]
    [InlineData("""{ "op": "upsert", "licenceId": "x" }""")]
    [InlineData("""{ "op": "upsert", "licenceId": "x", "product": "P", "expiresOn": "31/12/2026" }""")]
    [InlineData("""{ "op": "upsert", "licenceId": "x", "product": "P", "seats": "many" }""")]
    [InlineData("""{ "op": "upsert", "licenceId": "../x", "product": "P" }""")]
    public void A_bad_licence_is_refused(string payload)
    {
        _store.Submit("review.licence", payload);

        Assert.Equal(1, Failed());
        Assert.Equal(0L, _store.Scalar("SELECT COUNT(*) FROM licence"));
    }

    [Fact]
    public void A_key_date_needs_a_known_kind()
    {
        _store.Submit("review.key-date", """{ "op": "upsert", "keyDateId": "q4-report", "kind": "report", "title": "Quarterly report", "dueOn": "2026-10-25" }""");
        _store.Submit("review.key-date", """{ "op": "upsert", "keyDateId": "other", "kind": "party", "title": "x", "dueOn": "2026-10-25" }""");

        var report = _store.Manager().DrainOnce();

        Assert.Equal(1, report.Done);
        Assert.Equal(1, report.Failed);
    }
}
