using System.Text.Json;
using Keeper.Review.Config;

namespace Keeper.Review.Tests;

public sealed class OverridesConfigTests : IDisposable
{
    // Generic rule ids and a doc-range host; one of each decision shape.
    private static readonly OverrideRecord[] Sample =
    [
        new("ad-stale-user", "disable", "", "", null, "Rule retired for this tenant."),
        new("ad-weak-cipher", "exception", "host1.example.org", "", "2099-01-31", "Accepted until the box is replaced."),
        new("ad-stale-user-days", "threshold", "", "180", null, "Larger estate; 180 days fits."),
    ];

    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    [Fact]
    public void Write_then_read_then_write_is_byte_stable()
    {
        var yaml1 = OverridesConfig.Write("acme", Sample);
        var records = OverridesConfig.Read(yaml1, "mem", out var client);
        var yaml2 = OverridesConfig.Write(client, records);

        Assert.Equal("acme", client);
        Assert.Equal(yaml1, yaml2);
    }

    [Fact]
    public void Read_recovers_each_decision_shape()
    {
        var byCheck = OverridesConfig.Read(OverridesConfig.Write(null, Sample), "mem", out _)
            .ToDictionary(o => o.CheckId, StringComparer.Ordinal);

        Assert.Equal("", byCheck["ad-stale-user"].Entity);
        Assert.Null(byCheck["ad-stale-user"].Until);
        Assert.Equal("host1.example.org", byCheck["ad-weak-cipher"].Entity);
        Assert.Equal("2099-01-31", byCheck["ad-weak-cipher"].Until);
        Assert.Equal("180", byCheck["ad-stale-user-days"].Value);
    }

    [Fact]
    public void Export_import_export_through_the_store_is_stable_and_import_is_idempotent()
    {
        var yaml1 = OverridesConfig.Write("acme", Sample);
        var fromFile = OverridesConfig.Read(yaml1, "file", out var client);

        // Each new override is an 'add', queued with its own reason so the stored why matches the file.
        foreach (var o in fromFile)
            _store.Submit("review.override", Add(o), o.Reason);
        var report = _store.Manager().DrainOnce();
        Assert.Equal(Sample.Length, report.Done);
        Assert.Equal(0, report.Failed);

        var inStore = ActiveOverrides();
        var yaml2 = OverridesConfig.Write(client, inStore);
        Assert.Equal(yaml1, yaml2);

        // Idempotent: every file identity is now an active store identity, so a second import adds nothing.
        var active = inStore.Select(o => o.Identity).ToHashSet();
        foreach (var o in fromFile)
            Assert.Contains(o.Identity, active);
    }

    [Fact]
    public void An_override_in_the_store_but_not_in_the_file_is_left_active()
    {
        _store.Submit("review.override", Add(new OverrideRecord("only-in-store", "disable", "", "", null, "kept")), "kept");
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        foreach (var o in Sample)
            _store.Submit("review.override", Add(o), o.Reason);
        _store.Manager().DrainOnce();

        Assert.Equal(1L, _store.Scalar("SELECT COUNT(*) FROM override WHERE check_id = 'only-in-store' AND active = 1"));
    }

    [Theory]
    [InlineData("this: is: not: valid: yaml")]                                                                 // unparseable
    [InlineData("schema: wrong/9\noverrides: []")]                                                             // wrong schema
    [InlineData("schema: keeper.config/1")]                                                                    // missing overrides
    [InlineData("schema: keeper.config/1\noverrides:\n  - decision: disable\n    reason: 'r'")]                // missing checkId
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    reason: 'r'")]                     // missing decision
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: nope\n    reason: 'r'")] // bad decision
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: disable")]               // missing reason
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: disable\n    entity: 'e'\n    reason: 'r'")] // disable with entity
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: exception\n    reason: 'r'")]               // exception without entity
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: threshold\n    reason: 'r'")]               // threshold without value
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: disable\n    until: 'soon'\n    reason: 'r'")] // bad until
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: disable\n    reason: 'r'\n  - checkId: 'a'\n    decision: disable\n    reason: 'r2'")] // duplicate identity
    [InlineData("schema: keeper.config/1\noverrides:\n  - checkId: 'a'\n    decision: disable\n    reason: 'r'\n    bogus: 1")]    // unknown field
    public void A_malformed_file_throws_config_exception(string yaml)
    {
        var ex = Assert.Throws<ConfigException>(() => OverridesConfig.Read(yaml, "bad.yaml", out _));
        Assert.NotEmpty(ex.Errors);
    }

    [Fact]
    public void A_well_formed_empty_file_reads_as_no_overrides()
    {
        Assert.Empty(OverridesConfig.Read("schema: keeper.config/1\noverrides: []\n", "mem", out _));
    }

    private List<OverrideRecord> ActiveOverrides() =>
        _store.Rows("SELECT check_id, decision, entity, value, until, why FROM override WHERE active = 1")
            .Select(row => new OverrideRecord(
                (string)row["check_id"]!, (string)row["decision"]!, (string)row["entity"]!, (string)row["value"]!,
                row["until"] as string, (string)row["why"]!)).ToList();

    private static string Add(OverrideRecord o) => JsonSerializer.Serialize(new
    {
        op = "add",
        checkId = o.CheckId,
        decision = o.Decision,
        entity = o.Entity,
        value = o.Value,
        until = o.Until,
    });
}
