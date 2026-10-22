using System.Text.Json;
using Keeper.Review.Config;

namespace Keeper.Review.Tests;

public sealed class SettingsConfigTests : IDisposable
{
    private static readonly SettingRecord[] Sample =
    [
        new("report.footer", "Owner: Alex O'Brien"),              // a single quote, to exercise quoting
        new("threshold.ad.stale-user-days", "120"),
        new("threshold.cert.expiry-days", "30"),
    ];

    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    [Fact]
    public void Write_then_read_then_write_is_byte_stable()
    {
        var yaml1 = SettingsConfig.Write("acme", Sample);
        var records = SettingsConfig.Read(yaml1, "mem", out var client);
        var yaml2 = SettingsConfig.Write(client, records);

        Assert.Equal("acme", client);
        Assert.Equal(yaml1, yaml2);
    }

    [Fact]
    public void Read_recovers_keys_and_values_ordered_by_key()
    {
        var byKey = SettingsConfig.Read(SettingsConfig.Write(null, Sample), "mem", out _)
            .ToDictionary(s => s.Key, s => s.Value, StringComparer.Ordinal);

        Assert.Equal(["report.footer", "threshold.ad.stale-user-days", "threshold.cert.expiry-days"], byKey.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("Owner: Alex O'Brien", byKey["report.footer"]);
        Assert.Equal("120", byKey["threshold.ad.stale-user-days"]);
    }

    [Fact]
    public void Export_import_export_through_the_store_is_stable_and_import_is_idempotent()
    {
        var yaml1 = SettingsConfig.Write("acme", Sample);
        var fromFile = SettingsConfig.Read(yaml1, "file", out var client);

        foreach (var setting in fromFile)
            _store.Submit("review.setting", Upsert(setting));
        var report = _store.Manager().DrainOnce();
        Assert.Equal(Sample.Length, report.Done);
        Assert.Equal(0, report.Failed);

        var inStore = _store.Rows("SELECT key, value FROM setting ORDER BY key")
            .Select(row => new SettingRecord((string)row["key"]!, (string)row["value"]!)).ToList();
        var yaml2 = SettingsConfig.Write(client, inStore);
        Assert.Equal(yaml1, yaml2);

        var byKey = inStore.ToDictionary(s => s.Key, s => s.Value, StringComparer.Ordinal);
        foreach (var setting in fromFile)
            Assert.Equal(setting.Value, byKey[setting.Key]);   // nothing left to change on a second import
    }

    [Fact]
    public void A_setting_in_the_store_but_not_in_the_file_is_left_alone()
    {
        _store.Submit("review.setting", Upsert(new SettingRecord("tenant.only-in-store", "keep")));
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        foreach (var setting in Sample)
            _store.Submit("review.setting", Upsert(setting));
        _store.Manager().DrainOnce();

        Assert.Equal("keep", _store.Scalar("SELECT value FROM setting WHERE key = 'tenant.only-in-store'"));
    }

    [Theory]
    [InlineData("this: is: not: valid: yaml")]                                             // unparseable
    [InlineData("schema: wrong/9\nsettings: []")]                                          // wrong schema
    [InlineData("client: 'x'\nsettings: []")]                                              // missing schema
    [InlineData("schema: keeper.config/1")]                                                // missing settings
    [InlineData("schema: keeper.config/1\nsettings:\n  - value: 'v'")]                     // missing key
    [InlineData("schema: keeper.config/1\nsettings:\n  - key: threshold.x")]               // missing value
    [InlineData("schema: keeper.config/1\nsettings:\n  - key: threshold.x\n    value: 'v'\n    bogus: 1")] // unknown field
    [InlineData("schema: keeper.config/1\nsettings:\n  - key: 'Bad Key'\n    value: 'v'")] // bad key
    [InlineData("schema: keeper.config/1\nsettings:\n  - key: a.b\n    value: 'x'\n  - key: a.b\n    value: 'y'")] // duplicate key
    public void A_malformed_file_throws_config_exception(string yaml)
    {
        var ex = Assert.Throws<ConfigException>(() => SettingsConfig.Read(yaml, "bad.yaml", out _));
        Assert.NotEmpty(ex.Errors);
    }

    [Fact]
    public void A_well_formed_empty_file_reads_as_no_settings()
    {
        Assert.Empty(SettingsConfig.Read("schema: keeper.config/1\nsettings: []\n", "mem", out _));
    }

    private static string Upsert(SettingRecord s) => JsonSerializer.Serialize(new { key = s.Key, value = s.Value });
}
