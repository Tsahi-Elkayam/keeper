using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Review.Tests;

public sealed class SchemaTests : IDisposable
{
    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    [Fact]
    public void A_new_store_has_lookups_and_the_synthetic_systems()
    {
        using var connection = _store.Db.OpenReadOnly();

        Assert.Equal(ReviewComponent.Schema.Latest, SchemaManager.VersionOf(connection, "review"));
        Assert.Equal(5L, Sql.Scalar(connection, "SELECT COUNT(*) FROM severity"));
        Assert.Equal(12L, Sql.Scalar(connection, "SELECT COUNT(*) FROM category"));
        Assert.Equal(3L, Sql.Scalar(connection, "SELECT COUNT(*) FROM system WHERE system_id IN ('KEEPER', 'ORG', 'UNMAPPED')"));
    }

    [Fact]
    public void Check_constraints_refuse_unknown_vocabulary()
    {
        var ex = Assert.Throws<SqliteException>(() => _store.SeedFindings(("k1", "on-fire", "high", "open", "Not a kind")));

        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_setting_key_must_be_lower_case()
    {
        Assert.Throws<SqliteException>(() =>
            _store.Seed("INSERT INTO setting (key, value, actor, at, why) VALUES ('Threshold.X', '1', 'a', 'b', 'c');"));
    }

    [Fact]
    public void The_active_view_shows_only_open_findings_with_days_left()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"), ("k2", "broken", "high", "resolved", "Fixed"));
        _store.Seed("UPDATE finding SET deadline = date('now', '+10 days') WHERE finding_key = 'k1';");

        var rows = _store.Rows("SELECT finding_key, days_left FROM active_finding");

        var row = Assert.Single(rows);
        Assert.Equal("k1", row["finding_key"]);
        Assert.Equal(10L, row["days_left"]);
    }
}
