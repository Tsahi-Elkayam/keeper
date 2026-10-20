using Keeper.Testing;
using Microsoft.Data.Sqlite;

namespace Keeper.Store.Tests;

public sealed class StoreTests
{
    [Fact]
    public void Migrations_are_numbered_without_gaps()
    {
        Assert.NotEmpty(Migrations.All);
        Assert.Equal(Enumerable.Range(1, Migrations.Latest), Migrations.All.Select(m => m.Version));
    }

    [Fact]
    public void New_store_is_at_the_latest_version_with_lookups_seeded()
    {
        using var store = new TempStore();
        using var connection = store.Db.OpenReadOnly();

        Assert.Equal(Migrations.Latest, KeeperDb.Version(connection));
        Assert.Empty(Migrations.Pending(KeeperDb.Version(connection)));
        Assert.Equal(5L, Sql.Scalar(connection, "SELECT COUNT(*) FROM severity"));
        Assert.Equal(12L, Sql.Scalar(connection, "SELECT COUNT(*) FROM category"));
        Assert.Equal(1L, Sql.Scalar(connection, "SELECT COUNT(*) FROM system WHERE system_id = 'KEEPER'"));
    }

    [Fact]
    public void Read_only_connection_cannot_write()
    {
        using var store = new TempStore();
        using var connection = store.Db.OpenReadOnly();

        Assert.Throws<SqliteException>(() => Sql.Execute(connection, "INSERT INTO daily_metric VALUES ('2026-01-01', 'x', 1)"));
    }

    [Fact]
    public void Foreign_keys_are_enforced()
    {
        using var store = new TempStore();

        Assert.Throws<SqliteException>(() => store.Seed("INSERT INTO system_technology VALUES ('NO-SUCH-SYSTEM', 'no-such-technology')"));
    }

    [Fact]
    public void Check_constraints_refuse_unknown_vocabulary()
    {
        using var store = new TempStore();

        var ex = Assert.Throws<SqliteException>(() => store.SeedFindings(("k1", "on-fire", "high", "open", "Not a kind")));
        Assert.Contains("CHECK", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Store_at_another_version_is_refused()
    {
        using var store = new TempStore();
        store.Seed("PRAGMA user_version = 1;");
        using var connection = store.Db.OpenReadOnly();

        Assert.Throws<StoreException>(() => KeeperDb.EnsureCurrentVersion(connection));
    }

    [Fact]
    public void Backup_copies_the_whole_store()
    {
        using var store = new TempStore();
        var copy = new KeeperDb(Path.Combine(store.Dir, "backups", "copy.db"));

        store.Db.BackupTo(copy.DbFile);

        using var connection = copy.OpenReadOnly();
        Assert.Equal(Migrations.Latest, KeeperDb.Version(connection));
    }

    [Fact]
    public void Missing_store_is_reported_not_created()
    {
        var db = new KeeperDb(Path.Combine(Path.GetTempPath(), "keeper-test-" + Guid.NewGuid().ToString("N"), "keeper.db"));

        Assert.Throws<StoreException>(() => db.OpenReadOnly());
        Assert.False(db.Exists);
    }

    [Fact]
    public void Active_finding_view_hides_closed_findings()
    {
        using var store = new TempStore();
        store.SeedFindings(("k1", "broken", "high", "open", "Disk full"), ("k2", "broken", "high", "resolved", "Fixed"));

        Assert.Equal(1L, store.Scalar("SELECT COUNT(*) FROM active_finding"));
    }
}
