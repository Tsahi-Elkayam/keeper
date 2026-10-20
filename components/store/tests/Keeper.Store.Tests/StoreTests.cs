using Microsoft.Data.Sqlite;

namespace Keeper.Store.Tests;

public sealed class StoreTests : IDisposable
{
    private static readonly MigrationSet Alpha = MigrationSet.FromResources("alpha", typeof(StoreTests).Assembly, "alpha/");
    private static readonly MigrationSet Beta = MigrationSet.FromResources("beta", typeof(StoreTests).Assembly, "beta/", "alpha");

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database NewStore(params MigrationSet[] sets)
    {
        var db = new Database(Path.Combine(_dir, "store.db"));
        using var connection = db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, sets);
        return db;
    }

    [Fact]
    public void Applies_every_component_at_its_latest_version()
    {
        var db = NewStore(Beta, Alpha);
        using var connection = db.OpenReadOnly();

        Assert.Equal(2, SchemaManager.VersionOf(connection, "alpha"));
        Assert.Equal(1, SchemaManager.VersionOf(connection, "beta"));
        Assert.Empty(SchemaManager.Pending(connection, [Alpha, Beta]));
        SchemaManager.EnsureCurrent(connection, [Alpha, Beta]);
    }

    [Fact]
    public void Dependencies_come_first()
    {
        Assert.Equal(new[] { "alpha", "beta" }, SchemaManager.Ordered([Beta, Alpha]).Select(s => s.Component));
    }

    [Fact]
    public void A_missing_dependency_is_an_error()
    {
        var ex = Assert.Throws<StoreException>(() => SchemaManager.Ordered([Beta]));
        Assert.Contains("alpha", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_store_behind_the_build_is_refused()
    {
        var db = NewStore(Alpha);
        using var connection = db.OpenReadOnly();

        // beta was never applied
        Assert.Throws<StoreException>(() => SchemaManager.EnsureCurrent(connection, [Alpha, Beta]));
    }

    [Fact]
    public void A_store_ahead_of_the_build_is_refused()
    {
        var db = NewStore(Alpha);
        using (var write = db.OpenReadWrite())
            Sql.Execute(write, "UPDATE schema_version SET version = 99 WHERE component = 'alpha';");
        using var connection = db.OpenReadOnly();

        Assert.Throws<StoreException>(() => SchemaManager.Pending(connection, [Alpha]));
    }

    [Fact]
    public void Read_only_connection_cannot_write()
    {
        var db = NewStore(Alpha);
        using var connection = db.OpenReadOnly();

        Assert.Throws<SqliteException>(() => Sql.Execute(connection, "INSERT INTO alpha (id) VALUES ('x');"));
    }

    [Fact]
    public void Foreign_keys_are_enforced()
    {
        var db = NewStore(Alpha, Beta);
        using var connection = db.OpenReadWrite();

        Assert.Throws<SqliteException>(() => Sql.Execute(connection, "INSERT INTO beta (id, alpha_id) VALUES ('b', 'no-such-alpha');"));
    }

    [Fact]
    public void Backup_copies_the_whole_store()
    {
        var db = NewStore(Alpha, Beta);
        var copy = new Database(Path.Combine(_dir, "backups", "copy.db"));

        db.BackupTo(copy.DbFile);

        using var connection = copy.OpenReadOnly();
        Assert.Equal(2, SchemaManager.VersionOf(connection, "alpha"));
    }

    [Fact]
    public void A_missing_store_is_reported_not_created()
    {
        var db = new Database(Path.Combine(_dir, "nope", "store.db"));

        Assert.Throws<StoreException>(() => db.OpenReadOnly());
        Assert.False(db.Exists);
    }
}
