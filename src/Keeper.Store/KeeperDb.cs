using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Keeper.Store;

/// <summary>
/// The store: one SQLite file. Readers open it read-only; only keeper-qm (writes) and keeper-db
/// (migrations, backups) open it for writing.
/// </summary>
public sealed class KeeperDb
{
    public KeeperDb(string file) => DbFile = Path.GetFullPath(file);

    public string DbFile { get; }

    public bool Exists => File.Exists(DbFile);

    public SqliteConnection OpenReadOnly()
    {
        if (!Exists)
            throw new StoreException($"No store at {DbFile}. Run 'keeper-db init --apply'.");
        return Open(SqliteOpenMode.ReadOnly);
    }

    public SqliteConnection OpenReadWrite(bool create = false)
    {
        if (!create && !Exists)
            throw new StoreException($"No store at {DbFile}. Run 'keeper-db init --apply'.");
        if (create)
            Directory.CreateDirectory(Path.GetDirectoryName(DbFile)!);

        var connection = Open(create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite);
        Sql.Execute(connection, "PRAGMA journal_mode = WAL;");
        return connection;
    }

    public static int Version(SqliteConnection connection) =>
        Convert.ToInt32(Sql.Scalar(connection, "PRAGMA user_version;"), CultureInfo.InvariantCulture);

    /// <summary>Every binary except keeper-db refuses a store that is not at the version it was built for.</summary>
    public static void EnsureCurrentVersion(SqliteConnection connection)
    {
        var current = Version(connection);
        if (current != Migrations.Latest)
            throw new StoreException($"Store is at version {current}, this build expects {Migrations.Latest}. Run 'keeper-db migrate'.");
    }

    public void BackupTo(string destination)
    {
        var target = Path.GetFullPath(destination);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);

        using var source = OpenReadOnly();
        using var copy = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = target,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        copy.Open();
        source.BackupDatabase(copy);
    }

    private SqliteConnection Open(SqliteOpenMode mode)
    {
        // No pooling: a closed connection releases the file, so backups and moves are safe.
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DbFile,
            Mode = mode,
            Pooling = false,
            ForeignKeys = true,
        }.ToString());
        connection.Open();
        Sql.Execute(connection, "PRAGMA busy_timeout = 5000;");
        return connection;
    }
}

public sealed class StoreException(string message) : Exception(message);
