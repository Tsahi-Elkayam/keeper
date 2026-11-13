using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace Keeper.Store;

/// <summary>
/// One SQLite file. Readers open it read-only; writers open it read-write. Which binary may do which
/// is decided by whoever composes the binaries - this class only makes the two explicit.
/// </summary>
public sealed class Database
{
    public Database(string file) => DbFile = Path.GetFullPath(file);

    public string DbFile { get; }

    public bool Exists => File.Exists(DbFile);

    public SqliteConnection OpenReadOnly()
    {
        if (!Exists)
            throw new StoreException($"No store at {DbFile}.");
        return Open(SqliteOpenMode.ReadOnly);
    }

    public SqliteConnection OpenReadWrite(bool create = false)
    {
        if (!create && !Exists)
            throw new StoreException($"No store at {DbFile}.");
        if (create)
            Directory.CreateDirectory(Path.GetDirectoryName(DbFile)!);

        var connection = Open(create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite);
        Sql.Execute(connection, "PRAGMA journal_mode = WAL;");
        return connection;
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
        // SQLite has the REGEXP operator but no function behind it; .NET's, with a timeout, so a store rule
        // or a question can use a tenant's pattern setting (x REGEXP pattern).
        connection.CreateFunction("regexp", (string? pattern, string? input) => Regexp(pattern, input), isDeterministic: true);
        return connection;
    }

    private static readonly ConcurrentDictionary<string, Regex> Patterns = new(StringComparer.Ordinal);

    private static bool Regexp(string? pattern, string? input)
    {
        if (pattern is null || input is null)
            return false;
        if (Patterns.Count > 256)
            Patterns.Clear();
        return Patterns.GetOrAdd(pattern, p => new Regex(p, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1))).IsMatch(input);
    }
}

public sealed class StoreException(string message) : Exception(message);
