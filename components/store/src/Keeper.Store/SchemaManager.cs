using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Keeper.Store;

/// <summary>
/// Applies each component's migrations, dependencies first, and keeps one version per component in
/// schema_version. Every binary refuses a store whose components are not at the versions it was built for.
/// </summary>
public static class SchemaManager
{
    private const string VersionTable = """
        CREATE TABLE IF NOT EXISTS schema_version (
            component  TEXT PRIMARY KEY,
            version    INTEGER NOT NULL,
            applied_at TEXT NOT NULL
        ) STRICT;
        """;

    public static int VersionOf(SqliteConnection connection, string component)
    {
        if (!HasVersionTable(connection))
            return 0;
        using var command = Sql.Command(connection, "SELECT version FROM schema_version WHERE component = :c;", null, (":c", component));
        return command.ExecuteScalar() is long version ? (int)version : 0;
    }

    public static IReadOnlyList<SchemaStatus> Status(SqliteConnection connection, IEnumerable<MigrationSet> sets) =>
        Ordered(sets).Select(s => new SchemaStatus(s.Component, VersionOf(connection, s.Component), s.Latest)).ToList();

    public static IReadOnlyList<(MigrationSet Set, Migration Migration)> Pending(SqliteConnection connection, IEnumerable<MigrationSet> sets)
    {
        var pending = new List<(MigrationSet, Migration)>();
        foreach (var set in Ordered(sets))
        {
            var current = VersionOf(connection, set.Component);
            if (current > set.Latest)
                throw new StoreException($"{set.Component} is at version {current}, newer than this build ({set.Latest}). Use a newer build.");
            pending.AddRange(set.Migrations.Where(m => m.Version > current).Select(m => (set, m)));
        }
        return pending;
    }

    /// <summary>Applies every pending migration, each in its own transaction with its version row.</summary>
    public static int Apply(SqliteConnection connection, IEnumerable<MigrationSet> sets)
    {
        var list = sets.ToList();
        Sql.Execute(connection, VersionTable);
        var pending = Pending(connection, list);
        foreach (var (set, migration) in pending)
        {
            using var transaction = connection.BeginTransaction();
            Sql.Execute(connection, migration.Sql, transaction);
            using var stamp = Sql.Command(connection,
                """
                INSERT INTO schema_version (component, version, applied_at) VALUES (:c, :v, :at)
                ON CONFLICT (component) DO UPDATE SET version = excluded.version, applied_at = excluded.applied_at;
                """,
                transaction,
                (":c", set.Component), (":v", migration.Version),
                (":at", DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)));
            stamp.ExecuteNonQuery();
            transaction.Commit();
        }
        return pending.Count;
    }

    public static void EnsureCurrent(SqliteConnection connection, IEnumerable<MigrationSet> sets)
    {
        var stale = Status(connection, sets).Where(s => !s.UpToDate).ToList();
        if (stale.Count > 0)
            throw new StoreException(
                "The store does not match this build: " +
                string.Join(", ", stale.Select(s => $"{s.Component} {s.Current} (build {s.Latest})")) +
                ". Run 'keeper db migrate'.");
    }

    /// <summary>Dependencies first. A dependency that is not part of this build, or a cycle, is an error.</summary>
    public static IReadOnlyList<MigrationSet> Ordered(IEnumerable<MigrationSet> sets)
    {
        var byName = new Dictionary<string, MigrationSet>(StringComparer.Ordinal);
        foreach (var set in sets)
        {
            if (!byName.TryAdd(set.Component, set))
                throw new StoreException($"Two schemas are named '{set.Component}'.");
        }

        var ordered = new List<MigrationSet>();
        var state = new Dictionary<string, bool>(StringComparer.Ordinal);   // false = visiting, true = done

        void Visit(MigrationSet set)
        {
            if (state.TryGetValue(set.Component, out var done))
            {
                if (!done)
                    throw new StoreException($"Schema dependency cycle at '{set.Component}'.");
                return;
            }
            state[set.Component] = false;
            foreach (var dependency in set.DependsOn)
            {
                if (!byName.TryGetValue(dependency, out var required))
                    throw new StoreException($"{set.Component} depends on {dependency}, which is not part of this build.");
                Visit(required);
            }
            state[set.Component] = true;
            ordered.Add(set);
        }

        foreach (var set in byName.Values.OrderBy(s => s.Component, StringComparer.Ordinal))
            Visit(set);
        return ordered;
    }

    private static bool HasVersionTable(SqliteConnection connection) =>
        Sql.Scalar(connection, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version';") is long n && n > 0;
}
