using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Keeper.Store;

public sealed record Migration(int Version, string Name, string Sql);

/// <summary>
/// The schema, as numbered SQL files embedded from Migrations\NNN-name.sql. Applied in order,
/// each in its own transaction. A released migration is never edited; changes go in a new one.
/// </summary>
public static class Migrations
{
    private static readonly Lazy<IReadOnlyList<Migration>> Loaded = new(Load);

    public static IReadOnlyList<Migration> All => Loaded.Value;

    public static int Latest => All.Count;

    public static IReadOnlyList<Migration> Pending(int currentVersion) =>
        All.Where(m => m.Version > currentVersion).ToList();

    public static void Apply(SqliteConnection connection, IEnumerable<Migration> migrations)
    {
        foreach (var migration in migrations)
        {
            using var transaction = connection.BeginTransaction();
            Store.Sql.Execute(connection, migration.Sql, transaction);
            Store.Sql.Execute(connection, $"PRAGMA user_version = {migration.Version.ToString(CultureInfo.InvariantCulture)};", transaction);
            transaction.Commit();
        }
    }

    private static IReadOnlyList<Migration> Load()
    {
        const string prefix = "Migrations/";
        var assembly = typeof(Migrations).Assembly;
        var list = new List<Migration>();

        foreach (var resource in assembly.GetManifestResourceNames())
        {
            if (!resource.StartsWith(prefix, StringComparison.Ordinal) || !resource.EndsWith(".sql", StringComparison.Ordinal))
                continue;

            var file = resource[prefix.Length..^4];   // 001-review
            var dash = file.IndexOf('-', StringComparison.Ordinal);
            if (dash < 1 || !int.TryParse(file[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out var version))
                throw new StoreException($"Migration file names must be NNN-name.sql: {resource}");

            using var stream = assembly.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            list.Add(new Migration(version, file[(dash + 1)..], reader.ReadToEnd()));
        }

        list.Sort((a, b) => a.Version.CompareTo(b.Version));
        for (var i = 0; i < list.Count; i++)
        {
            if (list[i].Version != i + 1)
                throw new StoreException($"Migrations must be numbered 1..n with no gaps; found {list[i].Version} where {i + 1} was expected.");
        }
        return list;
    }
}
