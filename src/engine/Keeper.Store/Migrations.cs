using System.Globalization;
using System.Reflection;

namespace Keeper.Store;

public sealed record Migration(int Version, string Name, string Sql);

/// <summary>
/// One component's schema: its numbered migrations, and the components whose tables it references.
/// A released migration is never edited; changes go in a new one.
/// </summary>
public sealed record MigrationSet(string Component, IReadOnlyList<string> DependsOn, IReadOnlyList<Migration> Migrations)
{
    public int Latest => Migrations.Count;

    /// <summary>Loads NNN-name.sql embedded resources whose logical name starts with <paramref name="prefix"/>.</summary>
    public static MigrationSet FromResources(string component, Assembly assembly, string prefix, params string[] dependsOn)
    {
        var list = new List<Migration>();
        foreach (var resource in assembly.GetManifestResourceNames())
        {
            var name = resource.Replace('\\', '/');
            if (!name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(".sql", StringComparison.Ordinal))
                continue;

            var file = name[prefix.Length..^4];   // 001-review
            var dash = file.IndexOf('-', StringComparison.Ordinal);
            if (dash < 1 || !int.TryParse(file[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out var version))
                throw new StoreException($"{component}: migration file names must be NNN-name.sql: {resource}");

            using var stream = assembly.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            list.Add(new Migration(version, file[(dash + 1)..], reader.ReadToEnd()));
        }

        list.Sort((a, b) => a.Version.CompareTo(b.Version));
        for (var i = 0; i < list.Count; i++)
        {
            if (list[i].Version != i + 1)
                throw new StoreException($"{component}: migrations must be numbered 1..n with no gaps; found {list[i].Version} where {i + 1} was expected.");
        }
        if (list.Count == 0)
            throw new StoreException($"{component}: no migrations under '{prefix}'.");
        return new MigrationSet(component, dependsOn, list);
    }
}

public sealed record SchemaStatus(string Component, int Current, int Latest)
{
    public bool UpToDate => Current == Latest;
}
