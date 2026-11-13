using System.Reflection;

namespace Keeper.Query;

/// <summary>A component's questions: .sql files embedded under a resource prefix.</summary>
public sealed record QueryPack(string Name, Assembly Assembly, string Prefix)
{
    public IReadOnlyList<NamedQuery> Load()
    {
        var list = new List<NamedQuery>();
        foreach (var resource in Assembly.GetManifestResourceNames()
                     .Select(r => (Resource: r, Name: r.Replace('\\', '/')))
                     .Where(r => r.Name.StartsWith(Prefix, StringComparison.Ordinal) && r.Name.EndsWith(".sql", StringComparison.Ordinal))
                     .OrderBy(r => r.Name, StringComparer.Ordinal))
        {
            using var stream = Assembly.GetManifestResourceStream(resource.Resource)!;
            using var reader = new StreamReader(stream);
            list.Add(NamedQuery.Parse(reader.ReadToEnd(), $"{Name}:{resource.Name[Prefix.Length..]}"));
        }
        return list;
    }
}

/// <summary>
/// The questions a binary can answer: the packs it was built with, plus the tenant's own
/// (.sql files in a folder). A tenant query adds a question; it may not redefine one.
/// </summary>
public static class QueryCatalog
{
    public static IReadOnlyDictionary<string, NamedQuery> Load(IEnumerable<QueryPack> packs, string? tenantDir)
    {
        var all = new Dictionary<string, NamedQuery>(StringComparer.OrdinalIgnoreCase);
        foreach (var query in packs.SelectMany(p => p.Load()))
        {
            if (!all.TryAdd(query.Name, query))
                throw new QueryException($"'{query.Name}' is defined by both {all[query.Name].Origin} and {query.Origin}.");
        }

        if (tenantDir is null || !Directory.Exists(tenantDir))
            return all;

        foreach (var file in Directory.GetFiles(tenantDir, "*.sql").Order(StringComparer.OrdinalIgnoreCase))
        {
            var query = NamedQuery.Parse(File.ReadAllText(file), file);
            if (!all.TryAdd(query.Name, query))
                throw new QueryException($"{file}: '{query.Name}' is already defined by {all[query.Name].Origin}.");
        }
        return all;
    }
}
