namespace Keeper.Query;

/// <summary>
/// The questions Keeper answers: built-in queries (embedded Queries\*.sql) plus the tenant's own
/// (settings\queries\*.sql). A tenant query adds a question; it may not redefine a built-in one.
/// </summary>
public static class QueryCatalog
{
    public static IReadOnlyList<NamedQuery> LoadBuiltIns()
    {
        const string prefix = "Queries/";
        var assembly = typeof(QueryCatalog).Assembly;
        var list = new List<NamedQuery>();

        foreach (var resource in assembly.GetManifestResourceNames()
                     .Where(r => r.StartsWith(prefix, StringComparison.Ordinal))
                     .Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            list.Add(NamedQuery.Parse(reader.ReadToEnd(), "built-in " + resource[prefix.Length..]));
        }
        return list;
    }

    public static IReadOnlyDictionary<string, NamedQuery> Load(string? tenantDir)
    {
        var all = new Dictionary<string, NamedQuery>(StringComparer.OrdinalIgnoreCase);
        foreach (var query in LoadBuiltIns())
        {
            if (!all.TryAdd(query.Name, query))
                throw new QueryException($"Two built-in queries are named '{query.Name}'.");
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
