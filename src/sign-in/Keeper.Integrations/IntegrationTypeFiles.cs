namespace Keeper.Integrations;

/// <summary>
/// Moves a tenant's integration type files (settings/integration-types/*.yaml) between folders: 'keeper config
/// export|import integration-types'. A file is copied byte for byte. Nothing is written unless the folder it lands in
/// would load: every file valid, no type defined twice, none replacing a built-in type. A file only in the target
/// folder is left there and reported, as the other config parts do.
/// </summary>
public static class IntegrationTypeFiles
{
    public sealed record Result(IReadOnlyList<string> Added, IReadOnlyList<string> Changed, IReadOnlyList<string> Unchanged, IReadOnlyList<string> OnlyInTarget)
    {
        public int Written => Added.Count + Changed.Count;
    }

    /// <summary>The *.yaml files of a folder, by file name; none when it does not exist.</summary>
    public static IReadOnlyList<string> In(string folder) =>
        Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder, "*.yaml").Where(f => f.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.Ordinal).ToList()
            : [];

    /// <summary>
    /// The types a set of files defines, checked together as one tenant folder: each file against the built-in types,
    /// and no id in two files. Throws <see cref="IntegrationException"/> naming the file at fault.
    /// </summary>
    public static IReadOnlyList<IntegrationType> Validate(IEnumerable<(string Source, string Yaml)> files)
    {
        var types = new List<IntegrationType>();
        foreach (var (source, yaml) in files)
        {
            foreach (var type in IntegrationTypeCatalog.Parse(yaml, source, IntegrationTypes.BuiltIn))
            {
                if (types.FirstOrDefault(t => t.Id.Equals(type.Id, StringComparison.OrdinalIgnoreCase)) is { } first)
                    throw new IntegrationException($"{source}: integration type '{type.Id}' is also defined in {first.Source}.");
                types.Add(type);
            }
        }
        return types;
    }

    /// <summary>
    /// Copies every *.yaml file of <paramref name="from"/> into <paramref name="to"/>, once the folder that results has
    /// been validated as a whole. A file whose bytes are already there is left untouched.
    /// </summary>
    public static Result Copy(string from, string to)
    {
        var incoming = In(from).ToDictionary(f => Path.GetFileName(f), File.ReadAllBytes, StringComparer.OrdinalIgnoreCase);
        var present = In(to).ToDictionary(f => Path.GetFileName(f), File.ReadAllBytes, StringComparer.OrdinalIgnoreCase);

        // The target as it will be: its own files, with the incoming ones laid over them.
        var after = present.Keys.Union(incoming.Keys, StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal)
            .Select(name => incoming.TryGetValue(name, out var bytes)
                ? (Path.Combine(from, name), Text(bytes))
                : (Path.Combine(to, name), Text(present[name])));
        Validate(after);

        List<string> added = [], changed = [], unchanged = [];
        foreach (var (name, bytes) in incoming.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (present.TryGetValue(name, out var old) && old.AsSpan().SequenceEqual(bytes))
            {
                unchanged.Add(name);
                continue;
            }
            (present.ContainsKey(name) ? changed : added).Add(name);
            Directory.CreateDirectory(to);
            var target = Path.Combine(to, name);
            var temp = $"{target}.{Environment.ProcessId}.tmp";
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, target, overwrite: true);
        }
        var onlyInTarget = present.Keys.Where(n => !incoming.ContainsKey(n)).Order(StringComparer.Ordinal).ToList();
        return new Result(added, changed, unchanged, onlyInTarget);
    }

    private static string Text(byte[] bytes)
    {
        using var reader = new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
}
