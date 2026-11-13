using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Scan;

/// <summary>
/// Whether 'keeper run' should read a system's rule files today, or leave them for later and say why in one line.
/// A pack nobody set up is not a failed scan: an import pack whose report folder does not exist, a pack whose hosts
/// come from another system's scan that has not listed any yet, and a pack about a practice the organisation has not
/// taken up (opt_in). A scan that was asked for by name ('keeper scan &lt;system&gt;') still runs and says what is missing.
/// </summary>
public static class PackReadiness
{
    /// <summary>The kind of reason a pack waits: said together, one line per kind.</summary>
    public enum Waiting
    {
        /// <summary>An opt_in pack whose setting is off.</summary>
        Off,

        /// <summary>An import pack whose report folders do not exist.</summary>
        NoImport,

        /// <summary>A pack whose hosts come from the store, and the store lists none yet.</summary>
        NoHosts,
    }

    /// <param name="files">The system's rule files.</param>
    /// <param name="implicitIntegration">True when no integration was set up for it (files, host, keeper).</param>
    /// <param name="options">The integration's options (empty for an implicit one).</param>
    /// <param name="importsDir">The Keeper home's imports folder.</param>
    /// <param name="setting">A setting's value by its full key, or null.</param>
    /// <param name="threshold">A threshold's value by its name (without 'threshold.'), or null.</param>
    /// <param name="hosts">The hosts the store lists for a target spec.</param>
    /// <returns>Null when the pack should run; else why it waits and the one-line detail.</returns>
    public static (Waiting Kind, string Detail)? Check(
        IReadOnlyList<RuleFile> files,
        bool implicitIntegration,
        JsonObject options,
        string importsDir,
        Func<string, string?> setting,
        Func<string, string?> threshold,
        Func<TargetSpec, IReadOnlyList<string>> hosts)
    {
        if (files.Count == 0)
            return null;
        var system = files[0].System;

        foreach (var key in files.Select(f => f.OptIn).OfType<string>().Distinct(StringComparer.Ordinal))
        {
            if (!IsOn(setting(key)))
                return (Waiting.Off, $"{system} (keeper decide setting {key} true)");
        }

        if (implicitIntegration && ImportFolders(files, threshold) is { Count: > 0 } folders
            && !folders.Any(f => Directory.Exists(Path.Combine(importsDir, f))))
            return (Waiting.NoImport, $"{system} (imports/{string.Join(", imports/", folders)})");

        // Every file finds its hosts in the store, none is pointed at named hosts, and the store lists none yet.
        if (files.All(f => f.Targets is { List.Count: 0 }) && options["targets." + system] is not JsonArray
            && files.All(f => hosts(f.Targets!).Count == 0))
        {
            var entities = files.Select(f => f.Targets!.Entity ?? "host").Distinct(StringComparer.Ordinal);
            return (Waiting.NoHosts, $"{system} (no {string.Join(" or ", entities)} listed yet)");
        }
        return null;
    }

    /// <summary>
    /// The import folders (relative to imports/) the files read, when every query reads one: the file runner's
    /// path, or a host configuration folder under 'imports:' that no setting moves elsewhere. Empty when any query
    /// reads something else (a live system, a file on this machine): then the pack is not an import pack.
    /// </summary>
    public static IReadOnlyList<string> ImportFolders(IReadOnlyList<RuleFile> files, Func<string, string?> threshold)
    {
        var folders = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var query in files.SelectMany(f => f.Rules).Select(r => r.Query))
        {
            string? folder = null;
            if (query.Protocol == "file" && query.Text("path") is { } path)
                folder = Path.GetDirectoryName(path.Replace('\\', '/'))?.Replace('\\', '/');
            else if (query.Protocol == "host" && query.Text("folder") is { } hostFolder
                     && hostFolder.StartsWith("imports:", StringComparison.Ordinal)
                     && !(query.Text("folderSetting") is { } moved && threshold(moved) is { Length: > 0 }))
                folder = hostFolder["imports:".Length..];
            if (string.IsNullOrEmpty(folder))
                return [];
            folders.Add(folder);
        }
        return [.. folders];
    }

    public static bool IsOn(string? value) =>
        value is not null && (value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("on", StringComparison.OrdinalIgnoreCase)
                              || value.Equals("yes", StringComparison.OrdinalIgnoreCase) || value == "1");

    /// <summary>The one line 'keeper run' prints for the packs that wait for one reason.</summary>
    public static string Line(Waiting kind, IEnumerable<string> details) => kind switch
    {
        Waiting.Off => $"Off until turned on: {string.Join(", ", details)}",
        Waiting.NoImport => $"Not set up, no report to read: {string.Join(", ", details)} - put the tool's report there and the next run reads it",
        _ => $"Waiting for hosts from another scan: {string.Join(", ", details)} - they run once a scan has listed them",
    };
}
