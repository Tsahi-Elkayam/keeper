namespace Keeper.Home;

/// <summary>Where one tenant's files live. Everything derives from the settings file's location.</summary>
public sealed record KeeperPaths(string SettingsFile, string DataDir)
{
    /// <summary>settings\settings.json in the Keeper home (see <see cref="KeeperHome"/>).</summary>
    public static string DefaultSettingsFile => Path.Combine(KeeperHome.Resolve(), "settings", "settings.json");

    public string SettingsDir => Path.GetDirectoryName(SettingsFile)!;

    public string Database => Path.Combine(DataDir, "keeper.db");

    public string Spool => Path.Combine(DataDir, "spool");

    /// <summary>
    /// The client's configuration AS FILES (the record): a sibling of the data folder, so home\data\ pairs
    /// with home\config\ and clients\&lt;client&gt;\data\ with clients\&lt;client&gt;\config\. 'keeper config export/import'
    /// move systems.yaml and (later) integrations, thresholds and overrides between here and the store.
    /// </summary>
    public string Config => Path.GetFullPath(Path.Combine(DataDir, "..", "config"));

    /// <summary>One folder per scan: rows, results, findings, coverage, run.json.</summary>
    public string Runs => Path.Combine(DataDir, "runs");

    /// <summary>One folder per pipeline run: the files each stage hands to the next.</summary>
    public string Builds => Path.Combine(DataDir, "builds");

    public string Backups => Path.Combine(DataDir, "backups");

    /// <summary>Reports from other tools (PingCastle, Maester, ...) for file rules to read.</summary>
    public string Imports => Path.Combine(DataDir, "imports");

    public string Reports => Path.Combine(DataDir, "reports");

    /// <summary>The tenant's own named queries: settings\queries\*.sql.</summary>
    public string TenantQueries => Path.Combine(SettingsDir, "queries");

    /// <summary>The tenant's own rule files: settings\rules\*.yaml.</summary>
    public string TenantRules => Path.Combine(SettingsDir, "rules");
}
