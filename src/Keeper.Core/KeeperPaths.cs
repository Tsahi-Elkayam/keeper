namespace Keeper.Core;

/// <summary>Where one tenant's files live. Everything derives from the settings file's location.</summary>
public sealed record KeeperPaths(string SettingsFile, string DataDir)
{
    /// <summary>settings\settings.json in the Keeper home (see <see cref="KeeperHome"/>).</summary>
    public static string DefaultSettingsFile => Path.Combine(KeeperHome.Resolve(), "settings", "settings.json");

    public string Database => Path.Combine(DataDir, "keeper.db");

    public string Spool => Path.Combine(DataDir, "spool");

    public string Runs => Path.Combine(DataDir, "runs");

    public string Backups => Path.Combine(DataDir, "backups");

    /// <summary>The tenant's own named queries: settings\queries\*.sql.</summary>
    public string TenantQueries => Path.Combine(Path.GetDirectoryName(SettingsFile)!, "queries");
}
