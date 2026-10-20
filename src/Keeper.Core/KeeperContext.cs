namespace Keeper.Core;

public static class KeeperContext
{
    /// <summary>
    /// Loads settings for a keeper binary from --settings &lt;file&gt;, or the Keeper home. Refuses a
    /// settings file or data folder inside a source tree or beside the binaries.
    /// </summary>
    public static (KeeperSettings Settings, KeeperPaths Paths) Load(CliArgs cli)
    {
        var given = cli.Get("settings");
        var file = Path.GetFullPath(given ?? KeeperPaths.DefaultSettingsFile);
        KeeperHome.EnsureOutsideCode(file, "The settings file");

        if (given is null && !File.Exists(file))
            throw new SettingsException(
                $"No settings at {file}. Run build.ps1 to create the Keeper home, " +
                $"or set {KeeperHome.EnvironmentVariable} to the folder that holds settings\\ and data\\.");

        var settings = SettingsLoader.Load(file);
        var data = SettingsLoader.ResolveDataPath(settings, file);
        KeeperHome.EnsureOutsideCode(data, "The data folder");
        return (settings, new KeeperPaths(file, data));
    }
}
