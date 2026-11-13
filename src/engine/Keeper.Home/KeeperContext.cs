using Keeper.Common;

namespace Keeper.Home;

public static class KeeperContext
{
    /// <summary>
    /// Loads settings for a keeper binary from --settings &lt;file&gt;, or the Keeper home. Refuses a
    /// settings file or data folder inside a source tree, beside the binaries, or readable by others.
    /// </summary>
    /// <summary>
    /// Called with the home's paths each time a verb loads it, before the verb goes on: the keeper binary reads the
    /// tenant's own definitions there (integration types) for components this one does not know.
    /// </summary>
    public static event Action<KeeperPaths>? Loaded;

    public static (KeeperSettings Settings, KeeperPaths Paths) Load(CliArgs cli)
    {
        var given = cli.Get("settings");
        var file = Path.GetFullPath(given ?? KeeperPaths.DefaultSettingsFile);
        KeeperHome.EnsureOutsideCode(file, "The settings file");

        if (given is null && !File.Exists(file))
            throw new SettingsException(
                $"No settings at {file}. Run 'keeper setup' to create the Keeper home, " +
                $"or set {KeeperHome.EnvironmentVariable} to the folder that holds settings\\ and data\\.");

        var settings = SettingsLoader.Load(file);
        var data = SettingsLoader.ResolveDataPath(settings, file);
        KeeperHome.EnsureOutsideCode(data, "The data folder");
        HomeSecurity.EnsurePrivate(Path.GetDirectoryName(file)!, "The settings folder");
        if (Directory.Exists(data))
            HomeSecurity.EnsurePrivate(data, "The data folder");
        var paths = new KeeperPaths(file, data);
        Loaded?.Invoke(paths);
        return (settings, paths);
    }
}
