namespace Keeper.Home;

/// <summary>
/// The tenant's own folder: settings\ (settings.json, denylist.txt, queries\) and data\ (the store,
/// spool, runs, backups). It lives outside the source tree and outside the folder the binaries run
/// from, so a commit, a clean rebuild or a copied build carries none of it.
/// </summary>
public static class KeeperHome
{
    public const string EnvironmentVariable = "KEEPER_HOME";

    /// <summary>
    /// KEEPER_HOME if set - one folder per tenant - else the per-user application data folder:
    /// %LOCALAPPDATA%\Keeper on Windows, ~/Library/Application Support/Keeper on macOS.
    /// </summary>
    public static string Resolve()
    {
        var fromEnvironment = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
            return Path.GetFullPath(fromEnvironment);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Keeper");
    }

    /// <summary>Throws when a tenant path sits where it could be committed or shipped with the binaries.</summary>
    public static void EnsureOutsideCode(string path, string what)
    {
        var full = Path.GetFullPath(path);

        if (IsUnder(full, AppContext.BaseDirectory))
            throw new SettingsException(
                $"{what} is inside the folder the binaries run from ({AppContext.BaseDirectory}): {full}. " +
                $"Tenant files belong in the Keeper home ({Resolve()}); set {EnvironmentVariable} to choose another.");

        var tree = SourceTreeAbove(full);
        if (tree is not null)
            throw new SettingsException(
                $"{what} is inside a source tree ({tree}): {full}. " +
                $"Tenant files belong in the Keeper home ({Resolve()}); set {EnvironmentVariable} to choose another.");
    }

    /// <summary>The nearest folder at or above <paramref name="path"/> that holds a git repo or the Keeper solution.</summary>
    public static string? SourceTreeAbove(string path)
    {
        for (var dir = new DirectoryInfo(Path.GetFullPath(path)); dir is not null; dir = dir.Parent)
        {
            // .git is a folder in a clone and a file in a worktree.
            var git = Path.Combine(dir.FullName, ".git");
            if (Directory.Exists(git) || File.Exists(git) || File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        }
        return null;
    }

    private static bool IsUnder(string path, string folder)
    {
        // Windows and macOS file systems are case-insensitive by default; Linux is not.
        var comparison = OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar;
        return (Path.TrimEndingDirectorySeparator(path) + Path.DirectorySeparatorChar).StartsWith(root, comparison);
    }
}
