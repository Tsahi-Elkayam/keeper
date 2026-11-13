namespace Keeper.Common;

/// <summary>Keeps a path inside a folder: no "..", no absolute paths, no symbolic-link escapes.</summary>
public static class PathGuard
{
    public static bool IsUnder(string path, string folder)
    {
        var comparison = OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar;
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)) + Path.DirectorySeparatorChar;
        return full.StartsWith(root, comparison);
    }

    /// <summary>Resolves <paramref name="relative"/> under <paramref name="folder"/>, or throws.</summary>
    public static string Resolve(string folder, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative))
            throw new UnauthorizedAccessException($"'{relative}' must be a path relative to {folder}.");

        // Paths come from rules and settings written for Windows: a backslash separates folders on every OS here,
        // so "..\x" cannot slip through where the OS itself treats a backslash as an ordinary character.
        var normalised = relative.Replace('\\', Path.DirectorySeparatorChar);
        if (Path.IsPathRooted(normalised))
            throw new UnauthorizedAccessException($"'{relative}' must be a path relative to {folder}.");

        var full = Path.GetFullPath(Path.Combine(folder, normalised));
        if (!IsUnder(full, folder))
            throw new UnauthorizedAccessException($"'{relative}' leaves {folder}.");

        // A link inside the folder could still point outside it.
        var info = new FileInfo(full);
        if (info.Exists && info.LinkTarget is not null)
            throw new UnauthorizedAccessException($"'{relative}' is a link; links are not followed.");
        return full;
    }
}
