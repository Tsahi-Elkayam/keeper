using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Keeper.Common;

/// <summary>
/// Runs another keeper binary that sits beside this one. Only that folder is looked in - never PATH or
/// the current directory - so a planted keeper-*.exe elsewhere cannot be picked up.
/// </summary>
public static partial class Siblings
{
    [GeneratedRegex("^keeper-[a-z][a-z0-9-]{0,39}$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    public static string Folder => AppContext.BaseDirectory;

    public static string PathOf(string name)
    {
        if (!NamePattern().IsMatch(name))
            throw new ArgumentException($"'{name}' is not a keeper binary name.");
        return Path.Combine(Folder, OperatingSystem.IsWindows() ? name + ".exe" : name);
    }

    public static bool Exists(string name) => NamePattern().IsMatch(name) && File.Exists(PathOf(name));

    /// <summary>The keeper-* binaries in this folder, by name.</summary>
    public static IReadOnlyList<string> All()
    {
        var pattern = OperatingSystem.IsWindows() ? "keeper-*.exe" : "keeper-*";
        return Directory.GetFiles(Folder, pattern)
            .Select(f => Path.GetFileNameWithoutExtension(f)!)
            .Where(n => NamePattern().IsMatch(n))
            .Order(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Runs the binary on this console and returns its exit code.</summary>
    public static int Run(string name, IEnumerable<string> args)
    {
        var file = PathOf(name);
        if (!File.Exists(file))
            throw new FileNotFoundException($"{name} is not beside {Path.GetFileName(Environment.ProcessPath)} in {Folder}.");

        var start = new ProcessStartInfo(file) { UseShellExecute = false, WorkingDirectory = Environment.CurrentDirectory };
        foreach (var arg in args)
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException($"{name} did not start.");
        process.WaitForExit();
        return process.ExitCode;
    }
}
