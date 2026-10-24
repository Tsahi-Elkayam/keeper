using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Host;

/// <summary>What stat reports about a path.</summary>
public sealed record HostStat(bool Exists, bool IsLink, bool IsDirectory, long Size, DateTimeOffset Modified, int? Mode);

/// <summary>
/// One machine a host read looks at: the one Keeper runs on, or one reached over SSH. Everything a read may do
/// goes through here, so the same rules and guards apply to either, and nothing here changes the machine.
/// </summary>
public interface IHostSession : IDisposable
{
    /// <summary>The name rows carry as "host".</summary>
    string HostName { get; }

    /// <summary>The path as this machine writes it, made absolute (".." and "." resolved).</summary>
    string Normalize(string path);

    /// <summary>The path an include names, relative to the including file's folder.</summary>
    string ResolveInclude(string fromFile, string pattern);

    bool FileExists(string path);

    /// <summary>Why a file may not be read now (a secret behind a link, too large, a private key), or null.</summary>
    string? ReadProblem(string path);

    string ReadAllText(string path);

    HostStat Stat(string path);

    /// <summary>The files in a folder matching a pattern with * or ?, sorted. Empty when the folder is not there.</summary>
    IReadOnlyList<string> Glob(string folder, string pattern);

    /// <summary>facts: os, kernel, architecture, uptimeSeconds, osId, osVersion, osName.</summary>
    JsonObject Facts();

    /// <summary>Runs a command that HostCommands.Problem accepted.</summary>
    Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>The machine Keeper runs on.</summary>
internal sealed class LocalHostSession : IHostSession
{
    public string HostName => Environment.MachineName;

    public string Normalize(string path) => Path.GetFullPath(path);

    public string ResolveInclude(string fromFile, string pattern) =>
        Path.GetFullPath(Path.IsPathRooted(pattern) ? pattern : Path.Combine(Path.GetDirectoryName(fromFile)!, pattern));

    public bool FileExists(string path) => File.Exists(path);

    public string? ReadProblem(string path) => HostGuards.ReadProblem(path);

    public string ReadAllText(string path) => File.ReadAllText(path);

    public HostStat Stat(string path)
    {
        var info = new FileInfo(path);
        var isLink = info.LinkTarget is not null;
        var isDirectory = Directory.Exists(path);
        var exists = info.Exists || isDirectory || isLink;
        if (!exists)
            return new HostStat(false, false, false, 0, default, null);
        int? mode = OperatingSystem.IsWindows() ? null : (int)File.GetUnixFileMode(path);
        return new HostStat(true, isLink, isDirectory, info.Exists ? info.Length : 0, File.GetLastWriteTimeUtc(path), mode);
    }

    public IReadOnlyList<string> Glob(string folder, string pattern) =>
        Directory.Exists(folder) ? [.. Directory.GetFiles(folder, pattern).Order(StringComparer.Ordinal)] : [];

    public JsonObject Facts()
    {
        var row = new JsonObject
        {
            ["os"] = OperatingSystem.IsMacOS() ? "macos" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "other",
            ["kernel"] = Environment.OSVersion.VersionString,
            ["architecture"] = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
            ["uptimeSeconds"] = Environment.TickCount64 / 1000,
        };
        if (File.Exists("/etc/os-release"))
            FactsFromOsRelease(row, File.ReadAllText("/etc/os-release"));
        else
            row["osVersion"] = Environment.OSVersion.Version.ToString();
        return row;
    }

    internal static void FactsFromOsRelease(JsonObject row, string text)
    {
        var release = ConfigParsers.Kv(text, "/etc/os-release").ToDictionary(r => r["name"]!.ToString(), r => r["value"]!.ToString(), StringComparer.Ordinal);
        row["osId"] = release.GetValueOrDefault("id");
        row["osVersion"] = release.GetValueOrDefault("version_id");
        row["osName"] = release.GetValueOrDefault("pretty_name");
    }

    public Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken) =>
        HostCommands.RunAsync(name, args, timeout, cancellationToken);

    public void Dispose()
    {
    }
}
