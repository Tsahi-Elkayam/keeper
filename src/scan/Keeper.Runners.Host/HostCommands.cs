using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace Keeper.Runners.Host;

/// <summary>
/// The only commands a host read runs: a fixed table of read-only ones, started without a shell, with
/// parameters that must match a pattern, a fixed environment, a time limit and an output limit.
/// A rule names a command and its parameters; it never supplies a command line.
/// </summary>
public static class HostCommands
{
    public const int MaxOutputBytes = 1024 * 1024;

    /// <summary>How many objects one docker inspect may name.</summary>
    public const int MaxInspectIds = 50;

    private static readonly Regex Name = new(@"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Unit = new(@"^[A-Za-z0-9_@][A-Za-z0-9_@.:\-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Domain = new(@"^[A-Za-z0-9_][A-Za-z0-9_.\-/]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Key = new(@"^[A-Za-z0-9_][A-Za-z0-9_. \-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly string[] SearchPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    // Where Docker puts its command on a machine that is not Linux-packaged: Homebrew, a manual install, Docker Desktop.
    private static readonly string[] ExtraLocalPath =
        ["/usr/local/bin", "/opt/homebrew/bin", Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile), ".docker", "bin")];

    // An id, an image id (sha256:...), a volume or network name: never an option and never a path.
    private static readonly Regex DockerId = new(@"^[A-Za-z0-9][A-Za-z0-9_.:@\-]{0,127}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>A command: the program, a check of the parameters (an error text or null), and the arguments it gets.</summary>
    private sealed record Command(string Program, Func<IReadOnlyList<string>, string?> Check, Func<IReadOnlyList<string>, string[]> Build);

    private static string? None(IReadOnlyList<string> a) => a.Count == 0 ? null : "takes no parameters";

    private static Func<IReadOnlyList<string>, string?> One(Regex pattern, string what) =>
        a => a.Count == 1 && pattern.IsMatch(a[0]) ? null : $"takes one {what}";

    private static readonly Dictionary<string, Command> Table = new(StringComparer.Ordinal)
    {
        ["uname"] = new("uname", a => a.Count <= 1 && (a.Count == 0 || a[0] is "-s" or "-r" or "-m" or "-n" or "-a" or "-v") ? null : "takes one of -s -r -m -n -v -a", a => [.. a]),
        ["sysctl"] = new("sysctl", One(Name, "setting name"), a => ["-n", a[0]]),
        ["systemctl"] = new("systemctl",
            a => a.Count == 2 && a[0] is "is-active" or "is-enabled" or "is-failed" && Unit.IsMatch(a[1]) ? null
                : a.Count == 1 && a[0] == "list-unit-files" ? null : "takes is-active|is-enabled|is-failed <unit>, or list-unit-files",
            a => a[0] == "list-unit-files" ? ["list-unit-files", "--no-pager", "--no-legend"] : [a[0], a[1]]),
        ["sw_vers"] = new("sw_vers", None, _ => []),
        ["getenforce"] = new("getenforce", None, _ => []),
        ["id"] = new("id", a => a.Count == 0 || a.Count == 1 && Name.IsMatch(a[0]) ? null : "takes an optional user name", a => [.. a]),
        ["csrutil"] = new("csrutil", None, _ => ["status"]),
        ["spctl"] = new("spctl", None, _ => ["--status"]),
        ["fdesetup"] = new("fdesetup", None, _ => ["status"]),
        ["socketfilterfw"] = new("/usr/libexec/ApplicationFirewall/socketfilterfw", None, _ => ["--getglobalstate"]),
        ["dpkg-query"] = new("dpkg-query", None, _ => ["-W", "-f=${Package}\t${Version}\n"]),
        ["rpm"] = new("rpm", None, _ => ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]),
        ["ss"] = new("ss", None, _ => ["-H", "-lntu"]),
        ["mount"] = new("mount", None, _ => []),
        // Docker: listing and inspecting only. Nothing here starts, stops, runs, copies, pulls or removes anything.
        // CUPS: listing its queues, their state and its sharing settings. cupsctl with no argument only prints.
        ["lpstat-devices"] = new("lpstat", None, _ => ["-v"]),
        ["lpstat-printers"] = new("lpstat", None, _ => ["-p"]),
        ["lpstat-accepting"] = new("lpstat", None, _ => ["-a"]),
        ["cupsctl"] = new("cupsctl", None, _ => []),
        ["docker-ps-ids"] = new("docker", None, _ => ["ps", "--all", "--quiet", "--no-trunc"]),
        ["docker-image-ids"] = new("docker", None, _ => ["images", "--all", "--quiet", "--no-trunc"]),
        ["docker-network-ids"] = new("docker", None, _ => ["network", "ls", "--quiet", "--no-trunc"]),
        ["docker-volume-names"] = new("docker", None, _ => ["volume", "ls", "--quiet"]),
        ["docker-info"] = new("docker", None, _ => ["info", "--format", "{{json .}}"]),
        ["docker-inspect"] = new("docker",
            a => a.Count >= 2 && a.Count <= MaxInspectIds + 1 && a[0] is "container" or "image" or "network" or "volume" && a.Skip(1).All(DockerId.IsMatch)
                ? null : $"takes container|image|network|volume and 1 to {MaxInspectIds} plain ids",
            a => ["inspect", "--type", a[0], "--", .. a.Skip(1)]),
        ["defaults"] = new("defaults",
            a => a.Count == 2 && Domain.IsMatch(a[0]) && Key.IsMatch(a[1]) ? null : "takes a preference domain and a key",
            a => ["read", a[0], a[1]]),
    };

    public static IReadOnlyCollection<string> Names => Table.Keys;

    /// <summary>Why this command and these parameters are not allowed, or null.</summary>
    public static string? Problem(string? name, IReadOnlyList<string> args)
    {
        if (name is null || !Table.TryGetValue(name, out var command))
            return $"command '{name}' is not one Keeper runs; allowed: {string.Join(", ", Table.Keys.Order(StringComparer.Ordinal))}";
        var problem = command.Check(args);
        return problem is null ? null : $"{name} {problem}";
    }

    /// <summary>The program and arguments an allowed command runs with (already checked with <see cref="Problem"/>).</summary>
    public static (string Program, string[] Arguments) Plan(string name, IReadOnlyList<string> args)
    {
        var command = Table[name];
        return (command.Program, command.Build(args));
    }

    /// <summary><paramref name="Error"/> is the first line the command wrote to its error output, if any ("permission denied ...").</summary>
    public sealed record Output(bool Found, int ExitCode, IReadOnlyList<string> Lines, bool Truncated, bool TimedOut, string? Error = null);

    /// <summary>Runs an allowed command (already checked with <see cref="Problem"/>).</summary>
    public static async Task<Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var command = Table[name];
        var program = Resolve(command.Program);
        if (program is null)
            return new Output(false, 0, [], false, false);

        var start = new ProcessStartInfo(program)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        foreach (var argument in command.Build(args))
            start.ArgumentList.Add(argument);
        start.Environment.Clear();
        start.Environment["PATH"] = string.Join(':', SearchPath);
        start.Environment["LC_ALL"] = "C";

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"{name} did not start.");
        process.StandardInput.Close();
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        var errors = process.StandardError.ReadToEndAsync(CancellationToken.None);
        var lines = new List<string>();
        var bytes = 0;
        var truncated = false;
        try
        {
            while (await process.StandardOutput.ReadLineAsync(limit.Token).ConfigureAwait(false) is { } line)
            {
                bytes += line.Length + 1;
                if (bytes > MaxOutputBytes)
                {
                    truncated = true;
                    break;
                }
                if (line.Length > 0)
                    lines.Add(line.TrimEnd());
            }
            await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Kill(process);
            return new Output(true, -1, lines, truncated, TimedOut: true);
        }
        if (truncated)
            Kill(process);
        var errorText = (await errors.ConfigureAwait(false)).Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return new Output(true, truncated ? 0 : process.ExitCode, lines, truncated, false, errorText is null ? null : errorText[..Math.Min(errorText.Length, 200)]);
    }

    private static void Kill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }
    }

    private static string? Resolve(string program)
    {
        if (program.StartsWith('/'))
            return File.Exists(program) ? program : null;
        return SearchPath.Concat(ExtraLocalPath).Select(d => Path.Combine(d, program)).FirstOrDefault(File.Exists);
    }
}
