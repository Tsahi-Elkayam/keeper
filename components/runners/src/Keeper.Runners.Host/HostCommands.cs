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

    private static readonly Regex Name = new(@"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Unit = new(@"^[A-Za-z0-9_@][A-Za-z0-9_@.:\-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Domain = new(@"^[A-Za-z0-9_][A-Za-z0-9_.\-/]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Key = new(@"^[A-Za-z0-9_][A-Za-z0-9_. \-]*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly string[] SearchPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

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

    public sealed record Output(bool Found, int ExitCode, IReadOnlyList<string> Lines, bool Truncated, bool TimedOut);

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
        await errors.ConfigureAwait(false);
        return new Output(true, truncated ? 0 : process.ExitCode, lines, truncated, false);
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
        return SearchPath.Select(d => Path.Combine(d, program)).FirstOrDefault(File.Exists);
    }
}
