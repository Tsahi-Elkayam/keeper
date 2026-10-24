using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace Keeper.Runners.Host;

/// <summary>
/// One machine reached over SSH. Reads go through SFTP (open, stat, list - never a write call) and the allowlisted
/// commands run as one quoted command line. The credential is sent only to a host the integration's scope names, and
/// only after the host's key matches the fingerprint pinned for it.
/// </summary>
internal sealed class SshHostSession : IHostSession
{
    private const string Environment = "env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ";

    private readonly SshClient _ssh;
    private readonly SftpClient _sftp;

    private SshHostSession(string host, SshClient ssh, SftpClient sftp)
    {
        HostName = host;
        _ssh = ssh;
        _sftp = sftp;
    }

    public string HostName { get; }

    /// <summary>Opens a session to <c>context.Target</c> as the integration says, or throws HostSessionException saying why not.</summary>
    public static IHostSession Open(RunnerContext context)
    {
        var connection = context.Connection;
        var target = context.Target!.Trim();
        if (!SshScope.Allows(target, connection.Endpoint))
            throw new HostSessionException($"{target} is outside this integration's scope ({connection.Endpoint}); no credential was sent");

        var user = connection.Identity ?? throw new HostSessionException($"integration {connection.Instance} needs the account to sign in as (identity)");
        var port = connection.Options["port"] is null ? 22 : SshOptions.Port(connection.Options["port"]) ?? throw new HostSessionException("the port option must be a number from 1 to 65535");
        var pinned = connection.Options["hostKeys"] is JsonObject keys
            ? keys.ToDictionary(k => k.Key, k => k.Value?.ToString() ?? "", StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var acceptAny = SshOptions.Flag(connection.Options["acceptAnyHostKey"]) == true;

        string? refusal = null;
        string? unverified = null;
        SshClient? ssh = null;
        SftpClient? sftp = null;
        try
        {
            ssh = new SshClient(Info(connection, target, port, user, context.Timeout));
            sftp = new SftpClient(Info(connection, target, port, user, context.Timeout));
            foreach (BaseClient client in new BaseClient[] { ssh, sftp })
            {
                client.HostKeyReceived += (_, e) =>
                {
                    var decision = HostKeyPolicy.Decide(target, e.FingerPrintSHA256, pinned, acceptAny);
                    e.CanTrust = decision.Trust;
                    if (!decision.Trust)
                        refusal = decision.Reason;
                    else
                        unverified = decision.Reason;
                };
            }
            ssh.Connect();
            sftp.Connect();
            if (unverified is not null)
                context.Log(unverified);
            return new SshHostSession(target, ssh, sftp);
        }
        catch (Exception ex) when (ex is SshException or SocketException or TimeoutException or IOException)
        {
            sftp?.Dispose();
            ssh?.Dispose();
            throw new HostSessionException(refusal ?? Describe(ex, target, user));
        }
    }

    private static ConnectionInfo Info(IConnection connection, string host, int port, string user, TimeSpan timeout)
    {
        var methods = new List<AuthenticationMethod>();
        switch (connection.AuthKind)
        {
            case "ssh-key":
                var key = connection.Secret("privateKey") ?? throw new HostSessionException($"integration {connection.Instance} has no privateKey secret set");
                // Pasted as one line at the secret prompt, the key's line breaks arrive as the two characters \n.
                if (!key.Contains('\n', StringComparison.Ordinal))
                    key = key.Replace("\\n", "\n", StringComparison.Ordinal);
                try
                {
                    using var stream = new MemoryStream(Encoding.UTF8.GetBytes(key));
                    methods.Add(new PrivateKeyAuthenticationMethod(user, new PrivateKeyFile(stream, connection.Secret("passphrase"))));
                }
                catch (Exception ex) when (ex is SshException or ArgumentException or InvalidOperationException)
                {
                    throw new HostSessionException($"the privateKey secret of integration {connection.Instance} is not a usable private key (or its passphrase is wrong)");
                }
                break;
            case "ssh-password":
                var password = connection.Secret("password") ?? throw new HostSessionException($"integration {connection.Instance} has no password secret set");
                methods.Add(new PasswordAuthenticationMethod(user, password));
                var interactive = new KeyboardInteractiveAuthenticationMethod(user);
                interactive.AuthenticationPrompt += (_, e) =>
                {
                    foreach (var prompt in e.Prompts.Where(p => p.Request.Contains("assword", StringComparison.OrdinalIgnoreCase)))
                        prompt.Response = password;
                };
                methods.Add(interactive);
                break;
            default:
                throw new HostSessionException($"ssh integrations sign in with ssh-key or ssh-password, not {connection.AuthKind}");
        }
        return new ConnectionInfo(host, port, user, [.. methods]) { Timeout = timeout };
    }

    private static string Describe(Exception ex, string host, string user) => ex switch
    {
        SshAuthenticationException => $"{host} refused the sign-in of {user}",
        SocketException s => $"{host} could not be reached ({s.SocketErrorCode})",
        SshOperationTimeoutException or TimeoutException => $"{host} did not answer in time",
        _ => $"{host}: {ex.Message}",
    };

    public string Normalize(string path) => PosixPath.Normalize(path);

    public string ResolveInclude(string fromFile, string pattern) => PosixPath.ResolveInclude(fromFile, pattern);

    public bool FileExists(string path)
    {
        try
        {
            return _sftp.GetAttributes(path).IsRegularFile;
        }
        catch (SftpPathNotFoundException)
        {
            return false;
        }
    }

    public string? ReadProblem(string path)
    {
        var final = path;
        ISftpFile link;
        try
        {
            link = _sftp.Get(path);
        }
        catch (SftpPathNotFoundException)
        {
            return null;
        }
        if (link.IsSymbolicLink)
        {
            final = RealPath(path) ?? "";
            if (final.Length == 0)
                return "its link could not be followed";
        }
        if (HostGuards.IsSecretPath(final))
            return "it points at a file that holds secrets (credentials or keys); host reads never open it";
        try
        {
            var attributes = link.IsSymbolicLink ? _sftp.GetAttributes(final) : link.Attributes;
            if (attributes.Size > HostGuards.MaxFileBytes)
                return $"it is larger than {HostGuards.MaxFileBytes / (1024 * 1024)} MB";
            using var stream = _sftp.OpenRead(final);
            var head = new byte[(int)Math.Min(attributes.Size, 4096)];
            stream.ReadExactly(head);
            return Encoding.ASCII.GetString(head).Contains("PRIVATE KEY-----", StringComparison.Ordinal)
                ? "it holds a private key; host reads never open it"
                : null;
        }
        catch (SftpPermissionDeniedException)
        {
            return "it cannot be read by the account Keeper signs in as";
        }
    }

    private string? RealPath(string path)
    {
        foreach (var program in new[] { "realpath --", "readlink -f" })
        {
            using var command = _ssh.CreateCommand($"{Environment}{program} {RemoteCommand.Quote(path)}");
            var result = command.Execute().Trim();
            if (command.ExitStatus == 0 && result.StartsWith('/'))
                return result;
        }
        return null;
    }

    public string ReadAllText(string path) => _sftp.ReadAllText(path);

    public HostStat Stat(string path)
    {
        ISftpFile link;
        try
        {
            link = _sftp.Get(path);
        }
        catch (SftpPathNotFoundException)
        {
            return new HostStat(false, false, false, 0, default, null);
        }
        var attributes = link.Attributes;
        if (link.IsSymbolicLink)
        {
            try
            {
                attributes = _sftp.GetAttributes(path);
            }
            catch (SftpPathNotFoundException)
            {
                // A link to nothing: report the link itself.
            }
        }
        return new HostStat(true, link.IsSymbolicLink, attributes.IsDirectory, attributes.Size, new DateTimeOffset(attributes.LastWriteTimeUtc, TimeSpan.Zero), (int)Mode(attributes));
    }

    private static UnixFileMode Mode(SftpFileAttributes a)
    {
        var mode = UnixFileMode.None;
        void Set(bool on, UnixFileMode bit) => mode |= on ? bit : UnixFileMode.None;
        Set(a.OwnerCanRead, UnixFileMode.UserRead);
        Set(a.OwnerCanWrite, UnixFileMode.UserWrite);
        Set(a.OwnerCanExecute, UnixFileMode.UserExecute);
        Set(a.GroupCanRead, UnixFileMode.GroupRead);
        Set(a.GroupCanWrite, UnixFileMode.GroupWrite);
        Set(a.GroupCanExecute, UnixFileMode.GroupExecute);
        Set(a.OthersCanRead, UnixFileMode.OtherRead);
        Set(a.OthersCanWrite, UnixFileMode.OtherWrite);
        Set(a.OthersCanExecute, UnixFileMode.OtherExecute);
        return mode;
    }

    public IReadOnlyList<string> Glob(string folder, string pattern)
    {
        var match = new Regex("^" + Regex.Escape(pattern).Replace("\\*", "[^/]*", StringComparison.Ordinal).Replace("\\?", "[^/]", StringComparison.Ordinal) + "$",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        try
        {
            return [.. _sftp.ListDirectory(folder)
                .Where(f => f.Name is not ("." or "..") && (f.IsRegularFile || f.IsSymbolicLink) && match.IsMatch(f.Name))
                .Select(f => folder.TrimEnd('/') + "/" + f.Name)
                .Order(StringComparer.Ordinal)];
        }
        catch (SftpPathNotFoundException)
        {
            return [];
        }
    }

    public JsonObject Facts()
    {
        string One(string flag)
        {
            using var command = _ssh.CreateCommand(RemoteCommand.Line("uname", [flag]));
            return command.Execute().Trim();
        }
        var system = One("-s");
        var row = new JsonObject
        {
            ["os"] = system.Equals("Darwin", StringComparison.OrdinalIgnoreCase) ? "macos" : system.Equals("Linux", StringComparison.OrdinalIgnoreCase) ? "linux" : system.ToLowerInvariant(),
            ["kernel"] = One("-r"),
            ["architecture"] = One("-m").ToLowerInvariant(),
        };
        if (FileExists("/proc/uptime") && double.TryParse(_sftp.ReadAllText("/proc/uptime").Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture, out var uptime))
            row["uptimeSeconds"] = (long)uptime;
        if (FileExists("/etc/os-release"))
            LocalHostSession.FactsFromOsRelease(row, _sftp.ReadAllText("/etc/os-release"));
        return row;
    }

    public async Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var command = _ssh.CreateCommand(RemoteCommand.Line(name, args));
        command.CommandTimeout = timeout;
        try
        {
            await Task.Run(() => command.Execute(), cancellationToken).ConfigureAwait(false);
        }
        catch (SshOperationTimeoutException)
        {
            return new HostCommands.Output(true, -1, [], false, TimedOut: true);
        }
        // 127: the shell did not find the program, which is how a machine without it answers.
        if (command.ExitStatus == 127)
            return new HostCommands.Output(false, 127, [], false, false);

        var lines = new List<string>();
        var bytes = 0;
        var truncated = false;
        foreach (var line in command.Result.Split('\n'))
        {
            bytes += line.Length + 1;
            if (bytes > HostCommands.MaxOutputBytes)
            {
                truncated = true;
                break;
            }
            if (line.Trim().Length > 0)
                lines.Add(line.TrimEnd());
        }
        return new HostCommands.Output(true, command.ExitStatus ?? -1, lines, truncated, false);
    }

    public void Dispose()
    {
        _sftp.Dispose();
        _ssh.Dispose();
    }
}
