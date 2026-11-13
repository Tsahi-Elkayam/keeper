using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Messages.Transport;
using Renci.SshNet.Sftp;

namespace Keeper.Runners.Host;

/// <summary>
/// One machine reached over SSH. Reads go through SFTP (open, stat, list - never a write call) and the allowlisted
/// commands run as one quoted command line. The credential is sent only to a host the integration's scope names, and
/// only after the host's key matches the fingerprint pinned for it.
/// A scan keeps one session per host. The SSH connection (commands) is made when the session opens; the SFTP connection
/// (files) only when a read first needs a file - a host read that only runs commands signs in once, not twice.
/// </summary>
internal sealed class SshHostSession : IHostSession
{
    private const string Environment = "env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ";

    private readonly SshClient _ssh;
    private readonly Func<SftpClient> _openSftp;
    private readonly Lock _sftpLock = new();
    private SftpClient? _sftpClient;
    private Exception? _sftpFailure;
    private TimeSpan? _operationTimeout;

    private SshHostSession(string host, SshClient ssh, Func<SftpClient> openSftp)
    {
        HostName = host;
        _ssh = ssh;
        _openSftp = openSftp;
    }

    /// <summary>The SFTP client, connected on first use.</summary>
    private SftpClient Sftp
    {
        get
        {
            lock (_sftpLock)
            {
                // A host without SFTP (switched off on hardened hosts and appliances) is not signed in to again for every
                // file read: the first failure is the answer for the rest of the session.
                if (_sftpFailure is not null)
                    throw _sftpFailure;
                if (_sftpClient is null)
                {
                    try
                    {
                        _sftpClient = _openSftp();
                    }
                    catch (Exception ex)
                    {
                        _sftpFailure = ex;
                        throw;
                    }
                    if (_operationTimeout is { } timeout)
                        _sftpClient.OperationTimeout = timeout;
                }
                return _sftpClient;
            }
        }
    }

    /// <summary>Each file operation of the current query is given this long (the session itself was opened with one timeout).</summary>
    public void SetTimeout(TimeSpan timeout)
    {
        lock (_sftpLock)
        {
            _operationTimeout = timeout;
            if (_sftpClient is not null)
                _sftpClient.OperationTimeout = timeout;
        }
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
        try
        {
            ssh = new SshClient(Info(connection, target, port, user, context.Timeout));
            Trust(ssh);
            ssh.Connect();
            if (unverified is not null)
                context.Log(unverified);
            return new SshHostSession(target, ssh, () =>
            {
                // A second connection, signed in the same way as the first: it only happens after the first was accepted.
                SftpClient? sftp = null;
                try
                {
                    sftp = new SftpClient(Info(connection, target, port, user, context.Timeout));
                    Trust(sftp);
                    sftp.Connect();
                    return sftp;
                }
                catch (Exception ex) when (ex is SshException or SocketException or TimeoutException or IOException)
                {
                    sftp?.Dispose();
                    throw new HostSessionException(refusal ?? Describe(ex, target, user), SshFailures.Classify(ex), ex);
                }
            });
        }
        catch (Exception ex) when (ex is SshException or SocketException or TimeoutException or IOException)
        {
            ssh?.Dispose();
            // A host key that does not match is about this host, not about the credential: nothing was sent.
            throw refusal is not null
                ? new HostSessionException(refusal, FailureKind.Error, ex)
                : new HostSessionException(Describe(ex, target, user), SshFailures.Classify(ex), ex);
        }

        void Trust(BaseClient client) => client.HostKeyReceived += (_, e) =>
        {
            var decision = HostKeyPolicy.Decide(target, e.FingerPrintSHA256, pinned, acceptAny);
            e.CanTrust = decision.Trust;
            if (!decision.Trust)
                refusal = decision.Reason;
            else
                unverified = decision.Reason;
        };
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
                // Some servers take the password only as a keyboard-interactive answer, so both are offered - but a server that
                // turned the password away is not asked again the second way: that would be a second failed logon for one connect.
                var attempt = new PasswordAttempt();
                methods.Add(new PasswordOnce(user, password, attempt));
                var interactive = new InteractiveUnlessRefused(user, attempt);
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
        SshConnectionException { DisconnectReason: DisconnectReason.TooManyConnections } => $"{host} has too many connections open or is dropping new ones",
        SshConnectionException => $"{host} closed the connection ({ex.Message})",
        _ => $"{host}: {ex.Message}",
    };

    /// <summary>Whether the password method was tried and turned away on this connect.</summary>
    private sealed class PasswordAttempt
    {
        public volatile bool Failed;
    }

    private sealed class PasswordOnce(string user, string password, PasswordAttempt attempt) : PasswordAuthenticationMethod(user, password)
    {
        public override AuthenticationResult Authenticate(Session session)
        {
            var result = base.Authenticate(session);
            if (result == AuthenticationResult.Failure)
                attempt.Failed = true;
            return result;
        }
    }

    private sealed class InteractiveUnlessRefused(string user, PasswordAttempt attempt) : KeyboardInteractiveAuthenticationMethod(user)
    {
        public override AuthenticationResult Authenticate(Session session) =>
            attempt.Failed ? AuthenticationResult.Failure : base.Authenticate(session);
    }

    public string Normalize(string path) => PosixPath.Normalize(path);

    public string ResolveInclude(string fromFile, string pattern) => PosixPath.ResolveInclude(fromFile, pattern);

    public bool FileExists(string path)
    {
        try
        {
            return Sftp.GetAttributes(path).IsRegularFile;
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
            link = Sftp.Get(path);
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
            var attributes = link.IsSymbolicLink ? Sftp.GetAttributes(final) : link.Attributes;
            if (attributes.Size > HostGuards.MaxFileBytes)
                return $"it is larger than {HostGuards.MaxFileBytes / (1024 * 1024)} MB";
            using var stream = Sftp.OpenRead(final);
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

    public string ReadAllText(string path) => Sftp.ReadAllText(path);

    public HostStat Stat(string path)
    {
        ISftpFile link;
        try
        {
            link = Sftp.Get(path);
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
                attributes = Sftp.GetAttributes(path);
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
            return [.. Sftp.ListDirectory(folder)
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
        if (FileExists("/proc/uptime") && double.TryParse(Sftp.ReadAllText("/proc/uptime").Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture, out var uptime))
            row["uptimeSeconds"] = (long)uptime;
        if (FileExists("/etc/os-release"))
            LocalHostSession.FactsFromOsRelease(row, Sftp.ReadAllText("/etc/os-release"));
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
        var error = command.Error.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return new HostCommands.Output(true, command.ExitStatus ?? -1, lines, truncated, false, error is null ? null : error[..Math.Min(error.Length, 200)]);
    }

    public void Dispose()
    {
        lock (_sftpLock)
            _sftpClient?.Dispose();
        _ssh.Dispose();
    }
}

/// <summary>The kind of an SSH failure, so the scan can tell a refused credential from a busy or absent host.</summary>
public static class SshFailures
{
    public static FailureKind Classify(Exception? exception)
    {
        for (var ex = exception; ex is not null; ex = ex.InnerException)
        {
            switch (ex)
            {
                case SshAuthenticationException:
                    return FailureKind.Refused;
                case SshOperationTimeoutException:
                    return FailureKind.Timeout;
                case SftpPermissionDeniedException:
                    return FailureKind.Denied;
                case SshConnectionException connection:
                    return connection.DisconnectReason switch
                    {
                        // MaxStartups drops, resets and servers out of sessions: the host asks to be spared.
                        DisconnectReason.TooManyConnections or DisconnectReason.ConnectionLost or DisconnectReason.ByApplication
                            or DisconnectReason.ServiceNotAvailable => FailureKind.Throttled,
                        DisconnectReason.NoMoreAuthenticationMethodsAvailable or DisconnectReason.IllegalUserName => FailureKind.Refused,
                        // Nothing about the account: no credential was sent (a host key that does not match) or the host turns this machine away.
                        DisconnectReason.HostNotAllowedToConnect or DisconnectReason.HostKeyNotVerifiable => FailureKind.Error,
                        // A reset or a closed socket without a reason code: what the socket error says, else the host is shedding load.
                        _ => connection.InnerException is { } inner && Failures.Classify(inner) != FailureKind.Error
                            ? Failures.Classify(inner)
                            : FailureKind.Throttled,
                    };
            }
        }
        return Failures.Classify(exception);
    }
}
