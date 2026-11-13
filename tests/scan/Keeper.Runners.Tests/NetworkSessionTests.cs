using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Gpo;
using Keeper.Runners.Host;
using Keeper.Runners.Ldap;
using Keeper.Runners.Smb;
using Keeper.Runners.Sql;
using Renci.SshNet.Common;
using Renci.SshNet.Messages.Transport;
using Renci.SshNet.Sftp;

namespace Keeper.Runners.Tests;

/// <summary>Counts the waits a runner asks for and the signals it gives.</summary>
internal sealed class CountingPace : IPace
{
    private int _waits;
    private int _throttled;

    public int Waits => Volatile.Read(ref _waits);

    public int Throttled => Volatile.Read(ref _throttled);

    public List<FailureKind> Signals { get; } = [];

    public Task WaitAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _waits);
        return Task.CompletedTask;
    }

    public void Signal(FailureKind kind)
    {
        if (kind == FailureKind.Throttled)
            Interlocked.Increment(ref _throttled);
        lock (Signals)
            Signals.Add(kind);
    }
}

/// <summary>LDAP result codes and what Active Directory says in a failed bind, as the kinds the scan acts on.</summary>
public sealed class LdapFailureTests
{
    [Theory]
    [InlineData("8009030C: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563", "52e")]
    [InlineData("... AcceptSecurityContext error, data 775, v4563", "locked out")]
    [InlineData("... AcceptSecurityContext error, data 532, v4563", "expired")]
    [InlineData("... AcceptSecurityContext error, data 773, v4563", "changed")]
    [InlineData("... AcceptSecurityContext error, data 533, v4563", "disabled")]
    [InlineData("... AcceptSecurityContext error, data 701, v4563", "expired")]
    [InlineData("... AcceptSecurityContext error, data 530, v4563", "time of day")]
    [InlineData("... AcceptSecurityContext error, data 531, v4563", "workstation")]
    public void A_failed_bind_is_always_a_refused_credential_and_says_what_the_server_meant(string serverMessage, string meaning)
    {
        Assert.Equal(FailureKind.Refused, LdapRunner.Classify(49, serverMessage));
        Assert.Contains(meaning, LdapRunner.Describe(49, serverMessage, "x"), StringComparison.Ordinal);
    }

    [Fact]
    public void A_locked_account_reason_names_the_code()
    {
        Assert.Contains("the account is locked out (775)", LdapRunner.Describe(49, "x, data 775, v1", "x"), StringComparison.Ordinal);
        Assert.Contains("invalid credentials", LdapRunner.Describe(49, null, "x"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(49, FailureKind.Refused)]
    [InlineData(50, FailureKind.Denied)]
    [InlineData(51, FailureKind.Throttled)]
    [InlineData(52, FailureKind.Throttled)]
    [InlineData(81, FailureKind.Unreachable)]
    [InlineData(91, FailureKind.Unreachable)]
    [InlineData(85, FailureKind.Timeout)]
    [InlineData(32, FailureKind.Error)]
    [InlineData(0, FailureKind.Error)]
    public void Result_codes_have_a_kind(int code, FailureKind kind) => Assert.Equal(kind, LdapRunner.Classify(code, null));

    [Fact]
    public void The_ldap_runner_keeps_one_connection_per_integration()
    {
        var runner = new LdapRunner();

        Assert.IsAssignableFrom<ISessionRunner>(runner);
        Assert.Equal("ldap", runner.SessionFamily);
        Assert.False(runner.PerTarget);
    }
}

public sealed class SqlFailureTests
{
    [Theory]
    [InlineData(18456, FailureKind.Refused)]
    [InlineData(18486, FailureKind.Refused)]
    [InlineData(18487, FailureKind.Refused)]
    [InlineData(18488, FailureKind.Refused)]
    [InlineData(18470, FailureKind.Refused)]
    [InlineData(916, FailureKind.Denied)]
    [InlineData(4060, FailureKind.Denied)]
    [InlineData(229, FailureKind.Denied)]
    [InlineData(297, FailureKind.Denied)]
    [InlineData(-2, FailureKind.Timeout)]
    [InlineData(258, FailureKind.Timeout)]
    [InlineData(10928, FailureKind.Throttled)]
    [InlineData(10929, FailureKind.Throttled)]
    [InlineData(40501, FailureKind.Throttled)]
    [InlineData(40613, FailureKind.Throttled)]
    [InlineData(53, FailureKind.Unreachable)]
    [InlineData(40, FailureKind.Unreachable)]
    [InlineData(-1, FailureKind.Unreachable)]
    [InlineData(2, FailureKind.Unreachable)]
    [InlineData(11001, FailureKind.Unreachable)]
    [InlineData(102, FailureKind.Error)]
    public void Error_numbers_have_a_kind(int number, FailureKind kind) => Assert.Equal(kind, SqlRunner.Classify(number));

    [Fact]
    public void The_sql_runner_keeps_one_connection_per_instance()
    {
        var runner = new SqlRunner();

        Assert.IsAssignableFrom<ISessionRunner>(runner);
        Assert.Equal("sql", runner.SessionFamily);
        Assert.True(runner.PerTarget);
    }

    [Fact]
    public async Task A_query_the_guard_refuses_is_failed_before_any_sign_in()
    {
        var result = await new SqlRunner().RunAsync(Context.Query("sql", "k", ("text", "DROP TABLE x")), Context.For(new FakeConnection("sql01"), "sql01"), CancellationToken.None);

        Assert.Equal("failed", result.State);
    }
}

public sealed class SshFailureTests
{
    [Fact]
    public void A_refused_sign_in_is_the_credential_and_a_dropped_connection_is_the_host_pushing_back()
    {
        Assert.Equal(FailureKind.Refused, SshFailures.Classify(new SshAuthenticationException("Permission denied (password).")));
        Assert.Equal(FailureKind.Throttled, SshFailures.Classify(new SshConnectionException("too many", DisconnectReason.TooManyConnections)));
        Assert.Equal(FailureKind.Throttled, SshFailures.Classify(new SshConnectionException("lost", DisconnectReason.ConnectionLost)));
        Assert.Equal(FailureKind.Throttled, SshFailures.Classify(new SshConnectionException("An established connection was aborted by the server.")));
        Assert.Equal(FailureKind.Timeout, SshFailures.Classify(new SshOperationTimeoutException("no answer")));
        Assert.Equal(FailureKind.Denied, SshFailures.Classify(new SftpPermissionDeniedException("denied")));
    }

    [Fact]
    public void A_refused_connect_is_unreachable_and_a_reset_one_is_throttled()
    {
        Assert.Equal(FailureKind.Unreachable, SshFailures.Classify(new SocketException((int)SocketError.ConnectionRefused)));
        Assert.Equal(FailureKind.Throttled, SshFailures.Classify(new SocketException((int)SocketError.ConnectionReset)));
        Assert.Equal(FailureKind.Unreachable, SshFailures.Classify(new SshConnectionException("x", new SocketException((int)SocketError.ConnectionRefused))));
    }
}

public sealed class HostSessionTests
{
    private static QuerySpec Q(params (string Name, JsonNode? Value)[] fields) => Context.Query("host", "path", fields);

    [Fact]
    public void Only_an_ssh_integration_is_remote_and_paced()
    {
        var runner = new HostRunner();

        Assert.True(runner.IsRemote(new SshFakeConnection()));
        Assert.False(runner.IsRemote(new FakeConnection("local")));
        Assert.Equal("ssh", runner.SessionFamily);
    }

    [Fact]
    public async Task One_session_serves_every_query_of_a_host_and_is_opened_once()
    {
        var opened = 0;
        var session = new FakeSession("web01", new() { ["/etc/hostname"] = "web01\n" });
        var runner = new HostRunner(_ => { opened++; return session; });
        var context = Context.For(new SshFakeConnection(), "web01");

        await using var open = await runner.OpenAsync(context, CancellationToken.None);
        var one = await runner.RunAsync(open, Q(("read", "facts")), context, CancellationToken.None);
        var two = await runner.RunAsync(open, Q(("read", "stat"), ("path", "/etc/hostname")), context, CancellationToken.None);

        Assert.Equal(("ok", "ok", 1), (one.State, two.State, opened));
    }

    [Fact]
    public async Task A_refused_sign_in_fails_the_open_with_its_kind_and_a_failed_stateless_read_carries_it()
    {
        var runner = new HostRunner(_ => throw new HostSessionException("web01 refused the sign-in of keeper-reader", FailureKind.Refused));
        var context = Context.For(new SshFakeConnection(), "web01");

        var thrown = await Assert.ThrowsAsync<RunnerFailureException>(() => runner.OpenAsync(context, CancellationToken.None));
        var result = await runner.RunAsync(Q(("read", "facts")), context, CancellationToken.None);

        Assert.Equal(FailureKind.Refused, thrown.Kind);
        Assert.Equal((("failed", FailureKind.Refused)), (result.State, result.Failure));
    }

    [Fact]
    public async Task An_ssh_error_in_the_middle_of_a_read_is_a_classified_failed_read_not_a_crash()
    {
        var runner = new HostRunner(_ => new ThrowingSession(new SshConnectionException("reset", DisconnectReason.ConnectionLost)));

        var result = await runner.RunAsync(Q(("read", "stat"), ("path", "/etc/hostname")), Context.For(new SshFakeConnection(), "web01"), CancellationToken.None);

        Assert.Equal(("failed", FailureKind.Throttled), (result.State, result.Failure));
    }

    [Fact]
    public async Task A_folder_of_configs_waits_before_each_file()
    {
        var files = Enumerable.Range(1, 4).ToDictionary(i => $"/srv/configs/sw{i}.cfg", i => $"hostname sw{i}\n");
        var runner = new HostRunner(_ => new FakeSession("backup01", files));
        var pace = new CountingPace();
        var context = Context.For(new SshFakeConnection(), "backup01") with { Pace = pace };

        var result = await runner.RunAsync(Q(("read", "configs"), ("folder", "/srv/configs"), ("pattern", "*.cfg"), ("format", "files")), context, CancellationToken.None);

        Assert.Equal(("ok", 4), (result.State, pace.Waits));
    }

    [Fact]
    public async Task An_include_chain_waits_before_each_further_file()
    {
        var files = new Dictionary<string, string>
        {
            ["/etc/ssh/sshd_config"] = "Include sshd_config.d/*.conf\nPermitRootLogin yes\n",
            ["/etc/ssh/sshd_config.d/10.conf"] = "PermitRootLogin no\n",
        };
        var runner = new HostRunner(_ => new FakeSession("web01", files));
        var pace = new CountingPace();
        var context = Context.For(new SshFakeConnection(), "web01") with { Pace = pace };

        await runner.RunAsync(Q(("read", "file"), ("path", "/etc/ssh/sshd_config"), ("format", "kv")), context, CancellationToken.None);

        Assert.True(pace.Waits >= 2, $"waited {pace.Waits} times");
    }

    private sealed class ThrowingSession(Exception error) : IHostSession
    {
        public string HostName => "web01";
        public string Normalize(string path) => path;
        public string ResolveInclude(string fromFile, string pattern) => pattern;
        public bool FileExists(string path) => throw error;
        public string? ReadProblem(string path) => throw error;
        public string ReadAllText(string path) => throw error;
        public HostStat Stat(string path) => throw error;
        public IReadOnlyList<string> Glob(string folder, string pattern) => throw error;
        public JsonObject Facts() => throw error;
        public Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken) => throw error;
        public void Dispose()
        {
        }
    }
}

public sealed class SmbFailureTests
{
    [Theory]
    [InlineData(5, FailureKind.Denied)]
    [InlineData(53, FailureKind.Unreachable)]
    [InlineData(1722, FailureKind.Unreachable)]
    [InlineData(1326, FailureKind.Refused)]
    [InlineData(1909, FailureKind.Refused)]
    [InlineData(2310, FailureKind.Error)]
    public void Share_api_status_codes_have_a_kind(int status, FailureKind kind) => Assert.Equal(kind, SmbRunner.Kind(status));
}

/// <summary>The GPO runner reads SYSVOL's listing and each GPT.INI once for the five parts of a scan.</summary>
public sealed class GpoSessionTests : IDisposable
{
    private const string Gpo1 = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
    private const string Gpo2 = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";
    private readonly string _root = Directory.CreateTempSubdirectory("keeper-sysvol-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private void Gpt(string gpo, int version)
    {
        Directory.CreateDirectory(Path.Combine(_root, gpo));
        File.WriteAllText(Path.Combine(_root, gpo, "GPT.INI"), $"[General]\r\nVersion={version}\r\n", Encoding.UTF8);
    }

    [Fact]
    public async Task The_listing_and_the_gpt_files_are_read_once_per_session()
    {
        Gpt(Gpo1, 65537);
        Gpt(Gpo2, 3);
        var runner = new GpoRunner(_ => _root);
        var context = Context.For(new FakeConnection("example.org"));
        var query = Context.Query("gpo", "k", ("part", "gpt"));
        await using var session = await runner.OpenAsync(context, CancellationToken.None);

        var first = await runner.RunAsync(session, query, context, CancellationToken.None);
        // The files go away under the scan: a second part of the same session is answered from what was read.
        Directory.Delete(Path.Combine(_root, Gpo1), recursive: true);
        File.Delete(Path.Combine(_root, Gpo2, "GPT.INI"));
        var second = await runner.RunAsync(session, query, context, CancellationToken.None);
        var fresh = await runner.RunAsync(query, context, CancellationToken.None);

        Assert.Equal(("ok", 2, "ok", 2), (first.State, first.Rows.Count, second.State, second.Rows.Count));
        Assert.Equal("failed", fresh.State);
    }

    [Fact]
    public async Task Each_file_open_of_a_part_waits_its_turn()
    {
        Gpt(Gpo1, 1);
        Gpt(Gpo2, 2);
        var pace = new CountingPace();
        var context = Context.For(new FakeConnection("example.org")) with { Pace = pace };

        var result = await new GpoRunner(_ => _root).RunAsync(Context.Query("gpo", "k", ("part", "gpt")), context, CancellationToken.None);

        Assert.Equal(("ok", 2), (result.State, pace.Waits));
    }

    [Fact]
    public void The_gpo_runner_keeps_one_session_per_integration()
    {
        var runner = new GpoRunner();

        Assert.Equal("gpo", runner.SessionFamily);
        Assert.IsAssignableFrom<ISessionRunner>(runner);
    }
}
