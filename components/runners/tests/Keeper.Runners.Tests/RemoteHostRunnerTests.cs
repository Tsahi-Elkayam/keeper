using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

internal sealed class SshFakeConnection : IConnection
{
    public string Instance => "fleet";
    public string Type => "ssh";
    public string Endpoint => "192.0.2.0/24";
    public string AuthKind => "ssh-key";
    public string? Identity => "keeper-reader";
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>A machine in memory: POSIX paths, canned command output, nothing on the network.</summary>
internal sealed class FakeSession(string host, Dictionary<string, string> files, HostCommands.Output? command = null,
    Func<string, IReadOnlyList<string>, HostCommands.Output>? script = null) : IHostSession
{
    public List<string> Commands { get; } = [];

    public string HostName => host;

    public string Normalize(string path) => PosixPath.Normalize(path);

    public string ResolveInclude(string fromFile, string pattern) => PosixPath.ResolveInclude(fromFile, pattern);

    public bool FileExists(string path) => files.ContainsKey(path);

    public string? ReadProblem(string path) => HostGuards.IsSecretPath(path) ? "it holds secrets" : null;

    public string ReadAllText(string path) => files[path];

    public HostStat Stat(string path) => files.ContainsKey(path)
        ? new HostStat(true, false, false, files[path].Length, DateTimeOffset.UnixEpoch, Convert.ToInt32("640", 8))
        : new HostStat(false, false, false, 0, default, null);

    public IReadOnlyList<string> Glob(string folder, string pattern)
    {
        var match = new Regex("^" + Regex.Escape(folder.TrimEnd('/')) + "/" + Regex.Escape(pattern).Replace("\\*", "[^/]*") + "$");
        return [.. files.Keys.Where(k => match.IsMatch(k)).Order(StringComparer.Ordinal)];
    }

    public JsonObject Facts() => new() { ["os"] = "linux", ["kernel"] = "6.8.0", ["architecture"] = "x86_64" };

    public Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Commands.Add($"{name} {string.Join(' ', args)}".TrimEnd());
        return Task.FromResult(script?.Invoke(name, args) ?? command ?? new HostCommands.Output(true, 0, ["Linux"], false, false));
    }

    public void Dispose()
    {
    }
}

public sealed class RemoteHostRunnerTests
{
    private static QuerySpec Q(params (string Name, JsonNode? Value)[] fields) => Context.Query("host", "path", fields);

    private static Task<RunnerResult> Run(HostRunner runner, QuerySpec query, string? target) =>
        runner.RunAsync(query, Context.For(new SshFakeConnection(), target), CancellationToken.None);

    [Fact]
    public void An_ssh_integration_reads_each_of_its_hosts_and_the_local_one_is_a_single_read()
    {
        var runner = new HostRunner();

        Assert.True(runner.IsPerTarget(new SshFakeConnection()));
        Assert.False(runner.IsPerTarget(new FakeConnection("local")));
    }

    [Fact]
    public async Task A_remote_read_names_the_host_it_read_and_follows_includes_as_posix_paths()
    {
        var session = new FakeSession("web01.example.org", new()
        {
            ["/etc/ssh/sshd_config"] = "Include sshd_config.d/*.conf\nPermitRootLogin yes\n",
            ["/etc/ssh/sshd_config.d/10-hardening.conf"] = "PermitRootLogin no\n",
        });
        var runner = new HostRunner(_ => session);

        var result = await Run(runner, Q(("read", "file"), ("path", "/etc/ssh/sshd_config"), ("format", "kv")), "web01.example.org");

        Assert.Equal("ok", result.State);
        Assert.All(result.Rows, r => Assert.Equal("web01.example.org", r["host"]!.ToString()));
        var root = result.Rows.Where(r => r["name"]!.ToString() == "permitrootlogin").ToList();
        Assert.Equal(["no", "yes"], root.Select(r => r["value"]!.ToString()));
        Assert.Equal([1, 2], root.Select(r => (int)r["occurrence"]!));
        Assert.EndsWith("10-hardening.conf", root[0]["file"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_remote_read_without_a_target_host_is_a_failed_read_that_says_what_is_missing()
    {
        var result = await Run(new HostRunner(_ => new FakeSession("x", [])), Q(("read", "facts")), null);

        Assert.Equal("failed", result.State);
        Assert.Contains("targets", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_that_cannot_be_reached_or_trusted_is_a_failed_read_not_a_crash()
    {
        var runner = new HostRunner(_ => throw new HostSessionException("the host key of web01 is not pinned, so no credential was sent"));

        var result = await Run(runner, Q(("read", "facts")), "web01");

        Assert.Equal("failed", result.State);
        Assert.Contains("not pinned", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_secret_guards_apply_on_a_remote_machine_too()
    {
        var session = new FakeSession("web01", new() { ["/home/app/.ssh/id_rsa"] = "-----BEGIN OPENSSH PRIVATE KEY-----" });
        var runner = new HostRunner(_ => session);

        // The rule loader refuses this path; and even a session asked directly will not give it to a read.
        Assert.NotEmpty(runner.Validate(Q(("read", "file"), ("path", "/home/app/.ssh/id_rsa"), ("format", "lines"))));
        var result = await Run(runner, Q(("read", "file"), ("path", "/home/app/.ssh/id_rsa"), ("format", "lines")), "web01");

        Assert.Equal("failed", result.State);
        Assert.DoesNotContain("PRIVATE", result.Reason ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_remote_command_runs_through_the_session_and_its_output_becomes_rows_for_that_host()
    {
        var session = new FakeSession("web01", [], new HostCommands.Output(true, 0, ["Linux"], false, false));
        var runner = new HostRunner(_ => session);

        var result = await Run(runner, Q(("read", "command"), ("name", "uname"), ("args", new JsonArray("-s"))), "web01");

        var row = Assert.Single(result.Rows);
        Assert.Equal(("web01", "Linux"), (row["host"]!.ToString(), row["line"]!.ToString()));
        Assert.Equal(["uname -s"], session.Commands);
    }

    [Fact]
    public async Task A_missing_program_on_the_host_is_a_failed_read_unless_the_rule_says_it_may_be_absent()
    {
        var absent = new HostCommands.Output(false, 127, [], false, false);
        var runner = new HostRunner(_ => new FakeSession("web01", [], absent));
        var query = Q(("read", "command"), ("name", "getenforce"));
        var optional = Q(("read", "command"), ("name", "getenforce"), ("optional", true));

        Assert.Equal("failed", (await Run(runner, query, "web01")).State);
        var ok = await Run(runner, optional, "web01");
        Assert.Equal("ok", ok.State);
        Assert.Empty(ok.Rows);
    }

    [Fact]
    public async Task Facts_of_a_remote_host_carry_the_host_name()
    {
        var runner = new HostRunner(_ => new FakeSession("web01", []));

        var row = Assert.Single((await Run(runner, Q(("read", "facts")), "web01")).Rows);

        Assert.Equal(("web01", "linux"), (row["host"]!.ToString(), row["os"]!.ToString()));
    }

    [Fact]
    public async Task Stat_of_a_remote_file_reports_its_mode_in_octal()
    {
        var runner = new HostRunner(_ => new FakeSession("web01", new() { ["/etc/ssh/sshd_config"] = "x" }));

        var row = Assert.Single((await Run(runner, Q(("read", "stat"), ("path", "/etc/ssh/sshd_config")), "web01")).Rows);

        Assert.Equal("640", row["mode"]!.ToString());
        Assert.False((bool)row["worldWritable"]!);
    }
}
