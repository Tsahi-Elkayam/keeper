using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class HostRunnerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-host-").FullName;
    private readonly HostRunner _runner = new();

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Write(string relative, string text)
    {
        var path = Path.Combine(_dir, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    private static QuerySpec Q(params (string Name, JsonNode? Value)[] fields) => Context.Query("host", "path", fields);

    private Task<RunnerResult> Run(QuerySpec query) =>
        _runner.RunAsync(query, Context.For(new FakeConnection("local")), CancellationToken.None);

    [Fact]
    public void The_host_runner_reads_the_local_machine_and_is_not_per_target()
    {
        Assert.Equal("host", _runner.Protocol);
        Assert.False(_runner.PerTarget);
    }

    [Fact]
    public async Task A_config_file_is_read_as_rows_that_name_their_host_and_file()
    {
        var path = Write("sshd_config", "PermitRootLogin yes\nPasswordAuthentication no\n");

        var result = await Run(Q(("read", "file"), ("path", path), ("format", "kv")));

        Assert.Equal("ok", result.State);
        Assert.Equal(2, result.Rows.Count);
        Assert.Equal("yes", result.Rows[0]["value"]!.ToString());
        Assert.Equal(path, result.Rows[0]["file"]!.ToString());
        Assert.Equal(Environment.MachineName, result.Rows[0]["host"]!.ToString());
    }

    [Fact]
    public async Task A_secret_looking_setting_is_masked_in_the_rows()
    {
        var path = Write("app.conf", "password hunter2\nport 8080\n");

        var result = await Run(Q(("read", "file"), ("path", path), ("format", "kv")));

        var password = result.Rows.Single(r => r["name"]!.ToString() == "password");
        Assert.DoesNotContain("hunter2", password.ToJsonString(), StringComparison.Ordinal);
        Assert.Equal("8080", result.Rows.Single(r => r["name"]!.ToString() == "port")["value"]!.ToString());
    }

    [Fact]
    public async Task A_missing_file_is_a_failed_read_unless_the_rule_says_the_software_may_be_absent()
    {
        var path = Path.Combine(_dir, "nginx.conf");

        var strict = await Run(Q(("read", "file"), ("path", path), ("format", "kv")));
        var optional = await Run(Q(("read", "file"), ("path", path), ("format", "kv"), ("optional", true)));

        Assert.Equal("failed", strict.State);
        Assert.Equal("ok", optional.State);
        Assert.Empty(optional.Rows);
    }

    [Fact]
    public async Task A_file_that_cannot_be_parsed_is_a_failed_read_never_an_empty_pass()
    {
        var path = Write("nginx.conf", "http { server {");

        var result = await Run(Q(("read", "file"), ("path", path), ("format", "directives"), ("style", "nginx")));

        Assert.Equal("failed", result.State);
    }

    [Theory]
    [InlineData("/etc/shadow")]
    [InlineData("/etc/gshadow")]
    [InlineData("/private/etc/master.passwd")]
    [InlineData("/home/user/.ssh/id_rsa")]
    [InlineData("/home/user/.aws/credentials")]
    [InlineData("/etc/ssl/private/server.key")]
    [InlineData("/srv/app/tls.pfx")]
    [InlineData("/proc/1/environ")]
    public void Files_that_hold_secrets_are_refused_when_the_rule_is_loaded(string path)
    {
        var errors = _runner.Validate(Q(("read", "file"), ("path", path), ("format", "lines"))).ToList();

        Assert.Contains(errors, e => e.Contains("secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task A_link_into_a_secret_file_is_refused_when_it_is_read()
    {
        if (OperatingSystem.IsWindows())
            return;
        var secret = Write("home/.ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n");
        var link = Path.Combine(_dir, "innocent.conf");
        File.CreateSymbolicLink(link, secret);

        var result = await Run(Q(("read", "file"), ("path", link), ("format", "lines")));

        Assert.Equal("failed", result.State);
        Assert.DoesNotContain("PRIVATE", result.Reason ?? "", StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("relative/path.conf")]
    [InlineData("/etc/../etc/passwd")]
    public void Only_plain_absolute_paths_are_accepted(string path)
    {
        Assert.NotEmpty(_runner.Validate(Q(("read", "file"), ("path", path), ("format", "lines"))));
    }

    [Fact]
    public async Task Includes_are_followed_with_a_wildcard_and_their_rows_name_their_own_file()
    {
        Write("conf.d/a.conf", "server_tokens on;\n");
        Write("conf.d/b.conf", "autoindex on;\n");
        var main = Write("nginx.conf", $"http {{\n  include {Path.Combine(_dir, "conf.d", "*.conf")};\n}}\n");

        var result = await Run(Q(("read", "file"), ("path", main), ("format", "directives"), ("style", "nginx")));

        Assert.Equal("ok", result.State);
        var tokens = result.Rows.Single(r => r["name"]!.ToString() == "server_tokens");
        Assert.EndsWith("a.conf", tokens["file"]!.ToString(), StringComparison.Ordinal);
        Assert.Equal("http", tokens["context"]!.ToString());
        Assert.Contains(result.Rows, r => r["name"]!.ToString() == "autoindex");
    }

    [Fact]
    public async Task An_include_loop_ends_instead_of_running_forever()
    {
        var a = Path.Combine(_dir, "a.conf");
        var b = Path.Combine(_dir, "b.conf");
        File.WriteAllText(a, $"x 1;\ninclude {b};\n");
        File.WriteAllText(b, $"y 2;\ninclude {a};\n");

        var result = await Run(Q(("read", "file"), ("path", a), ("format", "directives"), ("style", "nginx")));

        Assert.Equal("partial", result.State);
        Assert.Contains("include", result.Reason ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Contains(result.Rows, r => r["name"]!.ToString() == "y");
    }

    [Fact]
    public async Task A_file_too_large_to_read_is_refused()
    {
        var path = Path.Combine(_dir, "big.log");
        using (var stream = File.Create(path))
            stream.SetLength(HostGuards.MaxFileBytes + 1);

        var result = await Run(Q(("read", "file"), ("path", path), ("format", "lines")));

        Assert.Equal("failed", result.State);
    }

    [Fact]
    public async Task Stat_reports_the_mode_and_whether_others_can_write()
    {
        if (OperatingSystem.IsWindows())
            return;
        var path = Write("secret.conf", "x");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);

        var result = await Run(Q(("read", "stat"), ("path", path)));

        var row = Assert.Single(result.Rows);
        Assert.Equal("602", row["mode"]!.ToString());
        Assert.True((bool)row["worldWritable"]!);
        Assert.True((bool)row["exists"]!);
        Assert.False((bool)row["isLink"]!);
    }

    [Fact]
    public async Task Stat_of_a_missing_path_is_a_row_that_says_it_does_not_exist()
    {
        var result = await Run(Q(("read", "stat"), ("path", Path.Combine(_dir, "nope"))));

        var row = Assert.Single(result.Rows);
        Assert.False((bool)row["exists"]!);
    }

    [Fact]
    public async Task Facts_say_which_machine_and_system_this_is()
    {
        var result = await Run(Q(("read", "facts")));

        var row = Assert.Single(result.Rows);
        Assert.Equal(Environment.MachineName, row["host"]!.ToString());
        Assert.Contains(row["os"]!.ToString(), new[] { "macos", "linux", "windows" });
        Assert.False(string.IsNullOrEmpty(row["kernel"]!.ToString()));
    }

    [Fact]
    public async Task An_allowed_command_runs_and_its_output_becomes_rows()
    {
        var result = await Run(Q(("read", "command"), ("name", "uname"), ("args", new JsonArray("-s"))));

        if (OperatingSystem.IsWindows())
            return;
        Assert.Equal("ok", result.State);
        var row = Assert.Single(result.Rows);
        Assert.Contains(row["line"]!.ToString(), new[] { "Darwin", "Linux" });
        Assert.Equal(0, (int)row["exitCode"]!);
    }

    [Theory]
    [InlineData("rm", "[]")]
    [InlineData("sh", "[\"-c\",\"id\"]")]
    [InlineData("uname", "[\"-s;id\"]")]
    [InlineData("sysctl", "[\"kernel.x;id\"]")]
    [InlineData("sysctl", "[\"-w\"]")]
    [InlineData("systemctl", "[\"restart\",\"sshd\"]")]
    public void Only_allowlisted_commands_with_valid_parameters_are_accepted(string name, string argsJson)
    {
        var query = Q(("read", "command"), ("name", name), ("args", JsonNode.Parse(argsJson)));

        Assert.NotEmpty(_runner.Validate(query));
    }

    [Theory]
    [InlineData("uname", "[\"-r\"]")]
    [InlineData("sysctl", "[\"kernel.randomize_va_space\"]")]
    [InlineData("systemctl", "[\"is-active\",\"sshd.service\"]")]
    public void Allowlisted_commands_with_valid_parameters_pass_validation(string name, string argsJson)
    {
        var query = Q(("read", "command"), ("name", name), ("args", JsonNode.Parse(argsJson)));

        Assert.Empty(_runner.Validate(query));
    }

    [Fact]
    public void A_query_without_a_known_read_is_refused()
    {
        Assert.NotEmpty(_runner.Validate(Q()));
        Assert.NotEmpty(_runner.Validate(Q(("read", "write"))));
    }
}

public sealed class HostKvSemanticsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-host-kv-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private async Task<IReadOnlyList<JsonObject>> Read(string path)
    {
        var query = Context.Query("host", "path", ("read", "file"), ("path", path), ("format", "kv"));
        var result = await new HostRunner().RunAsync(query, Context.For(new FakeConnection("local")), CancellationToken.None);
        Assert.Equal("ok", result.State);
        return result.Rows;
    }

    [Fact]
    public async Task The_first_value_of_a_key_is_marked_because_sshd_ignores_the_rest()
    {
        var path = Path.Combine(_dir, "sshd_config");
        File.WriteAllText(path, "PermitRootLogin no\nPermitRootLogin yes\n");

        var rows = await Read(path);

        Assert.Equal([1, 2], rows.Select(r => (int)r["occurrence"]!));
    }

    [Fact]
    public async Task Settings_after_a_match_line_are_marked_as_conditional()
    {
        var path = Path.Combine(_dir, "sshd_config");
        File.WriteAllText(path, "PasswordAuthentication no\nMatch User backup\n  PasswordAuthentication yes\n");

        var rows = await Read(path);

        Assert.Null(rows[0]["match"]);
        Assert.Equal("User backup", rows[2]["match"]!.ToString());
    }

    [Fact]
    public async Task An_include_is_followed_and_the_first_value_wins_across_files()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "sshd_config.d"));
        File.WriteAllText(Path.Combine(_dir, "sshd_config.d", "10-hardening.conf"), "PermitRootLogin no\n");
        var path = Path.Combine(_dir, "sshd_config");
        File.WriteAllText(path, "Include sshd_config.d/*.conf\nPermitRootLogin yes\n");

        var rows = await Read(path);

        var root = rows.Where(r => r["name"]!.ToString() == "permitrootlogin").ToList();
        Assert.Equal(("no", 1), (root[0]["value"]!.ToString(), (int)root[0]["occurrence"]!));
        Assert.Equal(("yes", 2), (root[1]["value"]!.ToString(), (int)root[1]["occurrence"]!));
    }
}
