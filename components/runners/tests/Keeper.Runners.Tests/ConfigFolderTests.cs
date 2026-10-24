using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class ConfigFolderTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-netcfg-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Put(string name, string text, string? folder = null)
    {
        var path = Path.Combine(folder ?? _dir, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    private static QuerySpec Q(params (string Name, JsonNode? Value)[] fields) => Context.Query("host", "device", [("read", "configs"), ("style", "ios"), .. fields]);

    private Task<RunnerResult> Run(QuerySpec query, Func<string, string?>? threshold = null, string? imports = null)
    {
        var context = Context.For(new FakeConnection("local"), imports: imports);
        if (threshold is not null)
            context = context with { Threshold = threshold };
        return new HostRunner().RunAsync(query, context, CancellationToken.None);
    }

    [Fact]
    public async Task Every_device_file_in_the_folder_is_read_and_its_rows_name_the_device()
    {
        Put("core-sw01.cfg", NetworkConfigTests.Ios);
        Put("edge-rt02.cfg", "hostname edge-rt02\nip ssh version 2\n");

        var result = await Run(Q(("folder", _dir), ("pattern", "*.cfg"), ("format", "lines")));

        Assert.Equal("ok", result.State);
        Assert.Equal(["core-sw01", "edge-rt02"], result.Rows.Select(r => r["device"]!.ToString()).Distinct().Order(StringComparer.Ordinal));
        var ssh = result.Rows.Single(r => r["device"]!.ToString() == "edge-rt02" && r["text"]!.ToString() == "ip ssh version 2");
        Assert.Equal(Environment.MachineName, ssh["host"]!.ToString());
        Assert.EndsWith("edge-rt02.cfg", ssh["file"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_pattern_chooses_which_files_are_device_configs()
    {
        Put("core-sw01.cfg", "hostname core-sw01\n");
        Put("notes.txt", "hostname not-a-device\n");

        var result = await Run(Q(("folder", _dir), ("pattern", "*.cfg"), ("format", "lines")));

        Assert.DoesNotContain(result.Rows, r => r["device"]!.ToString() == "notes");
    }

    [Fact]
    public async Task Blocks_mode_gives_sections_with_their_commands()
    {
        Put("core-sw01.cfg", NetworkConfigTests.Ios);

        var result = await Run(Q(("folder", _dir), ("format", "blocks")));

        var vty = result.Rows.Single(r => r["header"]!.ToString() == "line vty 0 4");
        Assert.Equal("core-sw01", vty["device"]!.ToString());
        Assert.Contains("transport input telnet", vty["body"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Files_mode_gives_one_row_per_device_with_the_age_of_its_backup()
    {
        var path = Put("core-sw01.cfg", "hostname core-sw01\n!\ninterface Gi0/1\n");
        File.SetLastWriteTimeUtc(path, new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc));

        var row = Assert.Single((await Run(Q(("folder", _dir), ("format", "files")))).Rows);

        Assert.Equal(("core-sw01", "2026-09-01T00:00:00Z"), (row["device"]!.ToString(), row["modified"]!.ToString()));
        Assert.True((long)row["size"]! > 0);
    }

    [Fact]
    public async Task Secrets_in_a_device_configuration_never_reach_the_rows()
    {
        Put("core-sw01.cfg", NetworkConfigTests.Ios);

        var result = await Run(Q(("folder", _dir), ("format", "lines")));

        var text = string.Join("\n", result.Rows.Select(r => r.ToJsonString()));
        foreach (var secret in new[] { "cisco123", "XYZsecrethash", "0822455D0A16", "s3cr3tRW", "AuthPass123", "NtpKey123" })
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_folder_is_a_failed_read_because_knowing_nothing_is_not_a_pass()
    {
        var result = await Run(Q(("folder", _dir), ("format", "lines")));

        Assert.Equal("failed", result.State);
        Assert.Contains("no configuration files", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_setting_can_point_the_read_at_the_real_backup_folder()
    {
        var backups = Path.Combine(_dir, "backups");
        Put("core-sw01.cfg", "hostname core-sw01\n", backups);

        var result = await Run(Q(("folder", Path.Combine(_dir, "nowhere")), ("folderSetting", "network.config-folder"), ("format", "lines")),
            threshold: name => name == "network.config-folder" ? backups : null);

        Assert.Equal("ok", result.State);
        Assert.Equal("core-sw01", result.Rows[0]["device"]!.ToString());
    }

    [Fact]
    public async Task The_imports_prefix_means_the_folder_under_the_keeper_homes_imports()
    {
        var imports = Path.Combine(_dir, "home-imports");
        Put("core-sw01.cfg", "hostname core-sw01\n", Path.Combine(imports, "network-config"));

        var result = await Run(Q(("folder", "imports:network-config"), ("format", "lines")), imports: imports);

        Assert.Equal("ok", result.State);
        Assert.Equal("core-sw01", result.Rows[0]["device"]!.ToString());
    }

    [Theory]
    [InlineData("imports:../etc")]
    [InlineData("relative/folder")]
    [InlineData("/home/user/.ssh")]
    [InlineData("/etc/ssl/private")]
    public void A_folder_must_be_absolute_or_under_imports_and_not_hold_secrets(string folder)
    {
        Assert.NotEmpty(new HostRunner().Validate(Q(("folder", folder), ("format", "lines"))));
    }

    [Theory]
    [InlineData("pattern", "../*.cfg")]
    [InlineData("pattern", "a/b")]
    [InlineData("format", "tree")]
    [InlineData("style", "junos")]
    public void The_other_fields_are_checked_when_the_rule_is_loaded(string field, string value)
    {
        Assert.NotEmpty(new HostRunner().Validate(Q(("folder", "/srv/configs"), (field, value))));
    }

    [Fact]
    public void A_good_query_validates()
    {
        Assert.Empty(new HostRunner().Validate(Q(("folder", "/srv/configs"), ("pattern", "*.cfg"), ("format", "blocks"))));
        Assert.Empty(new HostRunner().Validate(Q(("folder", "imports:network-config"), ("format", "files"))));
    }

    [Fact]
    public async Task Over_ssh_the_folder_is_on_the_backup_server_and_imports_does_not_exist()
    {
        var session = new FakeSession("backup01", new()
        {
            ["/srv/oxidized/core-sw01"] = "hostname core-sw01\nip ssh version 2\n",
            ["/srv/oxidized/edge-rt02"] = "hostname edge-rt02\n",
        });
        var runner = new HostRunner(_ => session);

        var ok = await runner.RunAsync(Q(("folder", "/srv/oxidized"), ("format", "lines")), Context.For(new SshFakeConnection(), "backup01"), CancellationToken.None);
        var imports = await runner.RunAsync(Q(("folder", "imports:network-config"), ("format", "lines")), Context.For(new SshFakeConnection(), "backup01"), CancellationToken.None);

        Assert.Equal("ok", ok.State);
        Assert.Equal(["core-sw01", "edge-rt02"], ok.Rows.Select(r => r["device"]!.ToString()).Distinct().Order(StringComparer.Ordinal));
        Assert.All(ok.Rows, r => Assert.Equal("backup01", r["host"]!.ToString()));
        Assert.Equal("failed", imports.State);
    }

    [Fact]
    public async Task A_file_that_holds_a_key_is_skipped_and_said_so_without_losing_the_others()
    {
        var session = new FakeSession("backup01", new()
        {
            ["/srv/oxidized/core-sw01"] = "hostname core-sw01\n",
            ["/srv/oxidized/old.key"] = "-----BEGIN PRIVATE KEY-----",
        });

        var result = await new HostRunner(_ => session).RunAsync(Q(("folder", "/srv/oxidized"), ("format", "lines")),
            Context.For(new SshFakeConnection(), "backup01"), CancellationToken.None);

        Assert.Equal("partial", result.State);
        Assert.Contains("old.key", result.Reason!, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", result.Reason!, StringComparison.Ordinal);
        Assert.Contains(result.Rows, r => r["device"]!.ToString() == "core-sw01");
    }
}
