using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class DockerReadTests
{
    private static QuerySpec Q(string what, params (string Name, JsonNode? Value)[] more) =>
        Context.Query("host", "Id", [("read", "docker"), ("what", what), .. more]);

    private static Task<RunnerResult> Run(HostRunner runner, QuerySpec query) =>
        runner.RunAsync(query, Context.For(new SshFakeConnection(), "docker01"), CancellationToken.None);

    private static HostCommands.Output Lines(params string[] lines) => new(true, 0, lines, false, false);

    private static HostCommands.Output Json(object value) => Lines(JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true }).Split('\n'));

    private static string Id(int n) => n.ToString("x").PadLeft(64, 'a');

    private static object Container(string id, string name, object? hostConfig = null, string[]? env = null) => new
    {
        Id = id,
        Name = "/" + name,
        HostConfig = hostConfig ?? new { Privileged = false },
        Config = new { Image = "app:1.0", Env = env ?? ["PATH=/usr/bin"], Cmd = new[] { "run" } },
    };

    [Theory]
    [InlineData("container")]
    [InlineData("image")]
    [InlineData("network")]
    [InlineData("volume")]
    public void Inspecting_a_known_kind_of_object_by_plain_ids_is_allowed(string kind)
    {
        Assert.Null(HostCommands.Problem("docker-inspect", [kind, "0123abcd", "my-volume_1.x"]));
    }

    [Theory]
    [InlineData("secret", "abc")]                       // a kind docker has but Keeper does not read
    [InlineData("container", "--format")]                // an option
    [InlineData("container", "-f")]
    [InlineData("container", "abc;id")]                  // a shell character
    [InlineData("container", "abc def")]
    [InlineData("container", "$(id)")]
    [InlineData("container", "../etc")]
    public void Docker_inspect_takes_a_kind_and_plain_ids_and_nothing_else(string kind, string id)
    {
        Assert.NotNull(HostCommands.Problem("docker-inspect", [kind, id]));
    }

    [Fact]
    public void Docker_inspect_needs_at_least_one_id_and_has_a_limit()
    {
        Assert.NotNull(HostCommands.Problem("docker-inspect", ["container"]));
        Assert.Null(HostCommands.Problem("docker-inspect", ["container", .. Enumerable.Range(1, HostCommands.MaxInspectIds).Select(Id)]));
        Assert.NotNull(HostCommands.Problem("docker-inspect", ["container", .. Enumerable.Range(1, HostCommands.MaxInspectIds + 1).Select(Id)]));
    }

    [Theory]
    [InlineData("docker-ps-ids")]
    [InlineData("docker-image-ids")]
    [InlineData("docker-network-ids")]
    [InlineData("docker-volume-names")]
    [InlineData("docker-info")]
    public void The_listing_commands_take_no_parameters(string name)
    {
        Assert.Null(HostCommands.Problem(name, []));
        Assert.NotNull(HostCommands.Problem(name, ["--all"]));
    }

    [Fact]
    public void There_is_no_docker_command_that_changes_anything()
    {
        var names = HostCommands.Names.Where(n => n.StartsWith("docker", StringComparison.Ordinal)).ToList();

        Assert.DoesNotContain(names, n => n.Contains("run") || n.Contains("exec") || n.Contains("rm") || n.Contains("stop") || n.Contains("pull") || n.Contains("cp"));
    }

    [Fact]
    public void A_docker_read_names_what_it_reads()
    {
        var runner = new HostRunner();

        Assert.Empty(runner.Validate(Q("containers")));
        Assert.NotEmpty(runner.Validate(Q("secrets")));
        Assert.NotEmpty(runner.Validate(Context.Query("host", "Id", ("read", "docker"))));
    }

    [Fact]
    public async Task Containers_are_listed_then_inspected_and_come_back_as_rows_named_for_their_host()
    {
        var session = new FakeSession("docker01", [], script: (name, args) => name switch
        {
            "docker-ps-ids" => Lines(Id(1), Id(2)),
            "docker-inspect" => Json(new[] { Container(Id(1), "web", new { Privileged = true }), Container(Id(2), "db") }),
            _ => throw new InvalidOperationException(name),
        });

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        Assert.Equal("ok", result.State);
        Assert.Equal(["web", "db"], result.Rows.Select(r => r["name"]!.ToString()));
        Assert.All(result.Rows, r => Assert.Equal("docker01", r["host"]!.ToString()));
        Assert.True((bool)result.Rows[0]["HostConfig"]!["Privileged"]!);
        Assert.Equal(["docker-ps-ids", $"docker-inspect container {Id(1)} {Id(2)}"], session.Commands);
    }

    [Fact]
    public async Task Many_containers_are_inspected_in_batches()
    {
        var count = HostCommands.MaxInspectIds * 2 + 5;
        var session = new FakeSession("docker01", [], script: (name, args) => name == "docker-ps-ids"
            ? Lines([.. Enumerable.Range(1, count).Select(Id)])
            : Json(args.Skip(1).Select(id => Container(id, "c" + id[^2..])).ToArray()));

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        Assert.Equal(count, result.Rows.Count);
        Assert.Equal(3, session.Commands.Count(c => c.StartsWith("docker-inspect", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Credentials_in_a_containers_environment_and_command_are_scrubbed()
    {
        var container = new
        {
            Id = Id(1), Name = "/web",
            Config = new { Env = new[] { "DB_PASSWORD=hunter2", "MODE=prod" }, Cmd = new[] { "run", "--api_key=abc123" }, Image = "app:1" },
        };
        var session = new FakeSession("docker01", [], script: (name, _) => name == "docker-ps-ids" ? Lines(Id(1)) : Json(new[] { container }));

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        var text = result.Rows[0].ToJsonString();
        Assert.DoesNotContain("hunter2", text, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", text, StringComparison.Ordinal);
        Assert.Contains("MODE=prod", text, StringComparison.Ordinal);
        Assert.Contains("DB_PASSWORD=set", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_with_no_containers_gives_no_rows_and_no_inspect_call()
    {
        var session = new FakeSession("docker01", [], script: (_, _) => Lines());

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        Assert.Equal("ok", result.State);
        Assert.Empty(result.Rows);
        Assert.Equal(["docker-ps-ids"], session.Commands);
    }

    [Fact]
    public async Task Docker_info_is_one_row()
    {
        var info = new { ServerVersion = "29.1.0", SecurityOptions = new[] { "name=seccomp,profile=builtin" }, LiveRestoreEnabled = false };
        var session = new FakeSession("docker01", [], script: (_, _) => Lines(JsonSerializer.Serialize(info)));

        var row = Assert.Single((await Run(new HostRunner(_ => session), Q("info"))).Rows);

        Assert.Equal("29.1.0", row["ServerVersion"]!.ToString());
        Assert.Equal("docker01", row["host"]!.ToString());
    }

    [Fact]
    public async Task A_machine_without_docker_is_a_failed_read_unless_the_rule_says_it_may_be_absent()
    {
        var session = new FakeSession("docker01", [], script: (_, _) => new HostCommands.Output(false, 127, [], false, false));
        var runner = new HostRunner(_ => session);

        Assert.Equal("failed", (await Run(runner, Q("containers"))).State);
        var optional = await Run(runner, Q("containers", ("optional", true)));
        Assert.Equal("ok", optional.State);
        Assert.Empty(optional.Rows);
    }

    [Fact]
    public async Task A_refused_docker_socket_is_a_failed_read_that_says_why()
    {
        var denied = new HostCommands.Output(true, 1, [], false, false, "permission denied while trying to connect to the Docker daemon socket");
        var session = new FakeSession("docker01", [], script: (_, _) => denied);

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        Assert.Equal("failed", result.State);
        Assert.Contains("permission denied", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Docker_that_returns_something_that_is_not_json_is_a_failed_read_never_an_empty_pass()
    {
        var session = new FakeSession("docker01", [], script: (name, _) => name == "docker-ps-ids" ? Lines(Id(1)) : Lines("this is not json"));

        var result = await Run(new HostRunner(_ => session), Q("containers"));

        Assert.Equal("failed", result.State);
    }
}
