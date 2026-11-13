using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Host;

namespace Keeper.Scan.Tests;

public sealed class DockerPackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-docker-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>A machine that answers Docker's listing and inspect commands from canned data.</summary>
    private sealed class DockerHost(object[] containers, object info) : IHostSession
    {
        public string HostName => "docker01";
        public string Normalize(string path) => path;
        public string ResolveInclude(string fromFile, string pattern) => pattern;
        public bool FileExists(string path) => false;
        public string? ReadProblem(string path) => null;
        public string ReadAllText(string path) => throw new FileNotFoundException(path);
        public HostStat Stat(string path) => new(false, false, false, 0, default, null);
        public IReadOnlyList<string> Glob(string folder, string pattern) => [];
        public JsonObject Facts() => [];
        public void Dispose() { }

        public Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var ids = containers.Select(c => (string)c.GetType().GetProperty("Id")!.GetValue(c)!).ToArray();
            var lines = name switch
            {
                "docker-ps-ids" => ids,
                "docker-info" => [JsonSerializer.Serialize(info)],
                "docker-inspect" => JsonSerializer.Serialize(containers.Where(c => args.Contains((string)c.GetType().GetProperty("Id")!.GetValue(c)!)).ToArray(), new JsonSerializerOptions { WriteIndented = true }).Split('\n'),
                _ => [],
            };
            return Task.FromResult(new HostCommands.Output(true, 0, lines, false, false));
        }
    }

    private sealed class Fleet : IConnection
    {
        public string Instance => "fleet";
        public string Type => "ssh";
        public string Endpoint => "192.0.2.0/24";
        public string AuthKind => "ssh-key";
        public string? Identity => "keeper-reader";
        public IReadOnlyList<string>? Protocols => ["host"];
        public JsonObject Options { get; } = new() { ["targets"] = new JsonArray("docker01") };
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private static string Id(char c) => new(c, 64);

    private static object Box(char id, string name, object? hostConfig = null, object? config = null, object? state = null, object[]? mounts = null, int restarts = 0) => new
    {
        Id = Id(id),
        Name = "/" + name,
        RestartCount = restarts,
        State = state ?? new { Restarting = false, Health = new { Status = "healthy" } },
        HostConfig = hostConfig ?? new { Privileged = false, NetworkMode = "bridge", Memory = 134217728 },
        Config = config ?? new { Image = "registry.example.org:5000/team/app@sha256:0123456789abcdef", User = "1000", Env = new[] { "MODE=prod" } },
        Mounts = mounts ?? [],
    };

    private async Task<List<FindingRecord>> Scan(object[] containers, object info)
    {
        var registry = new RunnerRegistry([new HostRunner(_ => new DockerHost(containers, info))]);
        var file = RuleLoader.LoadFile(Path.Combine(FindRepoRoot(), "rules", "docker.yaml"), "builtin", registry.Validators);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [file],
            Connection = new Fleet(),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
        }, CancellationToken.None);
        var path = Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings);
        return File.Exists(path) ? JsonLines.Read<FindingRecord>(path).ToList() : [];
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private static string[] Flagged(List<FindingRecord> findings, string rule) =>
        [.. findings.Where(f => f.RuleId == rule).Select(f => f.Target?.Split('|').Last() ?? "").Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Every_container_rule_flags_what_it_should_and_leaves_a_healthy_container_alone()
    {
        object[] containers =
        [
            Box('1', "ok"),
            Box('2', "priv", hostConfig: new { Privileged = true, NetworkMode = "bridge", Memory = 134217728 }),
            Box('3', "sock", mounts: [new { Source = "/var/run/docker.sock" }]),
            Box('4', "hostnet", hostConfig: new { Privileged = false, NetworkMode = "host", Memory = 134217728 }),
            Box('5', "caps", hostConfig: new { Privileged = false, NetworkMode = "bridge", Memory = 134217728, CapAdd = new[] { "SYS_ADMIN" } }),
            Box('6', "root", config: new { Image = "app@sha256:0123456789abcdef", User = "", Env = new[] { "DB_PASSWORD=hunter2" } }),
            Box('7', "nolimit", hostConfig: new { Privileged = false, NetworkMode = "bridge", Memory = 0 }),
            Box('8', "latest", config: new { Image = "nginx:latest", User = "1000", Env = new[] { "MODE=prod" } }),
            Box('9', "sick", state: new { Restarting = false, Health = new { Status = "unhealthy" } }),
            Box('a', "loop", state: new { Restarting = true, Health = new { Status = "healthy" } }, restarts: 12),
        ];
        var findings = await Scan(containers, new { ID = "daemon-1", Name = "docker01", LiveRestoreEnabled = true, RegistryConfig = new { InsecureRegistryCIDRs = new[] { "127.0.0.0/8" } } });

        Assert.Equal([Id('2')], Flagged(findings, "DOCKER-CONTAINER-PRIVILEGED"));
        Assert.Equal([Id('3')], Flagged(findings, "DOCKER-CONTAINER-RUNTIME-SOCKET"));
        Assert.Equal([Id('4')], Flagged(findings, "DOCKER-CONTAINER-HOST-NAMESPACE"));
        Assert.Equal([Id('5')], Flagged(findings, "DOCKER-CONTAINER-DANGEROUS-CAPABILITIES"));
        Assert.Equal([Id('6')], Flagged(findings, "DOCKER-CONTAINER-RUNS-AS-ROOT"));
        Assert.Equal([Id('7')], Flagged(findings, "DOCKER-CONTAINER-NO-MEMORY-LIMIT"));
        Assert.Equal([Id('8')], Flagged(findings, "DOCKER-CONTAINER-IMAGE-NOT-PINNED"));
        Assert.Equal([Id('9')], Flagged(findings, "DOCKER-CONTAINER-UNHEALTHY"));
        Assert.Equal([Id('a')], Flagged(findings, "DOCKER-CONTAINER-RESTART-LOOP"));
        Assert.DoesNotContain(findings, f => f.Target?.Contains(Id('1'), StringComparison.Ordinal) == true);   // the healthy one
        Assert.DoesNotContain("hunter2", string.Join("\n", findings.Select(f => f.Evidence)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Daemon_settings_are_flagged_from_docker_info()
    {
        var findings = await Scan([], new { ID = "daemon-1", Name = "docker01", LiveRestoreEnabled = false, RegistryConfig = new { InsecureRegistryCIDRs = new[] { "127.0.0.0/8", "10.0.0.0/8" } } });

        Assert.Single(findings, f => f.RuleId == "DOCKER-DAEMON-INSECURE-REGISTRY");
        Assert.Single(findings, f => f.RuleId == "DOCKER-DAEMON-NO-LIVE-RESTORE");
    }

    [Fact]
    public async Task A_daemon_with_only_the_default_local_registry_and_live_restore_has_no_findings()
    {
        var findings = await Scan([], new { ID = "daemon-1", Name = "docker01", LiveRestoreEnabled = true, RegistryConfig = new { InsecureRegistryCIDRs = new[] { "::1/128", "127.0.0.0/8" } } });

        Assert.Empty(findings);
    }
}
