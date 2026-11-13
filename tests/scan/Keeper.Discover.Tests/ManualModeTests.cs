using System.Net;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Files;
using Keeper.Scan;
using Keeper.Discover.Probes;
using Keeper.Discover.Sources;

namespace Keeper.Discover.Tests;

public sealed class ManualModeTests : IDisposable
{
    private readonly string _imports = Directory.CreateTempSubdirectory("keeper-discover-manual-").FullName;

    public void Dispose()
    {
        if (Directory.Exists(_imports))
            Directory.Delete(_imports, recursive: true);
    }

    private sealed class MapResolver(Dictionary<string, string> names) : IResolver
    {
        public Task<IReadOnlyList<IPAddress>> ResolveAddressesAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IPAddress>>(names.TryGetValue(host, out var ip) ? [IPAddress.Parse(ip)] : []);

        public Task<string?> ResolveReverseNameAsync(IPAddress address, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);
    }

    private static readonly PortProfile[] Profiles = [new PortProfile(22, "ssh", SendNothing: true)];

    private Task Run(string yaml, FakeDialer dialer, IResolver resolver) =>
        new Discoverer().RunAsync(new DiscoverRequest
        {
            Targets = TargetsLoader.Parse(yaml),
            ImportsDir = _imports,
            Dialer = dialer,
            Resolver = resolver,
            Profiles = Profiles,
        }, CancellationToken.None);

    [Fact]
    public async Task Manual_mode_probes_only_what_targets_lists_even_when_an_earlier_inventory_knows_more()
    {
        var resolver = new MapResolver(new() { ["old.example.com"] = "192.0.2.77", ["new.example.com"] = "192.0.2.20" });

        // Run 1 lists old.example.com, so the inventory now knows it.
        await Run("schema: keeper.discovery/1\nmode: manual\nscope: [192.0.2.0/24]\ntargets:\n  - host: old.example.com\n",
            new FakeDialer(), resolver);

        // Run 2 lists a different host only: the old one is no longer something the operator allowed.
        var second = new FakeDialer();
        await Run("schema: keeper.discovery/1\nmode: manual\nscope: [192.0.2.0/24]\ntargets:\n  - host: new.example.com\n",
            second, resolver);

        Assert.DoesNotContain(second.DialLog, d => d.Ip == "192.0.2.77");
        Assert.Contains(second.DialLog, d => d.Ip == "192.0.2.20");
    }

    [Fact]
    public async Task A_listed_target_that_answers_is_not_reported_as_an_unlisted_machine()
    {
        var dialer = new FakeDialer();
        dialer.MapTcpOpen("192.0.2.30", 22, "SSH-2.0-OpenSSH_9.0\r\n"u8.ToArray());
        await Run("schema: keeper.discovery/1\nmode: manual\nscope: [192.0.2.0/24]\ntargets: [192.0.2.30]\n",
            dialer, new MapResolver([]));
        File.SetLastWriteTimeUtc(Path.Combine(_imports, "discovery", "inventory.json"), DateTime.UtcNow);

        var rules = RuleLoader.LoadFile(Path.Combine(RepoRoot(), "rules", "network.yaml"), "builtin",
            new Dictionary<string, QueryValidator> { ["file"] = new FileRunner().Validate });
        var runs = Path.Combine(_imports, "runs");
        var report = await new Scanner(new RunnerRegistry([new FileRunner()])).RunAsync(new ScanRequest
        {
            Files = [rules],
            Connection = new FilesConnection(),
            RunsDir = runs,
            ImportsDir = _imports,
        }, CancellationToken.None);

        var findingsFile = Path.Combine(runs, report.Manifest.RunId, RunFolder.Findings);
        var findings = File.Exists(findingsFile) ? JsonLines.Read<FindingRecord>(findingsFile).ToList() : [];
        Assert.DoesNotContain(findings, f => f.RuleId == "NET-UNLISTED-MACHINE");
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private sealed class FilesConnection : IConnection
    {
        public string Instance => "files";
        public string Type => "files";
        public string Endpoint => "";
        public string AuthKind => "none";
        public string? Identity => null;
        public System.Text.Json.Nodes.JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
