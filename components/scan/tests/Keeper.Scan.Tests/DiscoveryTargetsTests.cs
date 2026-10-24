using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;

namespace Keeper.Scan.Tests;

public sealed class DiscoveryTargetsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-dtargets-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Imports => Path.Combine(_dir, "imports");

    private void Inventory(string health = "ok", int ageDays = 0)
    {
        var folder = Path.Combine(Imports, "discovery");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, "inventory.json");
        File.WriteAllText(path, $$"""
            {
              "schema": "keeper.inventory/1", "scanHealth": "{{health}}",
              "assets": [
                { "id": "prn-a.example.org", "names": ["prn-a.example.org"], "addresses": ["2001:db8::50", "192.0.2.50"], "state": "answering", "kind": "printer" },
                { "id": "ip:192.0.2.51", "names": [], "addresses": ["192.0.2.51"], "state": "answering", "kind": "printer" },
                { "id": "prn-gone", "names": ["prn-gone"], "addresses": ["192.0.2.52"], "state": "likely-gone", "kind": "printer" },
                { "id": "prn-quiet", "names": ["prn-quiet"], "addresses": ["192.0.2.53"], "state": "not-answering", "kind": "printer" },
                { "id": "prn-elsewhere", "names": ["prn-elsewhere"], "addresses": ["203.0.113.9"], "state": "answering", "kind": "printer" },
                { "id": "web01.example.org", "names": ["web01.example.org"], "addresses": ["192.0.2.60"], "state": "answering", "kind": "linux-unix" },
                { "id": "dc01.example.org", "names": ["dc01.example.org"], "addresses": ["192.0.2.10"], "state": "answering", "kind": "domain-controller" },
                { "id": "named-only", "names": ["named-only.example.org"], "addresses": [], "state": "answering", "kind": "printer" }
              ]
            }
            """);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-ageDays));
    }

    private sealed class Estate : IConnection
    {
        public Estate(string type, string endpoint, JsonObject options)
        {
            Type = type;
            Endpoint = endpoint;
            Options = options;
        }

        public string Instance => "estate";
        public string Type { get; }
        public string Endpoint { get; }
        public string AuthKind => "none";
        public string? Identity => null;
        public IReadOnlyList<string>? Protocols => ["probe"];
        public JsonObject Options { get; }
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class Probe : IRunner
    {
        public List<string> Targets { get; } = [];
        public string Protocol => "probe";
        public bool PerTarget => true;
        public IEnumerable<string> Validate(QuerySpec query) => [];

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            lock (Targets)
                Targets.Add(context.Target!);
            return Task.FromResult(RunnerResult.Ok([new JsonObject { ["host"] = context.Target }]));
        }
    }

    private async Task<(Probe Probe, ScanReport Report)> Run(string type, string endpoint, JsonObject options)
    {
        var yaml = Path.Combine(_dir, "probe.yaml");
        File.WriteAllText(yaml, """
            schema: keeper.rules/1
            system: probe
            integration: printer
            defaults: { lens: security, category: CFG, refresh: 1d, entity: printer, kind: misconfigured, severity: low }
            rules:
              - id: PROBE-X
                title: Probe
                query: { protocol: probe, key: host }
                each: { field: host, op: eq, value: never-matches }
            """);
        var probe = new Probe();
        var registry = new RunnerRegistry([probe]);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(yaml, "test", registry.Validators)],
            Connection = new Estate(type, endpoint, options),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Imports,
        }, CancellationToken.None);
        return (probe, report);
    }

    private static JsonObject From(string kinds, params string[] extra)
    {
        var options = new JsonObject { ["targetsFrom"] = "discovery", ["targetsKind"] = kinds };
        foreach (var pair in extra)
            options[pair.Split('=')[0]] = pair.Split('=')[1];
        return options;
    }

    [Fact]
    public async Task Printers_that_answer_inside_the_integrations_scope_become_its_targets()
    {
        Inventory();

        var (probe, report) = await Run("printer", "192.0.2.0/24", From("printer"));

        // The IPv4 address is preferred; gone and silent printers, one outside the scope, and other kinds are left out.
        Assert.Equal(["192.0.2.50", "192.0.2.51"], probe.Targets.Order(StringComparer.Ordinal));
        Assert.Equal("ok", report.Manifest.Status);
    }

    [Fact]
    public async Task Several_kinds_can_be_asked_for_and_a_device_with_only_a_name_is_reached_by_name()
    {
        Inventory();

        var (probe, _) = await Run("ssh", "192.0.2.0/24, *.example.org", From("linux-unix, printer"));

        Assert.Contains("192.0.2.60", probe.Targets);
        Assert.Contains("named-only.example.org", probe.Targets);
        Assert.DoesNotContain("192.0.2.10", probe.Targets);   // a domain controller was not asked for
    }

    [Fact]
    public async Task A_listed_targets_option_wins_over_discovery()
    {
        Inventory();
        var options = From("printer");
        options["targets"] = new JsonArray("192.0.2.77");

        var (probe, _) = await Run("printer", "192.0.2.0/24", options);

        Assert.Equal(["192.0.2.77"], probe.Targets);
    }

    private async Task<(Probe Probe, string Status)> RunWithFileTargetsAndStatus(string targetsYaml, JsonObject options)
    {
        var yaml = Path.Combine(_dir, "dynamic.yaml");
        File.WriteAllText(yaml, $$"""
            schema: keeper.rules/1
            system: dynamic
            integration: printer
            {{targetsYaml}}
            defaults: { lens: security, category: CFG, refresh: 1d, entity: computer, kind: misconfigured, severity: low }
            rules:
              - id: DYN-X
                title: Dynamic
                query: { protocol: probe, key: host }
                each: { field: host, op: eq, value: never-matches }
            """);
        var probe = new Probe();
        var registry = new RunnerRegistry([probe]);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(yaml, "test", registry.Validators)],
            Connection = new Estate("printer", "192.0.2.0/24", options),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Imports,
            ResolveTargets = _ => ["from-the-store-1", "from-the-store-2"],
            TargetsIncomplete = _ => "the directory reads were not all clean, so the list may miss hosts",
        }, CancellationToken.None);
        return (probe, report.Manifest.Status);
    }

    private async Task<Probe> RunWithFileTargets(string targetsYaml, JsonObject options) => (await RunWithFileTargetsAndStatus(targetsYaml, options)).Probe;

    [Fact]
    public async Task The_store_lists_incompleteness_warning_does_not_apply_to_a_list_the_integration_named()
    {
        var named = await RunWithFileTargetsAndStatus("targets: { entity: computer, field: dNSHostName }", new JsonObject { ["targets"] = new JsonArray("lab-pc-01") });
        var fromStore = await RunWithFileTargetsAndStatus("targets: { entity: computer, field: dNSHostName }", []);

        Assert.Equal("ok", named.Status);              // the hosts were named, nothing can be missing from the store's list
        Assert.Equal("partial", fromStore.Status);     // the store's list may be short: said
    }

    [Fact]
    public async Task A_rule_file_that_finds_its_hosts_in_the_store_can_be_pointed_at_named_hosts_by_the_integration()
    {
        var options = new JsonObject { ["targets"] = new JsonArray("lab-pc-01") };

        var probe = await RunWithFileTargets("targets: { entity: computer, field: dNSHostName }", options);

        Assert.Equal(["lab-pc-01"], probe.Targets);
    }

    [Fact]
    public async Task Without_such_a_list_the_store_still_supplies_the_hosts()
    {
        var probe = await RunWithFileTargets("targets: { entity: computer, field: dNSHostName }", []);

        Assert.Equal(["from-the-store-1", "from-the-store-2"], probe.Targets.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task A_list_written_into_the_rule_file_itself_is_the_rule_authors_choice_and_wins()
    {
        var options = new JsonObject { ["targets"] = new JsonArray("lab-pc-01") };

        var probe = await RunWithFileTargets("targets: { list: [fixed-host-1] }", options);

        Assert.Equal(["fixed-host-1"], probe.Targets);
    }

    [Fact]
    public async Task A_printer_integration_with_no_targets_does_not_try_to_scan_its_scope_as_a_host()
    {
        var (probe, report) = await Run("printer", "192.0.2.0/24", []);

        Assert.Empty(probe.Targets);
        Assert.Equal("failed", report.Manifest.Status);
    }

    [Fact]
    public async Task Without_an_inventory_the_scan_fails_and_says_to_run_discovery()
    {
        var (probe, report) = await Run("printer", "192.0.2.0/24", From("printer"));

        Assert.Empty(probe.Targets);
        Assert.Equal("failed", report.Manifest.Status);
        Assert.Contains(report.Manifest.Notes, n => n.Contains("keeper discover", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_degraded_or_old_inventory_makes_the_scan_partial_because_targets_may_be_missing()
    {
        Inventory(health: "degraded");
        var degraded = await Run("printer", "192.0.2.0/24", From("printer"));
        Inventory(ageDays: 40);
        var old = await Run("printer", "192.0.2.0/24", From("printer"));

        Assert.Equal("partial", degraded.Report.Manifest.Status);
        Assert.Contains(degraded.Report.Manifest.Notes, n => n.Contains("degraded", StringComparison.Ordinal));
        Assert.Equal("partial", old.Report.Manifest.Status);
        Assert.Contains(old.Report.Manifest.Notes, n => n.Contains("40 days", StringComparison.Ordinal));
        Assert.NotEmpty(degraded.Probe.Targets);             // still scanned: partial is not failed
    }

    [Fact]
    public async Task A_kind_with_nothing_answering_is_a_failed_read_not_a_pass()
    {
        Inventory();

        var (probe, report) = await Run("printer", "192.0.2.0/24", From("hypervisor"));

        Assert.Empty(probe.Targets);
        Assert.Equal("failed", report.Manifest.Status);
    }
}
