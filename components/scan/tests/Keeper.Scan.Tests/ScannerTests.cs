using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;

namespace Keeper.Scan.Tests;

internal sealed class FilesConnection : IConnection
{
    public string Instance => "files";
    public string Type => "files";
    public string Endpoint => "";
    public string AuthKind => "none";
    public string? Identity => null;
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class ScannerTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 6, 0, 0, TimeSpan.Zero);

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Imports => Path.Combine(_dir, "imports");
    private string Runs => Path.Combine(_dir, "runs");

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private const string Rules = """
        schema: keeper.rules/1
        system: example
        integration: files
        defaults: { lens: both, refresh: 1d }
        rules:
          - id: EX-USER-STALE
            title: Enabled account not used for a long time
            kind: misconfigured
            category: IAM
            severity: medium
            entity: user
            query: { protocol: file, path: "users/*.json", items: users, key: name, name: display }
            each:
              all:
                - { field: enabled, op: eq, value: true }
                - { field: lastLogon, op: age-gt, value: 90, threshold: example.stale-days }
            evidence: "{name} last signed in {lastLogon}"
          - id: EX-ADMINS-MANY
            title: Too many administrators
            kind: misconfigured
            category: IAM
            severity: high
            entity: user
            query: { protocol: file, path: "users/*.json", items: admins, key: name }
            count: { op: gt, value: 1 }
          - id: EX-CERT-EXPIRY
            title: Certificate expires soon
            kind: broken
            category: PKI
            entity: certificate
            severity:
              daysLeft: notAfter
              ranges: [ { max: 0, value: critical }, { max: 14, value: high } ]
              default: low
            deadline: notAfter
            query: { protocol: file, path: "certs/*.json", items: certs, key: host }
            each: { field: notAfter, op: until-lt, value: 60 }
          - id: EX-TOOL
            title: Tool finding
            kind: misconfigured
            category: CFG
            severity: medium
            entity: domain
            query: { protocol: file, path: "tool/*.json", items: results, key: id }
            each: any
            emit: { check: "TOOL-{id}", title: "{text}", severity: { field: points, ranges: [ { min: 50, value: high } ], default: low } }
        """;

    private RuleFile Load()
    {
        var path = Path.Combine(_dir, "example.yaml");
        File.WriteAllText(path, Rules);
        return RuleLoader.LoadFile(path, "test", Runners.Registry().Validators);
    }

    private void Drop(string relative, string json)
    {
        var path = Path.Combine(Imports, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, json);
    }

    private async Task<ScanReport> Scan(Func<string, string?>? threshold = null) =>
        await new Scanner(Runners.Registry(), new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [Load()],
            Connection = new FilesConnection(),
            RunsDir = Runs,
            ImportsDir = Imports,
            Threshold = threshold ?? (_ => null),
        }, CancellationToken.None);

    private void DropAll()
    {
        Drop("users/u.json", """
            { "users": [ { "name": "u1", "display": "User One", "enabled": true, "lastLogon": "2026-01-01" },
                         { "name": "u2", "enabled": true, "lastLogon": "2026-10-19" },
                         { "name": "u3", "enabled": false, "lastLogon": "2020-01-01" } ],
              "admins": [ { "name": "a1" }, { "name": "a2" }, { "name": "a3" } ] }
            """);
        Drop("certs/c.json", """{ "certs": [ { "host": "web1.example.org", "notAfter": "2026-10-25T00:00:00Z" }, { "host": "web2.example.org", "notAfter": "2028-01-01T00:00:00Z" } ] }""");
        Drop("tool/t.json", """{ "results": [ { "id": "A-Krbtgt", "text": "krbtgt is old", "points": 60 } ] }""");
    }

    // A run with nothing of a kind (no findings) has no file for it.
    private List<T> Read<T>(ScanReport report, string file) =>
        File.Exists(Path.Combine(Runs, report.Manifest.RunId, file)) ? JsonLines.Read<T>(Path.Combine(Runs, report.Manifest.RunId, file)).ToList() : [];

    [Fact]
    public async Task A_scan_writes_a_verified_run_with_results_findings_and_coverage()
    {
        DropAll();

        var report = await Scan();

        Assert.Equal("ok", report.Manifest.Status);
        RunFolder.Verify(Path.Combine(Runs, report.Manifest.RunId));
        Assert.Equal(4, report.Queries);                    // one per distinct query: users and admins are different items
        var findings = Read<FindingRecord>(report, RunFolder.Findings);
        Assert.Equal(new[] { "EX-USER-STALE", "EX-ADMINS-MANY", "EX-CERT-EXPIRY", "TOOL-A-Krbtgt" }, findings.Select(f => f.CheckId));

        var stale = findings[0];
        Assert.Equal("u1", stale.Target);
        Assert.Equal("User One", stale.EntityName);
        Assert.Equal("u1 last signed in 2026-01-01", stale.Evidence);
        Assert.True(stale.Security);

        var cert = findings.Single(f => f.RuleId == "EX-CERT-EXPIRY");
        Assert.Equal("2026-10-25", cert.Deadline);
        Assert.Equal("high", cert.Severity);                // 5 days left

        var tool = findings.Single(f => f.RuleId == "EX-TOOL");
        Assert.Equal("krbtgt is old", tool.Title);
        Assert.Equal("high", tool.Severity);

        var results = Read<ResultRecord>(report, RunFolder.Results);
        Assert.Equal("pass", results.Single(r => r.RuleId == "EX-USER-STALE" && r.EntityKey == "u2").State);
        Assert.Equal("pass", results.Single(r => r.RuleId == "EX-USER-STALE" && r.EntityKey == "u3").State);
    }

    [Fact]
    public async Task A_tenant_threshold_changes_the_outcome()
    {
        DropAll();

        var report = await Scan(name => name == "example.stale-days" ? "400" : null);

        Assert.DoesNotContain(Read<FindingRecord>(report, RunFolder.Findings), f => f.RuleId == "EX-USER-STALE");
    }

    [Theory]
    [InlineData("""{ "policies": [ { "name": "p1", "state": "enabled", "mfa": false }, { "name": "p2", "state": "reportOnly", "mfa": true } ] }""", true)]
    [InlineData("""{ "policies": [ { "name": "p1", "state": "enabled", "mfa": true } ] }""", false)]
    [InlineData("""{ "policies": [ { "name": "p1", "mfa": true } ] }""", true)]     // state unreadable: not counted as enforced
    [InlineData("""{ "policies": [] }""", true)]
    public async Task A_must_exist_rule_counts_only_the_rows_that_satisfy_it(string policies, bool finding)
    {
        const string mustExist = """
            schema: keeper.rules/1
            system: example
            integration: files
            rules:
              - id: EX-MFA-POLICY-MISSING
                title: No enforced policy requires MFA
                kind: missing
                category: AUT
                severity: high
                entity: tenant
                query: { protocol: file, path: "ca/*.json", items: policies, key: name }
                count:
                  op: lt
                  value: 1
                  where:
                    all:
                      - { field: state, op: eq, value: enabled }
                      - { field: mfa, op: eq, value: true }
            """;
        var path = Path.Combine(_dir, "must.yaml");
        File.WriteAllText(path, mustExist);
        Drop("ca/p.json", policies);

        var report = await new Scanner(Runners.Registry(), new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(path, "test", Runners.Registry().Validators)],
            Connection = new FilesConnection(),
            RunsDir = Runs,
            ImportsDir = Imports,
        }, CancellationToken.None);

        var found = Read<FindingRecord>(report, RunFolder.Findings).Where(f => f.RuleId == "EX-MFA-POLICY-MISSING").ToList();
        var results = Read<ResultRecord>(report, RunFolder.Results).Where(r => r.RuleId == "EX-MFA-POLICY-MISSING").Select(r => $"{r.State} {r.Value} {r.Why}");
        Assert.True(finding == (found.Count > 0), $"{report.Manifest.Status}: {string.Join("; ", found.Select(f => f.Evidence))} | {string.Join("; ", results)} | {string.Join("; ", report.Manifest.Notes)}");
    }

    /// <summary>A per-host runner with canned answers: each host's local Administrators members and hotfixes.</summary>
    private sealed class HostsRunner : IRunner
    {
        public string Protocol => "hosts";
        public bool PerTarget => true;
        public IEnumerable<string> Validate(QuerySpec query) => [];

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            JsonObject Row(string member) => new() { ["host"] = context.Target, ["member"] = member };
            JsonObject Fix(int daysAgo) => new() { ["host"] = context.Target, ["installedOn"] = Iso.Utc(Now.AddDays(-daysAgo)) };
            return Task.FromResult(query.Text("what") == "admins"
                ? context.Target switch
                {
                    "pc1.example.org" => RunnerResult.Ok([Row("Administrator"), Row("Domain Admins"), Row("user7"), Row("user9")]),
                    "pc2.example.org" => RunnerResult.Ok([Row("Administrator"), Row("Domain Admins")]),
                    _ => RunnerResult.Failed("access denied"),
                }
                : context.Target switch
                {
                    "pc1.example.org" => RunnerResult.Ok([Fix(200), Fix(400)]),
                    "pc2.example.org" => RunnerResult.Ok([Fix(10), Fix(300)]),
                    _ => RunnerResult.Failed("access denied"),
                });
        }
    }

    [Fact]
    public async Task Per_host_queries_count_per_host_and_composite_keys_keep_every_member()
    {
        const string hosts = """
            schema: keeper.rules/1
            system: hosts
            integration: cim
            targets: { list: [pc1.example.org, pc2.example.org, pc3.example.org] }
            rules:
              - id: EX-ADMIN-UNEXPECTED
                title: Unexpected local administrator
                kind: misconfigured
                category: IAM
                severity: high
                entity: local-admin
                query: { protocol: hosts, what: admins, key: "{host}|{member}" }
                each: { field: member, op: notin, value: [Administrator, Domain Admins] }
              - id: EX-ADMIN-MANY
                title: Too many local administrators on one host
                kind: misconfigured
                category: IAM
                severity: medium
                entity: computer
                query: { protocol: hosts, what: admins, key: "{host}|{member}" }
                count: { op: gt, value: 3 }
              - id: EX-NOT-PATCHED
                title: No update installed for 45 days
                kind: broken
                category: LCM
                severity: high
                entity: computer
                query: { protocol: hosts, what: fixes, key: "{host}|{installedOn}" }
                count: { op: lt, value: 1, where: { field: installedOn, op: age-lt, value: 45 } }
            """;
        var path = Path.Combine(_dir, "hosts.yaml");
        File.WriteAllText(path, hosts);
        var registry = new RunnerRegistry([new HostsRunner()]);

        var report = await new Scanner(registry, new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(path, "test", registry.Validators)],
            Connection = new FilesConnection(),
            RunsDir = Runs,
            ImportsDir = Imports,
        }, CancellationToken.None);

        var findings = Read<FindingRecord>(report, RunFolder.Findings);
        Assert.Equal(new[] { "pc1.example.org|user7", "pc1.example.org|user9" },
            findings.Where(f => f.RuleId == "EX-ADMIN-UNEXPECTED").Select(f => f.Target).Order(StringComparer.Ordinal));
        Assert.Equal("pc1.example.org", Assert.Single(findings, f => f.RuleId == "EX-ADMIN-MANY").Target);
        Assert.Equal("pc1.example.org", Assert.Single(findings, f => f.RuleId == "EX-NOT-PATCHED").Target);

        // pc3 could not be read: unknown for the per-host counts, never a pass.
        var results = Read<ResultRecord>(report, RunFolder.Results);
        Assert.Equal("unknown", results.Single(r => r.RuleId == "EX-NOT-PATCHED" && r.EntityKey == "pc3.example.org").State);
        Assert.Equal("pass", results.Single(r => r.RuleId == "EX-NOT-PATCHED" && r.EntityKey == "pc2.example.org").State);
        Assert.Equal("partial", report.Manifest.Status);
    }

    [Fact]
    public async Task A_failed_query_makes_its_rules_unknown_never_passed()
    {
        DropAll();
        File.Delete(Path.Combine(Imports, "certs", "c.json"));

        var report = await Scan();

        Assert.Equal("partial", report.Manifest.Status);
        var results = Read<ResultRecord>(report, RunFolder.Results).Where(r => r.RuleId == "EX-CERT-EXPIRY").ToList();
        Assert.Equal("unknown", Assert.Single(results).State);
        var coverage = Read<CoverageRecord>(report, RunFolder.Coverage);
        Assert.Equal("failed", coverage.Single(c => c.Scope == "rule" && c.Item == "EX-CERT-EXPIRY").State);
    }
}
