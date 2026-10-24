using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Http;

namespace Keeper.Scan.Tests;

public sealed class FortigatePackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-fgt-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class Answers(Func<string, string?> respond) : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            var body = respond(request.RequestUri.AbsolutePath);
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class Firewall(HttpMessageHandler handler) : IConnection
    {
        public string Instance => "edge-fw";
        public string Type => "fortigate";
        public string Endpoint => "https://198.51.100.1";
        public string AuthKind => "bearer";
        public string? Identity => null;
        public IReadOnlyList<string>? Protocols => IntegrationTypes.Find("fortigate")!.Protocols;
        public IReadOnlyList<string> ReadPaths => IntegrationTypes.Find("fortigate")!.ReadPaths;
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => name == "token" ? "rest-api-token" : null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => handler;

        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "rest-api-token");
            return Task.CompletedTask;
        }
    }

    /// <summary>FortiOS wraps every answer: an array for tables, an object for settings.</summary>
    private static string Results(object results) => JsonSerializer.Serialize(new { http_method = "GET", results, vdom = "root", status = "success" });

    private static string Respond(string path) => path switch
    {
        "/api/v2/cmdb/system/interface" => Results(new object[]
        {
            new { name = "wan1", allowaccess = "ping https ssh http" },
            new { name = "lan", allowaccess = "ping https ssh" },
            new { name = "mgmt", allowaccess = "ping telnet" },
        }),
        "/api/v2/cmdb/firewall/policy" => Results(new object[]
        {
            new { policyid = 1, name = "allow-all", status = "enable", action = "accept", srcaddr = new[] { new { name = "all" } }, dstaddr = new[] { new { name = "all" } }, service = new[] { new { name = "ALL" } }, logtraffic = "all" },
            new { policyid = 2, name = "web", status = "enable", action = "accept", srcaddr = new[] { new { name = "lan" } }, dstaddr = new[] { new { name = "web-srv" } }, service = new[] { new { name = "HTTPS" } }, logtraffic = "disable" },
            new { policyid = 3, name = "old-allow-all", status = "disable", action = "accept", srcaddr = new[] { new { name = "all" } }, dstaddr = new[] { new { name = "all" } }, service = new[] { new { name = "ALL" } }, logtraffic = "disable" },
            new { policyid = 4, name = "good", status = "enable", action = "accept", srcaddr = new[] { new { name = "lan" } }, dstaddr = new[] { new { name = "dmz" } }, service = new[] { new { name = "HTTPS" }, new { name = "SSH" } }, logtraffic = "all" },
        }),
        "/api/v2/cmdb/system/admin" => Results(new object[]
        {
            new Dictionary<string, object> { ["name"] = "admin", ["trusthost1"] = "0.0.0.0 0.0.0.0", ["two-factor"] = "disable" },
            new Dictionary<string, object> { ["name"] = "ops", ["trusthost1"] = "192.0.2.0 255.255.255.0", ["two-factor"] = "fortitoken" },
            new Dictionary<string, object> { ["name"] = "robot", ["two-factor"] = "fortitoken" },
        }),
        "/api/v2/cmdb/system/global" => Results(new Dictionary<string, object> { ["hostname"] = "edge-fw", ["admintimeout"] = 60, ["strong-crypto"] = "disable" }),
        "/api/v2/cmdb/system/snmp/community" => Results(new object[] { new { id = 1, name = "mon", status = "enable" }, new { id = 2, name = "off", status = "disable" } }),
        "/api/v2/cmdb/system/ntp" => Results(new { ntpsync = "disable" }),
        "/api/v2/cmdb/vpn.ipsec/phase1-interface" => Results(new object[]
        {
            new { name = "to-hq", proposal = "aes256-sha256 3des-sha1", dhgrp = "14 2" },
            new { name = "to-branch", proposal = "aes256-sha256 aes128gcm-prfsha256", dhgrp = "14 21" },
        }),
        _ => throw new InvalidOperationException("Keeper asked for " + path),
    };

    private async Task<(List<FindingRecord> Findings, Answers Answers)> Scan()
    {
        var answers = new Answers(Respond);
        var registry = new RunnerRegistry([new HttpRunner()]);
        var file = RuleLoader.LoadFile(Path.Combine(FindRepoRoot(), "rules", "fortigate.yaml"), "builtin", registry.Validators);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [file],
            Connection = new Firewall(answers),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
        }, CancellationToken.None);
        var path = Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings);
        return (File.Exists(path) ? JsonLines.Read<FindingRecord>(path).ToList() : [], answers);
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private static string[] Flagged(List<FindingRecord> findings, string rule) =>
        [.. findings.Where(f => f.RuleId == rule).Select(f => f.Target ?? "").Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Every_rule_flags_what_it_should_and_leaves_the_rest_alone()
    {
        var (findings, _) = await Scan();

        Assert.Equal(["mgmt", "wan1"], Flagged(findings, "FGT-ADMIN-ACCESS-OVER-CLEARTEXT"));
        Assert.Equal(["1"], Flagged(findings, "FGT-POLICY-ALLOWS-ALL"));                 // the disabled copy is not live
        Assert.Equal(["2"], Flagged(findings, "FGT-POLICY-NOT-LOGGED"));
        Assert.Equal(["admin", "robot"], Flagged(findings, "FGT-ADMIN-NO-TRUSTED-HOST"));   // a missing trusted host is the same as any
        Assert.Equal(["admin"], Flagged(findings, "FGT-ADMIN-NO-TWO-FACTOR"));
        Assert.Equal(["admin"], Flagged(findings, "FGT-ADMIN-DEFAULT-ACCOUNT"));
        Assert.Single(findings, f => f.RuleId == "FGT-STRONG-CRYPTO-OFF");
        Assert.Single(findings, f => f.RuleId == "FGT-ADMIN-TIMEOUT-LONG");
        Assert.Equal(["1"], Flagged(findings, "FGT-SNMP-COMMUNITY-IN-USE"));              // the disabled one does not count
        Assert.Single(findings, f => f.RuleId == "FGT-NTP-NOT-SYNCED");
        Assert.Equal(["to-hq"], Flagged(findings, "FGT-IPSEC-WEAK-PROPOSAL"));            // group 21 and gcm are fine
    }

    [Fact]
    public async Task Keeper_only_reads_the_allowed_tables()
    {
        var (_, answers) = await Scan();

        var allowed = IntegrationTypes.Find("fortigate")!.ReadPaths;
        Assert.NotEmpty(answers.Paths);
        Assert.All(answers.Paths, p => Assert.Contains(p, allowed));
    }

    [Fact]
    public async Task A_rule_that_asks_for_the_configuration_backup_is_refused_before_anything_is_sent()
    {
        var answers = new Answers(_ => "{}");
        var result = await new HttpRunner().RunAsync(
            new QuerySpec("http", new JsonObject { ["path"] = "/api/v2/monitor/system/config/backup", ["items"] = "results" }, "name", null),
            new RunnerContext(new Firewall(answers), null, _dir, null, DateTimeOffset.UtcNow, TimeSpan.FromSeconds(10), _ => { }), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Empty(answers.Paths);
    }
}
