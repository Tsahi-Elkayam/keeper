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

    private async Task<ScanReport> Scan(Func<string, string?>? threshold = null, Func<string, PreviousRead?>? previousRows = null, RuleFile? file = null) =>
        await new Scanner(Runners.Registry(), new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [file ?? Load()],
            Connection = new FilesConnection(),
            RunsDir = Runs,
            ImportsDir = Imports,
            Threshold = threshold ?? (_ => null),
            PreviousRows = previousRows ?? (_ => null),
        }, CancellationToken.None);

    private string UsersQuery => Load().Rules.Single(r => r.Id == "EX-USER-STALE").Query.Id;

    /// <summary>A directory-like runner: returns the rows it is given, per host when per-target. Never fails.</summary>
    private sealed class FakeRunner(bool perTarget, Dictionary<string, int> rowsPerHost) : IRunner
    {
        public string Protocol => "fake";
        public bool PerTarget => perTarget;
        public IEnumerable<string> Validate(QuerySpec query) => [];

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            var host = context.Target ?? "-";
            var rows = Enumerable.Range(1, rowsPerHost.GetValueOrDefault(host))
                .Select(i => new JsonObject { ["name"] = $"{host}|admin{i}", ["id"] = $"admin{i}", ["host"] = host }).ToList();
            return Task.FromResult(RunnerResult.Ok(rows));
        }
    }

    private const string FakeRules = """
        schema: keeper.rules/1
        system: example
        integration: files
        defaults: { lens: both, refresh: 1d, category: IAM, kind: misconfigured, severity: high, entity: member }
        TARGETS
        rules:
          - id: EX-ADMIN-UNEXPECTED
            title: Unexpected administrator
            query: { protocol: fake, key: name }
            each: { field: name, op: match, value: "admin9" }
          - id: EX-ADMINS-TOO-MANY
            title: Too many administrators
            query: { protocol: fake, key: name }
            count: { op: gt, value: 2 }
        """;

    private static Func<string, PreviousRead?> Clean(int? rows, params PartialRead[] since) => _ => rows is int n ? new PreviousRead(n, since) : null;

    /// <summary>A read the drop guard held back, <paramref name="daysAgo"/> before the scan.</summary>
    private static PartialRead Low(int count, double daysAgo) => new(count, Now.AddDays(-daysAgo), Low: true);

    /// <summary>A partial read for another reason (a row cap).</summary>
    private static PartialRead Other(int count, double daysAgo) => new(count, Now.AddDays(-daysAgo), Low: false);

    private async Task<ScanReport> ScanFake(Dictionary<string, int> rowsPerHost, Func<string, PreviousRead?> previousRows, bool perTarget = false)
    {
        var path = Path.Combine(_dir, "fake.yaml");
        File.WriteAllText(path, FakeRules.Replace("TARGETS", perTarget ? "targets: { list: [pc01.example.org, pc02.example.org] }" : "", StringComparison.Ordinal));
        var registry = new RunnerRegistry([new FakeRunner(perTarget, rowsPerHost)]);
        var file = RuleLoader.LoadFile(path, "test", registry.Validators);
        return await new Scanner(registry, new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [file], Connection = new FilesConnection(), RunsDir = Runs, ImportsDir = Imports, PreviousRows = previousRows,
        }, CancellationToken.None);
    }

    [Theory]
    [InlineData(null, "ok")]     // never read before
    [InlineData(3, "ok")]
    [InlineData(5, "ok")]        // 3 of 5 is more than half
    [InlineData(7, "partial")]   // 3 of 7 is less than half: a lost permission looks like this
    public async Task A_read_that_suddenly_returns_much_less_than_its_last_clean_read_is_partial(int? previous, string state)
    {
        var report = await ScanFake(new() { ["-"] = 3 }, Clean(previous));

        var query = Assert.Single(Read<CoverageRecord>(report, RunFolder.Coverage), c => c.Scope == "query");
        Assert.Equal(state, query.State);
        Assert.Equal(3, query.Count);
        // Its rules are not clean either, so the tracker can resolve nothing through them.
        Assert.Equal(state, Read<CoverageRecord>(report, RunFolder.Coverage).Single(c => c.Scope == "rule" && c.Item == "EX-ADMIN-UNEXPECTED").State);
        if (state == "partial")
        {
            Assert.Equal("partial", report.Manifest.Status);
            Assert.Contains("the last clean scan 7", query.Reason, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task An_empty_answer_after_rows_stays_partial_until_three_scans_over_two_days_read_as_low()
    {
        CoverageRecord QueryOf(ScanReport report) => Assert.Single(Read<CoverageRecord>(report, RunFolder.Coverage), c => c.Scope == "query");

        // The last clean read had 900 rows; then nothing, again and again. A role not activated looks the same.
        var first = QueryOf(await ScanFake(new() { ["-"] = 0 }, Clean(900)));
        var second = QueryOf(await ScanFake(new() { ["-"] = 0 }, Clean(900, Low(0, 1))));
        var third = QueryOf(await ScanFake(new() { ["-"] = 0 }, Clean(900, Low(0, 1), Low(0, 2))));
        // Three scans within the hour are not three days of evidence.
        var hasty = QueryOf(await ScanFake(new() { ["-"] = 0 }, Clean(900, Low(0, 0.02), Low(0, 0.04))));
        // A partial for another reason (a row cap) breaks the streak.
        var broken = QueryOf(await ScanFake(new() { ["-"] = 0 }, Clean(900, Low(0, 1), Other(850, 2))));

        Assert.Equal(new[] { "partial", "partial", "ok", "partial", "partial" }, new[] { first.State, second.State, third.State, hasty.State, broken.State });
        Assert.StartsWith(Scanner.LowReadMarker, first.Reason, StringComparison.Ordinal);
        Assert.Contains("accepted after 3 scans", third.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Each_host_of_a_per_host_query_is_judged_against_its_own_previous_read()
    {
        // pc01 reads as before; pc02 suddenly returns nothing (a broken WMI repository looks like this).
        var report = await ScanFake(new() { ["pc01.example.org"] = 3, ["pc02.example.org"] = 0 },
            item => new PreviousRead(item.EndsWith("@pc01.example.org", StringComparison.Ordinal) ? 3 : 4, []), perTarget: true);

        var hosts = Read<CoverageRecord>(report, RunFolder.Coverage).Where(c => c.Scope == "target").ToDictionary(c => c.Item.Split('@')[1], c => c.State);
        Assert.Equal("ok", hosts["pc01.example.org"]);
        Assert.Equal("partial", hosts["pc02.example.org"]);

        // pc02's count of administrators (0) is only a floor: not a pass. pc01's (3 > 2) fails as usual.
        var counts = Read<ResultRecord>(report, RunFolder.Results).Where(r => r.RuleId == "EX-ADMINS-TOO-MANY").ToDictionary(r => r.EntityKey, r => r.State);
        Assert.Equal("unknown", counts["pc02.example.org"]);
        Assert.Equal("fail", counts["pc01.example.org"]);
    }

    private async Task<ScanReport> ScanUsers(string countYaml, string? deadline = null)
    {
        Drop("users/d.json", """
            { "users": [ { "name": "a", "site": "north", "managed": false, "os": "10" }, { "name": "b", "site": "north", "managed": false, "os": "10" },
                         { "name": "c", "site": "north", "managed": true, "os": "11" }, { "name": "d", "site": "south", "managed": true, "os": "11" } ] }
            """);
        var path = Path.Combine(_dir, "count.yaml");
        File.WriteAllText(path, $$"""
            schema: keeper.rules/1
            system: example
            integration: files
            defaults: { lens: both, refresh: 1d, category: HYG, kind: misconfigured, severity: medium, entity: device }
            rules:
              - id: EX-COUNT
                title: Count
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: {{countYaml}}
            {{(deadline is null ? "" : $"    deadline: {deadline}")}}
            """);
        return await Scan(file: RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));
    }

    [Fact]
    public async Task A_count_by_group_judges_each_group_on_its_own()
    {
        var report = await ScanUsers("{ op: gt, value: 1, by: site, where: { field: managed, op: eq, value: false } }");

        var results = Read<ResultRecord>(report, RunFolder.Results).ToDictionary(r => r.EntityKey, r => r.State);
        Assert.Equal("fail", results["north"]);   // two unmanaged in the north
        Assert.Equal("pass", results["south"]);
        Assert.Equal("north", Assert.Single(Read<FindingRecord>(report, RunFolder.Findings)).Target);
    }

    [Fact]
    public async Task A_share_count_compares_the_percentage_of_judged_rows()
    {
        var report = await ScanUsers("{ op: ge, value: 50, percent: true, where: { field: managed, op: eq, value: false } }", deadline: "2026-12-31");

        var finding = Assert.Single(Read<FindingRecord>(report, RunFolder.Findings));   // 2 of 4 = 50%
        Assert.Contains("50% of 4 rows", finding.Evidence, StringComparison.Ordinal);
        Assert.Equal("2026-12-31", finding.Deadline);   // a deadline of its own, on a count finding too
    }

    [Fact]
    public async Task Rows_that_cannot_be_judged_never_turn_a_count_into_a_pass()
    {
        // Two devices unmanaged, two whose state is unreadable: "more than 3" is not known to pass.
        Drop("users/d.json", """
            { "users": [ { "name": "a", "managed": false }, { "name": "b", "managed": false }, { "name": "c" }, { "name": "d" } ] }
            """);
        var path = Path.Combine(_dir, "floor.yaml");
        File.WriteAllText(path, """
            schema: keeper.rules/1
            system: example
            integration: files
            defaults: { lens: both, refresh: 1d, category: HYG, kind: misconfigured, severity: medium, entity: device }
            rules:
              - id: EX-TOO-MANY
                title: Too many unmanaged
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: { op: gt, value: 3, where: { field: managed, op: eq, value: false } }
              - id: EX-SOME
                title: Some unmanaged
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: { op: gt, value: 1, where: { field: managed, op: eq, value: false } }
            """);

        var report = await Scan(file: RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));

        var results = Read<ResultRecord>(report, RunFolder.Results).ToDictionary(r => r.RuleId, r => r.State);
        Assert.Equal("n-a", results["EX-TOO-MANY"]);   // 2, but up to 4
        Assert.Equal("fail", results["EX-SOME"]);      // 2 > 1 whatever the other two are
    }

    [Theory]
    [InlineData("{ op: eq, value: 3, where: { field: managed, op: eq, value: false } }", "n-a")]   // 2 to 4: may be exactly 3
    [InlineData("{ op: ne, value: 3, where: { field: managed, op: eq, value: false } }", "n-a")]   // fails at 2, passes at 3
    [InlineData("{ op: eq, value: 7, where: { field: managed, op: eq, value: false } }", "pass")]  // 2 to 4 is never 7
    [InlineData("{ op: gt, value: 60, percent: true, where: { field: managed, op: eq, value: false } }", "n-a")]    // 50% to 100%: may be above 60
    [InlineData("{ op: gt, value: 40, percent: true, where: { field: managed, op: eq, value: false } }", "fail")]   // 50% to 100%: above 40 either way
    public async Task Eq_ne_and_shares_are_unknown_when_unjudged_rows_reach_the_limit(string countYaml, string state)
    {
        Drop("users/d.json", """{ "users": [ { "name": "a", "managed": false }, { "name": "b", "managed": false }, { "name": "c" }, { "name": "d" } ] }""");
        var path = Path.Combine(_dir, "eq.yaml");
        File.WriteAllText(path, $$"""
            schema: keeper.rules/1
            system: example
            integration: files
            defaults: { lens: both, refresh: 1d, category: HYG, kind: misconfigured, severity: medium, entity: device }
            rules:
              - id: EX-EQ
                title: Count
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: {{countYaml}}
            """);

        var report = await Scan(file: RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));

        Assert.Equal(state, Assert.Single(Read<ResultRecord>(report, RunFolder.Results)).State);
    }

    [Fact]
    public async Task Rows_without_the_group_field_are_not_a_group_that_could_pass()
    {
        Drop("users/d.json", """{ "users": [ { "name": "a", "managed": false, "site": "north" }, { "name": "b", "managed": false } ] }""");
        var path = Path.Combine(_dir, "nogroup.yaml");
        File.WriteAllText(path, """
            schema: keeper.rules/1
            system: example
            integration: files
            defaults: { lens: both, refresh: 1d, category: HYG, kind: misconfigured, severity: medium, entity: device }
            rules:
              - id: EX-BY-SITE
                title: Unmanaged per site
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: { op: gt, value: 0, by: site, where: { field: managed, op: eq, value: false } }
            """);

        var report = await Scan(file: RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));

        var results = Read<ResultRecord>(report, RunFolder.Results).ToDictionary(r => r.EntityKey, r => r.State);
        Assert.Equal("fail", results["north"]);
        Assert.Equal("n-a", results["(no site)"]);
    }

    [Fact]
    public async Task Rows_without_the_group_field_dilute_a_share_even_when_they_cannot_match()
    {
        // b is managed and has no site: it adds nothing to a count, but may belong to the north and halve its share.
        Drop("users/d.json", """{ "users": [ { "name": "a", "managed": false, "site": "north" }, { "name": "b", "managed": true } ] }""");
        var path = Path.Combine(_dir, "dilute.yaml");
        File.WriteAllText(path, """
            schema: keeper.rules/1
            system: example
            integration: files
            defaults: { lens: both, refresh: 1d, category: HYG, kind: misconfigured, severity: medium, entity: device }
            rules:
              - id: EX-SHARE
                title: Unmanaged share per site
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: { op: gt, value: 50, by: site, percent: true, where: { field: managed, op: eq, value: false } }
              - id: EX-COUNT
                title: Unmanaged per site
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                count: { op: gt, value: 0, by: site, where: { field: managed, op: eq, value: false } }
            """);

        var report = await Scan(file: RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));

        var results = Read<ResultRecord>(report, RunFolder.Results).ToDictionary(r => (r.RuleId, r.EntityKey), r => r.State);
        Assert.Equal("n-a", results[("EX-SHARE", "north")]);       // 100%, or 50% with b
        Assert.Equal("n-a", results[("EX-SHARE", "(no site)")]);
        Assert.Equal("fail", results[("EX-COUNT", "north")]);
        Assert.False(results.ContainsKey(("EX-COUNT", "(no site)")));   // b could not change the count
    }

    private async Task<ScanReport> ScanRules(string rules, Func<string, IReadOnlyDictionary<string, CleanRead>>? lastClean = null,
        Func<string, string?>? threshold = null)
    {
        var path = Path.Combine(_dir, "rules.yaml");
        File.WriteAllText(path, "schema: keeper.rules/1\nsystem: example\nintegration: files\n" +
            "defaults: { lens: both, refresh: 1d, category: IAM, kind: misconfigured, severity: high, entity: device }\nrules:\n" + rules);
        return await new Scanner(Runners.Registry(), new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(path, "test", Runners.Registry().Validators)], Connection = new FilesConnection(), RunsDir = Runs,
            ImportsDir = Imports, Threshold = threshold ?? (_ => null), LastCleanRows = lastClean ?? (_ => new Dictionary<string, CleanRead>()),
        }, CancellationToken.None);
    }

    private string RunText(ScanReport report) =>
        string.Concat(Directory.GetFiles(Path.Combine(Runs, report.Manifest.RunId)).Select(File.ReadAllText));

    [Fact]
    public async Task A_masked_field_never_leaves_the_scan_but_conditions_still_read_it()
    {
        Drop("devices/d.json", """{ "devices": [ { "name": "d1", "pin": "4821", "model": "old" }, { "name": "d2", "pin": "", "model": "new" } ] }""");

        var report = await ScanRules("""
              - id: EX-PIN-STORED
                title: A PIN is stored in clear
                query: { protocol: file, path: "devices/d.json", items: devices, key: name }
                each: { field: pin, op: notempty }
                mask: [pin]
                severity: { field: pin, ranges: [ { min: 1000, value: critical } ], default: low }
              - id: EX-PIN-SHORT
                title: Four-digit PIN
                query: { protocol: file, path: "devices/d.json", items: devices, key: name }
                each: { field: pin, op: match, value: "^[0-9]{4}$" }
                evidence: "{name} has PIN {pin}"
              - id: EX-OLD-MODEL
                title: Old model
                query: { protocol: file, path: "devices/d.json", items: devices, key: name }
                each: { field: model, op: eq, value: old }
            """);

        Assert.DoesNotContain("4821", RunText(report), StringComparison.Ordinal);
        var findings = Read<FindingRecord>(report, RunFolder.Findings).ToDictionary(f => f.RuleId);
        Assert.Equal("the value is masked", findings["EX-PIN-STORED"].Evidence);
        Assert.Equal("critical", findings["EX-PIN-STORED"].Severity);   // judged on the real value, which is not shown
        Assert.Equal("d1 has PIN set", findings["EX-PIN-SHORT"].Evidence);   // another rule's mask holds on the same rows
        var results = Read<ResultRecord>(report, RunFolder.Results).Where(r => r.EntityKey == "d1").ToDictionary(r => r.RuleId, r => r.Value);
        Assert.Equal("(masked)", results["EX-PIN-SHORT"]);
        Assert.Equal("old", results["EX-OLD-MODEL"]);   // a rule that does not read the masked field shows its value
        Assert.Contains(Read<RowRecord>(report, RunFolder.Rows), r => r.EntityKey == "d2" && r.Attrs["pin"]!.ToString() == "");
    }

    private const string ChangeRule = """
          - id: EX-MEMBERS-CHANGED
            title: Group membership changed
            query: { protocol: file, path: "groups/g.json", items: groups, key: name }
            each: { field: members, op: changed }
            evidence: "{name}: {members}, was {_previous.members}"
        """;

    [Fact]
    public async Task A_change_is_judged_against_the_entitys_last_clean_read()
    {
        Drop("groups/g.json", """{ "groups": [ { "name": "admins", "members": ["a", "c"] }, { "name": "ops", "members": ["x"] }, { "name": "new-group", "members": ["z"] } ] }""");
        var before = new CleanRead("2026-10-19T06:00:00Z", new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase)
        {
            ["admins"] = new() { ["name"] = "admins", ["members"] = new JsonArray("a", "b") },
            ["ops"] = new() { ["name"] = "ops", ["members"] = new JsonArray("x") },
        });

        var report = await ScanRules(ChangeRule, query => new Dictionary<string, CleanRead> { [query] = before });

        var results = Read<ResultRecord>(report, RunFolder.Results).ToDictionary(r => r.EntityKey, r => r.State);
        Assert.Equal(("fail", "pass", "fail"), (results["admins"], results["ops"], results["new-group"]));
        Assert.Contains(Read<FindingRecord>(report, RunFolder.Findings), f => f.Evidence == "admins: a, c, was a, b");
        Assert.DoesNotContain("_previous", RunText(report), StringComparison.Ordinal);   // rows are kept as read
    }

    [Fact]
    public async Task A_row_kept_before_a_field_was_masked_does_not_show_it_through_previous()
    {
        Drop("devices/d.json", """{ "devices": [ { "name": "d1", "pin": "4821" } ] }""");
        var before = new CleanRead("2026-10-19T06:00:00Z", new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase)
        {
            ["d1"] = new() { ["name"] = "d1", ["pin"] = "1234" },   // kept when pin was not masked yet
        });

        var report = await ScanRules("""
              - id: EX-PIN-CHANGED
                title: PIN set or cleared
                query: { protocol: file, path: "devices/d.json", items: devices, key: name }
                each: { field: pin, op: changed }
                mask: [pin]
                evidence: "{name}: was {_previous.pin}"
              - id: EX-ANY
                title: Every device
                query: { protocol: file, path: "devices/d.json", items: devices, key: name }
                each: { field: _new, op: eq, value: false }
                evidence: "{name} was {_previous.pin}"
            """, query => new Dictionary<string, CleanRead> { [query] = before });

        Assert.DoesNotContain("1234", RunText(report), StringComparison.Ordinal);
        Assert.Equal("pass", Read<ResultRecord>(report, RunFolder.Results).Single(r => r.RuleId == "EX-PIN-CHANGED").State);   // set then, set now
        Assert.Equal("d1 was set", Read<FindingRecord>(report, RunFolder.Findings).Single(f => f.RuleId == "EX-ANY").Evidence);
    }

    [Fact]
    public async Task With_no_earlier_clean_read_a_change_cannot_be_judged()
    {
        Drop("groups/g.json", """{ "groups": [ { "name": "admins", "members": ["a"] } ] }""");

        var report = await ScanRules(ChangeRule);

        Assert.Equal("n-a", Assert.Single(Read<ResultRecord>(report, RunFolder.Results)).State);
    }

    [Fact]
    public async Task An_hour_of_the_day_is_not_configured_until_the_time_zone_is_set()
    {
        Drop("users/d.json", """{ "users": [ { "name": "u1", "at": "2026-10-19T23:00:00Z" } ] }""");
        const string night = """
              - id: EX-NIGHT
                title: Sign-in at night
                query: { protocol: file, path: "users/d.json", items: users, key: name }
                each: { field: at, op: hour-in, value: "22-6" }
            """;

        var unset = Assert.Single(Read<ResultRecord>(await ScanRules(night), RunFolder.Results));
        var set = Assert.Single(Read<ResultRecord>(await ScanRules(night, threshold: n => n == Rule.TimeZoneSetting ? "UTC" : null), RunFolder.Results));

        Assert.Equal("n-a", unset.State);
        Assert.Contains("threshold.time-zone", unset.Why, StringComparison.Ordinal);
        Assert.Equal("fail", set.State);
    }

    [Fact]
    public async Task A_distinct_count_counts_values_not_rows()
    {
        var report = await ScanUsers("{ op: gt, value: 1, distinct: os }");

        Assert.Contains("2 distinct", Assert.Single(Read<FindingRecord>(report, RunFolder.Findings)).Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_per_host_key_always_names_its_host_so_two_machines_never_share_an_entity()
    {
        var registry = new RunnerRegistry([new FakeRunner(true, new() { ["pc01.example.org"] = 1, ["pc02.example.org"] = 1 })]);
        var path = Path.Combine(_dir, "keys.yaml");
        // The key is a field that is the same on both machines (an event id, a service name).
        File.WriteAllText(path, """
            schema: keeper.rules/1
            system: example
            integration: files
            targets: { list: [pc01.example.org, pc02.example.org] }
            rules:
              - id: EX-MEMBER
                title: Member
                kind: misconfigured
                lens: both
                category: IAM
                severity: low
                entity: member
                query: { protocol: fake, key: id }
                each: any
            """);
        var file = RuleLoader.LoadFile(path, "test", registry.Validators);

        var report = await new Scanner(registry, new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [file], Connection = new FilesConnection(), RunsDir = Runs, ImportsDir = Imports,
        }, CancellationToken.None);

        var keys = Read<RowRecord>(report, RunFolder.Rows).Select(r => r.EntityKey).ToList();
        Assert.Equal(2, keys.Distinct().Count());
        Assert.All(keys, k => Assert.Matches("^pc0[12]\\.example\\.org\\|", k));
    }

    [Fact]
    public async Task A_short_host_name_inside_a_key_is_not_mistaken_for_the_host()
    {
        // Hosts named "admin1" and "db": their row ids are admin1 (the host itself - kept) and admin1 (not "db" - prefixed).
        var registry = new RunnerRegistry([new FakeRunner(true, new() { ["admin1"] = 1, ["db"] = 1 })]);
        var path = Path.Combine(_dir, "short.yaml");
        File.WriteAllText(path, """
            schema: keeper.rules/1
            system: example
            integration: files
            targets: { list: [admin1, db] }
            rules:
              - id: EX-MEMBER
                title: Member
                kind: misconfigured
                lens: both
                category: IAM
                severity: low
                entity: member
                query: { protocol: fake, key: id }
                each: any
            """);

        var report = await new Scanner(registry, new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [RuleLoader.LoadFile(path, "test", registry.Validators)], Connection = new FilesConnection(), RunsDir = Runs, ImportsDir = Imports,
        }, CancellationToken.None);

        Assert.Equal(new[] { "admin1", "db|admin1" }, Read<RowRecord>(report, RunFolder.Rows).Select(r => r.EntityKey).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Imported_files_are_not_drop_checked_because_they_cannot_lose_sight_of_rows()
    {
        DropAll();   // three users, where the previous scan read seven

        var report = await Scan(previousRows: q => q == UsersQuery ? new PreviousRead(7, []) : null);

        Assert.Equal("ok", Read<CoverageRecord>(report, RunFolder.Coverage).Single(c => c.Scope == "query" && c.Item == UsersQuery).State);
    }

    [Fact]
    public async Task Fewer_rows_than_min_rows_is_partial_whatever_the_previous_scan_said()
    {
        DropAll();
        var path = Path.Combine(_dir, "min.yaml");
        File.WriteAllText(path, Rules.Replace("query: { protocol: file, path: \"users/*.json\", items: users, key: name, name: display }",
            "query: { protocol: file, path: \"users/*.json\", items: users, key: name, name: display, min_rows: 5 }", StringComparison.Ordinal));
        var file = RuleLoader.LoadFile(path, "test", Runners.Registry().Validators);
        var queryId = file.Rules.Single(r => r.Id == "EX-USER-STALE").Query.Id;

        var report = await Scan(file: file);

        var query = Read<CoverageRecord>(report, RunFolder.Coverage).Single(c => c.Scope == "query" && c.Item == queryId);
        Assert.Equal("partial", query.State);
        Assert.Contains("at least 5", query.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("many")]
    public void Min_rows_must_be_a_whole_number_of_at_least_one(string value)
    {
        var path = Path.Combine(_dir, "bad.yaml");
        File.WriteAllText(path, Rules.Replace("items: admins, key: name }", $"items: admins, key: name, min_rows: {value} }}", StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "test", Runners.Registry().Validators));
        Assert.Contains("min_rows", ex.Message, StringComparison.Ordinal);
    }

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
