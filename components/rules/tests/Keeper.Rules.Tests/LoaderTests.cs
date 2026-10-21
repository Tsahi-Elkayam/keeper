namespace Keeper.Rules.Tests;

public sealed class LoaderTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static readonly IReadOnlyDictionary<string, QueryValidator> Protocols = new Dictionary<string, QueryValidator>
    {
        ["ldap"] = q => q.Text("filter") is null ? ["filter is required"] : [],
    };

    private string Write(string name, string yaml)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, yaml);
        return path;
    }

    private const string Valid = """
        schema: keeper.rules/1
        system: active-directory
        name: Active Directory
        integration: ldap
        defaults:
          lens: security
          category: IAM
          refresh: 1d
          entity: user
        rules:
          - id: AD-USER-PWD-NEVER-EXPIRES
            title: Enabled users whose password never expires
            kind: misconfigured
            severity: medium
            query:
              protocol: ldap
              filter: "(&(objectCategory=person)(objectClass=user))"
              attributes: [sAMAccountName, userAccountControl]
              key: sAMAccountName
            each:
              all:
                - { field: userAccountControl, op: flag, value: 65536 }
                - { field: userAccountControl, op: noflag, value: 2 }
            evidence: "{sAMAccountName}"
          - id: AD-DOMAIN-ADMINS-MANY
            title: Too many Domain Admins
            kind: misconfigured
            severity: high
            query:
              protocol: ldap
              filter: "(memberOf=CN=Domain Admins,CN=Users,{DOMAINDN})"
              key: sAMAccountName
            count: { op: gt, value: 5, threshold: ad.max-domain-admins }
        """;

    [Fact]
    public void A_valid_file_loads_with_defaults_applied()
    {
        var file = RuleLoader.LoadFile(Write("ad.yaml", Valid), "builtin", Protocols);

        Assert.Equal("active-directory", file.System);
        Assert.Equal(2, file.Rules.Count);
        var first = file.Rules[0];
        Assert.Equal("IAM", first.Category);
        Assert.Equal("user", first.EntityType);
        Assert.Equal(TimeSpan.FromDays(1), first.Refresh);
        Assert.IsType<AllCondition>(first.Each);
        Assert.Equal("ad.max-domain-admins", file.Rules[1].Count!.Threshold);
    }

    [Fact]
    public void Element_conditions_and_grouped_counts_load()
    {
        var file = RuleLoader.LoadFile(Write("ok.yaml", """
            schema: keeper.rules/1
            system: example
            integration: ldap
            defaults: { lens: security, category: IAM, refresh: 1d, entity: policy, kind: misconfigured, severity: medium }
            rules:
              - id: EX-ASSIGNED-TO-ALL
                title: Required for everyone
                query: { protocol: ldap, filter: "(x=1)", key: id }
                each:
                  element:
                    of: assignments
                    match: all
                    where: { all: [ { field: group, op: eq, value: All }, { field: intent, op: eq, value: required } ] }
              - id: EX-SITE-SHARE
                title: Too many unmanaged devices per site
                query: { protocol: ldap, filter: "(x=2)", key: id }
                count: { op: gt, value: 20, by: site, percent: true, where: { field: managed, op: eq, value: false } }
                deadline: 2026-12-31
            """), "builtin", Protocols);

        var element = Assert.IsType<ElementCondition>(file.Rules[0].Each);
        Assert.True(element.All);
        Assert.Equal("assignments", element.Of);
        Assert.Equal(("site", true), (file.Rules[1].Count!.By, file.Rules[1].Count!.Percent));
        Assert.Equal("2026-12-31", file.Rules[1].Deadline);
    }

    [Theory]
    [InlineData("op: flag, value: 65536", "op: version-lt, value: soon", "needs a version")]
    [InlineData("op: flag, value: 65536", "op: in-cidr, value: \"192.0.2.0/24,not-a-net\"", "'not-a-net' is not a network")]
    [InlineData("op: flag, value: 65536", "op: duration-gt, value: P30D", "needs a number")]
    [InlineData("count: { op: gt, value: 5, threshold: ad.max-domain-admins }", "count: { op: gt, value: 5, percent: true, distinct: site }", "cannot be combined with distinct")]
    [InlineData("count: { op: gt, value: 5, threshold: ad.max-domain-admins }", "count: { op: gt, value: 5, percent: maybe }", "percent must be true or false")]
    [InlineData("evidence: \"{sAMAccountName}\"", "evidence: \"{sAMAccountName}\"\n    deadline: 2026-02-30", "not a real date")]
    public void New_operators_and_count_options_are_checked_at_load(string from, string to, string expected)
    {
        var path = Write("bad.yaml", Valid.Replace(from, to, StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "builtin", Protocols));

        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rules_with_the_same_query_share_its_id()
    {
        var a = new QuerySpec("ldap", new System.Text.Json.Nodes.JsonObject { ["filter"] = "(x=1)", ["base"] = "domain" }, "cn", null);
        var b = new QuerySpec("ldap", new System.Text.Json.Nodes.JsonObject { ["base"] = "domain", ["filter"] = "(x=1)" }, "cn", "displayName");
        var c = new QuerySpec("ldap", new System.Text.Json.Nodes.JsonObject { ["filter"] = "(x=2)" }, "cn", null);

        Assert.Equal(a.Id, b.Id);
        Assert.NotEqual(a.Id, c.Id);
    }

    [Theory]
    [InlineData("kind: misconfigured", "kind: on-fire", "kind 'on-fire'")]
    [InlineData("op: flag, value: 65536", "op: bitset, value: 65536", "unknown op 'bitset'")]
    [InlineData("evidence:", "evidnce:", "unknown field 'evidnce'")]
    [InlineData("severity: medium", "severity: urgent", "severity 'urgent'")]
    [InlineData("refresh: 1d", "refresh: daily", "refresh 'daily'")]
    [InlineData("threshold: ad.max-domain-admins", "threshold: Ad.Max", "threshold 'Ad.Max'")]
    [InlineData("protocol: ldap\n      filter: \"(&(objectCategory=person)(objectClass=user))\"", "protocol: carrier-pigeon", "unknown protocol 'carrier-pigeon'")]
    public void A_mistake_is_reported_with_its_place(string from, string to, string expected)
    {
        var path = Write("bad.yaml", Valid.Replace(from, to, StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "builtin", Protocols));

        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
        Assert.Contains("bad.yaml:", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Each_and_count_together_are_refused()
    {
        var path = Write("bad.yaml", Valid.Replace("    count: { op: gt", "    each: any\n    count: { op: gt", StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "builtin", Protocols));
        Assert.Contains("exactly one of 'each' or 'count'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_protocol_specific_problem_comes_from_the_runner()
    {
        var path = Write("bad.yaml", Valid.Replace("      filter: \"(&(objectCategory=person)(objectClass=user))\"\n", "", StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "builtin", Protocols));
        Assert.Contains("filter is required", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Anchors_and_aliases_are_refused()
    {
        var path = Write("bad.yaml", Valid.Replace("defaults:", "defaults: &d", StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(path, "builtin", Protocols));
        Assert.Contains("anchors", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_rule_ids_across_files_are_refused()
    {
        Write("a.yaml", Valid);
        Write("b.yaml", Valid.Replace("system: active-directory", "system: active-directory-2", StringComparison.Ordinal));

        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadAll([(_dir, "builtin")], Protocols));
        Assert.Contains("already defined", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_severity_map_by_days_left_is_read()
    {
        var yaml = """
            schema: keeper.rules/1
            system: certificates
            integration: tls
            rules:
              - id: TLS-CERT-EXPIRY
                title: Certificate expires soon
                kind: broken
                category: PKI
                entity: endpoint
                severity:
                  daysLeft: notAfter
                  ranges:
                    - { max: 0, value: critical }
                    - { max: 14, value: high }
                    - { max: 30, value: medium }
                  default: low
                deadline: notAfter
                query: { protocol: tls, port: 443, key: endpoint }
                each: { field: notAfter, op: until-lt, value: 60, threshold: tls.cert-notice-days }
            """;

        var file = RuleLoader.LoadFile(Write("tls.yaml", yaml), "builtin", null);

        var rule = Assert.Single(file.Rules);
        Assert.Equal("notAfter", rule.SeverityBy!.DaysLeft);
        Assert.Equal(3, rule.SeverityBy.Ranges.Count);
        Assert.Equal("low", rule.Severity);
        Assert.Equal("notAfter", rule.Deadline);
    }
}
