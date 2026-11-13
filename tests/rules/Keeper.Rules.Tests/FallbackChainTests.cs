namespace Keeper.Rules.Tests;

public sealed class FallbackChainTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-chain-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static readonly IReadOnlyDictionary<string, QueryValidator> Protocols = new Dictionary<string, QueryValidator>
    {
        ["registry"] = _ => [],
        ["cim"] = _ => [],
        ["ldap"] = _ => [],
        ["eventlog"] = _ => [],
    };

    private const string Header = """
        schema: keeper.rules/1
        system: windows-example
        integration: cim
        defaults: { lens: security, category: CFG, refresh: 1d, entity: computer, kind: misconfigured, severity: medium }
        """;

    private RuleFile Load(string rules) =>
        RuleLoader.LoadFile(Path.Combine(_dir, Write(rules)), "builtin", Protocols);

    private string Write(string rules)
    {
        File.WriteAllText(Path.Combine(_dir, "r.yaml"), $"{Header}\n{rules}");
        return "r.yaml";
    }

    private static string Rule(string chain, string protocol = "registry", string id = "EX-1") => $$"""
        rules:
          - id: {{id}}
            title: Example
            {{chain}}
            query: { protocol: {{protocol}}, path: 'SOFTWARE\Example', key: host }
            each: { field: exists, op: eq, value: false }
        """;

    [Fact]
    public void A_rule_can_name_the_transports_to_try_and_their_order()
    {
        var file = Load(Rule("fallback_chain: [dcom, wsman]"));

        Assert.Equal(["dcom", "wsman"], file.Rules[0].Query.List("fallback_chain"));
    }

    [Fact]
    public void Winrm_and_rpc_are_other_names_for_wsman_and_dcom()
    {
        var file = Load(Rule("fallback_chain: [winrm, rpc]"));

        Assert.Equal(["wsman", "dcom"], file.Rules[0].Query.List("fallback_chain"));
    }

    [Fact]
    public void A_rule_without_a_chain_leaves_the_engine_to_decide()
    {
        var file = Load(Rule(""));

        Assert.Empty(file.Rules[0].Query.List("fallback_chain"));
    }

    [Fact]
    public void Two_rules_asking_the_same_question_by_different_routes_do_not_share_one_read()
    {
        var file = Load(Rule("fallback_chain: [wsman]", id: "EX-1") + "\n" + Rule("fallback_chain: [dcom]", id: "EX-2").Replace("rules:\n", ""));

        Assert.NotEqual(file.Rules[0].Query.Id, file.Rules[1].Query.Id);
    }

    [Fact]
    public void Aliases_do_not_split_a_shared_read()
    {
        var file = Load(Rule("fallback_chain: [winrm]", id: "EX-1") + "\n" + Rule("fallback_chain: [wsman]", id: "EX-2").Replace("rules:\n", ""));

        Assert.Equal(file.Rules[0].Query.Id, file.Rules[1].Query.Id);
    }

    [Theory]
    [InlineData("fallback_chain: [smb]", "smb")]
    [InlineData("fallback_chain: [registry]", "registry")]
    [InlineData("fallback_chain: [carrier-pigeon]", "carrier-pigeon")]
    public void A_transport_that_cannot_carry_the_query_is_refused_by_name(string chain, string named)
    {
        var ex = Assert.Throws<RuleException>(() => Load(Rule(chain)));

        Assert.Contains(named, ex.Message, StringComparison.Ordinal);
        Assert.Contains("EX-1", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_chain_is_refused()
    {
        Assert.Throws<RuleException>(() => Load(Rule("fallback_chain: []")));
    }

    [Fact]
    public void The_same_transport_twice_is_refused()
    {
        Assert.Throws<RuleException>(() => Load(Rule("fallback_chain: [wsman, winrm]")));
    }

    [Theory]
    [InlineData("ldap")]
    [InlineData("eventlog")]
    public void A_chain_only_means_something_for_the_wmi_protocols(string protocol)
    {
        var ex = Assert.Throws<RuleException>(() => Load(Rule("fallback_chain: [wsman]", protocol: protocol)));

        Assert.Contains("fallback_chain", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_chain_belongs_on_the_rule_not_inside_its_query()
    {
        var rule = """
            rules:
              - id: EX-1
                title: Example
                query: { protocol: registry, path: 'SOFTWARE\Example', key: host, fallback_chain: [wsman] }
                each: { field: exists, op: eq, value: false }
            """;

        Assert.Throws<RuleException>(() => Load(rule));
    }
}
