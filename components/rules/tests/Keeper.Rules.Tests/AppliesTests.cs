namespace Keeper.Rules.Tests;

public sealed class AppliesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-applies-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static readonly IReadOnlyDictionary<string, QueryValidator> Protocols = new Dictionary<string, QueryValidator>
    {
        ["registry"] = _ => [],
    };

    private string Write(string yaml)
    {
        var path = Path.Combine(_dir, "r.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    private const string Header = """
        schema: keeper.rules/1
        system: windows-example
        integration: cim
        defaults: { lens: security, category: CFG, refresh: 1d, entity: computer, kind: misconfigured, severity: medium }
        """;

    private const string Targets = """
        targets:
          entity: computer
          field: dNSHostName
          where: { field: operatingSystem, op: match, value: '^Windows' }
        """;

    private const string RuleWithApplies = """
        rules:
          - id: EX-SERVER-ONLY
            title: Only meant for servers
            applies: { field: operatingSystem, op: match, value: Server }
            query: { protocol: registry, path: 'SOFTWARE\Example', key: host }
            each: { field: exists, op: eq, value: false }
        """;

    private const string RuleWithoutApplies = """
        rules:
          - id: EX-ANY-HOST
            title: Meant for every host
            query: { protocol: registry, path: 'SOFTWARE\Example', key: host }
            each: { field: exists, op: eq, value: false }
        """;

    [Fact]
    public void A_rule_can_say_which_hosts_it_applies_to()
    {
        var file = RuleLoader.LoadFile(Write($"{Header}\n{Targets}\n{RuleWithApplies}"), "builtin", Protocols);

        Assert.NotNull(file.Rules[0].Applies);
    }

    [Fact]
    public void A_rule_without_applies_applies_to_every_target()
    {
        var file = RuleLoader.LoadFile(Write($"{Header}\n{Targets}\n{RuleWithoutApplies}"), "builtin", Protocols);

        Assert.Null(file.Rules[0].Applies);
    }

    [Fact]
    public void Applies_is_refused_when_the_file_has_no_entity_targets_to_read_attributes_from()
    {
        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(Write($"{Header}\n{RuleWithApplies}"), "builtin", Protocols));

        Assert.Contains("applies", ex.Message, StringComparison.Ordinal);
        Assert.Contains("EX-SERVER-ONLY", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Applies_is_refused_when_the_targets_are_a_fixed_list()
    {
        const string listTargets = "targets:\n  list: [host1.example.org]\n";
        var ex = Assert.Throws<RuleException>(() => RuleLoader.LoadFile(Write($"{Header}\n{listTargets}\n{RuleWithApplies}"), "builtin", Protocols));

        Assert.Contains("applies", ex.Message, StringComparison.Ordinal);
    }
}
