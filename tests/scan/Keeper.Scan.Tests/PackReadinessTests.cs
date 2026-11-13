using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Scan.Tests;

public sealed class PackReadinessTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Imports => Path.Combine(_dir, "imports");

    private RuleFile Load(string yaml)
    {
        var path = Path.Combine(_dir, $"{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        return RuleLoader.LoadFile(path, "test", Keeper.Scan.Runners.Registry().Validators);
    }

    private const string Rule = """
          - id: EX-1
            title: One
            kind: misconfigured
            lens: both
            category: CFG
            severity: low
            entity: thing
            query: QUERY
            each: any
        """;

    private RuleFile Pack(string system, string integration, string query, string header = "") => Load($"""
        schema: keeper.rules/1
        system: {system}
        integration: {integration}
        {header}
        rules:
        {Rule.Replace("QUERY", query, StringComparison.Ordinal)}
        """);

    private (PackReadiness.Waiting Kind, string Detail)? Check(RuleFile file, bool implicitIntegration = true, JsonObject? options = null,
        Dictionary<string, string>? settings = null, Dictionary<string, string>? thresholds = null, IReadOnlyList<string>? hosts = null) =>
        PackReadiness.Check([file], implicitIntegration, options ?? [], Imports,
            key => settings?.GetValueOrDefault(key), name => thresholds?.GetValueOrDefault(name), _ => hosts ?? []);

    private const string PingCastleQuery = "{ protocol: file, path: 'pingcastle/ad_hc_*.xml', format: xml, items: '/a/b', key: id }";

    [Fact]
    public void An_import_pack_without_its_report_folder_waits_and_names_the_folder()
    {
        var waiting = Check(Pack("pingcastle", "files", PingCastleQuery));

        Assert.Equal(PackReadiness.Waiting.NoImport, waiting?.Kind);
        Assert.Contains("imports/pingcastle", waiting?.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void An_import_pack_runs_once_its_folder_exists_even_if_empty_so_a_missing_report_is_said()
    {
        Directory.CreateDirectory(Path.Combine(Imports, "pingcastle"));

        Assert.Null(Check(Pack("pingcastle", "files", PingCastleQuery)));
    }

    [Fact]
    public void A_configuration_folder_moved_by_a_setting_counts_as_set_up()
    {
        var file = Pack("cisco-ios", "host", "{ protocol: host, read: configs, folder: 'imports:network-config', folderSetting: network.config-folder, format: blocks, key: id }");

        Assert.Equal(PackReadiness.Waiting.NoImport, Check(file)?.Kind);
        Assert.Null(Check(file, thresholds: new() { ["network.config-folder"] = "/srv/backups/network" }));
    }

    [Fact]
    public void A_pack_that_reads_this_machine_is_not_an_import_pack()
    {
        Assert.Null(Check(Pack("sshd", "host", "{ protocol: host, read: file, path: /etc/ssh/sshd_config, format: kv, key: name }")));
    }

    [Fact]
    public void An_import_pack_through_an_integration_someone_set_up_runs_and_says_what_is_missing()
    {
        Assert.Null(Check(Pack("pingcastle", "files", PingCastleQuery), implicitIntegration: false));
    }

    [Fact]
    public void An_opt_in_pack_waits_until_its_setting_is_on()
    {
        var file = Pack("obligations", "keeper", "{ protocol: store, text: 'SELECT 1 AS id', key: id }", "opt_in: obligations.enabled");

        var off = Check(file);
        Assert.Equal(PackReadiness.Waiting.Off, off?.Kind);
        Assert.Contains("keeper decide setting obligations.enabled true", off?.Detail, StringComparison.Ordinal);
        Assert.Equal(PackReadiness.Waiting.Off, Check(file, settings: new() { ["obligations.enabled"] = "false" })?.Kind);
        Assert.Null(Check(file, settings: new() { ["obligations.enabled"] = "true" }));
    }

    private const string DcQuery = "{ protocol: tls, port: 636, key: host }";

    [Fact]
    public void A_pack_whose_hosts_come_from_the_store_waits_until_a_scan_lists_some()
    {
        var file = Pack("dc-certificates", "tls", DcQuery, "targets: { entity: computer, field: dNSHostName }");
        var generic = new JsonObject { ["targets"] = new JsonArray("web.example.org") };

        var waiting = Check(file, implicitIntegration: false, options: generic);
        Assert.Equal(PackReadiness.Waiting.NoHosts, waiting?.Kind);
        Assert.Contains("computer", waiting?.Detail, StringComparison.Ordinal);
        Assert.Null(Check(file, implicitIntegration: false, options: generic, hosts: ["dc1.example.org"]));
    }

    [Fact]
    public void A_store_pack_pointed_at_named_hosts_runs_without_the_store()
    {
        var file = Pack("dc-certificates", "tls", DcQuery, "targets: { entity: computer, field: dNSHostName }");

        Assert.Null(Check(file, implicitIntegration: false, options: new JsonObject { ["targets.dc-certificates"] = new JsonArray("lab-dc.example.org") }));
    }

    [Fact]
    public void Waiting_packs_are_said_in_one_line_per_reason()
    {
        var line = PackReadiness.Line(PackReadiness.Waiting.NoImport, ["pingcastle (imports/pingcastle)", "prowler (imports/prowler)"]);

        Assert.StartsWith("Not set up", line, StringComparison.Ordinal);
        Assert.Contains("pingcastle (imports/pingcastle), prowler (imports/prowler)", line, StringComparison.Ordinal);
    }
}
