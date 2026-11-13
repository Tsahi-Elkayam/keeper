using System.Text.Json.Nodes;
using Keeper.Runners.Files;
using Keeper.Store;

namespace Keeper.Runners.Tests;

public sealed class FileAndStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Imports => Path.Combine(_dir, "imports");

    private Task<RunnerResult> File(params (string, JsonNode?)[] fields) =>
        new FileRunner().RunAsync(Context.Query("file", "id", fields), Context.For(new FakeConnection(""), imports: Imports), CancellationToken.None);

    private void Drop(string relative, string content, DateTime? modified = null)
    {
        var path = Path.Combine(Imports, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllText(path, content);
        if (modified is not null)
            System.IO.File.SetLastWriteTimeUtc(path, modified.Value);
    }

    [Fact]
    public async Task Json_items_are_read_from_the_newest_matching_file()
    {
        Drop("maester/old.json", """{ "Tests": [ { "Id": "OLD" } ] }""", new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        Drop("maester/new.json", """{ "Tests": [ { "Id": "MT.1001", "Result": "Failed" }, { "Id": "MT.1002", "Result": "Passed" } ] }""",
            new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc));

        var result = await File(("path", "maester/*.json"), ("items", "Tests"));

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "MT.1001", "MT.1002" }, result.Rows.Select(r => r["Id"]!.ToString()));
        Assert.Equal("new.json", result.Rows[0]["_file"]!.ToString());
    }

    [Fact]
    public async Task Xml_rows_come_from_an_xpath()
    {
        Drop("pingcastle/ad_hc_example.org.xml", """
            <HealthcheckData>
              <RiskRules>
                <HealthcheckRiskRule><Points>50</Points><Category>Anomalies</Category><RiskId>A-Krbtgt</RiskId><Rationale>krbtgt password is old</Rationale></HealthcheckRiskRule>
                <HealthcheckRiskRule><Points>5</Points><Category>StaleObjects</Category><RiskId>S-Inactive</RiskId><Rationale>inactive accounts</Rationale></HealthcheckRiskRule>
              </RiskRules>
            </HealthcheckData>
            """);

        var result = await File(("path", "pingcastle/ad_hc_*.xml"), ("format", "xml"), ("items", "//HealthcheckRiskRule"));

        Assert.Equal(2, result.Rows.Count);
        Assert.Equal("A-Krbtgt", result.Rows[0]["RiskId"]!.ToString());
        Assert.Equal("50", result.Rows[0]["Points"]!.ToString());
    }

    [Fact]
    public async Task An_xml_file_with_a_dtd_is_refused()
    {
        Drop("evil/x.xml", """
            <?xml version="1.0"?>
            <!DOCTYPE r [ <!ENTITY e SYSTEM "file:///c:/windows/win.ini"> ]>
            <r><row>&e;</row></r>
            """);

        var result = await File(("path", "evil/x.xml"), ("format", "xml"), ("items", "//row"));

        Assert.Equal("failed", result.State);
    }

    [Fact]
    public async Task Csv_handles_quotes_and_line_breaks()
    {
        Drop("export/certs.csv", "Host,Expires,Note\r\nweb1.example.org,2026-11-01,\"plain\"\r\nweb2.example.org,2027-01-01,\"has, a comma\nand a line\"\r\n");

        var result = await File(("path", "export/certs.csv"), ("format", "csv"));

        Assert.Equal(2, result.Rows.Count);
        Assert.Equal("has, a comma\nand a line", result.Rows[1]["Note"]!.ToString());
    }

    [Fact]
    public async Task A_path_outside_the_imports_folder_is_refused()
    {
        Assert.NotEmpty(new FileRunner().Validate(Context.Query("file", "id", ("path", "../settings/settings.json"))));

        var result = await File(("path", "../*.json"));
        Assert.Equal("failed", result.State);
    }

    [Fact]
    public async Task A_missing_report_is_a_failure_not_an_empty_pass()
    {
        var result = await File(("path", "nothing-here/*.json"));

        Assert.Equal("failed", result.State);
        Assert.Contains("imports", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_store_answers_register_rules_read_only()
    {
        var file = Path.Combine(_dir, "keeper.db");
        using (var connection = new Database(file).OpenReadWrite(create: true))
            Keeper.Store.Sql.Execute(connection, """
                CREATE TABLE licence (licence_id TEXT, expires_on TEXT);
                INSERT INTO licence VALUES ('soon', date('now', '+10 days')), ('later', date('now', '+400 days'));
                CREATE TABLE integration_secret (x TEXT);
                """);

        var runner = new StoreRunner();
        var ok = await runner.RunAsync(Context.Query("store", "licence_id", ("text", "SELECT licence_id FROM licence WHERE expires_on <= date(:today, '+60 days')")),
            Context.For(new FakeConnection(""), store: file), CancellationToken.None);
        var refused = await runner.RunAsync(Context.Query("store", "x", ("text", "SELECT x FROM integration_secret")),
            Context.For(new FakeConnection(""), store: file), CancellationToken.None);

        Assert.Equal(new[] { "soon" }, ok.Rows.Select(r => r["licence_id"]!.ToString()));
        Assert.Equal("failed", refused.State);
    }
}
