using Keeper.Runners.Cim;
using Keeper.Runners.Http;

namespace Keeper.Runners.Tests;

public sealed class GuardTests
{
    [Theory]
    [InlineData("SELECT name FROM sys.databases")]
    [InlineData("WITH x AS (SELECT 1 AS n) SELECT n FROM x")]
    [InlineData("SELECT 'drop table x' AS text")]
    [InlineData("SELECT REPLACE(name, 'a', 'b') FROM t -- ; DROP TABLE t")]
    [InlineData("select 1;")]
    public void Read_only_sql_is_accepted(string text)
    {
        Assert.Null(SqlGuard.Problem(text));
    }

    [Theory]
    [InlineData("DELETE FROM t")]
    [InlineData("SELECT 1; DROP TABLE t")]
    [InlineData("SELECT * INTO copy FROM t")]
    [InlineData("EXEC xp_cmdshell 'whoami'")]
    [InlineData("SELECT * FROM OPENROWSET('x','y','z')")]
    [InlineData("SELECT 1 WAITFOR DELAY '00:01'")]
    [InlineData("")]
    public void Anything_else_is_refused(string text)
    {
        Assert.NotNull(SqlGuard.Problem(text));
    }

    [Theory]
    [InlineData("SELECT * FROM integration_secret")]
    [InlineData("SELECT * FROM [integration_secret]")]
    [InlineData("SELECT * FROM \"vault_key\"")]
    public void Secret_tables_are_refused_however_they_are_quoted(string text)
    {
        Assert.NotNull(SqlGuard.Problem(text, ["integration_secret", "vault_key"]));
    }

    [Theory]
    [InlineData("https://evil.example.com/x")]
    [InlineData("//evil.example.com/x")]
    [InlineData("/a/../b")]
    [InlineData("relative/path")]
    [InlineData("/a\\b")]
    [InlineData("/user@host")]
    public void Http_paths_cannot_leave_the_endpoint(string path)
    {
        Assert.NotNull(HttpPaths.Problem(path));
    }

    [Theory]
    [InlineData("query { issues { nodes { id } } }", true)]
    [InlineData("{ me { id } }", true)]
    [InlineData("query { search(text: \"mutation\") { id } }", true)]
    [InlineData("mutation { deleteEverything }", false)]
    [InlineData("query { a } mutation { b }", false)]
    [InlineData("subscription { events { id } }", false)]
    public void Graphql_accepts_queries_only(string document, bool accepted)
    {
        Assert.Equal(accepted, GraphQlRunner.Problem(document) is null);
    }

    [Theory]
    [InlineData("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3", true)]
    [InlineData("ASSOCIATORS OF {Win32_Service.Name='x'}", false)]
    [InlineData("SELECT * FROM Win32_Process; SELECT 1", false)]
    public void Cim_accepts_one_select(string wql, bool accepted)
    {
        Assert.Equal(accepted, CimRunner.Problem(wql) is null);
    }

    [Theory]
    [InlineData("pc01.example.org", "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='PC01',Name='Administrators'\"")]
    [InlineData("PC-02", "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='PC-02',Name='Administrators'\"")]
    [InlineData("pc'01.example.org", null)]
    [InlineData("pc01\" OR 1=1", null)]
    public void Cim_host_macro_takes_only_a_clean_computer_name(string target, string? expected)
    {
        const string wql = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{HOST}',Name='Administrators'\"";
        Assert.Equal(expected, CimRunner.Expand(wql, target));
    }

    [Fact]
    public void Event_log_queries_filter_on_the_host_by_id_provider_and_window()
    {
        var query = Context.Query("eventlog", "recordId", ("log", "System"), ("ids", new System.Text.Json.Nodes.JsonArray("41", "6008")),
            ("providers", new System.Text.Json.Nodes.JsonArray("EventLog")), ("days", "3"));

        Assert.Empty(new EventLogRunner().Validate(query));
        Assert.Equal("*[System[(EventID=41 or EventID=6008) and Provider[@Name='EventLog'] and TimeCreated[timediff(@SystemTime) <= 259200000]]]",
            EventLogRunner.XPath(query));
    }

    [Theory]
    [InlineData("System", "x' or 1=1", "providers")]
    [InlineData("System]]", null, "log")]
    public void Event_log_names_that_could_change_the_query_are_refused(string log, string? provider, string field)
    {
        var fields = new List<(string, System.Text.Json.Nodes.JsonNode?)> { ("log", log) };
        if (provider is not null)
            fields.Add(("providers", new System.Text.Json.Nodes.JsonArray(provider)));

        Assert.Contains(new EventLogRunner().Validate(Context.Query("eventlog", "recordId", [.. fields])), p => p.StartsWith(field, StringComparison.Ordinal));
    }

    [Fact]
    public void Event_data_comes_back_by_name()
    {
        const string xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System><EventID>7031</EventID></System>
              <EventData><Data Name="param1">Example Service</Data><Data Name="param2">1</Data><Data>unnamed</Data></EventData>
            </Event>
            """;

        Assert.Equal(new[] { ("param1", "Example Service"), ("param2", "1") }, EventLogRunner.EventData(xml));
    }

    [Fact]
    public void Registry_keys_must_be_plain_paths_and_credentials_are_never_read()
    {
        Assert.Empty(new RegistryRunner().Validate(Context.Query("registry", "host",
            ("key", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"), ("values", new System.Text.Json.Nodes.JsonArray("EnableLUA")))));
        Assert.NotEmpty(new RegistryRunner().Validate(Context.Query("registry", "host", ("key", @"SOFTWARE\..\SAM"), ("hive", "HKCR"))));
        Assert.Contains("DefaultPassword", RegistryRunner.SecretValues);
    }

    [Fact]
    public void Secret_attributes_are_known()
    {
        Assert.True(SecretAttributes.IsSecret("ms-Mcs-AdmPwd"));
        Assert.True(SecretAttributes.IsSecret("UNICODEPWD"));
        Assert.False(SecretAttributes.IsSecret("ms-Mcs-AdmPwdExpirationTime"));
    }
}
