using Keeper.Runners.Cim;
using Keeper.Runners.Http;
using Keeper.Runners.Sql;

namespace Keeper.Runners.Tests;

public sealed class GuardTests
{
    [Theory]
    [InlineData("https://prod-12.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers&sv=1.0&sig=Zm9vYmFy",
        "https://prod-12.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers&sv=1.0&sig=set")]
    [InlineData("https://bucket.s3.amazonaws.com/a.csv?X-Amz-Credential=AKID%2F2026&X-Amz-Signature=abc123",
        "https://bucket.s3.amazonaws.com/a.csv?X-Amz-Credential=set&X-Amz-Signature=set")]
    [InlineData("https://fn.example.org/api/run?code=s3cr3t&name=x", "https://fn.example.org/api/run?code=set&name=x")]
    [InlineData("https://app.example.org/cb#access_token=eyJabc&state=1", "https://app.example.org/cb#access_token=set&state=1")]
    [InlineData("https://login.example.org/token?client_id=a&client_secret=s3cr3t", "https://login.example.org/token?client_id=a&client_secret=set")]
    [InlineData("see https://example.org/page?id=7", "see https://example.org/page?id=7")]
    [InlineData("key=value, not a URL", "key=value, not a URL")]
    public void A_url_that_carries_its_own_credential_keeps_only_the_rest(string text, string masked)
    {
        Assert.Equal(masked, SecretProperties.MaskUrls(text));

        var row = new System.Text.Json.Nodes.JsonObject { ["flowTriggerUri"] = text, ["links"] = new System.Text.Json.Nodes.JsonArray(text) };
        SecretProperties.Mask(row);
        Assert.Equal(masked, row["flowTriggerUri"]!.ToString());
        Assert.Equal(masked, row["links"]![0]!.ToString());
    }

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
    [InlineData("SELECT session_id FROM sys.dm_exec_sessions", false, true, "VIEW SERVER STATE")]
    [InlineData("SELECT name FROM sys . dm_os_volume_stats(1, 1)", false, true, "VIEW SERVER STATE")]
    [InlineData("SELECT name, is_disabled FROM sys.server_principals", true, false, "VIEW ANY DEFINITION")]
    [InlineData("SELECT * FROM sys.dm_exec_sessions s JOIN sys.sql_logins l ON 1 = 1", false, false, "VIEW SERVER STATE|VIEW ANY DEFINITION")]
    [InlineData("SELECT name FROM sys.tables WHERE is_ms_shipped = 0", true, false, "VIEW ANY DEFINITION")]
    [InlineData("SELECT name FROM sys.server_principals", true, true, null)]          // held: a full answer
    [InlineData("SELECT name, state_desc FROM sys.databases", false, false, null)]    // every login sees every row
    public void A_sql_read_that_the_login_cannot_fully_see_is_partial_with_the_reason(string text, bool serverState, bool anyDefinition, string? lacks)
    {
        var missing = SqlPermissions.Missing(text, @"EXAMPLE\reader", serverState, anyDefinition);

        if (lacks is null)
        {
            Assert.Null(missing);
            return;
        }
        Assert.StartsWith(@"read as EXAMPLE\reader, which lacks ", missing, StringComparison.Ordinal);
        foreach (var permission in new[] { "VIEW SERVER STATE", "VIEW ANY DEFINITION" })
            Assert.Equal(lacks.Split('|').Contains(permission), missing!.Contains(permission, StringComparison.Ordinal));
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
            ("path", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"), ("values", new System.Text.Json.Nodes.JsonArray("EnableLUA")))));
        Assert.NotEmpty(new RegistryRunner().Validate(Context.Query("registry", "host", ("path", @"SOFTWARE\..\SAM"), ("hive", "HKCR"))));
        Assert.Contains("DefaultPassword", RegistryRunner.SecretValues);
    }

    [Fact]
    public void Plain_values_in_an_answer_become_rows_so_a_count_over_them_is_real()
    {
        var list = RowValues.ItemsOf(System.Text.Json.Nodes.JsonNode.Parse("""["ntp1.example.org", "ntp2.example.org"]"""), null);
        var single = RowValues.ItemsOf(System.Text.Json.Nodes.JsonNode.Parse("\"GREEN\""), null);

        Assert.Equal(new[] { "ntp1.example.org", "ntp2.example.org" }, list.Select(r => r["value"]!.ToString()));
        Assert.Equal("GREEN", Assert.Single(single)["value"]!.ToString());
        Assert.True(Keeper.Runners.Ldap.LdapValues.IsBinary("objectSid"));
        Assert.False(Keeper.Runners.Ldap.LdapValues.IsBinary("sAMAccountName"));
    }

    [Fact]
    public void Secrets_in_a_json_answer_come_back_as_set_at_any_depth_and_facts_about_them_stay()
    {
        var body = System.Text.Json.Nodes.JsonNode.Parse("""
            { "value": [ {
                "displayName": "Office Wi-Fi", "preSharedKey": "hunter2-not-real", "passwordPolicies": "DisablePasswordExpiration",
                "lastPasswordChangeDateTime": "2026-01-01T00:00:00Z", "password": "",
                "settings": [ { "name": "vpn", "sharedSecret": "s3cret-not-real" } ],
                "detectionScriptContent": "JHBhc3N3b3JkID0gJ3gn"
            } ] }
            """);

        var row = Assert.Single(RowValues.ItemsOf(body, null));
        var text = row.ToJsonString();

        Assert.DoesNotContain("not-real", text, StringComparison.Ordinal);
        Assert.DoesNotContain("JHBhc3N3b3Jk", text, StringComparison.Ordinal);
        Assert.Equal("set", row["preSharedKey"]!.ToString());
        Assert.Equal("set", row["settings"]![0]!["sharedSecret"]!.ToString());
        Assert.Equal("", row["password"]!.ToString());   // not set is still visible as not set
        Assert.Equal("DisablePasswordExpiration", row["passwordPolicies"]!.ToString());
        Assert.Equal("2026-01-01T00:00:00Z", row["lastPasswordChangeDateTime"]!.ToString());
    }

    [Fact]
    public void Secret_attributes_are_known()
    {
        Assert.True(SecretAttributes.IsSecret("ms-Mcs-AdmPwd"));
        Assert.True(SecretAttributes.IsSecret("UNICODEPWD"));
        Assert.False(SecretAttributes.IsSecret("ms-Mcs-AdmPwdExpirationTime"));
    }
}
