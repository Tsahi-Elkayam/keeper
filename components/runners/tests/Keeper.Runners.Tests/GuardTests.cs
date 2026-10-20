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

    [Fact]
    public void Secret_attributes_are_known()
    {
        Assert.True(SecretAttributes.IsSecret("ms-Mcs-AdmPwd"));
        Assert.True(SecretAttributes.IsSecret("UNICODEPWD"));
        Assert.False(SecretAttributes.IsSecret("ms-Mcs-AdmPwdExpirationTime"));
    }
}
