using System.Text;

namespace Keeper.Integrations.Tests;

public sealed class GraphPermissionsTests
{
    private static string Token(string payloadJson) =>
        "eyJhbGciOiJub25lIn0." + Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".sig";

    [Fact]
    public void The_built_in_map_loads_and_asks_only_for_read_permissions()
    {
        Assert.NotEmpty(GraphPermissions.Map);
        var all = GraphPermissions.Map.SelectMany(e => e.Any).Distinct().ToList();
        Assert.All(all, p => Assert.Matches(@"\.Read(Basic)?(\.|$)|^MailboxSettings\.Read$", p));
        // Never the permissions that read secret values or content.
        Assert.DoesNotContain("BitlockerKey.Read.All", all);
        Assert.DoesNotContain("DeviceLocalCredential.Read.All", all);
        Assert.DoesNotContain(all, p => p.StartsWith("Mail.", StringComparison.Ordinal) || p.StartsWith("Files.", StringComparison.Ordinal) || p.StartsWith("Sites.", StringComparison.Ordinal));
    }

    [Fact]
    public void The_longest_matching_path_decides_and_ids_and_arguments_match_any_segment()
    {
        Assert.Equal("AuditLog.Read.All", GraphPermissions.Needs("/reports/authenticationMethods/userRegistrationDetails", [])!.Single().Any[0]);
        Assert.Equal("Reports.Read.All", GraphPermissions.Needs("/reports/getMailboxUsageDetail(period='D30')", [])!.Single().Any[0]);
        Assert.Equal("Synchronization.Read.All", GraphPermissions.Needs("/servicePrincipals/{id}/synchronization/jobs", [])!.Single().Any[0]);
        Assert.Equal("Application.Read.All", GraphPermissions.Needs("/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo", [])!.Single().Any[0]);
        Assert.Null(GraphPermissions.Needs("/not/in/the/map", []));
    }

    [Fact]
    public void Selecting_sign_in_activity_also_needs_the_audit_log_permission()
    {
        Assert.Single(GraphPermissions.Needs("/users", ["id", "userPrincipalName"])!);
        var needs = GraphPermissions.Needs("/users", ["id", "signInActivity"])!;
        Assert.Equal(2, needs.Count);
        Assert.Contains(needs, n => n.Any.Contains("AuditLog.Read.All"));
    }

    [Fact]
    public void A_need_is_met_by_any_one_of_its_permissions()
    {
        var need = GraphPermissions.Needs("/groups", [])!.Single();
        Assert.True(need.MetBy(new HashSet<string>(["Directory.Read.All"], StringComparer.OrdinalIgnoreCase)));
        Assert.False(need.MetBy(new HashSet<string>(["User.Read.All"], StringComparer.OrdinalIgnoreCase)));
        Assert.StartsWith("GroupMember.Read.All (or ", need.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_token_grants_its_application_roles_and_delegated_scopes()
    {
        var app = GraphPermissions.Granted(Token("""{"aud":"https://graph.microsoft.com","roles":["Policy.Read.All","User.Read.All"],"exp":1900000000,"app_displayname":"Keeper reader"}"""));
        var user = GraphPermissions.Granted(Token("""{"scp":"Policy.Read.All Directory.Read.All"}"""));

        Assert.Equal(["Policy.Read.All", "User.Read.All"], app.Order(StringComparer.Ordinal));
        Assert.Contains("Directory.Read.All", user);
        Assert.Equal("Keeper reader", GraphPermissions.Describe(Token("""{"app_displayname":"Keeper reader","exp":1900000000}""")).AppName);
    }

    [Theory]
    [InlineData("opaque-token")]
    [InlineData("a.b")]
    [InlineData("a.!!!.c")]
    public void A_token_that_is_not_a_jwt_is_refused_plainly(string token)
    {
        var ex = Record.Exception(() => GraphPermissions.Granted(token));
        Assert.True(ex is ArgumentException or FormatException, ex?.GetType().Name ?? "no exception");
    }

    [Fact]
    public void An_audience_that_is_not_a_string_does_not_break_the_description()
    {
        var (aud, _, app) = GraphPermissions.Describe(Token("""{"aud":["a","b"],"app_displayname":42}"""));

        Assert.Null(aud);
        Assert.Null(app);
    }

    [Fact]
    public void Permissions_that_can_change_the_tenant_are_named()
    {
        var writes = GraphPermissions.Writes(new HashSet<string>(
            ["Policy.Read.All", "Directory.ReadWrite.All", "User.ReadWrite.All", "Mail.Send", "DeviceManagementManagedDevices.PrivilegedOperations.All", "Sites.FullControl.All"],
            StringComparer.OrdinalIgnoreCase));

        Assert.Equal(["Directory.ReadWrite.All", "Mail.Send", "Sites.FullControl.All", "User.ReadWrite.All"], writes);
        Assert.Empty(GraphPermissions.Writes(new HashSet<string>(GraphPermissions.Recommended(), StringComparer.OrdinalIgnoreCase)));
    }

    [Fact]
    public void A_path_whose_longest_entry_needs_an_unselected_field_falls_back_to_the_shorter_path()
    {
        var map = GraphPermissions.Parse("""
            - { path: /users, any: [User.Read.All] }
            - { path: /users/*/extras, select: secretField, any: [Extra.Read.All] }
            """);

        Assert.Equal("User.Read.All", GraphPermissions.Needs("/users/{id}/extras", [], map)!.Single().Any[0]);
        Assert.Equal("Extra.Read.All", GraphPermissions.Needs("/users/{id}/extras", ["secretField"], map)!.Single().Any[0]);
    }
}
