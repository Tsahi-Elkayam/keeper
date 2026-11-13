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
}
