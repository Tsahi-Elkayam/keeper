using System.Text.Json.Nodes;
using Keeper.Integrations;

namespace Keeper.Scan.Tests;

public sealed class ConnectVerbTests
{
    private static IntegrationRecord Graph(string id, string tenant, bool enabled = true) =>
        new(id, "graph", "https://graph.microsoft.com", "entra-certificate", null, new JsonObject { ["tenantId"] = tenant }, enabled,
            new Dictionary<string, StoredSecret>());

    [Theory]
    [InlineData("AADSTS700016: Application with identifier 'x' was not found", "check --client-id")]
    [InlineData("AADSTS700027: Client assertion contains an invalid signature", "upload its public part")]
    [InlineData("AADSTS90002: Tenant 'x' not found", "Directory (tenant) ID")]
    [InlineData("AADSTS53003: Access has been blocked by Conditional Access policies", "Conditional Access")]
    public void A_first_sign_in_error_is_said_as_what_to_do(string error, string expected) =>
        Assert.Contains(expected, ConnectVerb.Hint(error), StringComparison.Ordinal);

    [Fact]
    public void An_unknown_error_gets_no_made_up_advice() =>
        Assert.Null(ConnectVerb.Hint("AADSTS50000: something else"));

    [Fact]
    public void An_integration_that_scanned_one_tenant_is_not_pointed_at_another_and_a_second_tenant_is_said()
    {
        const string a = "11111111-1111-1111-1111-111111111111", b = "22222222-2222-2222-2222-222222222222";
        IntegrationRecord[] home = [Graph("microsoft", a)];
        static bool Scanned(string _) => true;
        static bool Never(string _) => false;

        // Re-pointing 'microsoft' after it scanned tenant A would reuse A's finding keys: refused.
        Assert.Equal(ConnectVerb.TenantClash.Repointed, ConnectVerb.Clash(home, "microsoft", b, Scanned).Kind);
        // Before any scan it is a mistyped tenant being fixed: fine.
        Assert.Equal(ConnectVerb.TenantClash.None, ConnectVerb.Clash(home, "microsoft", b, Never).Kind);
        Assert.Equal(ConnectVerb.TenantClash.None, ConnectVerb.Clash(home, "microsoft", " " + a.ToUpperInvariant(), Scanned).Kind);
        // Another tenant under another name keeps its own finding keys; the home then reads two tenants, and says so.
        var second = ConnectVerb.Clash(home, "city-b", b, Scanned);
        Assert.Equal((ConnectVerb.TenantClash.SecondTenant, "microsoft"), (second.Kind, second.Other?.Id));
        Assert.Equal(ConnectVerb.TenantClash.SecondTenant, ConnectVerb.Clash([Graph("old", b, enabled: false)], "microsoft", a, Scanned).Kind);
        Assert.Equal(ConnectVerb.TenantClash.None, ConnectVerb.Clash([], "microsoft", a, Scanned).Kind);
    }
}
