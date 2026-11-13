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
    public void A_second_tenant_in_the_same_home_is_found_and_the_same_tenant_again_is_not()
    {
        IntegrationRecord[] home = [Graph("microsoft", "11111111-1111-1111-1111-111111111111")];

        Assert.Equal("microsoft", ConnectVerb.OtherTenant(home, "city-b", "22222222-2222-2222-2222-222222222222")?.Id);
        Assert.Null(ConnectVerb.OtherTenant(home, "microsoft", "22222222-2222-2222-2222-222222222222"));
        Assert.Null(ConnectVerb.OtherTenant(home, "second-app", "11111111-1111-1111-1111-111111111111"));
        Assert.Null(ConnectVerb.OtherTenant([Graph("old", "33333333-3333-3333-3333-333333333333", enabled: false)], "microsoft", "x.onmicrosoft.com"));
    }
}
