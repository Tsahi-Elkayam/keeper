using System.Text.Json.Nodes;
using Keeper.Runners.Http;

namespace Keeper.Runners.Tests;

/// <summary>What a Cloud Asset Inventory answer may carry that must never reach a row, and the one path the gcp type reads.</summary>
public sealed class GcpGuardTests
{
    [Fact]
    public void Instance_scripts_and_environments_come_back_as_set_and_settings_stay()
    {
        var row = JsonNode.Parse("""
            {
              "resource": { "data": {
                "metadata": { "items": [
                  { "key": "startup-script", "value": "#!/bin/sh\necho example" },
                  { "key": "sysprep-specialize-script-ps1", "value": "Write-Host example" },
                  { "key": "enable-oslogin", "value": "TRUE" },
                  { "key": "block-project-ssh-keys", "value": "true" }
                ] },
                "environmentVariables": { "DB_HOST": "db.example.org" },
                "env": [ { "name": "API_TOKEN", "value": "example-value" }, { "name": "MAX_PASSWORD_AGE", "value": "90" }, { "name": "REGION", "value": "europe-west1" } ]
              } }
            }
            """)!.AsObject();

        SecretProperties.Mask(row);

        var items = row["resource"]!["data"]!["metadata"]!["items"]!.AsArray();
        Assert.Equal("set", (string?)items[0]!["value"]);
        Assert.Equal("set", (string?)items[1]!["value"]);
        Assert.Equal("TRUE", (string?)items[2]!["value"]);
        Assert.Equal("true", (string?)items[3]!["value"]);
        Assert.Equal("set", (string?)row["resource"]!["data"]!["environmentVariables"]);
        var env = row["resource"]!["data"]!["env"]!.AsArray();
        Assert.Equal("set", (string?)env[0]!["value"]);
        Assert.Equal("90", (string?)env[1]!["value"]);            // a number under such a name is a setting
        Assert.Equal("europe-west1", (string?)env[2]!["value"]);
    }

    [Theory]
    [InlineData("/v1/organizations/123456789012/assets", true)]
    [InlineData("/v1/projects/example-project/assets", true)]
    [InlineData("/v1/organizations/123456789012:searchAllResources", false)]
    [InlineData("/v1/organizations/123456789012/assets:exportAssets", false)]
    [InlineData("/v1/organizations/123456789012/feeds", false)]
    public void The_gcp_type_reads_list_assets_only(string path, bool allowed) =>
        Assert.Equal(allowed, ReadPost.Allow(["/v1/*/*/assets"], path));
}
