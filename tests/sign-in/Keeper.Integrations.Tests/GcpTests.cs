using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Integrations.Tests;

public sealed class GcpTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 22, 8, 0, 0, TimeSpan.Zero);

    private static JsonObject Part(string jwt, int index)
    {
        var text = jwt.Split('.')[index].Replace('-', '+').Replace('_', '/');
        text += new string('=', (4 - (text.Length % 4)) % 4);
        return JsonNode.Parse(Convert.FromBase64String(text))!.AsObject();
    }

    [Fact]
    public void The_assertion_is_signed_by_the_key_and_asks_only_for_the_read_only_scope()
    {
        using var rsa = RSA.Create(2048);
        var jwt = IntegrationConnection.GoogleAssertion("reader@example-project.iam.gserviceaccount.com", rsa.ExportPkcs8PrivateKeyPem(), Now);

        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.Equal("RS256", (string?)Part(jwt, 0)["alg"]);
        var claims = Part(jwt, 1);
        Assert.Equal("reader@example-project.iam.gserviceaccount.com", (string?)claims["iss"]);
        Assert.Equal("https://www.googleapis.com/auth/cloud-platform.read-only", (string?)claims["scope"]);
        Assert.Equal("https://oauth2.googleapis.com/token", (string?)claims["aud"]);
        Assert.Equal(3600L, (long)claims["exp"]! - (long)claims["iat"]!);

        var signature = Convert.FromBase64String(parts[2].Replace('-', '+').Replace('_', '/') + new string('=', (4 - (parts[2].Length % 4)) % 4));
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void The_key_files_private_key_value_pasted_as_one_line_is_accepted()
    {
        using var rsa = RSA.Create(2048);
        // As the key file holds it, and as the secret prompt takes it: one line, its line breaks written \n.
        var oneLine = "\"" + rsa.ExportPkcs8PrivateKeyPem().Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "\\n\"";

        Assert.Equal(3, IntegrationConnection.GoogleAssertion("reader@example-project.iam.gserviceaccount.com", oneLine, Now).Split('.').Length);
    }

    [Fact]
    public void The_bare_base64_body_of_the_key_is_accepted()
    {
        using var rsa = RSA.Create(2048);

        var jwt = IntegrationConnection.GoogleAssertion("reader@example-project.iam.gserviceaccount.com", Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()), Now);

        var parts = jwt.Split('.');
        var signature = Convert.FromBase64String(parts[2].Replace('-', '+').Replace('_', '/') + new string('=', (4 - (parts[2].Length % 4)) % 4));
        Assert.True(rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void A_value_that_is_not_a_key_is_refused_without_echoing_it()
    {
        var ex = Assert.Throws<IntegrationException>(() =>
            IntegrationConnection.GoogleAssertion("reader@example-project.iam.gserviceaccount.com", "not-a-key-at-all", Now));

        Assert.DoesNotContain("not-a-key-at-all", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/v1/organizations/123456789012", true)]
    [InlineData("/v1/folders/123456789012", true)]
    [InlineData("/v1/projects/example-project", true)]
    [InlineData("/v1/organizations/123456789012/assets", false)]
    [InlineData("/", false)]
    public void The_gcp_endpoint_names_a_scope_and_nothing_else(string path, bool allowed)
    {
        var gcp = IntegrationTypes.Find("gcp")!;

        Assert.Equal(allowed, gcp.AllowsEndpointPath(path));
        Assert.True(gcp.Guarded);
        Assert.True(gcp.AllowsHost("cloudasset.googleapis.com"));
        Assert.False(gcp.AllowsHost("compute.googleapis.com"));
        Assert.Equal(["privateKey"], IntegrationTypes.SecretsFor["gcp-service-account"]);
    }
}
