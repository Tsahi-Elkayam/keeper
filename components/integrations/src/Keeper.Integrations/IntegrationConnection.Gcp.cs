using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Integrations;

public sealed partial class IntegrationConnection
{
    // ---- Google Cloud: a service account's own signed assertion, exchanged for a read-only token -------------

    /// <summary>The only place a Google assertion is sent: never a URL from the integration's options.</summary>
    public static readonly Uri GoogleTokenUrl = new("https://oauth2.googleapis.com/token");

    /// <summary>
    /// The scope every Google token asks for. Whatever roles the service account holds, a token with only this
    /// scope cannot change anything: Google refuses every write made with it.
    /// </summary>
    public const string GoogleReadOnlyScope = "https://www.googleapis.com/auth/cloud-platform.read-only";

    private async Task<(string, DateTimeOffset)> GoogleServiceAccountAsync(CancellationToken cancellationToken)
    {
        var email = _record.Identity
            ?? throw new IntegrationException($"Integration {_record.Id} needs the service account's email (client_email in its key file) as the identity.");
        var assertion = GoogleAssertion(email, RequiredSecret("privateKey"), DateTimeOffset.UtcNow);
        var token = await OAuthAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ["assertion"] = assertion,
        }, GoogleTokenUrl, cancellationToken).ConfigureAwait(false);
        _signedInAs = email;
        return token;
    }

    /// <summary>
    /// The JWT a service account signs to ask Google for a token (RS256, an hour, read-only scope). The key is
    /// the private_key value of the account's key file: PEM, or that value pasted as one line with its \n as
    /// text, which is how the secret prompt takes it.
    /// </summary>
    public static string GoogleAssertion(string email, string privateKey, DateTimeOffset now)
    {
        using var rsa = RSA.Create();
        try
        {
            // A PEM block (it starts with its dashed header line), or the bare base64 body of a PKCS#8 key.
            var text = privateKey.Trim().Trim('"').Replace("\\n", "\n", StringComparison.Ordinal).Trim();
            if (text.StartsWith('-'))
                rsa.ImportFromPem(text);
            else
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(text), out _);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or FormatException)
        {
            throw new IntegrationException("The privateKey is not a private key: paste the private_key value from the service account's key file.");
        }

        var header = Base64Url("""{"alg":"RS256","typ":"JWT"}"""u8);
        var claims = new JsonObject
        {
            ["iss"] = email,
            ["scope"] = GoogleReadOnlyScope,
            ["aud"] = GoogleTokenUrl.ToString(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddHours(1).ToUnixTimeSeconds(),
        };
        var payload = Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()));
        var signature = rsa.SignData(Encoding.ASCII.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Base64Url(signature)}";
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
