using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Keeper.Runners;

/// <summary>Attributes that hold secrets. Never returned, whatever a rule asks for; their expiry times are fine.</summary>
public static class SecretAttributes
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory", "unicodePwd", "userPassword",
        "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials", "msDS-ManagedPassword",
        "msDS-ManagedPasswordId", "msDS-ManagedPasswordPreviousId", "msFVE-RecoveryPassword", "msFVE-KeyPackage",
        "msTPM-OwnerInformation", "msTPM-TpmInformationForComputer", "msDS-KeyCredentialLink", "trustAuthIncoming",
        "trustAuthOutgoing", "currentValue", "priorValue", "initialAuthIncoming", "initialAuthOutgoing",
    };

    public static bool IsSecret(string attribute) => Names.Contains(attribute);

    public static IEnumerable<string> In(IEnumerable<string> attributes) => attributes.Where(IsSecret);
}

/// <summary>
/// Properties of a JSON answer (Graph, REST and GraphQL APIs, imported reports) that hold a secret: a
/// Wi-Fi or VPN key in a device profile, a script that may embed a credential, a token. Exact names only -
/// passwordPolicies and lastPasswordChangeDateTime are facts, not secrets. A secret that is there comes
/// back as "set", so a rule can still say whether one exists; its value never reaches a row.
/// </summary>
public static class SecretProperties
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "pwd", "user_password", "passphrase", "secret", "secretText", "clientSecret", "sharedSecret",
        "preSharedKey", "wpaPreSharedKey", "privateKey", "apiKey", "api_key", "token", "accessToken", "access_token",
        "refreshToken", "refresh_token", "connectionString", "scriptContent", "detectionScriptContent",
        "remediationScriptContent", "recoveryKey", "bitLockerRecoveryKey",
    };

    public static bool IsSecret(string property) => Names.Contains(property);

    // A URL that carries its own credential: a SAS or flow-trigger sig, an S3 presigned signature or token, an
    // Azure Functions code, a key in the query. The rest of the URL stays, so evidence can still name it.
    private static readonly System.Text.RegularExpressions.Regex SignedUrl = new(
        @"([?&#;](?:sig|signature|x-amz-signature|x-amz-security-token|x-amz-credential|x-goog-signature|code|api[-_]?key|access_token|id_token|token|key|client_secret|secret|password|pwd)=)[^&#;\s""]+",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    /// <summary>A text with the credentials of any URL in it replaced by "set".</summary>
    public static string MaskUrls(string text)
    {
        if (!text.Contains('=', StringComparison.Ordinal) || !text.Contains("://", StringComparison.Ordinal))
            return text;
        try
        {
            return SignedUrl.Replace(text, "$1set");
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            return "set";   // too odd to read safely: hidden whole
        }
    }

    /// <summary>
    /// Replaces every secret value in <paramref name="node"/>, at any depth, with "set" - by name, and the
    /// credential in any signed URL. Changes the node in place.
    /// </summary>
    public static void Mask(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).ToList())
                {
                    if (IsSecret(name))
                    {
                        if (o[name] is not null && !(o[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length == 0))
                            o[name] = "set";
                    }
                    else if (o[name] is JsonValue value && value.TryGetValue<string>(out var text) && MaskUrls(text) is var masked && !string.Equals(masked, text, StringComparison.Ordinal))
                    {
                        o[name] = masked;
                    }
                    else
                    {
                        Mask(o[name]);
                    }
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue value && value.TryGetValue<string>(out var text) && MaskUrls(text) is var masked && !string.Equals(masked, text, StringComparison.Ordinal))
                        a[i] = masked;
                    else
                        Mask(a[i]);
                }
                break;
        }
    }
}

/// <summary>
/// The read-only guard for SQL text (the sql and store protocols): one SELECT or WITH statement, no
/// statement that changes anything or reaches outside the database. Defence in depth - the runners also
/// read inside a transaction that is always rolled back, or on a read-only connection.
/// </summary>
public static partial class SqlGuard
{
    private static readonly string[] Forbidden =
    [
        "insert", "update", "delete", "merge", "drop", "alter", "create", "truncate", "exec", "execute", "grant", "revoke",
        "deny", "backup", "restore", "dbcc", "shutdown", "kill", "openrowset", "openquery", "opendatasource", "bulk",
        "into", "attach", "detach", "pragma", "vacuum", "reindex", "waitfor", "reconfigure", "use",
    ];

    /// <returns>Null when the text is acceptable; otherwise why it is not.</returns>
    public static string? Problem(string? text, IReadOnlyCollection<string>? forbiddenTables = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "the query text is empty";

        // Tables are checked against the raw text, quotes and brackets included: [secret] is still secret.
        if (forbiddenTables is not null)
        {
            foreach (Match word in Word().Matches(text))
            {
                if (forbiddenTables.Contains(word.Value.ToLowerInvariant()))
                    return $"table '{word.Value}' is not readable by rules";
            }
        }

        var code = StripCommentsAndStrings(text).Trim().TrimEnd(';').Trim();
        if (code.Contains(';'))
            return "only one statement is allowed";
        if (!StartsRead().IsMatch(code))
            return "only SELECT or WITH statements are allowed";

        foreach (Match word in Word().Matches(code))
        {
            var lower = word.Value.ToLowerInvariant();
            if (Forbidden.Contains(lower) || lower.StartsWith("xp_", StringComparison.Ordinal) || lower.StartsWith("sp_", StringComparison.Ordinal))
                return $"'{word.Value}' is not allowed in a read-only query";
        }
        return null;
    }

    private static string StripCommentsAndStrings(string text)
    {
        var output = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '-' && i + 1 < text.Length && text[i + 1] == '-')
            {
                while (i < text.Length && text[i] != '\n')
                    i++;
                output.Append(' ');
            }
            else if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? text.Length : end + 1;
                output.Append(' ');
            }
            else if (c is '\'' or '"' or '[')
            {
                var close = c == '[' ? ']' : c;
                i++;
                while (i < text.Length && text[i] != close)
                    i++;
                output.Append(" '' ");
            }
            else
            {
                output.Append(c);
            }
        }
        return output.ToString();
    }

    [GeneratedRegex(@"^\s*(select|with)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StartsRead();

    [GeneratedRegex(@"[A-Za-z_][A-Za-z0-9_]*", RegexOptions.CultureInvariant)]
    private static partial Regex Word();
}

/// <summary>Relative HTTP paths only: a rule can never point a credential at another host.</summary>
public static class HttpPaths
{
    public static string? Problem(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "path is required";
        if (!path.StartsWith('/'))
            return "path must start with / (it is relative to the integration's endpoint)";
        if (path.StartsWith("//", StringComparison.Ordinal) || path.Contains("://", StringComparison.Ordinal))
            return "path must not name a host";
        if (path.Split('/', '?').Any(segment => segment is ".." or "."))
            return "path must not contain . or .. segments";
        if (path.Contains('\\') || path.Contains('@') || path.Any(char.IsControl))
            return "path contains characters that are not allowed";
        return null;
    }
}

/// <summary>Refuses any request that is not to the integration's own host, scheme and port.</summary>
public sealed class HostPinningHandler(Uri endpoint, HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri ?? throw new InvalidOperationException("A request needs a URI.");
        if (!uri.Scheme.Equals(endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
            || !uri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || uri.Port != endpoint.Port)
            throw new UnauthorizedAccessException($"Refused a request to {uri.Scheme}://{uri.Host}:{uri.Port}; this integration may only reach {endpoint.Host}.");
        return base.SendAsync(request, cancellationToken);
    }
}
