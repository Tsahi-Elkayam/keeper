using System.Text;
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
