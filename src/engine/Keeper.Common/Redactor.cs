using System.Text.RegularExpressions;

namespace Keeper.Common;

/// <summary>
/// The one place free text is cleaned before it is written anywhere: logs, evidence, error messages.
/// Removes what looks like a credential. Identifiers (host names, accounts, rule ids) are kept - the
/// store is the tenant's own and needs them.
/// </summary>
public static partial class Redactor
{
    public const string Mask = "<redacted>";

    public static string Clean(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return text ?? "";

        var cleaned = SecretPair().Replace(text, m => m.Groups["name"].Value + m.Groups["sep"].Value + Mask);
        cleaned = Bearer().Replace(cleaned, "Bearer " + Mask);
        cleaned = Jwt().Replace(cleaned, Mask);
        cleaned = UrlCredentials().Replace(cleaned, m => m.Groups["scheme"].Value + Mask + "@");
        return cleaned;
    }

    // A credential's name, then = or :, then its value - in query strings, JSON and config text alike.
    [GeneratedRegex("""(?<name>(?:pass(?:word|wd)?|pwd|secret|client_?secret|api_?key|access_?key|token|auth|credential)s?["']?)(?<sep>\s*[:=]\s*["']?)[^\s"',;&]+""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SecretPair();

    [GeneratedRegex(@"Bearer\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Bearer();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Jwt();

    [GeneratedRegex(@"(?<scheme>[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex UrlCredentials();
}
