using System.Text.RegularExpressions;

namespace Keeper.Runners;

/// <summary>
/// Credentials written as text: "DB_PASSWORD=x", "--password=x", "api_key: x". The name stays, the value becomes
/// "set". A setting about passwords ("PasswordAuthentication no") and a path to one ("ssl_password_file") are not
/// credentials and are left alone.
/// </summary>
public static class CredentialText
{
    /// <summary>Words in a name that say the value is a location, not the secret itself.</summary>
    public static readonly string[] LocationWords = ["file", "path", "dir", "url"];

    private static readonly Regex Plain = new(
        @"^(yes|no|on|off|true|false|enabled|disabled|none|required|optional|[0-9]+)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static readonly Regex Credential = new(
        @"(?<name>[\w.\-]*(password|passwd|passphrase|secret|api[_-]?key|apitoken|access[_-]?token|auth[_-]?token|credential)[\w.\-]*)(?<sep>\s*[=:]\s*)(?<value>\S.*)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>A value that is a plain setting word or a number: yes, off, 90.</summary>
    public static bool IsPlainSetting(string value) => Plain.IsMatch(value);

    public static string Scrub(string text)
    {
        try
        {
            return Credential.Replace(text, m =>
            {
                var name = m.Groups["name"].Value.ToLowerInvariant();
                var value = m.Groups["value"].Value.Trim().Trim('"', '\'');
                return LocationWords.Any(w => name.Contains(w, StringComparison.Ordinal)) || IsPlainSetting(value)
                    ? m.Value
                    : m.Groups["name"].Value + m.Groups["sep"].Value + "set";
            });
        }
        catch (RegexMatchTimeoutException)
        {
            return "set";   // too odd to read safely: hidden whole
        }
    }
}
