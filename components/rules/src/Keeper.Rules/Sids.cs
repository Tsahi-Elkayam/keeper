using System.Globalization;
using System.Text.RegularExpressions;

namespace Keeper.Rules;

/// <summary>
/// Security identifiers a condition can name (sid-in, sid-notin): the fixed well-known SIDs by name
/// (everyone, authenticated-users, builtin-administrators), a domain's own groups by name or RID
/// (domain-admins, rid:512) - which match that RID in any domain - and literal SIDs.
/// </summary>
public static partial class Sids
{
    private static readonly Dictionary<string, string> Fixed = new(StringComparer.OrdinalIgnoreCase)
    {
        ["everyone"] = "S-1-1-0",
        ["creator-owner"] = "S-1-3-0",
        ["network"] = "S-1-5-2",
        ["batch"] = "S-1-5-3",
        ["interactive"] = "S-1-5-4",
        ["service"] = "S-1-5-6",
        ["anonymous"] = "S-1-5-7",
        ["enterprise-domain-controllers"] = "S-1-5-9",
        ["self"] = "S-1-5-10",
        ["authenticated-users"] = "S-1-5-11",
        ["local-system"] = "S-1-5-18",
        ["local-service"] = "S-1-5-19",
        ["network-service"] = "S-1-5-20",
        ["builtin-administrators"] = "S-1-5-32-544",
        ["builtin-users"] = "S-1-5-32-545",
        ["builtin-guests"] = "S-1-5-32-546",
        ["power-users"] = "S-1-5-32-547",
        ["account-operators"] = "S-1-5-32-548",
        ["server-operators"] = "S-1-5-32-549",
        ["print-operators"] = "S-1-5-32-550",
        ["backup-operators"] = "S-1-5-32-551",
        ["pre-windows-2000-compatible-access"] = "S-1-5-32-554",
        ["remote-desktop-users"] = "S-1-5-32-555",
        ["network-configuration-operators"] = "S-1-5-32-556",
        ["remote-management-users"] = "S-1-5-32-580",
        ["local-account"] = "S-1-5-113",
        ["local-account-and-administrator"] = "S-1-5-114",
    };

    private static readonly Dictionary<string, int> DomainRids = new(StringComparer.OrdinalIgnoreCase)
    {
        ["administrator"] = 500,
        ["guest"] = 501,
        ["krbtgt"] = 502,
        ["domain-admins"] = 512,
        ["domain-users"] = 513,
        ["domain-guests"] = 514,
        ["domain-computers"] = 515,
        ["domain-controllers"] = 516,
        ["cert-publishers"] = 517,
        ["schema-admins"] = 518,
        ["enterprise-admins"] = 519,
        ["group-policy-creator-owners"] = 520,
        ["read-only-domain-controllers"] = 521,
        ["cloneable-domain-controllers"] = 522,
        ["protected-users"] = 525,
        ["key-admins"] = 526,
        ["enterprise-key-admins"] = 527,
        ["ras-and-ias-servers"] = 553,
        ["allowed-rodc-password-replication"] = 571,
        ["denied-rodc-password-replication"] = 572,
    };

    [GeneratedRegex(@"^S-1-\d{1,14}(-\d{1,10}){1,15}$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex Sid();

    [GeneratedRegex(@"^S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}-(\d{1,10})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex DomainSid();

    public static bool IsSid(string text) => Sid().IsMatch(text.Trim());

    /// <summary>A name, rid:N or S-1-... a condition may list.</summary>
    public static bool IsKnown(string entry) => Resolve(entry) is not null;

    /// <summary>Whether a SID is the one the entry names; for a domain group, the same RID in any domain.</summary>
    public static bool Matches(string sid, string entry) => Resolve(entry) switch
    {
        string fixedSid => string.Equals(sid.Trim(), fixedSid, StringComparison.OrdinalIgnoreCase),
        int rid => DomainSid().Match(sid.Trim()) is { Success: true } m && m.Groups[1].Value == rid.ToString(CultureInfo.InvariantCulture),
        _ => false,
    };

    private static object? Resolve(string entry)
    {
        entry = entry.Trim();
        if (Fixed.TryGetValue(entry, out var sid))
            return sid;
        if (DomainRids.TryGetValue(entry, out var rid))
            return rid;
        if (entry.StartsWith("rid:", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(entry[4..], NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number > 0)
            return number;
        return IsSid(entry) ? entry : null;
    }
}
