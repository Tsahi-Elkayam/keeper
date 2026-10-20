using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Runners.Ldap;

/// <summary>
/// LDAP values as rule rows read them: FILETIME and generalized-time attributes become ISO dates
/// (FILETIME 0 and "never" stay as they are, so conditions can tell), SIDs and GUIDs become text,
/// other binary values are dropped, and multi-valued attributes become arrays.
/// </summary>
public static class LdapValues
{
    public static readonly IReadOnlySet<string> FileTimeAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "pwdLastSet", "lastLogonTimestamp", "lastLogon", "accountExpires", "badPasswordTime", "lockoutTime",
        "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "msDS-UserPasswordExpiryTimeComputed",
        "msDS-LastSuccessfulInteractiveLogonTime", "creationTime", "forceLogoff", "maxPwdAge", "minPwdAge", "lockoutDuration",
    };

    public static readonly IReadOnlySet<string> GeneralizedTimeAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "whenCreated", "whenChanged", "dSCorePropagationData", "msDS-ApproximateLastLogonTimeStamp",
    };

    private static readonly IReadOnlySet<string> SidAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "objectSid", "sIDHistory", "securityIdentifier",
    };

    /// <summary>Security descriptors whose allowed trustees are what a rule needs (who may delegate to this computer).</summary>
    private static readonly IReadOnlySet<string> DescriptorAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    };

    private static readonly IReadOnlySet<string> DurationAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "maxPwdAge", "minPwdAge", "lockoutDuration", "lockOutObservationWindow",
    };

    /// <summary>
    /// Attributes whose values are bytes. The LDAP client hands back any value that happens to be valid
    /// UTF-8 as a string, so these are always asked for as bytes - a SID must never arrive as text noise.
    /// </summary>
    public static bool IsBinary(string attribute) =>
        SidAttributes.Contains(attribute) || DescriptorAttributes.Contains(attribute) || attribute.Equals("objectGUID", StringComparison.OrdinalIgnoreCase);

    public static JsonNode? Convert(string attribute, IReadOnlyList<object> values)
    {
        var converted = values.Select(v => One(attribute, v)).Where(v => v is not null).ToList();
        if (converted.Count == 0)
            return null;
        return converted.Count == 1 && !IsMultiValuedByNature(attribute)
            ? converted[0]
            : new JsonArray(converted.ToArray());
    }

    private static bool IsMultiValuedByNature(string attribute) =>
        attribute is "memberOf" or "member" or "servicePrincipalName" or "objectClass" or "proxyAddresses" or "sIDHistory"
            or "msDS-AllowedToDelegateTo" or "dNSHostName-alt";

    private static JsonNode? One(string attribute, object value)
    {
        if (value is byte[] bytes)
        {
            if (SidAttributes.Contains(attribute))
                return Sid(bytes);
            if (DescriptorAttributes.Contains(attribute))
                return AllowedTrustees(bytes) is { } trustees ? new JsonArray([.. trustees.Select(t => (JsonNode)JsonValue.Create(t))]) : null;
            if (attribute.Equals("objectGUID", StringComparison.OrdinalIgnoreCase) && bytes.Length == 16)
                return new Guid(bytes).ToString();
            // Text arrives as bytes from some servers.
            var text = Encoding.UTF8.GetString(bytes);
            return text.All(c => !char.IsControl(c)) ? JsonValue.Create(Text(attribute, text)) : null;
        }
        return value is string s ? JsonValue.Create(Text(attribute, s)) : null;
    }

    private static string Text(string attribute, string value)
    {
        if (DurationAttributes.Contains(attribute) && long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks))
        {
            // The most negative value means "never" (no maximum age, locked until an admin unlocks);
            // Math.Abs of it overflows, so it is answered before any arithmetic.
            if (ticks == long.MinValue)
                return "never";
            return (Math.Abs(ticks) / TimeSpan.TicksPerDay).ToString(CultureInfo.InvariantCulture);   // days
        }
        if (FileTimeAttributes.Contains(attribute) && long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileTime))
        {
            if (fileTime <= 0 || fileTime == long.MaxValue || fileTime >= DateTime.MaxValue.ToFileTimeUtc())
                return value;   // never / not set: left for conditions to read as such
            return RowValues.Iso(new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime)));
        }
        if (GeneralizedTimeAttributes.Contains(attribute) && value.Length >= 14 &&
            DateTime.TryParseExact(value[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var generalized))
            return RowValues.Iso(new DateTimeOffset(generalized, TimeSpan.Zero));
        return value;
    }

    /// <summary>
    /// The SIDs a self-relative security descriptor's DACL allows (ACCESS_ALLOWED_ACE, type 0), without
    /// Windows-only APIs. Null when the bytes are not a well-formed descriptor; anything malformed is
    /// refused rather than guessed at.
    /// </summary>
    public static IReadOnlyList<string>? AllowedTrustees(byte[] bytes)
    {
        if (bytes.Length < 20 || bytes[0] != 1)
            return null;
        var daclOffset = BitConverter.ToInt32(bytes, 16);
        if (daclOffset == 0)
            return [];
        if (daclOffset < 20 || daclOffset + 8 > bytes.Length)
            return null;

        var aceCount = BitConverter.ToUInt16(bytes, daclOffset + 4);
        var position = daclOffset + 8;
        var trustees = new List<string>();
        for (var i = 0; i < aceCount; i++)
        {
            if (position + 4 > bytes.Length)
                return null;
            var type = bytes[position];
            var size = BitConverter.ToUInt16(bytes, position + 2);
            if (size < 8 || position + size > bytes.Length)
                return null;
            if (type == 0 && Sid(bytes[(position + 8)..(position + size)]) is { } sid)
                trustees.Add(sid);
            position += size;
        }
        return trustees;
    }

    /// <summary>Binary SID to S-1-5-21-... text, without Windows-only APIs.</summary>
    public static string? Sid(byte[] bytes)
    {
        if (bytes.Length < 8 || bytes[0] != 1)
            return null;
        int count = bytes[1];
        if (bytes.Length < 8 + (4 * count))
            return null;
        long authority = 0;
        for (var i = 2; i < 8; i++)
            authority = (authority << 8) | bytes[i];
        var sid = new StringBuilder($"S-1-{authority.ToString(CultureInfo.InvariantCulture)}");
        for (var i = 0; i < count; i++)
            sid.Append('-').Append(BitConverter.ToUInt32(bytes, 8 + (4 * i)).ToString(CultureInfo.InvariantCulture));
        return sid.ToString();
    }
}

/// <summary>
/// The filter macros earlier LDAP rules used, so they port as they are:
/// {USER} {COMPUTER} {ENABLED} {UAC:n} {FT:n} (FILETIME n days ago) {GT:n} (generalized time n days ago)
/// {DOMAINDN} {CONFIGDN} {SCHEMADN} {ROOTDN}, and {IFATTR:attribute|clause} (the clause only if the
/// schema has the attribute).
/// </summary>
public static class LdapMacros
{
    public static string Expand(string filter, DateTimeOffset now, IReadOnlyDictionary<string, string> namingContexts, Func<string, bool> schemaHas)
    {
        var output = new StringBuilder(filter.Length + 64);
        for (var i = 0; i < filter.Length; i++)
        {
            if (filter[i] != '{')
            {
                output.Append(filter[i]);
                continue;
            }
            var end = filter.IndexOf('}', i + 1);
            if (end < 0)
                throw new FormatException("unclosed { in filter");
            output.Append(Macro(filter[(i + 1)..end], now, namingContexts, schemaHas));
            i = end;
        }
        return output.ToString();
    }

    private static string Macro(string macro, DateTimeOffset now, IReadOnlyDictionary<string, string> contexts, Func<string, bool> schemaHas)
    {
        var colon = macro.IndexOf(':');
        var name = colon < 0 ? macro : macro[..colon];
        var argument = colon < 0 ? "" : macro[(colon + 1)..];
        int Days() => int.TryParse(argument, NumberStyles.None, CultureInfo.InvariantCulture, out var d)
            ? d
            : throw new FormatException($"{{{name}:n}} needs a number of days");

        switch (name)
        {
            case "USER": return "(&(objectCategory=person)(objectClass=user))";
            case "COMPUTER": return "(objectCategory=computer)";
            case "ENABLED": return "(!(userAccountControl:1.2.840.113556.1.4.803:=2))";
            case "UAC": return $"(userAccountControl:1.2.840.113556.1.4.803:={long.Parse(argument, CultureInfo.InvariantCulture)})";
            case "FT": return now.AddDays(-Days()).UtcDateTime.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
            case "GT": return now.AddDays(-Days()).UtcDateTime.ToString("yyyyMMddHHmmss'.0Z'", CultureInfo.InvariantCulture);
            case "DOMAINDN": return contexts.GetValueOrDefault("domain", "");
            case "CONFIGDN": return contexts.GetValueOrDefault("config", "");
            case "SCHEMADN": return contexts.GetValueOrDefault("schema", "");
            case "ROOTDN": return contexts.GetValueOrDefault("root", "");
            case "IFATTR":
                var bar = argument.IndexOf('|');
                if (bar < 1)
                    throw new FormatException("{IFATTR:attribute|clause} needs an attribute and a clause");
                return schemaHas(argument[..bar]) ? argument[(bar + 1)..] : "";
            default:
                throw new FormatException($"unknown filter macro {{{macro}}}");
        }
    }
}
