using System.Text.Json.Nodes;

namespace Keeper.Runners.Ldap;

/// <summary>
/// An Active Directory object's security descriptor (nTSecurityDescriptor, self-relative) as a row field:
/// owner, group, whether the DACL is protected from inheritance, and each DACL entry - trustee (a SID), type
/// (allow, deny, allow-object, deny-object), the rights as a mask and by name, the object type it is limited
/// to (an attribute, a property set or an extended right, by GUID and, when Keeper knows it, by name), and
/// whether it was inherited. Parsed by hand, on any platform; a malformed descriptor is refused, never guessed.
/// </summary>
public static class Descriptors
{
    private const ushort DaclProtected = 0x1000;
    private const ushort DaclPresent = 0x0004;

    // Access rights of directory objects (ADS_RIGHTS_ENUM).
    private static readonly (int Bit, string Name)[] Rights =
    [
        (0x1, "CreateChild"), (0x2, "DeleteChild"), (0x4, "ListChildren"), (0x8, "Self"), (0x10, "ReadProperty"),
        (0x20, "WriteProperty"), (0x40, "DeleteTree"), (0x80, "ListObject"), (0x100, "ExtendedRight"), (0x10000, "Delete"),
        (0x20000, "ReadControl"), (0x40000, "WriteDacl"), (0x80000, "WriteOwner"), (0x10000000, "GenericAll"),
        (0x20000000, "GenericExecute"), (0x40000000, "GenericWrite"), (unchecked((int)0x80000000), "GenericRead"),
    ];

    /// <summary>Schema and extended-right GUIDs that matter to rules, by name - the same in every forest.</summary>
    public static readonly IReadOnlyDictionary<string, string> KnownObjectTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"] = "DS-Replication-Get-Changes",
        ["1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"] = "DS-Replication-Get-Changes-All",
        ["89e95b76-444d-4c62-991a-0facbeda640c"] = "DS-Replication-Get-Changes-In-Filtered-Set",
        ["00299570-246d-11d0-a768-00aa006e0529"] = "User-Force-Change-Password",
        ["ab721a53-1e2f-11d0-9819-00aa0040529b"] = "User-Change-Password",
        ["bf9679c0-0de6-11d0-a285-00aa003049e2"] = "member",
        ["5b47d60f-6090-40b2-9f37-2a4de88f3063"] = "msDS-KeyCredentialLink",
        ["f3a64788-5306-11d1-a9c5-0000f80367c1"] = "servicePrincipalName",
        ["3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"] = "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ["f30e3bbe-9ff0-11d1-b603-0000f80367c1"] = "gPLink",
        ["bf967a68-0de6-11d0-a285-00aa003049e2"] = "userAccountControl",
        ["0e10c968-78fb-11d2-90d4-00c04f79dc55"] = "Certificate-Enrollment",
        ["a05b8cc2-17bc-4802-a710-e7c15ab866a2"] = "Certificate-AutoEnrollment",
        ["bf967aba-0de6-11d0-a285-00aa003049e2"] = "user",
        ["bf967a86-0de6-11d0-a285-00aa003049e2"] = "computer",
        ["bf967a9c-0de6-11d0-a285-00aa003049e2"] = "group",
        ["4828cc14-1437-45bc-9b07-ad6f015e5f28"] = "inetOrgPerson",
    };

    /// <summary>The descriptor as an object, or null when the bytes are not a well-formed self-relative descriptor.</summary>
    public static JsonObject? Parse(byte[] bytes)
    {
        if (bytes.Length < 20 || bytes[0] != 1)
            return null;
        var control = BitConverter.ToUInt16(bytes, 2);
        // Offsets are unsigned and checked as such: a garbled one must be refused, never wrap around or throw.
        long ownerOffset = BitConverter.ToUInt32(bytes, 4), groupOffset = BitConverter.ToUInt32(bytes, 8), daclOffset = BitConverter.ToUInt32(bytes, 16);
        if (ownerOffset > bytes.Length || groupOffset > bytes.Length || daclOffset > bytes.Length)
            return null;
        var result = new JsonObject
        {
            ["owner"] = SidAt(bytes, (int)ownerOffset),
            ["group"] = SidAt(bytes, (int)groupOffset),
            ["protected"] = (control & DaclProtected) != 0,
        };
        // Without SE_DACL_PRESENT the descriptor says nothing about access (it was not asked for, or not given):
        // nothing can be judged from it.
        if ((control & DaclPresent) == 0)
            return null;
        if (daclOffset == 0)
        {
            // A DACL that is there but null: everyone has every right. Said as itself, so a rule can fire on it.
            result["noDacl"] = true;
            result["dacl"] = new JsonArray();
            return result;
        }
        if (daclOffset < 20 || daclOffset + 8 > bytes.Length)
            return null;

        // The ACL's own size bounds its entries: a count too high must not read the SIDs that follow it.
        var aclSize = BitConverter.ToUInt16(bytes, (int)daclOffset + 2);
        var aclEnd = daclOffset + aclSize;
        if (aclSize < 8 || aclEnd > bytes.Length)
            return null;
        var aceCount = BitConverter.ToUInt16(bytes, (int)daclOffset + 4);
        var position = (int)daclOffset + 8;
        var entries = new JsonArray();
        for (var i = 0; i < aceCount; i++)
        {
            if (position + 8 > aclEnd)
                return null;
            var type = bytes[position];
            var flags = bytes[position + 1];
            var size = BitConverter.ToUInt16(bytes, position + 2);
            if (size < 8 || position + size > aclEnd)
                return null;
            var ace = bytes[position..(position + size)];
            position += size;
            if (type is not (0 or 1 or 5 or 6))
                continue;   // audit and callback entries are no grant of access

            var mask = BitConverter.ToInt32(ace, 4);
            var at = 8;
            string? objectType = null;
            string? inheritedObjectType = null;
            if (type is 5 or 6)
            {
                if (ace.Length < 12)
                    return null;
                var present = BitConverter.ToInt32(ace, 8);
                at = 12;
                if ((present & 1) != 0)
                {
                    if (at + 16 > ace.Length)
                        return null;
                    objectType = new Guid(ace.AsSpan(at, 16)).ToString();
                    at += 16;
                }
                if ((present & 2) != 0)
                {
                    if (at + 16 > ace.Length)
                        return null;
                    inheritedObjectType = new Guid(ace.AsSpan(at, 16)).ToString();
                    at += 16;
                }
            }
            if (LdapValues.Sid(ace[at..]) is not { } trustee)
                return null;

            entries.Add(new JsonObject
            {
                ["trustee"] = trustee,
                ["type"] = type switch { 0 => "allow", 1 => "deny", 5 => "allow-object", _ => "deny-object" },
                ["mask"] = mask,
                ["rights"] = new JsonArray([.. Rights.Where(r => (mask & r.Bit) == r.Bit).Select(r => (JsonNode?)r.Name)]),
                ["objectType"] = objectType,
                ["objectTypeName"] = objectType is null ? null : KnownObjectTypes.GetValueOrDefault(objectType),
                ["inheritedObjectType"] = inheritedObjectType,
                ["inheritedObjectTypeName"] = inheritedObjectType is null ? null : KnownObjectTypes.GetValueOrDefault(inheritedObjectType),
                ["inherited"] = (flags & 0x10) != 0,
                ["inheritOnly"] = (flags & 0x08) != 0,
                ["containerInherit"] = (flags & 0x02) != 0,
            });
        }
        result["dacl"] = entries;
        return result;
    }

    private static string? SidAt(byte[] bytes, int offset) =>
        offset > 0 && (long)offset + 8 <= bytes.Length ? LdapValues.Sid(bytes[offset..]) : null;
}
