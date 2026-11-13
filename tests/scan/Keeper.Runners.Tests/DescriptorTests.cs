using Keeper.Runners.Ldap;

namespace Keeper.Runners.Tests;

/// <summary>Security descriptors built byte by byte, the way a domain controller hands them over.</summary>
public sealed class DescriptorTests
{
    /// <summary>S-1-5-a-b-...: revision 1, the count, the NT authority, the parts little-endian.</summary>
    private static byte[] Sid(params uint[] parts) =>
        [1, (byte)parts.Length, 0, 0, 0, 0, 0, 5, .. parts.SelectMany(BitConverter.GetBytes)];

    private static byte[] Ace(byte type, byte flags, int mask, byte[] sid, Guid? objectType = null)
    {
        List<byte> body = [.. BitConverter.GetBytes(mask)];
        if (objectType is { } guid)
        {
            body.AddRange(BitConverter.GetBytes(1));   // the object type is there
            body.AddRange(guid.ToByteArray());
        }
        body.AddRange(sid);
        return [type, flags, .. BitConverter.GetBytes((ushort)(body.Count + 4)), .. body];
    }

    private static byte[] Descriptor(bool isProtected, params byte[][] aces)
    {
        var owner = Sid(32, 544);
        var group = Sid(32, 544);
        var aclBody = aces.SelectMany(a => a).ToArray();
        byte[] acl = [4, 0, .. BitConverter.GetBytes((ushort)(8 + aclBody.Length)), .. BitConverter.GetBytes((ushort)aces.Length), 0, 0, .. aclBody];
        var ownerAt = 20;
        var groupAt = ownerAt + owner.Length;
        var daclAt = groupAt + group.Length;
        ushort control = (ushort)(0x8004 | (isProtected ? 0x1000 : 0));
        return [1, 0, .. BitConverter.GetBytes(control), .. BitConverter.GetBytes(ownerAt), .. BitConverter.GetBytes(groupAt),
            .. BitConverter.GetBytes(0), .. BitConverter.GetBytes(daclAt), .. owner, .. group, .. acl];
    }

    [Fact]
    public void Each_dacl_entry_is_its_trustee_type_rights_object_type_and_inheritance()
    {
        var bytes = Descriptor(true,
            Ace(0, 0, 0x10000000, Sid(21, 1, 2, 3, 1105)),
            Ace(5, 0x10, 0x100, Sid(21, 1, 2, 3, 1106), Guid.Parse("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")));

        var descriptor = Descriptors.Parse(bytes)!;

        Assert.Equal("S-1-5-32-544", descriptor["owner"]!.ToString());
        Assert.True((bool)descriptor["protected"]!);
        var dacl = descriptor["dacl"]!.AsArray();
        Assert.Equal(2, dacl.Count);
        Assert.Equal(("S-1-5-21-1-2-3-1105", "allow", """["GenericAll"]""", false),
            (dacl[0]!["trustee"]!.ToString(), dacl[0]!["type"]!.ToString(), dacl[0]!["rights"]!.ToJsonString(), (bool)dacl[0]!["inherited"]!));
        Assert.Equal(("allow-object", "DS-Replication-Get-Changes-All", true),
            (dacl[1]!["type"]!.ToString(), dacl[1]!["objectTypeName"]!.ToString(), (bool)dacl[1]!["inherited"]!));
    }

    [Fact]
    public void A_descriptor_that_is_cut_or_malformed_is_refused_not_guessed()
    {
        var bytes = Descriptor(false, Ace(0, 0, 0x20, Sid(21, 1, 2, 3, 1105)));

        Assert.Null(Descriptors.Parse(bytes[..^4]));            // the last entry is cut short
        Assert.Null(Descriptors.Parse([2, .. bytes[1..]]));      // not revision 1
        Assert.NotNull(Descriptors.Parse(bytes));
    }

    [Fact]
    public void No_dacl_at_all_is_said_as_itself()
    {
        var bytes = Descriptor(false);
        bytes[16] = bytes[17] = bytes[18] = bytes[19] = 0;   // the DACL offset: none

        Assert.True((bool)Descriptors.Parse(bytes)!["noDacl"]!);
    }

    [Fact]
    public void The_descriptor_is_read_as_bytes_and_becomes_an_object_on_the_row()
    {
        Assert.True(LdapValues.IsBinary("nTSecurityDescriptor"));
        var bytes = Descriptor(false, Ace(0, 0, 0x40000, Sid(21, 1, 2, 3, 513)));

        var value = LdapValues.Convert("nTSecurityDescriptor", [bytes]);

        Assert.Equal("WriteDacl", value!["dacl"]![0]!["rights"]![0]!.ToString());
    }
}
