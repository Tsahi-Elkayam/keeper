using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Keeper.Discover;

/// <summary>
/// IPv4 and IPv6 addresses and CIDR ranges: strict parsing, canonical form, range expansion with caps,
/// and the always-excluded address classes (unspecified, broadcast, multicast, loopback when asked).
/// </summary>
public static class Addresses
{
    public const int MinIpv6Prefix = 112;
    public const int DefaultMaxExpandedAddresses = 65536;

    /// <summary>Parses a strict IPv4 (four dotted decimal octets) or IPv6 address and normalises IPv4-mapped IPv6.</summary>
    public static bool TryParseAddress(string? text, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var trimmed = text.Trim();
        if (trimmed.Contains('%', StringComparison.Ordinal))
            return false; // Zone IDs are local to one interface and not canonical.

        if (trimmed.Contains(':', StringComparison.Ordinal))
        {
            if (!IPAddress.TryParse(trimmed, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetworkV6)
                return false;
            address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : CleanV6(parsed);
            return true;
        }

        var parts = trimmed.Split('.');
        if (parts.Length != 4 || !parts.All(p => p.Length is > 0 and <= 3 && p.All(char.IsAsciiDigit) && (p.Length == 1 || p[0] != '0')))
            return false;
        if (!IPAddress.TryParse(trimmed, out var v4) || v4.AddressFamily != AddressFamily.InterNetwork)
            return false;
        address = v4;
        return true;
    }

    public static IPAddress ParseAddress(string text) =>
        TryParseAddress(text, out var address)
            ? address
            : throw new ArgumentException($"'{text}' is not a valid IPv4 or IPv6 address.");

    public static string Canonical(IPAddress address) =>
        (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address.AddressFamily == AddressFamily.InterNetworkV6 ? CleanV6(address) : address).ToString();

    /// <summary>Parses a CIDR network or a single IP address (as /32 or /128), masking the base address to its prefix.</summary>
    public static bool TryParseNetwork(string? text, out IPNetwork network, out string? error)
    {
        network = default;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "network is empty.";
            return false;
        }
        var trimmed = text.Trim();
        var slash = trimmed.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
        {
            if (!TryParseAddress(trimmed, out var single))
            {
                error = $"'{trimmed}' is not a valid IP address or CIDR range.";
                return false;
            }
            network = new IPNetwork(single, single.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }

        var addrPart = trimmed[..slash];
        var prefixPart = trimmed[(slash + 1)..];
        if (!TryParseAddress(addrPart, out var addr))
        {
            error = $"'{trimmed}' has an invalid IP address '{addrPart}'.";
            return false;
        }
        var maxPrefix = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixPart.Length == 0 || !prefixPart.All(char.IsAsciiDigit)
            || !int.TryParse(prefixPart, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix)
            || prefix < 0 || prefix > maxPrefix)
        {
            error = $"'{trimmed}' has an invalid prefix length (must be 0..{maxPrefix}).";
            return false;
        }

        var masked = MaskAddress(addr, prefix);
        network = new IPNetwork(masked, prefix);
        return true;
    }

    public static IPNetwork ParseNetwork(string text) =>
        TryParseNetwork(text, out var network, out var error)
            ? network
            : throw new ArgumentException(error);

    public static bool Contains(IPNetwork network, IPAddress address)
    {
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (network.BaseAddress.AddressFamily != norm.AddressFamily)
            return false;
        return network.Contains(norm);
    }

    public static bool ContainsNetwork(IPNetwork outer, IPNetwork inner)
    {
        if (outer.BaseAddress.AddressFamily != inner.BaseAddress.AddressFamily || outer.PrefixLength > inner.PrefixLength)
            return false;
        return outer.Contains(inner.BaseAddress);
    }

    /// <summary>Whether an address is in an always-excluded class: unspecified (0.0.0.0, ::), loopback, link-local, multicast, or IPv4 broadcast.</summary>
    public static bool IsAlwaysExcluded(IPAddress address, out string? reason)
    {
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (norm.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = norm.GetAddressBytes();
            if (bytes[0] == 0)
            {
                reason = "unspecified (0.0.0.0/8)";
                return true;
            }
            if (bytes[0] == 127)
            {
                reason = "loopback (127.0.0.0/8)";
                return true;
            }
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                reason = "link-local (169.254.0.0/16)";
                return true;
            }
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
            {
                reason = "limited broadcast (255.255.255.255)";
                return true;
            }
            if (bytes[0] is >= 224 and <= 239)
            {
                reason = "IPv4 multicast (224.0.0.0/4)";
                return true;
            }
            if (bytes[0] >= 240)
            {
                reason = "reserved class E (240.0.0.0/4)";
                return true;
            }
            reason = null;
            return false;
        }

        if (norm.Equals(IPAddress.IPv6Any))
        {
            reason = "unspecified (::)";
            return true;
        }
        if (IPAddress.IsLoopback(norm))
        {
            reason = "loopback (::1)";
            return true;
        }
        if (norm.IsIPv6LinkLocal)
        {
            reason = "link-local (fe80::/10)";
            return true;
        }
        if (norm.IsIPv6Multicast)
        {
            reason = "IPv6 multicast (ff00::/8)";
            return true;
        }
        reason = null;
        return false;
    }

    /// <summary>
    /// Expands a CIDR range into probeable host addresses.
    /// IPv4 ranges wider than /31 exclude their network (first) and broadcast (last) addresses.
    /// IPv6 ranges wider than /112 are refused.
    /// </summary>
    public static IReadOnlyList<IPAddress> Expand(IPNetwork network, int maxAddresses = DefaultMaxExpandedAddresses)
    {
        if (maxAddresses <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxAddresses), "maxAddresses must be positive.");

        if (network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (network.PrefixLength < MinIpv6Prefix)
                throw new ArgumentException($"IPv6 range {network} is wider than /{MinIpv6Prefix}; wide IPv6 sweeps are refused.");

            var hostBitsV6 = 128 - network.PrefixLength;
            var totalV6 = 1UL << hostBitsV6;
            if (totalV6 > (ulong)maxAddresses)
                throw new ArgumentException($"Range {network} expands to {totalV6} addresses, exceeding the cap of {maxAddresses}.");

            var baseBytes = network.BaseAddress.GetAddressBytes();
            var low64 = BinaryPrimitives.ReadUInt64BigEndian(baseBytes.AsSpan(8, 8));
            var listV6 = new List<IPAddress>((int)totalV6);
            Span<byte> buf = stackalloc byte[16];
            baseBytes.AsSpan(0, 8).CopyTo(buf);
            for (ulong i = 0; i < totalV6; i++)
            {
                BinaryPrimitives.WriteUInt64BigEndian(buf[8..], low64 + i);
                var candidate = new IPAddress(buf);
                if (!IsAlwaysExcluded(candidate, out _))
                    listV6.Add(candidate);
            }
            return listV6;
        }

        var hostBits = 32 - network.PrefixLength;
        var total = 1UL << hostBits;
        var usable = network.PrefixLength <= 30 ? total - 2 : total;
        if (usable > (ulong)maxAddresses)
            throw new ArgumentException($"Range {network} expands to {usable} addresses, exceeding the cap of {maxAddresses}.");

        var start = BinaryPrimitives.ReadUInt32BigEndian(network.BaseAddress.GetAddressBytes());
        var firstOffset = network.PrefixLength <= 30 ? 1UL : 0UL;
        var lastOffset = network.PrefixLength <= 30 ? total - 2 : total - 1;

        var list = new List<IPAddress>((int)usable);
        Span<byte> v4Buf = stackalloc byte[4];
        for (var offset = firstOffset; offset <= lastOffset; offset++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(v4Buf, start + (uint)offset);
            var candidate = new IPAddress(v4Buf);
            if (!IsAlwaysExcluded(candidate, out _))
                list.Add(candidate);
        }
        return list;
    }

    /// <summary>Widens an address to a network with the given prefix length.</summary>
    public static IPNetwork Widen(IPAddress address, int prefixLength)
    {
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        var max = norm.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > max)
            throw new ArgumentOutOfRangeException(nameof(prefixLength), $"Prefix length must be between 0 and {max}.");
        if (norm.AddressFamily == AddressFamily.InterNetworkV6 && prefixLength < MinIpv6Prefix)
            throw new ArgumentException($"IPv6 widening prefix /{prefixLength} is wider than /{MinIpv6Prefix}.");
        return new IPNetwork(MaskAddress(norm, prefixLength), prefixLength);
    }

    private static IPAddress MaskAddress(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        var remBits = prefixLength % 8;
        if (fullBytes < bytes.Length)
        {
            if (remBits > 0)
            {
                bytes[fullBytes] &= (byte)(0xFF << (8 - remBits));
                fullBytes++;
            }
            for (var i = fullBytes; i < bytes.Length; i++)
                bytes[i] = 0;
        }
        return new IPAddress(bytes);
    }

    private static IPAddress CleanV6(IPAddress v6) => new(v6.GetAddressBytes());
}
