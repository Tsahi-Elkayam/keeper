using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Keeper.Runners.Printer;

/// <summary>
/// A read-only SNMP v2c client: GET and GETNEXT, nothing else - a SET, a bulk request or an inform cannot be built.
/// An answer counts only if it carries the id of the request just sent. A walk says whether it reached the end of
/// its subtree or stopped early, and a silent device is reported as silent, never as an empty answer.
/// </summary>
public static partial class SnmpV2c
{
    private const byte Get = 0xA0;
    private const byte GetNext = 0xA1;

    public sealed record Walk(IReadOnlyList<(string Oid, object? Value)> Rows, bool Complete, string? Problem);

    private sealed record Reply(int RequestId, int ErrorStatus, string Oid, object? Value, bool EndOfMib);

    private sealed class NoValue
    {
        public static readonly NoValue Instance = new();
    }

    [GeneratedRegex(@"^\d+(\.\d+)+$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex OidShape();

    public static byte[] BuildRequest(byte pduTag, string community, int requestId, string oid)
    {
        if (pduTag is not (Get or GetNext))
            throw new InvalidOperationException($"Refused SNMP PDU tag 0x{pduTag:X2}: Keeper only reads.");
        if (string.IsNullOrEmpty(community))
            throw new ArgumentException("an SNMP community is required", nameof(community));
        if (!OidShape().IsMatch(oid))
            throw new ArgumentException($"'{oid}' is not a numeric OID", nameof(oid));

        var varbind = Tlv(0x30, [.. Tlv(0x06, EncodeOid(oid)), 0x05, 0x00]);
        var pdu = Tlv(pduTag, [.. Tlv(0x02, Integer(requestId)), .. Tlv(0x02, [0]), .. Tlv(0x02, [0]), .. Tlv(0x30, varbind)]);
        return Tlv(0x30, [.. Tlv(0x02, [1]), .. Tlv(0x04, Encoding.UTF8.GetBytes(community)), .. pdu]);
    }

    public static async Task<(string Oid, object? Value)?> GetAsync(IPEndPoint endpoint, string community, string oid, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var reply = await ExchangeAsync(endpoint, community, Get, oid, timeout, cancellationToken).ConfigureAwait(false);
        return reply is null || reply.ErrorStatus != 0 || reply.Value is NoValue ? null : (reply.Oid, reply.Value);
    }

    public static async Task<Walk> WalkAsync(IPEndPoint endpoint, string community, string prefix, int maxRows, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var rows = new List<(string, object?)>();
        var current = prefix;
        while (true)
        {
            var reply = await ExchangeAsync(endpoint, community, GetNext, current, timeout, cancellationToken).ConfigureAwait(false);
            if (reply is null)
                return new Walk(rows, false, rows.Count == 0 ? "no answer from the device (SNMP off, a different community, or blocked)" : "the device stopped answering during the walk");
            if (reply.ErrorStatus != 0 || reply.EndOfMib || !reply.Oid.StartsWith(prefix + ".", StringComparison.Ordinal))
                return new Walk(rows, true, null);
            if (Compare(reply.Oid, current) <= 0)
                return new Walk(rows, false, "the device answered with an OID that did not move forward");
            if (rows.Count >= maxRows)
                return new Walk(rows, false, $"more than {maxRows} rows under {prefix}; the rest were not read");
            rows.Add((reply.Oid, reply.Value is NoValue ? null : reply.Value));
            current = reply.Oid;
        }
    }

    private static async Task<Reply?> ExchangeAsync(IPEndPoint endpoint, string community, byte pduTag, string oid, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(endpoint.AddressFamily);
        udp.Connect(endpoint);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var requestId = Random.Shared.Next(1, 0x3FFFFFFF);
            await udp.SendAsync(BuildRequest(pduTag, community, requestId, oid), cancellationToken).ConfigureAwait(false);
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(timeout);
            try
            {
                while (true)
                {
                    var received = await udp.ReceiveAsync(limit.Token).ConfigureAwait(false);
                    if (TryParse(received.Buffer, out var reply) && reply.RequestId == requestId)
                        return reply;
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // No answer in time: ask once more.
            }
            catch (SocketException)
            {
                return null;
            }
        }
        return null;
    }

    private static bool TryParse(byte[] packet, out Reply reply)
    {
        reply = null!;
        try
        {
            var position = 0;
            var top = Read(packet, ref position, out var topTag);
            if (topTag != 0x30)
                return false;
            var p = 0;
            Read(top, ref p, out _);                                  // version
            Read(top, ref p, out _);                                  // community
            var pdu = Read(top, ref p, out var pduTag);
            if (pduTag != 0xA2)
                return false;
            var q = 0;
            var requestId = (int)ToLong(Read(pdu, ref q, out _));
            var errorStatus = (int)ToLong(Read(pdu, ref q, out _));
            Read(pdu, ref q, out _);                                  // error index
            var list = Read(pdu, ref q, out _);
            var l = 0;
            var varbind = Read(list, ref l, out _);
            var v = 0;
            var oidBytes = Read(varbind, ref v, out _);
            var valueBytes = Read(varbind, ref v, out var valueTag);
            reply = valueTag is 0x80 or 0x81 or 0x82
                ? new Reply(requestId, errorStatus, DecodeOid(oidBytes), NoValue.Instance, valueTag == 0x82)
                : new Reply(requestId, errorStatus, DecodeOid(oidBytes), DecodeValue(valueTag, valueBytes), false);
            return true;
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or OverflowException)
        {
            return false;
        }
    }

    private static object? DecodeValue(byte tag, byte[] bytes) => tag switch
    {
        0x02 => ToSigned(bytes),
        0x04 or 0x44 => bytes,
        0x05 => null,
        0x06 => DecodeOid(bytes),
        0x40 when bytes.Length == 4 => string.Join('.', bytes),
        0x41 or 0x42 or 0x43 or 0x46 => ToUnsigned(bytes),
        _ => bytes,
    };

    /// <summary>The text of an OCTET STRING, or its hex when it is not readable text; numbers as numbers.</summary>
    public static string AsText(object? value)
    {
        if (value is byte[] bytes)
        {
            var text = Encoding.UTF8.GetString(bytes);
            return bytes.Length > 0 && text.All(c => !char.IsControl(c) || c is '\t' or '\n' or '\r') && !text.Contains('�', StringComparison.Ordinal)
                ? text.Trim('\0', ' ')
                : Convert.ToHexString(bytes);
        }
        return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "";
    }

    private static int Compare(string a, string b)
    {
        var x = a.Split('.').Select(long.Parse).ToArray();
        var y = b.Split('.').Select(long.Parse).ToArray();
        for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
        {
            if (x[i] != y[i])
                return x[i].CompareTo(y[i]);
        }
        return x.Length.CompareTo(y.Length);
    }

    private static byte[] Read(byte[] data, ref int position, out byte tag)
    {
        tag = data[position++];
        int length = data[position++];
        if (length >= 0x80)
        {
            var count = length & 0x7F;
            if (count is 0 or > 3)
                throw new OverflowException("unsupported BER length");
            length = 0;
            for (var i = 0; i < count; i++)
                length = (length << 8) | data[position++];
        }
        var content = data[position..(position + length)];
        position += length;
        return content;
    }

    private static long ToSigned(byte[] bytes)
    {
        if (bytes.Length is 0 or > 8)
            return 0;
        long value = (bytes[0] & 0x80) != 0 ? -1 : 0;
        foreach (var b in bytes)
            value = (value << 8) | b;
        return value;
    }

    private static long ToUnsigned(byte[] bytes)
    {
        ulong value = 0;
        foreach (var b in bytes.Length > 9 ? [] : bytes)
            value = (value << 8) | b;
        return value > long.MaxValue ? long.MaxValue : (long)value;
    }

    private static long ToLong(byte[] bytes) => ToSigned(bytes);

    private static byte[] Integer(int value)
    {
        var bytes = new List<byte>();
        var v = value;
        do
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }
        while (v != 0 && v != -1 || (bytes[0] & 0x80) != 0 != (v < 0));
        return [.. bytes];
    }

    private static byte[] Tlv(byte tag, byte[] content) =>
        content.Length < 128 ? [tag, (byte)content.Length, .. content] : [tag, 0x82, (byte)(content.Length >> 8), (byte)content.Length, .. content];

    private static byte[] EncodeOid(string oid)
    {
        var arcs = oid.Split('.').Select(uint.Parse).ToArray();
        var bytes = new List<byte> { (byte)(arcs[0] * 40 + arcs[1]) };
        foreach (var arc in arcs.Skip(2))
        {
            var chunk = new List<byte> { (byte)(arc & 0x7F) };
            for (var v = arc >> 7; v > 0; v >>= 7)
                chunk.Insert(0, (byte)(0x80 | (v & 0x7F)));
            bytes.AddRange(chunk);
        }
        return [.. bytes];
    }

    private static string DecodeOid(byte[] bytes)
    {
        if (bytes.Length == 0)
            return "";
        var arcs = new List<ulong> { (ulong)(bytes[0] / 40), (ulong)(bytes[0] % 40) };
        ulong value = 0;
        foreach (var b in bytes.Skip(1))
        {
            value = (value << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0)
            {
                arcs.Add(value);
                value = 0;
            }
        }
        return string.Join('.', arcs);
    }
}
