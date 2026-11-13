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

    internal sealed record Reply(int RequestId, int ErrorStatus, string Oid, object? Value, bool EndOfMib);

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

    /// <summary>
    /// One UDP socket to one device for a whole scan, and what it has learned about the device: a community it
    /// did not answer for is not asked again (an agent drops a wrong community without a word, and each unanswered
    /// request costs the full timeout twice). Thread-safe; requests are sent one at a time.
    /// </summary>
    public sealed class Channel(IPEndPoint endpoint) : IDisposable
    {
        private readonly UdpClient _udp = Connected(endpoint);
        private readonly SemaphoreSlim _one = new(1, 1);
        private readonly HashSet<string> _silent = new(StringComparer.Ordinal);

        public IPEndPoint Endpoint => endpoint;

        /// <summary>How many requests went out, retries included: what the device was actually asked.</summary>
        public int Sent { get; private set; }

        /// <summary>Whether the device did not answer for this community earlier in the scan.</summary>
        public bool IsSilent(string community)
        {
            lock (_silent)
                return _silent.Contains(community);
        }

        private static UdpClient Connected(IPEndPoint endpoint)
        {
            var udp = new UdpClient(endpoint.AddressFamily);
            udp.Connect(endpoint);
            return udp;
        }

        internal async Task<Reply?> ExchangeAsync(string community, byte pduTag, string oid, TimeSpan timeout, Func<CancellationToken, Task>? before,
            CancellationToken cancellationToken)
        {
            if (IsSilent(community))
                return null;
            await _one.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    var requestId = Random.Shared.Next(1, 0x3FFFFFFF);
                    if (before is not null)
                        await before(cancellationToken).ConfigureAwait(false);
                    await _udp.SendAsync(BuildRequest(pduTag, community, requestId, oid), cancellationToken).ConfigureAwait(false);
                    Sent++;
                    using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    limit.CancelAfter(timeout);
                    try
                    {
                        while (true)
                        {
                            var received = await _udp.ReceiveAsync(limit.Token).ConfigureAwait(false);
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
                        break;
                    }
                }
                lock (_silent)
                    _silent.Add(community);
                return null;
            }
            finally
            {
                _one.Release();
            }
        }

        public async Task<(string Oid, object? Value)?> GetAsync(string community, string oid, TimeSpan timeout, Func<CancellationToken, Task>? before,
            CancellationToken cancellationToken)
        {
            var reply = await ExchangeAsync(community, Get, oid, timeout, before, cancellationToken).ConfigureAwait(false);
            return reply is null || reply.ErrorStatus != 0 || reply.Value is NoValue ? null : (reply.Oid, reply.Value);
        }

        public Task<Walk> WalkAsync(string community, string prefix, int maxRows, TimeSpan timeout, Func<CancellationToken, Task>? before,
            CancellationToken cancellationToken) =>
            SnmpV2c.WalkAsync((tag, oid) => ExchangeAsync(community, tag, oid, timeout, before, cancellationToken), prefix, maxRows);

        public void Dispose()
        {
            _udp.Dispose();
            _one.Dispose();
        }
    }

    public static async Task<(string Oid, object? Value)?> GetAsync(IPEndPoint endpoint, string community, string oid, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var channel = new Channel(endpoint);
        return await channel.GetAsync(community, oid, timeout, null, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<Walk> WalkAsync(IPEndPoint endpoint, string community, string prefix, int maxRows, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var channel = new Channel(endpoint);
        return await channel.WalkAsync(community, prefix, maxRows, timeout, null, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<Walk> WalkAsync(Func<byte, string, Task<Reply?>> exchange, string prefix, int maxRows)
    {
        var rows = new List<(string, object?)>();
        var current = prefix;
        while (true)
        {
            var reply = await exchange(GetNext, current).ConfigureAwait(false);
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
