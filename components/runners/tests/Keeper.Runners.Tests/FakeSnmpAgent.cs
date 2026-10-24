using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Keeper.Runners.Tests;

/// <summary>An SNMP v2c agent on a loopback UDP port: answers GET and GETNEXT from a table, silent for any other community.</summary>
internal sealed class FakeSnmpAgent : IDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _stop = new();
    private readonly SortedDictionary<int[], object> _table = new(new OidComparer());
    private readonly string _community;

    public FakeSnmpAgent(string community, Dictionary<string, object> values)
    {
        _community = community;
        foreach (var (oid, value) in values)
            _table[Arcs(oid)] = value;
        _ = Task.Run(Serve);
    }

    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    /// <summary>Every request PDU tag seen, so a test can prove that nothing but GET and GETNEXT arrived.</summary>
    public List<byte> PduTags { get; } = [];

    /// <summary>Requests answered with an old request id first, to prove a late or spoofed answer is ignored.</summary>
    public bool SendStaleAnswerFirst { get; set; }

    private static int[] Arcs(string oid) => oid.Split('.').Select(int.Parse).ToArray();

    private sealed class OidComparer : IComparer<int[]>
    {
        public int Compare(int[]? a, int[]? b)
        {
            for (var i = 0; i < Math.Min(a!.Length, b!.Length); i++)
            {
                if (a[i] != b[i])
                    return a[i].CompareTo(b[i]);
            }
            return a.Length.CompareTo(b.Length);
        }
    }

    private async Task Serve()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                var received = await _udp.ReceiveAsync(_stop.Token);
                var reply = Answer(received.Buffer);
                if (reply is null)
                    continue;
                if (SendStaleAnswerFirst)
                    await _udp.SendAsync(reply.Value.Stale, received.RemoteEndPoint);
                await _udp.SendAsync(reply.Value.Good, received.RemoteEndPoint);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
        }
    }

    private (byte[] Good, byte[] Stale)? Answer(byte[] packet)
    {
        var pos = 0;
        Read(packet, ref pos, out _, out var top);
        var p = 0;
        Read(top, ref p, out _, out _);                         // version
        Read(top, ref p, out _, out var community);
        if (Encoding.UTF8.GetString(community) != _community)
            return null;
        Read(top, ref p, out var pduTag, out var pdu);
        lock (PduTags)
            PduTags.Add(pduTag);
        var q = 0;
        Read(pdu, ref q, out _, out var id);
        Read(pdu, ref q, out _, out _);
        Read(pdu, ref q, out _, out _);
        Read(pdu, ref q, out _, out var list);
        var l = 0;
        Read(list, ref l, out _, out var varbind);
        var v = 0;
        Read(varbind, ref v, out _, out var oidBytes);
        var oid = DecodeOid(oidBytes);
        var requestId = ToInt(id);

        byte[] value;
        string answerOid;
        if (pduTag == 0xA0)
        {
            answerOid = string.Join('.', oid);
            value = _table.TryGetValue(oid, out var exact) ? Encode(exact) : [0x80, 0x00];
        }
        else
        {
            var next = _table.Keys.FirstOrDefault(k => new OidComparer().Compare(k, oid) > 0);
            answerOid = next is null ? string.Join('.', oid) : string.Join('.', next);
            value = next is null ? [0x82, 0x00] : Encode(_table[next]);
        }
        return (Response(requestId, answerOid, value), Response(requestId + 1000, answerOid, value));
    }

    private byte[] Response(int requestId, string oid, byte[] value)
    {
        var varbind = Tlv(0x30, [.. Tlv(0x06, EncodeOid(oid)), .. value]);
        var pdu = Tlv(0xA2, [.. Tlv(0x02, Int(requestId)), .. Tlv(0x02, [0]), .. Tlv(0x02, [0]), .. Tlv(0x30, varbind)]);
        return Tlv(0x30, [.. Tlv(0x02, [1]), .. Tlv(0x04, Encoding.UTF8.GetBytes(_community)), .. pdu]);
    }

    private static byte[] Encode(object value) => value switch
    {
        long n when n > int.MaxValue => Tlv(0x41, UnsignedBytes(n)),          // Counter32
        long n => Tlv(0x02, Int((int)n)),
        string s => Tlv(0x04, Encoding.UTF8.GetBytes(s)),
        byte[] b => Tlv(0x04, b),
        _ => [0x05, 0x00],
    };

    private static byte[] UnsignedBytes(long n)
    {
        var bytes = new List<byte>();
        for (var v = n; v > 0; v >>= 8)
            bytes.Insert(0, (byte)(v & 0xFF));
        if ((bytes[0] & 0x80) != 0)
            bytes.Insert(0, 0);
        return [.. bytes];
    }

    private static byte[] Int(int n)
    {
        if (n >= 0)
            return n < 128 ? [(byte)n] : UnsignedBytes(n);
        // Two's complement, shortest form: -3 is one byte, 0xFD.
        var bytes = new List<byte>();
        var v = n;
        do
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }
        while (v != -1 || (bytes[0] & 0x80) == 0);
        return [.. bytes];
    }

    private static byte[] Tlv(byte tag, byte[] content) =>
        content.Length < 128 ? [tag, (byte)content.Length, .. content] : [tag, 0x82, (byte)(content.Length >> 8), (byte)content.Length, .. content];

    private static byte[] EncodeOid(string oid)
    {
        var arcs = Arcs(oid);
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

    private static int[] DecodeOid(byte[] bytes)
    {
        var arcs = new List<int> { bytes[0] / 40, bytes[0] % 40 };
        var value = 0;
        foreach (var b in bytes.Skip(1))
        {
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0)
            {
                arcs.Add(value);
                value = 0;
            }
        }
        return [.. arcs];
    }

    private static int ToInt(byte[] bytes) => bytes.Aggregate(0, (acc, b) => (acc << 8) | b);

    private static void Read(byte[] data, ref int pos, out byte tag, out byte[] content)
    {
        tag = data[pos++];
        int length = data[pos++];
        if (length >= 0x80)
        {
            var count = length & 0x7F;
            length = 0;
            for (var i = 0; i < count; i++)
                length = (length << 8) | data[pos++];
        }
        content = data[pos..(pos + length)];
        pos += length;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _udp.Dispose();
    }
}
