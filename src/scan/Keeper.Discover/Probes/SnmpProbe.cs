using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Keeper.Discover.Probes;

public sealed record SnmpCredential(
    string Id,
    string AuthKind,
    IPNetwork Scope,
    string? Username = null,
    string? AuthPassword = null,
    string? PrivPassword = null,
    string? Community = null,
    string AuthProtocol = "sha256",
    string PrivProtocol = "aes128");

public sealed record SnmpProbeOutcome(
    SnmpInfo? Info,
    int? RttMs,
    IReadOnlyList<IPAddress> NeighbourAddresses);

/// <summary>
/// In-process read-only SNMP probe (UDP 161):
/// - SNMPv3 engine discovery (no credentials needed: discovers engineId, engineBoots, engineTime, and v3 support).
/// - SNMPv3 USM authenticated/encrypted GET and GETNEXT (system group + ARP/neighbour tables).
/// - SNMPv2c GET and GETNEXT only when allow-cleartext is true and within credential scope.
/// Never builds or sends an SNMP SetRequest-PDU (0xA3).
/// </summary>
public static class SnmpProbe
{
    public const int DefaultPort = 161;
    public const byte GetRequestPduTag = 0xA0;
    public const byte GetNextRequestPduTag = 0xA1;
    public const byte GetResponsePduTag = 0xA2;
    public const byte SetRequestPduTag = 0xA3;
    public const byte GetBulkRequestPduTag = 0xA5;
    public const byte ReportPduTag = 0xA8;

    /// <summary>The only PDU tags this probe can ever emit: read-only GET, GETNEXT, GETBULK.</summary>
    public static readonly IReadOnlyList<byte> AllowedOutboundPduTags = [GetRequestPduTag, GetNextRequestPduTag];

    public const string OidSysDescr = "1.3.6.1.2.1.1.1.0";
    public const string OidSysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string OidSysUpTime = "1.3.6.1.2.1.1.3.0";
    public const string OidSysName = "1.3.6.1.2.1.1.5.0";

    // Neighbour tables (ARP ipNetToMediaNetAddress, ipNetToPhysicalNetAddress, LLDP)
    public const string OidIpNetToMediaNetAddress = "1.3.6.1.2.1.4.22.1.3";
    public const string OidIpNetToPhysicalNetAddress = "1.3.6.1.2.1.4.35.1.3";
    public const string OidLldpRemManAddr = "1.0.8802.1.1.2.1.4.2.1.4";

    public static async Task<SnmpProbeOutcome> ProbeHostAsync(
        ProbeGate gate,
        IPAddress address,
        IReadOnlyList<string>? names,
        SnmpSettings settings,
        IReadOnlyList<SnmpCredential> credentials,
        bool fetchNeighbours,
        int port = DefaultPort,
        CancellationToken cancellationToken = default,
        IReadOnlyCollection<string>? neighbourCredentials = null)
    {
        // Walking neighbour tables needs a credential that 'sources.snmp-neighbours.credentials' names.
        // null means the caller does not restrict it (used by tests that call the probe directly).
        bool MayWalk(SnmpCredential c) => fetchNeighbours
            && (neighbourCredentials is null || neighbourCredentials.Contains(c.Id, StringComparer.OrdinalIgnoreCase));

        if (gate.IsGentle(address))
            return new SnmpProbeOutcome(null, null, []);

        int? bestRtt = null;
        void RecordRtt(int? rtt)
        {
            if (rtt is { } v && (bestRtt is null || v < bestRtt.Value))
                bestRtt = v;
        }

        // 1. Credential-free SNMPv3 Engine ID discovery
        var discoveryReq = BuildV3DiscoveryPacket(requestId: 1001);
        var discReply = await gate.ExchangeUdpAsync(address, port, discoveryReq, null, names, cancellationToken).ConfigureAwait(false);
        RecordRtt(discReply.RttMs);

        var v3Supported = false;
        byte[]? engineIdBytes = null;
        string? engineIdHex = null;
        int? engineBoots = null;
        int? engineTime = null;
        string? sysDescr = null;
        string? sysObjectId = null;
        long? sysUpTime = null;
        string? sysName = null;
        var neighbours = new List<IPAddress>();

        if (discReply.State == DialStates.Open && discReply.Payload is { Length: > 0 } rawDisc)
        {
            if (TryParseV3Packet(rawDisc, out var engId, out var boots, out var time, out var discVars))
            {
                v3Supported = true;
                if (engId.Length > 0)
                {
                    engineIdBytes = engId;
                    engineIdHex = Convert.ToHexStringLower(engId);
                }
                engineBoots = boots;
                engineTime = time;
                ApplySystemVars(discVars, ref sysDescr, ref sysObjectId, ref sysUpTime, ref sysName);
            }
        }

        // 2. Try configured SNMPv3 credentials whose scope covers this address
        if (v3Supported && engineIdBytes is { Length: > 0 })
        {
            foreach (var v3Id in settings.V3)
            {
                var cred = credentials.FirstOrDefault(c => c.Id.Equals(v3Id, StringComparison.OrdinalIgnoreCase) && c.AuthKind == "snmp-v3");
                if (cred is null || string.IsNullOrEmpty(cred.Username))
                    continue;
                if (!gate.IsApproved(address, cred.Id, "snmp") || !gate.AllowsCredential(address, cred.Scope, names, out _))
                    continue;

                var getPacket = BuildV3SystemGetPacket(
                    requestId: 1002,
                    engineIdBytes,
                    engineBoots ?? 0,
                    engineTime ?? 0,
                    cred);
                var getReply = await gate.ExchangeUdpAsync(address, port, getPacket, cred.Scope, names, cancellationToken).ConfigureAwait(false);
                RecordRtt(getReply.RttMs);
                if (getReply.State == DialStates.Open && getReply.Payload is { Length: > 0 } rawGet
                    && TryParseV3Packet(rawGet, out _, out _, out _, out var sysVars, cred, engineIdBytes, engineBoots ?? 0, engineTime ?? 0)
                    && sysVars.Count > 0 && !IsUsmErrorReport(sysVars))
                {
                    ApplySystemVars(sysVars, ref sysDescr, ref sysObjectId, ref sysUpTime, ref sysName);
                    if (MayWalk(cred))
                    {
                        var found = await WalkNeighboursV3Async(gate, address, names, port, engineIdBytes, engineBoots ?? 0, engineTime ?? 0, cred, cancellationToken).ConfigureAwait(false);
                        neighbours.AddRange(found);
                    }
                    break;
                }
            }
        }

        // 3. Try configured SNMPv2c credentials ONLY when allow-cleartext is true
        var v2cSupported = false;
        if (settings.AllowCleartext && settings.V2c.Count > 0)
        {
            foreach (var v2cId in settings.V2c)
            {
                var cred = credentials.FirstOrDefault(c => c.Id.Equals(v2cId, StringComparison.OrdinalIgnoreCase) && c.AuthKind == "snmp-v2c");
                if (cred is null || string.IsNullOrEmpty(cred.Community))
                    continue;
                if (!gate.IsApproved(address, cred.Id, "snmp") || !gate.AllowsCredential(address, cred.Scope, names, out _))
                    continue;

                var v2Req = BuildV2cGetPacket(cred.Community, requestId: 2001, [OidSysDescr, OidSysObjectId, OidSysUpTime, OidSysName]);
                var v2Reply = await gate.ExchangeUdpAsync(address, port, v2Req, cred.Scope, names, cancellationToken).ConfigureAwait(false);
                RecordRtt(v2Reply.RttMs);
                if (v2Reply.State == DialStates.Open && v2Reply.Payload is { Length: > 0 } rawV2
                    && TryParseV2cResponse(rawV2, out var vars) && vars.Count > 0)
                {
                    v2cSupported = true;
                    ApplySystemVars(vars, ref sysDescr, ref sysObjectId, ref sysUpTime, ref sysName);
                    if (MayWalk(cred) && neighbours.Count == 0)
                    {
                        var found = await WalkNeighboursV2cAsync(gate, address, names, port, cred, cancellationToken).ConfigureAwait(false);
                        neighbours.AddRange(found);
                    }
                    break;
                }
            }
        }

        if (!v3Supported && !v2cSupported)
            return new SnmpProbeOutcome(null, bestRtt, []);

        var info = new SnmpInfo
        {
            Version = v3Supported ? "v3" : "v2c",
            V3Supported = v3Supported,
            V2cSupported = v2cSupported,
            EngineId = engineIdHex,
            EngineBoots = engineBoots,
            EngineTime = engineTime,
            SysName = sysName,
            SysDescr = sysDescr,
            SysObjectId = sysObjectId,
            SysUpTimeCs = sysUpTime,
        };
        return new SnmpProbeOutcome(info, bestRtt, neighbours.Distinct().ToList());
    }

    private static async Task<List<IPAddress>> WalkNeighboursV3Async(
        ProbeGate gate,
        IPAddress address,
        IReadOnlyList<string>? names,
        int port,
        byte[] engineId,
        int boots,
        int time,
        SnmpCredential cred,
        CancellationToken cancellationToken)
    {
        var results = new List<IPAddress>();
        foreach (var rootOid in new[] { OidIpNetToMediaNetAddress, OidIpNetToPhysicalNetAddress })
        {
            var currentOid = rootOid;
            for (var step = 0; step < 64; step++)
            {
                var pkt = BuildV3GetNextPacket(3000 + step, engineId, boots, time, cred, currentOid);
                var rep = await gate.ExchangeUdpAsync(address, port, pkt, cred.Scope, names, cancellationToken).ConfigureAwait(false);
                if (rep.State != DialStates.Open || rep.Payload is null
                    || !TryParseV3Packet(rep.Payload, out _, out _, out _, out var vars, cred, engineId, boots, time)
                    || vars.Count == 0)
                {
                    break;
                }
                var (oid, val) = vars[0];
                if (!oid.StartsWith(rootOid + ".", StringComparison.Ordinal))
                    break;
                if (TryExtractNeighbourIp(oid, val, out var ip))
                    results.Add(ip);
                currentOid = oid;
            }
        }
        return results;
    }

    private static async Task<List<IPAddress>> WalkNeighboursV2cAsync(
        ProbeGate gate,
        IPAddress address,
        IReadOnlyList<string>? names,
        int port,
        SnmpCredential cred,
        CancellationToken cancellationToken)
    {
        var results = new List<IPAddress>();
        foreach (var rootOid in new[] { OidIpNetToMediaNetAddress, OidIpNetToPhysicalNetAddress })
        {
            var currentOid = rootOid;
            for (var step = 0; step < 64; step++)
            {
                var pkt = BuildV2cPduPacket(GetNextRequestPduTag, cred.Community!, 4000 + step, [currentOid]);
                var rep = await gate.ExchangeUdpAsync(address, port, pkt, cred.Scope, names, cancellationToken).ConfigureAwait(false);
                if (rep.State != DialStates.Open || rep.Payload is null
                    || !TryParseV2cResponse(rep.Payload, out var vars) || vars.Count == 0)
                {
                    break;
                }
                var (oid, val) = vars[0];
                if (!oid.StartsWith(rootOid + ".", StringComparison.Ordinal))
                    break;
                if (TryExtractNeighbourIp(oid, val, out var ip))
                    results.Add(ip);
                currentOid = oid;
            }
        }
        return results;
    }

    private static bool TryExtractNeighbourIp(string oid, object? value, out IPAddress address)
    {
        address = IPAddress.None;
        if (value is IPAddress direct)
        {
            address = direct;
            return true;
        }
        if (value is byte[] bytes && bytes.Length is 4 or 16)
        {
            address = new IPAddress(bytes);
            return true;
        }
        if (value is string s && Addresses.TryParseAddress(s, out var parsed))
        {
            address = parsed;
            return true;
        }
        // Fallback: trailing 4 arcs of OID as IPv4
        var parts = oid.Split('.');
        if (parts.Length >= 4 && Addresses.TryParseAddress(string.Join('.', parts[^4..]), out var tailIp))
        {
            address = tailIp;
            return true;
        }
        return false;
    }

    public static byte[] BuildV3DiscoveryPacket(int requestId)
    {
        // RFC 3414 section 4: reportable flag (0x04), noAuthNoPriv, empty securityName and engineID, empty varbind list
        var globalData = BerSequence(
        [
            .. BerInt(requestId),
            .. BerInt(65507),
            .. BerOctet([0x04]), // reportable = 1, auth = 0, priv = 0
            .. BerInt(3),        // securityModel = USM (3)
        ]);
        var usm = BerSequence(
        [
            .. BerOctet([]), // msgAuthoritativeEngineID
            .. BerInt(0),    // msgAuthoritativeEngineBoots
            .. BerInt(0),    // msgAuthoritativeEngineTime
            .. BerOctet([]), // msgUserName
            .. BerOctet([]), // msgAuthenticationParameters
            .. BerOctet([]), // msgPrivacyParameters
        ]);
        var pdu = BuildPdu(GetRequestPduTag, requestId, []);
        var scopedPdu = BerSequence([.. BerOctet([]), .. BerOctet([]), .. pdu]);
        return BerSequence([.. BerInt(3), .. globalData, .. BerOctet(usm), .. scopedPdu]);
    }

    public static byte[] BuildV3SystemGetPacket(int requestId, byte[] engineId, int boots, int time, SnmpCredential cred) =>
        BuildV3AuthenticatedPacket(GetRequestPduTag, requestId, engineId, boots, time, cred,
            [OidSysDescr, OidSysObjectId, OidSysUpTime, OidSysName]);

    public static byte[] BuildV3GetNextPacket(int requestId, byte[] engineId, int boots, int time, SnmpCredential cred, string oid) =>
        BuildV3AuthenticatedPacket(GetNextRequestPduTag, requestId, engineId, boots, time, cred, [oid]);

    private static byte[] BuildV3AuthenticatedPacket(
        byte pduTag,
        int requestId,
        byte[] engineId,
        int boots,
        int time,
        SnmpCredential cred,
        IReadOnlyList<string> oids)
    {
        if (!AllowedOutboundPduTags.Contains(pduTag))
            throw new InvalidOperationException($"Refused SNMP PDU tag 0x{pduTag:X2}: Keeper is strictly read-only.");

        var hasAuth = !string.IsNullOrEmpty(cred.AuthPassword);
        var hasPriv = hasAuth && !string.IsNullOrEmpty(cred.PrivPassword);
        byte flags = 0x04; // reportable
        if (hasAuth)
            flags |= 0x01;
        if (hasPriv)
            flags |= 0x02;

        var globalData = BerSequence(
        [
            .. BerInt(requestId),
            .. BerInt(65507),
            .. BerOctet([flags]),
            .. BerInt(3),
        ]);

        var pdu = BuildPdu(pduTag, requestId, oids);
        var plainScopedPdu = BerSequence([.. BerOctet(engineId), .. BerOctet([]), .. pdu]);

        byte[] scopedPduPart;
        var privParams = Array.Empty<byte>();
        if (hasPriv)
        {
            privParams = RandomNumberGenerator.GetBytes(8);
            var privKey = LocalizeKey(cred.PrivPassword!, engineId, cred.AuthProtocol)[..16];
            var iv = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(0, 4), boots);
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4, 4), time);
            privParams.CopyTo(iv, 8);
            var encrypted = AesCfb128Encrypt(privKey, iv, plainScopedPdu);
            scopedPduPart = BerOctet(encrypted);
        }
        else
        {
            scopedPduPart = plainScopedPdu;
        }

        var macLen = cred.AuthProtocol.Equals("sha1", StringComparison.OrdinalIgnoreCase) ? 12 : 24;
        var zeroMac = hasAuth ? new byte[macLen] : [];
        var usmPlaceholder = BerSequence(
        [
            .. BerOctet(engineId),
            .. BerInt(boots),
            .. BerInt(time),
            .. BerOctet(Encoding.UTF8.GetBytes(cred.Username ?? "")),
            .. BerOctet(zeroMac),
            .. BerOctet(privParams),
        ]);

        var whole = BerSequence([.. BerInt(3), .. globalData, .. BerOctet(usmPlaceholder), .. scopedPduPart]);
        if (!hasAuth)
            return whole;

        var authKey = LocalizeKey(cred.AuthPassword!, engineId, cred.AuthProtocol);
        var digest = ComputeHmac(authKey, whole, cred.AuthProtocol)[..macLen];

        // Replace the zeroMac inside the packet with the truncated HMAC
        var usmSigned = BerSequence(
        [
            .. BerOctet(engineId),
            .. BerInt(boots),
            .. BerInt(time),
            .. BerOctet(Encoding.UTF8.GetBytes(cred.Username ?? "")),
            .. BerOctet(digest),
            .. BerOctet(privParams),
        ]);
        return BerSequence([.. BerInt(3), .. globalData, .. BerOctet(usmSigned), .. scopedPduPart]);
    }

    public static byte[] BuildV2cGetPacket(string community, int requestId, IReadOnlyList<string> oids) =>
        BuildV2cPduPacket(GetRequestPduTag, community, requestId, oids);

    public static byte[] BuildV2cPduPacket(byte pduTag, string community, int requestId, IReadOnlyList<string> oids)
    {
        if (!AllowedOutboundPduTags.Contains(pduTag))
            throw new InvalidOperationException($"Refused SNMP PDU tag 0x{pduTag:X2}: Keeper is strictly read-only.");

        var pdu = BuildPdu(pduTag, requestId, oids);
        return BerSequence(
        [
            .. BerInt(1), // version = 1 (SNMPv2c)
            .. BerOctet(Encoding.UTF8.GetBytes(community)),
            .. pdu,
        ]);
    }

    public static bool TryParseV3Packet(
        ReadOnlySpan<byte> packet,
        out byte[] engineId,
        out int engineBoots,
        out int engineTime,
        out List<(string Oid, object? Value)> varbinds,
        SnmpCredential? cred = null,
        byte[]? expectedEngineId = null,
        int expectedBoots = 0,
        int expectedTime = 0)
    {
        engineId = [];
        engineBoots = 0;
        engineTime = 0;
        varbinds = [];

        if (!TryReadBer(packet, out var topTag, out var topBody, out _) || topTag != 0x30)
            return false;
        if (!TryReadBer(topBody, out var verTag, out var verVal, out var afterVer) || verTag != 0x02 || ReadInt(verVal) != 3)
            return false;
        if (!TryReadBer(afterVer, out var hdrTag, out _, out var afterHdr) || hdrTag != 0x30)
            return false;
        if (!TryReadBer(afterHdr, out var usmOctTag, out var usmBytes, out var scopedPart) || usmOctTag != 0x04)
            return false;
        if (!TryReadBer(usmBytes, out var usmSeqTag, out var usmBody, out _) || usmSeqTag != 0x30)
            return false;

        if (!TryReadBer(usmBody, out var eTag, out var eBytes, out var u1) || eTag != 0x04)
            return false;
        if (!TryReadBer(u1, out var bTag, out var bBytes, out var u2) || bTag != 0x02)
            return false;
        if (!TryReadBer(u2, out var tTag, out var tBytes, out var u3) || tTag != 0x02)
            return false;
        if (!TryReadBer(u3, out _, out _, out var u4))
            return false;
        if (!TryReadBer(u4, out _, out _, out var u5))
            return false;
        if (!TryReadBer(u5, out var privTag, out var privParams, out _) || privTag != 0x04)
            return false;

        engineId = eBytes.ToArray();
        engineBoots = ReadInt(bBytes);
        engineTime = ReadInt(tBytes);

        ReadOnlySpan<byte> scopedSeq = scopedPart;
        if (scopedPart.Length > 0 && scopedPart[0] == 0x04)
        {
            // Encrypted ScopedPDU
            if (cred is null || string.IsNullOrEmpty(cred.PrivPassword) || string.IsNullOrEmpty(cred.AuthPassword) || privParams.Length != 8)
                return false;
            if (!TryReadBer(scopedPart, out _, out var cipherBytes, out _))
                return false;
            var keyEngine = engineId.Length > 0 ? engineId : expectedEngineId ?? [];
            var privKey = LocalizeKey(cred.PrivPassword!, keyEngine, cred.AuthProtocol)[..16];
            var iv = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(0, 4), engineBoots != 0 ? engineBoots : expectedBoots);
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4, 4), engineTime != 0 ? engineTime : expectedTime);
            privParams.CopyTo(iv.AsSpan(8, 8));
            scopedSeq = AesCfb128Decrypt(privKey, iv, cipherBytes);
        }

        if (!TryReadBer(scopedSeq, out var scTag, out var scBody, out _) || scTag != 0x30)
            return false;
        if (!TryReadBer(scBody, out _, out _, out var s1))
            return false;
        if (!TryReadBer(s1, out _, out _, out var pduSpan))
            return false;

        return TryParsePdu(pduSpan, out varbinds);
    }

    public static bool TryParseV2cResponse(ReadOnlySpan<byte> packet, out List<(string Oid, object? Value)> varbinds)
    {
        varbinds = [];
        if (!TryReadBer(packet, out var topTag, out var topBody, out _) || topTag != 0x30)
            return false;
        if (!TryReadBer(topBody, out var verTag, out var verVal, out var afterVer) || verTag != 0x02 || ReadInt(verVal) is not (0 or 1))
            return false;
        if (!TryReadBer(afterVer, out var commTag, out _, out var pduSpan) || commTag != 0x04)
            return false;
        return TryParsePdu(pduSpan, out varbinds);
    }

    private static bool TryParsePdu(ReadOnlySpan<byte> pduSpan, out List<(string Oid, object? Value)> varbinds)
    {
        varbinds = [];
        if (!TryReadBer(pduSpan, out var pduTag, out var pduBody, out _))
            return false;
        if (pduTag is not (GetResponsePduTag or ReportPduTag))
            return false;

        if (!TryReadBer(pduBody, out _, out _, out var p1)) // request-id
            return false;
        if (!TryReadBer(p1, out _, out var errStat, out var p2)) // error-status
            return false;
        if (ReadInt(errStat) != 0)
            return false;
        if (!TryReadBer(p2, out _, out _, out var vbListSpan)) // error-index
            return false;
        if (!TryReadBer(vbListSpan, out var vblTag, out var vbs, out _) || vblTag != 0x30)
            return false;

        while (vbs.Length > 0)
        {
            if (!TryReadBer(vbs, out var vbTag, out var vbBody, out vbs) || vbTag != 0x30)
                break;
            if (!TryReadBer(vbBody, out var oidTag, out var oidBytes, out var valSpan) || oidTag != 0x06)
                continue;
            var oid = DecodeOid(oidBytes);
            if (!TryReadBer(valSpan, out var valTag, out var valBytes, out _))
                continue;
            var val = DecodeValue(valTag, valBytes);
            varbinds.Add((oid, val));
        }
        return true;
    }

    private static void ApplySystemVars(
        List<(string Oid, object? Value)> vars,
        ref string? sysDescr,
        ref string? sysObjectId,
        ref long? sysUpTime,
        ref string? sysName)
    {
        foreach (var (oid, val) in vars)
        {
            switch (oid)
            {
                case OidSysDescr when val is string s:
                    sysDescr = s;
                    break;
                case OidSysObjectId when val is string s:
                    sysObjectId = s;
                    break;
                case OidSysUpTime when val is long ticks:
                    sysUpTime = ticks;
                    break;
                case OidSysUpTime when val is int ticksInt:
                    sysUpTime = ticksInt;
                    break;
                case OidSysName when val is string s:
                    sysName = s;
                    break;
            }
        }
    }

    private static bool IsUsmErrorReport(List<(string Oid, object? Value)> vars) =>
        vars.Count > 0 && vars.All(v => v.Oid.StartsWith("1.3.6.1.6.3.15.1.1.", StringComparison.Ordinal));

    private static byte[] BuildPdu(byte pduTag, int requestId, IReadOnlyList<string> oids)
    {
        var vbs = new List<byte>();
        foreach (var oid in oids)
            vbs.AddRange(BerSequence([.. EncodeOid(oid), 0x05, 0x00]));

        return BerTlv(pduTag,
        [
            .. BerInt(requestId),
            .. BerInt(0),
            .. BerInt(0),
            .. BerSequence(vbs),
        ]);
    }

    public static byte[] EncodeOid(string oid)
    {
        var arcs = oid.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(uint.Parse).ToArray();
        if (arcs.Length < 2)
            throw new ArgumentException($"Invalid OID '{oid}'.");
        var bytes = new List<byte> { (byte)(arcs[0] * 40 + arcs[1]) };
        for (var i = 2; i < arcs.Length; i++)
        {
            var v = arcs[i];
            if (v < 128)
            {
                bytes.Add((byte)v);
                continue;
            }
            var stack = new Stack<byte>();
            stack.Push((byte)(v & 0x7F));
            v >>= 7;
            while (v > 0)
            {
                stack.Push((byte)((v & 0x7F) | 0x80));
                v >>= 7;
            }
            bytes.AddRange(stack);
        }
        return BerTlv(0x06, [.. bytes]);
    }

    public static string DecodeOid(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
            return "";
        var sb = new StringBuilder();
        var first = bytes[0];
        var arc0 = Math.Min(2, first / 40);
        var arc1 = first - arc0 * 40;
        sb.Append(arc0).Append('.').Append(arc1);
        uint current = 0;
        for (var i = 1; i < bytes.Length; i++)
        {
            var b = bytes[i];
            current = (current << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0)
            {
                sb.Append('.').Append(current);
                current = 0;
            }
        }
        return sb.ToString();
    }

    private static object? DecodeValue(byte tag, ReadOnlySpan<byte> bytes) => tag switch
    {
        0x02 => ReadInt(bytes), // INTEGER
        0x04 => IsPrintableAscii(bytes) ? Encoding.UTF8.GetString(bytes) : bytes.ToArray(), // OCTET STRING
        0x06 => DecodeOid(bytes), // OBJECT IDENTIFIER
        0x40 when bytes.Length == 4 => new IPAddress(bytes), // IpAddress
        0x41 or 0x42 or 0x43 => ReadUInt(bytes), // Counter32, Gauge32, TimeTicks
        _ => null,
    };

    private static bool IsPrintableAscii(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            if (b is < 0x20 or > 0x7E && b is not ((byte)'\r' or (byte)'\n' or (byte)'\t'))
                return false;
        }
        return true;
    }

    private static int ReadInt(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
            return 0;
        var val = (bytes[0] & 0x80) != 0 ? -1 : 0;
        foreach (var b in bytes)
            val = (val << 8) | b;
        return val;
    }

    private static long ReadUInt(ReadOnlySpan<byte> bytes)
    {
        long val = 0;
        foreach (var b in bytes)
            val = (val << 8) | b;
        return val;
    }

    public static byte[] BerInt(int value)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(tmp, value);
        var start = 0;
        while (start < 3 && ((tmp[start] == 0x00 && (tmp[start + 1] & 0x80) == 0) || (tmp[start] == 0xFF && (tmp[start + 1] & 0x80) != 0)))
            start++;
        return BerTlv(0x02, tmp[start..]);
    }

    public static byte[] BerOctet(ReadOnlySpan<byte> bytes) => BerTlv(0x04, bytes);

    public static byte[] BerSequence(IReadOnlyCollection<byte> content) => BerTlv(0x30, content.ToArray());

    public static byte[] BerTlv(byte tag, ReadOnlySpan<byte> content)
    {
        var len = content.Length;
        if (len < 128)
        {
            var res = new byte[2 + len];
            res[0] = tag;
            res[1] = (byte)len;
            content.CopyTo(res.AsSpan(2));
            return res;
        }
        if (len <= 255)
        {
            var res = new byte[3 + len];
            res[0] = tag;
            res[1] = 0x81;
            res[2] = (byte)len;
            content.CopyTo(res.AsSpan(3));
            return res;
        }
        var res2 = new byte[4 + len];
        res2[0] = tag;
        res2[1] = 0x82;
        res2[2] = (byte)(len >> 8);
        res2[3] = (byte)(len & 0xFF);
        content.CopyTo(res2.AsSpan(4));
        return res2;
    }

    private static bool TryReadBer(ReadOnlySpan<byte> input, out byte tag, out ReadOnlySpan<byte> content, out ReadOnlySpan<byte> rest)
    {
        tag = 0;
        content = default;
        rest = default;
        if (input.Length < 2)
            return false;
        tag = input[0];
        var b1 = input[1];
        int length;
        int headerLen;
        if ((b1 & 0x80) == 0)
        {
            length = b1;
            headerLen = 2;
        }
        else
        {
            var n = b1 & 0x7F;
            if (n is 0 or > 4 || input.Length < 2 + n)
                return false;
            length = 0;
            for (var i = 0; i < n; i++)
                length = (length << 8) | input[2 + i];
            headerLen = 2 + n;
        }
        if (length < 0 || input.Length < headerLen + length)
            return false;
        content = input.Slice(headerLen, length);
        rest = input[(headerLen + length)..];
        return true;
    }

    public static byte[] LocalizeKey(string password, byte[] engineId, string authProto)
    {
        // RFC 3414 / RFC 7860 password-to-key (1 MB expansion, then localize with engineId)
        var pwBytes = Encoding.UTF8.GetBytes(password);
        if (pwBytes.Length == 0)
            pwBytes = [0];
        var useSha1 = authProto.Equals("sha1", StringComparison.OrdinalIgnoreCase);
        using IncrementalHash hash = IncrementalHash.CreateHash(useSha1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256);
        var buf = new byte[64];
        var total = 0;
        var pwIndex = 0;
        while (total < 1_048_576)
        {
            for (var i = 0; i < 64; i++)
                buf[i] = pwBytes[pwIndex++ % pwBytes.Length];
            hash.AppendData(buf);
            total += 64;
        }
        var ku = hash.GetHashAndReset();
        hash.AppendData(ku);
        hash.AppendData(engineId);
        hash.AppendData(ku);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeHmac(byte[] key, byte[] message, string authProto) =>
        authProto.Equals("sha1", StringComparison.OrdinalIgnoreCase)
            ? HMACSHA1.HashData(key, message)
            : HMACSHA256.HashData(key, message);

    private static byte[] AesCfb128Encrypt(byte[] key16, byte[] iv16, ReadOnlySpan<byte> plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = key16;
        var outBytes = new byte[plaintext.Length];
        Span<byte> feedback = stackalloc byte[16];
        iv16.CopyTo(feedback);
        Span<byte> block = stackalloc byte[16];
        for (var offset = 0; offset < plaintext.Length; offset += 16)
        {
            aes.EncryptEcb(feedback, block, PaddingMode.None);
            var chunk = Math.Min(16, plaintext.Length - offset);
            for (var i = 0; i < chunk; i++)
            {
                var c = (byte)(plaintext[offset + i] ^ block[i]);
                outBytes[offset + i] = c;
                feedback[i] = c;
            }
        }
        return outBytes;
    }

    private static byte[] AesCfb128Decrypt(byte[] key16, byte[] iv16, ReadOnlySpan<byte> ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = key16;
        var outBytes = new byte[ciphertext.Length];
        Span<byte> feedback = stackalloc byte[16];
        iv16.CopyTo(feedback);
        Span<byte> block = stackalloc byte[16];
        for (var offset = 0; offset < ciphertext.Length; offset += 16)
        {
            aes.EncryptEcb(feedback, block, PaddingMode.None);
            var chunk = Math.Min(16, ciphertext.Length - offset);
            for (var i = 0; i < chunk; i++)
            {
                var c = ciphertext[offset + i];
                outBytes[offset + i] = (byte)(c ^ block[i]);
                feedback[i] = c;
            }
        }
        return outBytes;
    }
}
