using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Runners.Tls;

namespace Keeper.Discover.Probes;

public sealed record HostSweepResult(
    bool Answered,
    IReadOnlyList<string> AnsweredProtocols,
    IReadOnlyList<AssetService> Services,
    IReadOnlyList<JsonObject> TlsCertificates,
    int? BestRttMs);

/// <summary>
/// Credential-free TCP connect and protocol handshake probes (SSH banner, HTTP/WinRM, TLS, SMB2 NEGOTIATE, LDAP RootDSE).
/// Never sends bytes on raw print ports or gentle ranges; enforces strict time and byte caps (64 KB max).
/// </summary>
public static partial class HandshakeProbes
{
    public const int MaxReadBytes = 64 * 1024;
    public const int MaxBannerBytes = 512;

    public static async Task<HostSweepResult> SweepHostAsync(
        ProbeGate gate,
        IPAddress address,
        IReadOnlyList<string>? names,
        IReadOnlyList<PortProfile>? profiles,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var portList = (profiles ?? PortProfiles.Defaults).Select(PortProfiles.Sanitize).ToList();
        var gentle = gate.IsGentle(address);
        var hostLabel = names is { Count: > 0 } ? names[0] : Addresses.Canonical(address);

        var services = new List<AssetService>();
        var tlsCerts = new List<JsonObject>();
        var protocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var anyAnswered = false;
        int? bestRtt = null;

        foreach (var profile in portList)
        {
            var dial = await gate.ConnectTcpAsync(address, profile.Port, names, cancellationToken).ConfigureAwait(false);
            if (dial.RttMs is { } rtt && (bestRtt is null || rtt < bestRtt.Value))
                bestRtt = rtt;

            if (dial.State == DialStates.Closed)
            {
                // A TCP RST (connection refused) proves a live host stack even though the port is closed.
                anyAnswered = true;
                continue;
            }

            if (dial.State != DialStates.Open)
                continue;

            anyAnswered = true;
            var serviceName = profile.Service;
            JsonObject? detail = null;

            await using (var session = dial.Session)
            {
                if (session is not null && !gentle && !profile.SendNothing && !PortProfiles.IsRawPrintPort(profile.Port))
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    cts.CancelAfter(gate.Timeout);
                    try
                    {
                        var (probedDetail, tlsRow, detectedService) = await RunHandshakeAsync(
                            session.Stream,
                            hostLabel,
                            profile,
                            now,
                            cts.Token).ConfigureAwait(false);
                        detail = probedDetail;
                        if (tlsRow is not null)
                            tlsCerts.Add(tlsRow);
                        if (detectedService is not null)
                            serviceName = detectedService;
                    }
                    catch (Exception) when (!cancellationToken.IsCancellationRequested)
                    {
                        // Malformed handshake or timeout after connect: keep the open TCP port with no detail.
                    }
                }
            }

            protocols.Add(NormalizeProtocolName(serviceName));
            if (profile.Tls)
                protocols.Add("tls");

            services.Add(new AssetService
            {
                Port = profile.Port,
                Transport = "tcp",
                Service = serviceName,
                State = DialStates.Open,
                RttMs = dial.RttMs,
                Detail = detail,
            });
        }

        var orderedProtocols = protocols.OrderBy(p => p, StringComparer.Ordinal).ToList();
        var orderedServices = services.OrderBy(s => s.Port).ToList();
        return new HostSweepResult(anyAnswered, orderedProtocols, orderedServices, tlsCerts, bestRtt);
    }

    private static async Task<(JsonObject? Detail, JsonObject? TlsRow, string? DetectedService)> RunHandshakeAsync(
        Stream rawStream,
        string host,
        PortProfile profile,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        Stream activeStream = rawStream;
        SslStream? sslStream = null;
        JsonObject? tlsRow = null;

        try
        {
            if (profile.Tls)
            {
                SslPolicyErrors policyErrors = SslPolicyErrors.None;
                var chainStatus = new List<string>();
                sslStream = new SslStream(rawStream, leaveInnerStreamOpen: true, (_, _, chain, errs) =>
                {
                    policyErrors = errs;
                    if (chain is not null)
                        chainStatus.AddRange(chain.ChainStatus.Select(s => s.Status.ToString()));
                    return true;
                });

                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, cancellationToken).ConfigureAwait(false);

                if (sslStream.RemoteCertificate is not null)
                {
                    using var cert = X509CertificateLoader.LoadCertificate(sslStream.RemoteCertificate.GetRawCertData());
                    tlsRow = TlsRunner.Row(host, profile.Port, cert, sslStream, policyErrors, chainStatus, now);
                }

                activeStream = sslStream;
                if (profile.Probe == "tls")
                    return (null, tlsRow, null);
            }

            return profile.Probe switch
            {
                "ssh" => (await ProbeSshBannerAsync(activeStream, cancellationToken).ConfigureAwait(false), tlsRow, null),
                "http" => await ProbeHttpAsync(activeStream, host, path: "/", isWinRmPort: false, cancellationToken).ConfigureAwait(false) is var (httpDetail, isWinRm)
                    ? (httpDetail, tlsRow, isWinRm ? "winrm" : null)
                    : (null, tlsRow, null),
                "winrm" => await ProbeHttpAsync(activeStream, host, path: "/wsman", isWinRmPort: true, cancellationToken).ConfigureAwait(false) is var (winRmDetail, _)
                    ? (winRmDetail, tlsRow, "winrm")
                    : (null, tlsRow, null),
                "smb2" => (await ProbeSmb2NegotiateAsync(activeStream, cancellationToken).ConfigureAwait(false), tlsRow, null),
                "ldap" => (await ProbeLdapRootDseAsync(activeStream, cancellationToken).ConfigureAwait(false), tlsRow, null),
                _ => (null, tlsRow, null),
            };
        }
        finally
        {
            if (sslStream is not null)
                await sslStream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Reads the server's SSH identification banner without sending any bytes.</summary>
    public static async Task<JsonObject?> ProbeSshBannerAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxBannerBytes];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
                break;
            total += read;
            if (buffer.AsSpan(0, total).IndexOf((byte)'\n') >= 0)
                break;
        }
        if (total == 0)
            return null;

        var text = Encoding.ASCII.GetString(buffer, 0, total);
        var line = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(l => l.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase))
            ?? text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

        if (string.IsNullOrWhiteSpace(line))
            return null;

        var trimmed = line.Trim();
        var obj = new JsonObject { ["banner"] = trimmed };
        if (trimmed.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase))
        {
            var parts = trimmed.Split('-', 3);
            if (parts.Length >= 3)
            {
                obj["protocolVersion"] = parts[1];
                var swAndComment = parts[2].Split(' ', 2);
                obj["software"] = swAndComment[0];
            }
        }
        return obj;
    }

    /// <summary>Sends a single HTTP/1.1 GET (never follows redirects, max 64 KB) and parses status, Server, WWW-Authenticate, and HTML title.</summary>
    public static async Task<(JsonObject? Detail, bool IsWinRm)> ProbeHttpAsync(
        Stream stream,
        string host,
        string path,
        bool isWinRmPort,
        CancellationToken cancellationToken)
    {
        var safeHost = host.Contains(':', StringComparison.Ordinal) && !host.StartsWith('[') ? $"[{host}]" : host;
        var req = $"GET {path} HTTP/1.1\r\nHost: {safeHost}\r\nUser-Agent: Keeper-Discover/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        var reqBytes = Encoding.ASCII.GetBytes(req);
        await stream.WriteAsync(reqBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var buffer = new byte[MaxReadBytes];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
                break;
            total += read;
        }

        if (total == 0)
            return (null, false);

        var raw = Encoding.UTF8.GetString(buffer, 0, total);
        var headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerBlock = headerEnd >= 0 ? raw[..headerEnd] : raw;
        var bodyBlock = headerEnd >= 0 ? raw[(headerEnd + 4)..] : "";

        var lines = headerBlock.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0 || !lines[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            return (null, false);

        var statusParts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var statusCode))
            return (null, false);

        string? server = null;
        var wwwAuth = new List<string>();
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
                continue;
            var name = line[..colon].Trim();
            var val = line[(colon + 1)..].Trim();
            if (name.Equals("Server", StringComparison.OrdinalIgnoreCase))
                server = val;
            else if (name.Equals("WWW-Authenticate", StringComparison.OrdinalIgnoreCase))
                wwwAuth.Add(val);
        }

        string? title = null;
        if (bodyBlock.Length > 0 && TitleRegex().Match(bodyBlock) is { Success: true } match)
        {
            title = Regex.Replace(match.Groups[1].Value, @"\s+", " ").Trim();
            if (title.Length > 160)
                title = title[..160];
        }

        var detail = new JsonObject { ["status"] = statusCode };
        if (!string.IsNullOrEmpty(server))
            detail["server"] = server;
        if (wwwAuth.Count > 0)
            detail["wwwAuthenticate"] = string.Join(", ", wwwAuth);
        if (!string.IsNullOrEmpty(title))
            detail["title"] = title;

        var isWinRm = isWinRmPort
            && (server?.Contains("Microsoft-HTTPAPI", StringComparison.OrdinalIgnoreCase) == true
                || wwwAuth.Any(a => a.Contains("Negotiate", StringComparison.OrdinalIgnoreCase) || a.Contains("Kerberos", StringComparison.OrdinalIgnoreCase))
                || statusCode is 401 or 405);

        return (detail, isWinRm);
    }

    /// <summary>Sends an SMB2 NEGOTIATE request (no session setup, no credentials) and parses dialect and signing requirement.</summary>
    public static async Task<JsonObject?> ProbeSmb2NegotiateAsync(Stream stream, CancellationToken cancellationToken)
    {
        var packet = BuildSmb2NegotiatePacket();
        await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var lenBuf = new byte[4];
        if (!await ReadExactAsync(stream, lenBuf, cancellationToken).ConfigureAwait(false))
            return null;

        var payloadLen = ((lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3]);
        if (payloadLen is < 64 or > MaxReadBytes)
            return null;

        var body = new byte[payloadLen];
        if (!await ReadExactAsync(stream, body, cancellationToken).ConfigureAwait(false))
            return null;

        return ParseSmb2NegotiateResponse(body);
    }

    public static byte[] BuildSmb2NegotiatePacket()
    {
        // 64-byte SMB2 header + 36-byte NEGOTIATE request + 5 dialects (10 bytes) = 110 bytes + 4-byte NetBIOS header
        ReadOnlySpan<ushort> dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
        const int smbLen = 64 + 36 + 10;
        var buf = new byte[4 + smbLen];
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = smbLen;

        var smb = buf.AsSpan(4);
        // ProtocolId: 0xFE 'S' 'M' 'B'
        smb[0] = 0xFE;
        smb[1] = (byte)'S';
        smb[2] = (byte)'M';
        smb[3] = (byte)'B';
        BinaryPrimitives.WriteUInt16LittleEndian(smb[4..], 64); // StructureSize
        BinaryPrimitives.WriteUInt16LittleEndian(smb[12..], 0); // Command = NEGOTIATE (0)
        BinaryPrimitives.WriteUInt16LittleEndian(smb[14..], 1); // CreditRequest = 1

        var neg = smb[64..];
        BinaryPrimitives.WriteUInt16LittleEndian(neg[0..], 36); // StructureSize = 36
        BinaryPrimitives.WriteUInt16LittleEndian(neg[2..], (ushort)dialects.Length); // DialectCount = 5
        BinaryPrimitives.WriteUInt16LittleEndian(neg[4..], 1); // SecurityMode = Signing Enabled (1)
        // ClientGuid left as deterministic non-random zeros except 1 byte so we send no identifying host GUID
        neg[12] = 1;
        for (var i = 0; i < dialects.Length; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(neg[(36 + i * 2)..], dialects[i]);

        return buf;
    }

    public static JsonObject? ParseSmb2NegotiateResponse(ReadOnlySpan<byte> body)
    {
        if (body.Length < 64 + 64)
            return null;
        if (body[0] != 0xFE || body[1] != (byte)'S' || body[2] != (byte)'M' || body[3] != (byte)'B')
            return null;

        var status = BinaryPrimitives.ReadUInt32LittleEndian(body[8..]);
        var command = BinaryPrimitives.ReadUInt16LittleEndian(body[12..]);
        if (command != 0 || status != 0)
            return null;

        var neg = body[64..];
        var structSize = BinaryPrimitives.ReadUInt16LittleEndian(neg[0..]);
        if (structSize != 65)
            return null;

        var securityMode = BinaryPrimitives.ReadUInt16LittleEndian(neg[2..]);
        var dialectRev = BinaryPrimitives.ReadUInt16LittleEndian(neg[4..]);
        var signingRequired = (securityMode & 0x02) != 0;
        var dialect = dialectRev switch
        {
            0x0202 => "2.0.2",
            0x0210 => "2.1",
            0x02FF => "2.wildcard",
            0x0300 => "3.0",
            0x0302 => "3.0.2",
            0x0311 => "3.1.1",
            _ => $"0x{dialectRev:x4}",
        };

        return new JsonObject
        {
            ["dialect"] = dialect,
            ["signingRequired"] = signingRequired,
        };
    }

    /// <summary>Sends an anonymous ASN.1 BER LDAP SearchRequest for the RootDSE and parses the returned attributes.</summary>
    public static async Task<JsonObject?> ProbeLdapRootDseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var req = BuildLdapRootDseSearchRequest();
        await stream.WriteAsync(req, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var buffer = new byte[8192];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
                break;
            total += read;
            if (ParseLdapRootDseResponse(buffer.AsSpan(0, total)) is { } parsed)
                return parsed;
        }
        return total > 0 ? ParseLdapRootDseResponse(buffer.AsSpan(0, total)) : null;
    }

    public static byte[] BuildLdapRootDseSearchRequest()
    {
        string[] attrs = ["defaultNamingContext", "dnsHostName", "forestFunctionality", "domainControllerFunctionality", "vendorName"];
        var attrBytes = new List<byte>();
        foreach (var a in attrs)
            attrBytes.AddRange(BerOctetString(Encoding.ASCII.GetBytes(a)));

        var filterPresent = BerTlv(0x87, Encoding.ASCII.GetBytes("objectClass")); // [7] Present filter
        var searchBody = new List<byte>();
        searchBody.AddRange(BerOctetString([]));        // baseObject ""
        searchBody.AddRange([0x0A, 0x01, 0x00]);        // scope: baseObject (0)
        searchBody.AddRange([0x0A, 0x01, 0x00]);        // derefAliases: neverDerefAliases (0)
        searchBody.AddRange([0x02, 0x01, 0x01]);        // sizeLimit: 1
        searchBody.AddRange([0x02, 0x01, 0x05]);        // timeLimit: 5
        searchBody.AddRange([0x01, 0x01, 0x00]);        // typesOnly: false
        searchBody.AddRange(filterPresent);
        searchBody.AddRange(BerTlv(0x30, attrBytes));   // AttributeDescriptionList

        var searchReq = BerTlv(0x63, searchBody);       // [APPLICATION 3] SearchRequest
        var msgBody = new List<byte>([0x02, 0x01, 0x01]); // messageID = 1
        msgBody.AddRange(searchReq);
        return BerTlv(0x30, msgBody);                   // LDAPMessage SEQUENCE
    }

    public static JsonObject? ParseLdapRootDseResponse(ReadOnlySpan<byte> data)
    {
        // Walk BER TLVs to find SearchResultEntry (0x64) inside LDAPMessage (0x30).
        if (!TryReadBerTlv(data, out var tag, out var msgContent, out _) || tag != 0x30)
            return null;
        // Skip messageID (0x02)
        if (!TryReadBerTlv(msgContent, out var idTag, out _, out var afterId) || idTag != 0x02)
            return null;
        if (!TryReadBerTlv(afterId, out var opTag, out var entryContent, out _))
            return null;
        if (opTag != 0x64) // SearchResultEntry
            return null;

        // objectName OCTET STRING
        if (!TryReadBerTlv(entryContent, out var dnTag, out _, out var afterDn) || dnTag != 0x04)
            return null;
        // PartialAttributeList SEQUENCE
        if (!TryReadBerTlv(afterDn, out var attrsTag, out var attrsSpan, out _) || attrsTag != 0x30)
            return null;

        var result = new JsonObject();
        while (attrsSpan.Length > 0)
        {
            if (!TryReadBerTlv(attrsSpan, out var paTag, out var paContent, out attrsSpan) || paTag != 0x30)
                break;
            if (!TryReadBerTlv(paContent, out var typeTag, out var typeBytes, out var afterType) || typeTag != 0x04)
                continue;
            var attrName = Encoding.UTF8.GetString(typeBytes);
            if (!TryReadBerTlv(afterType, out var setTag, out var valsSpan, out _) || setTag != 0x31)
                continue;
            if (TryReadBerTlv(valsSpan, out var valTag, out var valBytes, out _) && valTag == 0x04)
                result[attrName] = Encoding.UTF8.GetString(valBytes);
        }

        return result.Count > 0 ? result : new JsonObject { ["rootDse"] = true };
    }

    private static byte[] BerOctetString(ReadOnlySpan<byte> bytes) => BerTlv(0x04, bytes);

    private static byte[] BerTlv(byte tag, IReadOnlyCollection<byte> content) =>
        BerTlv(tag, content.ToArray().AsSpan());

    private static byte[] BerTlv(byte tag, ReadOnlySpan<byte> content)
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
        var res2 = new byte[4 + len];
        res2[0] = tag;
        res2[1] = 0x82;
        res2[2] = (byte)(len >> 8);
        res2[3] = (byte)(len & 0xFF);
        content.CopyTo(res2.AsSpan(4));
        return res2;
    }

    private static bool TryReadBerTlv(ReadOnlySpan<byte> input, out byte tag, out ReadOnlySpan<byte> content, out ReadOnlySpan<byte> rest)
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
            var numLenBytes = b1 & 0x7F;
            if (numLenBytes is 0 or > 4 || input.Length < 2 + numLenBytes)
                return false;
            length = 0;
            for (var i = 0; i < numLenBytes; i++)
                length = (length << 8) | input[2 + i];
            headerLen = 2 + numLenBytes;
        }
        if (length < 0 || input.Length < headerLen + length)
            return false;
        content = input.Slice(headerLen, length);
        rest = input[(headerLen + length)..];
        return true;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0)
                return false;
            offset += read;
        }
        return true;
    }

    private static string NormalizeProtocolName(string service) => service switch
    {
        "https" or "http-alt" or "https-alt" => "http",
        "winrms" => "winrm",
        "ldaps" or "ldap-gc" or "ldaps-gc" => "ldap",
        "smb2" => "smb",
        _ => service,
    };

    [GeneratedRegex(@"<\s*title[^>]*>(.*?)<\s*/\s*title\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant, 1000)]
    private static partial Regex TitleRegex();
}
