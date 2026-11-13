using System.Buffers.Binary;
using System.Net;
using System.Text;
using Keeper.Discover.Probes;

namespace Keeper.Discover.Tests;

public sealed class ProbeAndGateTests
{
    [Fact]
    public async Task ProbeGate_NeverDialsExcludedOrOutOfScopeTargets()
    {
        var targets = TargetsLoader.Parse("""
            schema: keeper.discovery/1
            mode: free
            scope: [192.0.2.0/24]
            exclude:
              - { cidr: 192.0.2.250/32, why: "fragile PLC" }
              - { name: "*.lab.example.com", why: "lab hosts" }
            rate: { retries: 0 }
            """);

        var dialer = new FakeDialer();
        dialer.MapTcpOpen("192.0.2.250", 22);
        dialer.MapTcpOpen("198.51.100.10", 22);
        dialer.MapTcpOpen("192.0.2.15", 22);

        using var gate = new ProbeGate(dialer, targets);

        // Excluded by CIDR
        var resCidr = await gate.ConnectTcpAsync(IPAddress.Parse("192.0.2.250"), 22);
        Assert.Equal(DialStates.RefusedByGate, resCidr.State);

        // Excluded by hostname pattern after resolution
        var resName = await gate.ConnectTcpAsync(IPAddress.Parse("192.0.2.15"), 22, ["box1.lab.example.com"]);
        Assert.Equal(DialStates.RefusedByGate, resName.State);

        // Out of scope
        var resScope = await gate.ConnectTcpAsync(IPAddress.Parse("198.51.100.10"), 22);
        Assert.Equal(DialStates.RefusedByGate, resScope.State);

        // Always-excluded multicast
        var resMcast = await gate.ConnectTcpAsync(IPAddress.Parse("224.0.0.1"), 22);
        Assert.Equal(DialStates.RefusedByGate, resMcast.State);

        // None of those four ever reached the dialer!
        Assert.Empty(dialer.DialLog);

        // Allowed target inside scope
        var resAllowed = await gate.ConnectTcpAsync(IPAddress.Parse("192.0.2.15"), 22, ["srv1.example.com"]);
        Assert.Equal(DialStates.Open, resAllowed.State);
        resAllowed.Session?.Dispose();
        Assert.Single(dialer.DialLog);
    }

    [Fact]
    public async Task ProbeGate_EnforcesScanWindowAndCredentialScope()
    {
        var targets = TargetsLoader.Parse("""
            schema: keeper.discovery/1
            mode: free
            scope: [192.0.2.0/24]
            windows: [{ days: [sat, sun], from: "20:00", to: "06:00" }]
            """);

        var dialer = new FakeDialer();
        // Wednesday 12:00 UTC -> outside sat/sun window
        var clock = new FixedClock(new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero));
        using var gate = new ProbeGate(dialer, targets, clock);

        await Assert.ThrowsAsync<ScanWindowClosedException>(() =>
            gate.ConnectTcpAsync(IPAddress.Parse("192.0.2.10"), 22));
        Assert.Empty(dialer.DialLog);

        // Move clock to Saturday 21:00 UTC -> inside window
        clock.Now = new DateTimeOffset(2026, 10, 24, 21, 0, 0, TimeSpan.Zero);
        Assert.True(gate.IsWithinWindow());

        // Credential scope check
        var credScope = Addresses.ParseNetwork("192.0.2.0/25");
        Assert.True(gate.AllowsCredential(IPAddress.Parse("192.0.2.10"), credScope, null, out _));
        Assert.False(gate.AllowsCredential(IPAddress.Parse("192.0.2.200"), credScope, null, out var reason));
        Assert.Contains("outside credential scope", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandshakeProbes_NeverSendsBytesOnPrintPortsOrGentleHosts()
    {
        var targets = TargetsLoader.Parse("""
            schema: keeper.discovery/1
            mode: manual
            gentle: [192.0.2.50/32]
            rate: { retries: 0 }
            """);

        var dialer = new FakeDialer();
        var printWritten = dialer.MapTcpOpen("192.0.2.10", 9100, Encoding.ASCII.GetBytes("READY"));
        var lpdWritten = dialer.MapTcpOpen("192.0.2.10", 515, Encoding.ASCII.GetBytes("READY"));
        var gentleHttpWritten = dialer.MapTcpOpen("192.0.2.50", 80, Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"));

        using var gate = new ProbeGate(dialer, targets);
        var now = DateTimeOffset.UtcNow;

        // Even if someone passes a bogus profile with Probe: "http" on port 9100/515, PortProfiles.Sanitize strips it
        var customProfiles = new[]
        {
            new PortProfile(9100, "jetdirect", Probe: "http", SendNothing: false),
            new PortProfile(515, "lpd", Probe: "http", SendNothing: false),
        };
        var sweepPrinter = await HandshakeProbes.SweepHostAsync(gate, IPAddress.Parse("192.0.2.10"), null, customProfiles, now, CancellationToken.None);
        Assert.True(sweepPrinter.Answered);
        Assert.Empty(printWritten);
        Assert.Empty(lpdWritten);

        // Gentle host connects on port 80, but does not send HTTP GET
        var sweepGentle = await HandshakeProbes.SweepHostAsync(gate, IPAddress.Parse("192.0.2.50"), null, [new PortProfile(80, "http", Probe: "http")], now, CancellationToken.None);
        Assert.True(sweepGentle.Answered);
        Assert.Empty(gentleHttpWritten);
    }

    [Fact]
    public async Task HandshakeProbes_ParsesSshHttpWinRmSmb2AndLdapRootDse()
    {
        var targets = TargetsLoader.Parse("""
            schema: keeper.discovery/1
            mode: manual
            rate: { retries: 0 }
            """);

        var dialer = new FakeDialer();
        var sshWritten = dialer.MapTcpOpen("192.0.2.20", 22, Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"));
        dialer.MapTcpOpen("192.0.2.20", 80, Encoding.UTF8.GetBytes(
            "HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nContent-Type: text/html\r\n\r\n<html><head><title>Switch Admin</title></head></html>"));
        dialer.MapTcpOpen("192.0.2.20", 5985, Encoding.UTF8.GetBytes(
            "HTTP/1.1 405 Method Not Allowed\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\n\r\n"));
        dialer.MapTcpOpen("192.0.2.20", 445, BuildFakeSmb2NegotiateReply(dialect: 0x0311, signingRequired: false));
        dialer.MapTcpOpen("192.0.2.20", 389, BuildFakeLdapRootDseReply("DC=example,DC=com", "dc01.example.com"));

        using var gate = new ProbeGate(dialer, targets);
        var profiles = new[]
        {
            new PortProfile(22, "ssh", Probe: "ssh"),
            new PortProfile(80, "http", Probe: "http"),
            new PortProfile(389, "ldap", Probe: "ldap"),
            new PortProfile(445, "smb", Probe: "smb2"),
            new PortProfile(5985, "winrm", Probe: "winrm"),
        };

        var result = await HandshakeProbes.SweepHostAsync(gate, IPAddress.Parse("192.0.2.20"), ["dc01.example.com"], profiles, DateTimeOffset.UtcNow, CancellationToken.None);

        Assert.True(result.Answered);
        Assert.Empty(sshWritten); // SSH probe sends nothing
        Assert.Equal(["http", "ldap", "smb", "ssh", "winrm"], result.AnsweredProtocols);

        var ssh = result.Services.Single(s => s.Port == 22);
        Assert.Equal("OpenSSH_9.6p1", ssh.Detail?["software"]?.GetValue<string>());

        var http = result.Services.Single(s => s.Port == 80);
        Assert.Equal(200, http.Detail?["status"]?.GetValue<int>());
        Assert.Equal("nginx/1.26.0", http.Detail?["server"]?.GetValue<string>());
        Assert.Equal("Switch Admin", http.Detail?["title"]?.GetValue<string>());

        var winrm = result.Services.Single(s => s.Port == 5985);
        Assert.Equal("winrm", winrm.Service);
        Assert.Equal("Microsoft-HTTPAPI/2.0", winrm.Detail?["server"]?.GetValue<string>());

        var smb = result.Services.Single(s => s.Port == 445);
        Assert.Equal("3.1.1", smb.Detail?["dialect"]?.GetValue<string>());
        Assert.False(smb.Detail?["signingRequired"]?.GetValue<bool>());

        var ldap = result.Services.Single(s => s.Port == 389);
        Assert.Equal("DC=example,DC=com", ldap.Detail?["defaultNamingContext"]?.GetValue<string>());
        Assert.Equal("dc01.example.com", ldap.Detail?["dnsHostName"]?.GetValue<string>());
    }

    private static byte[] BuildFakeSmb2NegotiateReply(ushort dialect, bool signingRequired)
    {
        const int bodyLen = 64 + 65;
        var packet = new byte[4 + bodyLen];
        packet[3] = bodyLen;
        var smb = packet.AsSpan(4);
        smb[0] = 0xFE;
        smb[1] = (byte)'S';
        smb[2] = (byte)'M';
        smb[3] = (byte)'B';
        BinaryPrimitives.WriteUInt16LittleEndian(smb[4..], 64);
        BinaryPrimitives.WriteUInt32LittleEndian(smb[8..], 0); // STATUS_SUCCESS
        BinaryPrimitives.WriteUInt16LittleEndian(smb[12..], 0); // NEGOTIATE

        var neg = smb[64..];
        BinaryPrimitives.WriteUInt16LittleEndian(neg[0..], 65);
        BinaryPrimitives.WriteUInt16LittleEndian(neg[2..], (ushort)(signingRequired ? 0x03 : 0x01));
        BinaryPrimitives.WriteUInt16LittleEndian(neg[4..], dialect);
        return packet;
    }

    internal static byte[] BuildFakeLdapRootDseReply(string namingContext, string dnsHostName)
    {
        static byte[] Tlv(byte tag, ReadOnlySpan<byte> content)
        {
            var res = new byte[2 + content.Length];
            res[0] = tag;
            res[1] = (byte)content.Length;
            content.CopyTo(res.AsSpan(2));
            return res;
        }
        static byte[] Attr(string name, string val)
        {
            var n = Tlv(0x04, Encoding.UTF8.GetBytes(name));
            var v = Tlv(0x31, Tlv(0x04, Encoding.UTF8.GetBytes(val)));
            return Tlv(0x30, [.. n, .. v]);
        }

        var attrs = Tlv(0x30, [.. Attr("defaultNamingContext", namingContext), .. Attr("dnsHostName", dnsHostName)]);
        var entry = Tlv(0x64, [0x04, 0x00, .. attrs]);
        return Tlv(0x30, [0x02, 0x01, 0x01, .. entry]);
    }

    internal sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            callback(state);
            return new NoopTimer();
        }

        private sealed class NoopTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
