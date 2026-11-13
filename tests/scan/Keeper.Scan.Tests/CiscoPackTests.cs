using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Host;

namespace Keeper.Scan.Tests;

public sealed class CiscoPackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-cisco-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class ThisMachine : IConnection
    {
        public string Instance => "host";
        public string Type => "host";
        public string Endpoint => "";
        public string AuthKind => "none";
        public string? Identity => null;
        public IReadOnlyList<string>? Protocols => ["host"];
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private const string BadSwitch = """
        !
        version 15.2
        no service password-encryption
        !
        hostname core-sw01
        !
        enable password cisco123
        enable secret 5 $1$abcd$XYZsecrethash
        !
        username admin privilege 15 password 7 0822455D0A16
        username ops secret 9 $9$abc$defsecrethash
        !
        aaa new-model
        !
        interface GigabitEthernet0/1
         description uplink
         ip address 192.0.2.1 255.255.255.0
         no shutdown
        !
        interface GigabitEthernet0/2
         switchport mode access
         ip ospf message-digest-key 1 md5 7 094F471A1A0A
        !
        ip http server
        no ip http secure-server
        ip ssh version 1
        !
        snmp-server community public RO
        snmp-server community s3cr3tRW RW 10
        snmp-server user mon grp v3 auth sha AuthPass123 priv aes 128 PrivPass123
        tacacs-server host 198.51.100.5 key 7 0822455D0A16
        ntp authentication-key 1 md5 NtpKey123
        !
        banner motd ^C
        Authorized users only - password is not here
        ^C
        !
        line con 0
         exec-timeout 0 0
        line vty 0 4
         password cisco
         login
         transport input telnet
        line vty 5 15
         access-class 10 in
         transport input ssh
        !
        end
        """;

    private const string Good = """
        hostname good-sw
        service password-encryption
        enable secret 9 $9$abc$goodhash
        aaa new-model
        username ops secret 9 $9$def$opshash
        ip ssh version 2
        ntp server 192.0.2.50
        logging host 192.0.2.60
        snmp-server community Corp2026 RO
        no ip http server
        ip http secure-server
        line vty 0 4
         access-class 10 in
         transport input ssh
        """;

    private async Task<List<FindingRecord>> Scan()
    {
        var configs = Path.Combine(_dir, "configs");
        Directory.CreateDirectory(configs);
        File.WriteAllText(Path.Combine(configs, "good-sw.cfg"), Good);
        File.WriteAllText(Path.Combine(configs, "bad-sw.cfg"), BadSwitch);
        File.WriteAllText(Path.Combine(configs, "bare-sw.cfg"), "hostname bare-sw\n");
        var stale = Path.Combine(configs, "stale-sw.cfg");
        File.WriteAllText(stale, Good.Replace("good-sw", "stale-sw", StringComparison.Ordinal));
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddDays(-60));

        var registry = new RunnerRegistry([new HostRunner()]);
        var file = RuleLoader.LoadFile(Path.Combine(FindRepoRoot(), "rules", "cisco-ios.yaml"), "builtin", registry.Validators);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [file],
            Connection = new ThisMachine(),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
            Threshold = name => name == "network.config-folder" ? configs : null,
        }, CancellationToken.None);
        var path = Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings);
        return File.Exists(path) ? JsonLines.Read<FindingRecord>(path).ToList() : [];
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private static string[] Devices(List<FindingRecord> findings, string rule) =>
        [.. findings.Where(f => f.RuleId == rule).Select(f => (f.Target ?? "").Split('|')[0]).Distinct().Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Each_rule_names_the_devices_that_break_it_and_never_the_clean_one()
    {
        var findings = await Scan();

        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-VTY-NOT-SSH-ONLY"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-VTY-NO-ACCESS-CLASS"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-ENABLE-PASSWORD"));
        Assert.Equal(["bare-sw"], Devices(findings, "NET-IOS-ENABLE-SECRET-MISSING"));
        Assert.Equal(["bare-sw"], Devices(findings, "NET-IOS-AAA-NOT-ENABLED"));
        Assert.Equal(["bad-sw", "bare-sw"], Devices(findings, "NET-IOS-SSH-V2-MISSING"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-SSH-V1"));
        Assert.Equal(["bad-sw", "bare-sw"], Devices(findings, "NET-IOS-PASSWORD-ENCRYPTION-OFF"));      // "no service password-encryption" is not the setting
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-HTTP-SERVER"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-SNMP-DEFAULT-COMMUNITY"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-SNMP-WRITE-COMMUNITY"));
        Assert.Equal(["bad-sw"], Devices(findings, "NET-IOS-WEAK-USER-PASSWORD"));
        Assert.Equal(["bad-sw", "bare-sw"], Devices(findings, "NET-IOS-NTP-MISSING"));                  // a key for ntp is not a time source
        Assert.Equal(["bad-sw", "bare-sw"], Devices(findings, "NET-IOS-LOGGING-HOST-MISSING"));
        Assert.Equal(["stale-sw"], Devices(findings, "NET-IOS-CONFIG-BACKUP-STALE"));
        Assert.DoesNotContain(findings, f => (f.Target ?? "").StartsWith("good-sw", StringComparison.Ordinal));
    }

    [Fact]
    public async Task No_secret_of_the_estate_is_in_any_finding()
    {
        var findings = await Scan();

        var text = string.Join("\n", findings.Select(f => f.Evidence));
        foreach (var secret in new[] { "cisco123", "XYZsecrethash", "0822455D0A16", "s3cr3tRW", "goodhash", "opshash", "Corp2026" })
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
    }
}
