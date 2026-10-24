using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Discover.Probes;
using Keeper.Discover.Sources;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Files;
using Keeper.Scan;
using Keeper.Store;

namespace Keeper.Discover.Tests;

public sealed class DiscovererAndSnmpTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-discover-e2e-").FullName;

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private sealed class FakeClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Current { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Current;
    }

    private sealed class FakeResolver : IResolver
    {
        public Dictionary<string, IReadOnlyList<IPAddress>> Forward { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<IPAddress, string?> Reverse { get; } = [];

        public Task<IReadOnlyList<IPAddress>> ResolveAddressesAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(Forward.TryGetValue(host, out var list) ? list : (IReadOnlyList<IPAddress>)[]);

        public Task<string?> ResolveReverseNameAsync(IPAddress address, CancellationToken cancellationToken) =>
            Task.FromResult(Reverse.TryGetValue(address, out var name) ? name : null);
    }

    private sealed class TestConnection(string instance, string type, string endpoint, string authKind, string? identity = null,
        Dictionary<string, string>? secrets = null, JsonObject? options = null) : IConnection
    {
        public string Instance => instance;
        public string Type => type;
        public string Endpoint => endpoint;
        public string AuthKind => authKind;
        public string? Identity => identity;
        public JsonObject Options { get; } = options ?? [];
        public string? Secret(string name) => secrets is not null && secrets.TryGetValue(name, out var val) ? val : null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    [Fact]
    public async Task Snmp_probe_reads_v2c_when_allowed_refuses_without_opt_in_and_never_sends_set_pdu()
    {
        var dialer = new FakeDialer();
        var ip = IPAddress.Parse("192.0.2.25");
        var sentPayloads = new List<byte[]>();

        dialer.MapUdp("192.0.2.25", 161, payload =>
        {
            sentPayloads.Add(payload);
            var response = BuildSnmpV2cResponse(
                ("1.3.6.1.2.1.1.1.0", "Cisco IOS Software, C2960 Software"),
                ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9.1.716"),
                ("1.3.6.1.2.1.1.5.0", "sw-core-01.example.com"));
            return new UdpDialResult(DialStates.Open, 3, response);
        });

        var cred = new SnmpCredential(
            Id: "snmp-legacy",
            AuthKind: "snmp-v2c",
            Scope: IPNetwork.Parse("192.0.2.0/24"),
            Community: "public-ro");

        // 1. Refused when AllowCleartext is false
        var blockedTargets = new DiscoveryTargets
        {
            Schema = Schemas.DiscoveryTargets,
            Mode = "manual",
            Targets = [TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.0/24"))],
            Snmp = new SnmpSettings { V2c = ["snmp-legacy"], AllowCleartext = false },
        };
        var blockedGate = new ProbeGate(dialer, blockedTargets);
        var blocked = await SnmpProbe.ProbeHostAsync(blockedGate, ip, null, blockedTargets.Snmp, [cred], fetchNeighbours: false, cancellationToken: CancellationToken.None);
        Assert.Null(blocked.Info);
        // Only the credential-free SNMPv3 engine discovery packet is sent; the v2c community string is never sent
        Assert.Single(sentPayloads);
        Assert.DoesNotContain("public-ro", Encoding.ASCII.GetString(sentPayloads[0]));
        sentPayloads.Clear();

        // 2. Allowed when AllowCleartext is true and Approve Rule grants snmp-legacy on 192.0.2.0/24
        var allowedTargets = new DiscoveryTargets
        {
            Schema = Schemas.DiscoveryTargets,
            Mode = "manual",
            Targets = [TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.0/24"))],
            Approve = [new ApproveRule(IPNetwork.Parse("192.0.2.0/24"), ["snmp"], "snmp-legacy")],
            Snmp = new SnmpSettings { V2c = ["snmp-legacy"], AllowCleartext = true },
        };
        var allowedGate = new ProbeGate(dialer, allowedTargets);
        var outcome = await SnmpProbe.ProbeHostAsync(allowedGate, ip, null, allowedTargets.Snmp, [cred], fetchNeighbours: false, cancellationToken: CancellationToken.None);
        Assert.NotNull(outcome.Info);
        Assert.Equal("v2c", outcome.Info!.Version);
        Assert.Contains("Cisco IOS", outcome.Info.SysDescr);
        Assert.Equal("sw-core-01.example.com", outcome.Info.SysName);

        // Verify no outbound packet ever uses SetRequest-PDU tag (0xA3)
        Assert.NotEmpty(sentPayloads);
        foreach (var packet in sentPayloads)
            Assert.DoesNotContain(SnmpProbe.SetRequestPduTag, packet);
    }

    [Fact]
    public void Snmp_v3_key_localization_and_integration_validation_work()
    {
        var engineId = new byte[] { 0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04 };
        var key256 = SnmpProbe.LocalizeKey("auth-secret-passphrase", engineId, "sha256");
        Assert.Equal(32, key256.Length);

        var key1 = SnmpProbe.LocalizeKey("auth-secret-passphrase", engineId, "sha1");
        Assert.Equal(20, key1.Length);

        var snmpType = IntegrationTypes.Find("snmp");
        Assert.NotNull(snmpType);
        Assert.Contains("snmp-v3", snmpType!.AuthKinds);
        Assert.Contains("snmp-v2c", snmpType.AuthKinds);
        Assert.Equal(["authPassword", "privPassword"], IntegrationTypes.SecretsFor["snmp-v3"]);
        Assert.Equal(["community"], IntegrationTypes.SecretsFor["snmp-v2c"]);
    }

    [Fact]
    public void Classifier_identifies_all_supported_device_kinds()
    {
        // 1. Domain controller (88 + 389 + 445)
        var dc = Classifier.Classify(
            ["kerberos", "ldap", "smb"],
            [
                new AssetService { Port = 88, Transport = "tcp", Service = "kerberos", State = "open" },
                new AssetService { Port = 389, Transport = "tcp", Service = "ldap", State = "open", Detail = new JsonObject { ["defaultNamingContext"] = "DC=example,DC=com" } },
                new AssetService { Port = 445, Transport = "tcp", Service = "smb", State = "open" },
            ],
            null);
        Assert.Equal("domain-controller", dc.Kind);

        // 2. Windows server (445 + 5985)
        var win = Classifier.Classify(
            ["smb", "winrm"],
            [
                new AssetService { Port = 445, Transport = "tcp", Service = "smb", State = "open", Detail = new JsonObject { ["dialect"] = "0x0311" } },
                new AssetService { Port = 5985, Transport = "tcp", Service = "winrm", State = "open" },
            ],
            null);
        Assert.Equal("windows", win.Kind);

        // 3. Printer (9100 raw print port)
        var printer = Classifier.Classify(
            ["http", "raw-print"],
            [
                new AssetService { Port = 80, Transport = "tcp", Service = "http", State = "open" },
                new AssetService { Port = 9100, Transport = "tcp", Service = "raw-print", State = "open" },
            ],
            null);
        Assert.Equal("printer", printer.Kind);

        // 4. Network device (SNMP Cisco IOS, no SMB/WinRM)
        var sw = Classifier.Classify(
            ["ssh", "snmp"],
            [new AssetService { Port = 22, Transport = "tcp", Service = "ssh", State = "open", Detail = new JsonObject { ["banner"] = "SSH-2.0-Cisco-1.25" } }],
            new SnmpInfo { Version = "v3", V3Supported = true, SysDescr = "Cisco IOS Software, Catalyst L3 Switch", SysObjectId = "1.3.6.1.4.1.9.1.716" });
        Assert.Equal("network-device", sw.Kind);

        // 5. Hypervisor (ESXi HTTP title)
        var esxi = Classifier.Classify(
            ["ssh", "https"],
            [
                new AssetService { Port = 22, Transport = "tcp", Service = "ssh", State = "open" },
                new AssetService { Port = 443, Transport = "tcp", Service = "https", State = "open", Detail = new JsonObject { ["title"] = "VMware ESXi" } },
            ],
            null);
        Assert.Equal("hypervisor", esxi.Kind);

        // 6. Linux/Unix (SSH OpenSSH, no SMB/WinRM)
        var linux = Classifier.Classify(
            ["ssh", "https"],
            [
                new AssetService { Port = 22, Transport = "tcp", Service = "ssh", State = "open", Detail = new JsonObject { ["banner"] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu" } },
                new AssetService { Port = 443, Transport = "tcp", Service = "https", State = "open" },
            ],
            null);
        Assert.Equal("linux-unix", linux.Kind);
    }

    [Fact]
    public async Task End_to_end_discover_and_network_rules_produce_inventory_coverage_and_findings()
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-10-01T02:00:00Z"));
        var storePath = Path.Combine(_dir, "keeper.db");
        var importsDir = Path.Combine(_dir, "imports");
        var runsDir = Path.Combine(_dir, "runs");

        // Seed AD computers in store:
        // - dc01.example.com (answers as DC)
        // - old-srv.example.com (resolves to 192.0.2.50, never answers -> becomes likely-gone after 3 scans / 15 days)
        // - ghost.example.com (does not resolve in DNS -> unresolved)
        var db = new Database(storePath);
        using var storeConn = db.OpenReadWrite(create: true);
        Sql.Execute(storeConn,
            """
            CREATE TABLE setting (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE override (
                check_id TEXT NOT NULL,
                entity TEXT NOT NULL,
                decision TEXT NOT NULL,
                value TEXT,
                until TEXT,
                active INTEGER NOT NULL
            );
            CREATE TABLE run (
                run_id TEXT PRIMARY KEY,
                instance TEXT NOT NULL,
                system TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                status TEXT NOT NULL,
                folder TEXT NOT NULL,
                manifest TEXT NOT NULL,
                loaded_at TEXT NOT NULL
            );
            CREATE TABLE latest_run (
                instance TEXT NOT NULL,
                system TEXT NOT NULL,
                run_id TEXT NOT NULL,
                status TEXT NOT NULL,
                PRIMARY KEY (instance, system)
            );
            CREATE TABLE coverage (
                run_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                item TEXT NOT NULL,
                state TEXT NOT NULL,
                count INTEGER,
                reason TEXT
            );
            CREATE TABLE row_seen (
                run_id TEXT NOT NULL,
                query TEXT NOT NULL,
                target TEXT,
                entity_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                entity_name TEXT,
                attrs TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            """);
        var at = Iso.Utc(clock.Current);
        Sql.Execute(storeConn,
            """
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at) VALUES ('r1', 'ad-1', 'active-directory', :at, :at, 'ok', 'r1', '{}', :at);
            INSERT INTO latest_run (instance, system, run_id, status) VALUES ('ad-1', 'active-directory', 'r1', 'ok');
            INSERT INTO coverage (run_id, scope, item, state, count) VALUES ('r1', 'query', 'q-computers', 'ok', 3);
            """,
            null, (":at", at));
        foreach (var (key, dnsName) in new[]
                 {
                     ("DC01", "dc01.example.com"),
                     ("OLD-SRV", "old-srv.example.com"),
                     ("GHOST", "ghost.example.com"),
                 })
        {
            var attrs = new JsonObject { ["dNSHostName"] = dnsName }.ToJsonString();
            Sql.Execute(storeConn,
                "INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at) VALUES ('r1', 'q-computers', 'computer', :k, :n, :a, :at);",
                null, (":k", key), (":n", dnsName), (":a", attrs), (":at", at));
        }

        var resolver = new FakeResolver();
        var dcIp = IPAddress.Parse("192.0.2.10");
        var oldSrvIp = IPAddress.Parse("192.0.2.50");
        var unlistedIp = IPAddress.Parse("192.0.2.11"); // found via widening /28 around 192.0.2.10

        resolver.Forward["dc01.example.com"] = [dcIp];
        resolver.Reverse[dcIp] = "dc01.example.com";
        resolver.Forward["old-srv.example.com"] = [oldSrvIp];
        resolver.Reverse[oldSrvIp] = "old-srv.example.com";
        // ghost.example.com has no forward DNS entry -> unresolved

        var dialer = new FakeDialer();
        void ConfigureActiveNetwork(FakeDialer d)
        {
            // dc01 answers on 88, 389, 445 (with SMB signingRequired = false -> triggers NET-SMB-SIGNING-OFF)
            d.MapTcpOpen("192.0.2.10", 88);
            d.MapTcpOpen("192.0.2.10", 389);
            d.MapTcpOpen("192.0.2.10", 445, BuildSmb2NegotiateResponse(securityMode: 0x01, dialect: 0x0311));

            // unlisted host 192.0.2.11 answers on port 23 (Telnet) only -> triggers NET-UNLISTED-MACHINE, NET-TELNET-OPEN, NET-NO-MANAGEMENT-PROTOCOL
            d.MapTcpOpen("192.0.2.11", 23);

            // two more listed hosts answer, so the outage run below has the 4-host baseline an outage needs
            d.MapTcpOpen("192.0.2.12", 23);
            d.MapTcpOpen("192.0.2.13", 23);

            // excluded host 192.0.2.99 has port 22 mapped in FakeDialer, but must never be dialed because it is in Exclude
            d.MapTcpOpen("192.0.2.99", 22, "SSH-2.0-OpenSSH_9.0\r\n"u8.ToArray());
        }
        ConfigureActiveNetwork(dialer);

        var targets = new DiscoveryTargets
        {
            Schema = Schemas.DiscoveryTargets,
            Mode = "free",
            Scope = [IPNetwork.Parse("192.0.2.0/24")],
            Exclude = [new ExcludeRule(IPNetwork.Parse("192.0.2.99/32"), null, "legacy appliance")],
            Targets = [TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.99/32")),
                TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.12/32")), TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.13/32"))],
            Sources = new SourcesSettings
            {
                Ad = new AdSourceSettings(Enabled: true),
                Dns = new DnsSourceSettings(Forward: true, Reverse: true),
                SnmpNeighbours = new SnmpNeighboursSettings(Enabled: false),
            },
            Widen = new WidenSettings
            {
                FromAd = new WidenRule(28),
                MaxNewAddresses = 64,
            },
            Rate = new RateSettings { ConnectionsPerSecond = 10000, Retries = 0 },
            Staleness = new StalenessSettings { GoneAfterScans = 3, GoneAfterDays = 14 },
        };

        var profiles = new[]
        {
            new PortProfile(22, "ssh", Probe: "ssh"),
            new PortProfile(23, "telnet", SendNothing: true),
            new PortProfile(88, "kerberos", SendNothing: true),
            new PortProfile(389, "ldap", Probe: "ldap"),
            new PortProfile(445, "smb", Probe: "smb2"),
        };

        var discoverer = new Discoverer(clock);

        // Run 1 (Day 0): dc01 and 192.0.2.11 answer; old-srv misses (1)
        await discoverer.RunAsync(new DiscoverRequest
        {
            Targets = targets,
            ImportsDir = importsDir,
            Dialer = dialer,
            Resolver = resolver,
            StoreConnection = storeConn,
            Profiles = profiles,
        }, CancellationToken.None);

        // Run 2 (Day 8): dc01 and 192.0.2.11 answer; old-srv misses (2)
        clock.Current = clock.Current.AddDays(8);
        await discoverer.RunAsync(new DiscoverRequest
        {
            Targets = targets,
            ImportsDir = importsDir,
            Dialer = dialer,
            Resolver = resolver,
            StoreConnection = storeConn,
            Profiles = profiles,
        }, CancellationToken.None);

        // Outage Run (Day 12): nothing answers (< 50% of previous 4 answering assets) -> degraded, misses must stay 2!
        clock.Current = clock.Current.AddDays(4);
        var outageDialer = new FakeDialer();
        var outageResult = await discoverer.RunAsync(new DiscoverRequest
        {
            Targets = targets,
            ImportsDir = importsDir,
            Dialer = outageDialer,
            Resolver = resolver,
            StoreConnection = storeConn,
            Profiles = profiles,
        }, CancellationToken.None);
        Assert.Equal(ScanHealthStates.Degraded, outageResult.Document.ScanHealth);
        Assert.Equal(2, outageResult.Document.Assets.Single(a => a.Id == "old-srv.example.com").Misses);

        // Run 3 (Day 16): restore network; dc01 and 192.0.2.11 answer; old-srv reaches 3 misses over 16 days -> likely-gone!
        clock.Current = clock.Current.AddDays(4);
        var finalResult = await discoverer.RunAsync(new DiscoverRequest
        {
            Targets = targets,
            ImportsDir = importsDir,
            Dialer = dialer,
            Resolver = resolver,
            StoreConnection = storeConn,
            Profiles = profiles,
        }, CancellationToken.None);

        var doc = finalResult.Document;
        Assert.Equal(ScanHealthStates.Ok, doc.ScanHealth);
        Assert.True(doc.Coverage.Summary.Answering >= 2);
        Assert.Equal(1, doc.Coverage.Summary.Unresolved);
        Assert.Equal(1, doc.Coverage.Summary.Excluded);
        Assert.Contains(doc.Coverage.Sources, s => s.Item == "ad" && s.State == "ok");

        // Verify excluded IP 192.0.2.99 was never dialed
        Assert.DoesNotContain(dialer.DialLog, a => a.Ip == "192.0.2.99");

        var dcAsset = doc.Assets.Single(a => a.Id == "dc01.example.com");
        Assert.Equal(AssetStates.Answering, dcAsset.State);
        Assert.Equal("domain-controller", dcAsset.Kind);

        var unlistedAsset = doc.Assets.Single(a => a.Id == "ip:192.0.2.11");
        Assert.Equal(AssetStates.Answering, unlistedAsset.State);
        Assert.Contains(unlistedAsset.Sources, s => s.Kind == "widened-from:ad");

        var oldSrvAsset = doc.Assets.Single(a => a.Id == "old-srv.example.com");
        Assert.Equal(AssetStates.LikelyGone, oldSrvAsset.State);
        Assert.False(oldSrvAsset.EverAnswered);

        var ghostAsset = doc.Assets.Single(a => a.Id == "ghost.example.com");
        Assert.Equal(AssetStates.Unresolved, ghostAsset.State);

        // Set inventory file timestamp to match clock so NET-INVENTORY-OLD does not fire on fresh file
        Assert.NotNull(finalResult.InventoryPath);
        File.SetLastWriteTimeUtc(finalResult.InventoryPath!, clock.Current.UtcDateTime);

        // Now scan inventory.json using rules/network.yaml!
        var rulesPath = FindRepoRoot();
        var networkRuleFile = RuleLoader.LoadFile(
            Path.Combine(rulesPath, "rules", "network.yaml"),
            "builtin",
            new Dictionary<string, QueryValidator> { ["file"] = new FileRunner().Validate });

        var registry = new RunnerRegistry([new FileRunner()]);
        var scanner = new Scanner(registry, clock);
        var scanReport = await scanner.RunAsync(new ScanRequest
        {
            Files = [networkRuleFile],
            Connection = new TestConnection("files", "files", "", "none"),
            RunsDir = runsDir,
            ImportsDir = importsDir,
            StoreFile = storePath,
        }, CancellationToken.None);

        Assert.Equal(0, scanReport.FailedQueries);
        var findings = JsonLines.Read<FindingRecord>(Path.Combine(runsDir, scanReport.Manifest.RunId, RunFolder.Findings)).ToList();
        var ruleIds = findings.Select(f => f.RuleId).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("NET-RECORD-NOTHING-BEHIND", ruleIds);
        Assert.Contains("NET-UNLISTED-MACHINE", ruleIds);
        Assert.Contains("NET-NAME-UNRESOLVED", ruleIds);
        Assert.Contains("NET-TELNET-OPEN", ruleIds);
        Assert.Contains("NET-SMB-SIGNING-OFF", ruleIds);
        Assert.Contains("NET-NO-MANAGEMENT-PROTOCOL", ruleIds);
        Assert.DoesNotContain("NET-INVENTORY-OLD", ruleIds);
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private static byte[] BuildSmb2NegotiateResponse(byte securityMode, ushort dialect)
    {
        var payload = new byte[1 + 3 + 64 + 65];
        var len = 64 + 65;
        payload[1] = (byte)((len >> 16) & 0xFF);
        payload[2] = (byte)((len >> 8) & 0xFF);
        payload[3] = (byte)(len & 0xFF);
        var smb = payload.AsSpan(4);
        smb[0] = 0xFE;
        smb[1] = (byte)'S';
        smb[2] = (byte)'M';
        smb[3] = (byte)'B';
        smb[4] = 64;
        var body = smb[64..];
        body[0] = 65;
        body[2] = securityMode;
        body[4] = (byte)(dialect & 0xFF);
        body[5] = (byte)((dialect >> 8) & 0xFF);
        return payload;
    }

    private static byte[] BuildSnmpV2cResponse(params (string Oid, string Value)[] bindings)
    {
        var varbinds = new List<byte>();
        foreach (var (oid, val) in bindings)
        {
            var oidTlv = EncodeOid(oid);
            var valBytes = Encoding.UTF8.GetBytes(val);
            var valTlv = EncodeTlv(0x04, valBytes);
            var bindTlv = EncodeTlv(0x30, [.. oidTlv, .. valTlv]);
            varbinds.AddRange(bindTlv);
        }

        var varbindList = EncodeTlv(0x30, [.. varbinds]);
        var reqId = EncodeTlv(0x02, [0x01]);
        var err = EncodeTlv(0x02, [0x00]);
        var errIdx = EncodeTlv(0x02, [0x00]);
        var pdu = EncodeTlv(0xA2, [.. reqId, .. err, .. errIdx, .. varbindList]);
        var ver = EncodeTlv(0x02, [0x01]);
        var comm = EncodeTlv(0x04, "public-ro"u8.ToArray());
        return EncodeTlv(0x30, [.. ver, .. comm, .. pdu]);
    }

    private static byte[] EncodeOid(string oid)
    {
        var arcs = oid.Split('.').Select(uint.Parse).ToArray();
        var body = new List<byte> { (byte)(arcs[0] * 40 + arcs[1]) };
        for (var i = 2; i < arcs.Length; i++)
        {
            var v = arcs[i];
            if (v < 128)
            {
                body.Add((byte)v);
            }
            else
            {
                var stack = new Stack<byte>();
                stack.Push((byte)(v & 0x7F));
                v >>= 7;
                while (v > 0)
                {
                    stack.Push((byte)((v & 0x7F) | 0x80));
                    v >>= 7;
                }
                body.AddRange(stack);
            }
        }
        return EncodeTlv(0x06, [.. body]);
    }

    private static byte[] EncodeTlv(byte tag, byte[] value)
    {
        var res = new List<byte> { tag };
        if (value.Length < 128)
        {
            res.Add((byte)value.Length);
        }
        else
        {
            res.Add(0x82);
            res.Add((byte)((value.Length >> 8) & 0xFF));
            res.Add((byte)(value.Length & 0xFF));
        }
        res.AddRange(value);
        return [.. res];
    }
}
