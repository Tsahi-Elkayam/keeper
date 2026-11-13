using System.Net;
using Keeper.Contracts;

namespace Keeper.Discover.Tests;

public sealed class FoundationTests
{
    [Fact]
    public void Addresses_Expand_Ipv4_HandlesBoundariesAndExclusions()
    {
        // /24 -> 254 usable hosts (.1 .. .254)
        var net24 = Addresses.ParseNetwork("192.0.2.0/24");
        var hosts24 = Addresses.Expand(net24);
        Assert.Equal(254, hosts24.Count);
        Assert.Equal("192.0.2.1", hosts24[0].ToString());
        Assert.Equal("192.0.2.254", hosts24[^1].ToString());

        // /31 -> 2 hosts (RFC 3021 point-to-point)
        var net31 = Addresses.ParseNetwork("192.0.2.10/31");
        var hosts31 = Addresses.Expand(net31);
        Assert.Equal(2, hosts31.Count);
        Assert.Equal("192.0.2.10", hosts31[0].ToString());
        Assert.Equal("192.0.2.11", hosts31[1].ToString());

        // /32 -> 1 host
        var net32 = Addresses.ParseNetwork("192.0.2.42/32");
        var hosts32 = Addresses.Expand(net32);
        Assert.Single(hosts32);
        Assert.Equal("192.0.2.42", hosts32[0].ToString());

        // Cap exceeded throws
        Assert.Throws<ArgumentException>(() => Addresses.Expand(net24, maxAddresses: 100));
    }

    [Fact]
    public void Addresses_Ipv6_RefusesWideSweepAndCanonicalizes()
    {
        var wide = Addresses.ParseNetwork("2001:db8::/64");
        Assert.Throws<ArgumentException>(() => Addresses.Expand(wide));

        var narrow = Addresses.ParseNetwork("2001:db8:0:0::/126");
        Assert.Equal("2001:db8::", narrow.BaseAddress.ToString());
        var expanded = Addresses.Expand(narrow);
        Assert.Equal(4, expanded.Count);
        Assert.Equal("2001:db8::", expanded[0].ToString());
        Assert.Equal("2001:db8::3", expanded[3].ToString());
    }

    [Fact]
    public void Addresses_AlwaysExcluded_FlagsReservedClasses()
    {
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("0.0.0.0"), out _));
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("255.255.255.255"), out _));
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("224.0.0.1"), out _));
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("240.0.0.1"), out _));
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("::"), out _));
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse("ff02::1"), out _));

        Assert.False(Addresses.IsAlwaysExcluded(IPAddress.Parse("192.0.2.1"), out _));
        Assert.False(Addresses.IsAlwaysExcluded(IPAddress.Parse("2001:db8::1"), out _));
    }

    [Fact]
    public void TargetsLoader_ParsesValidSpecExample()
    {
        const string yaml = """
            schema: keeper.discovery/1
            mode: free
            scope: [192.0.2.0/24, 198.51.100.0/23, "2001:db8:10::/120"]
            targets:
              - 192.0.2.0/25
              - 198.51.100.10
              - host: printer-01.example.com
            exclude:
              - { cidr: 192.0.2.250/32, why: "old controller, crashes under scans" }
              - { name: "*.lab.example.com" }
            gentle: [198.51.100.64/27]
            approve: []
            sources:
              ad: { enabled: true }
              dns: { forward: true, reverse: false }
              snmp-neighbours: { enabled: false, credentials: [snmp-core] }
            widen:
              from-ad: { ipv4-prefix: 24 }
              from-dns: { ipv4-prefix: 24 }
              from-snmp-neighbours: { ipv4-prefix: 32 }
              max-new-addresses: 4096
            snmp: { v3: [snmp-core], v2c: [], allow-cleartext: false }
            rate: { connections-per-second: 50, concurrent: 64, per-host: 2, timeout-ms: 1500, retries: 1 }
            staleness: { gone-after-scans: 3, gone-after-days: 14 }
            windows: [{ days: [sat, sun], from: "20:00", to: "06:00" }]
            history: { keep: 20 }
            """;

        var parsed = TargetsLoader.Parse(yaml);
        Assert.Equal("free", parsed.Mode);
        Assert.Equal(3, parsed.Scope.Count);
        Assert.Equal(3, parsed.Targets.Count);
        Assert.Equal("printer-01.example.com", parsed.Targets[2].Host);
        Assert.Equal(2, parsed.Exclude.Count);
        Assert.True(parsed.Sources.Ad.Enabled);
        Assert.Equal(24, parsed.Widen.FromAd?.Ipv4Prefix);
        Assert.Single(parsed.Windows);
        Assert.Equal(20, parsed.History.Keep);
    }

    [Theory]
    [InlineData("schema: keeper.discovery/1\nmode: free\nunknownField: 1\nscope: [192.0.2.0/24]", "unknownField")]
    [InlineData("schema: keeper.discovery/1\nmode: free\n", "scope")]
    [InlineData("schema: keeper.discovery/1\nmode: manual\nsnmp: { v2c: [pub], allow-cleartext: false }", "allow-cleartext")]
    [InlineData("schema: keeper.discovery/1\nmode: manual\ntargets: ['2001:db8::/64']", "/112")]
    [InlineData("schema: keeper.discovery/1\nmode: free\nscope: [192.0.2.0/24]\ntargets: [198.51.100.1]", "outside 'scope'")]
    [InlineData("schema: keeper.discovery/1\nmode: manual\nwindows: [{ days: [funday], from: '20:00', to: '06:00' }]", "funday")]
    public void TargetsLoader_RefusesInvalidConfigurations(string yaml, string expectedErrorFragment)
    {
        var ex = Assert.Throws<ArgumentException>(() => TargetsLoader.Parse(yaml));
        Assert.Contains(expectedErrorFragment, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InventoryFile_RoundTripsCapsHistoryAndRotatesFresh()
    {
        var temp = Path.Combine(Path.GetTempPath(), "keeper-discover-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(temp);
            var history = Enumerable.Range(1, 5)
                .Select(i => new AssetHistoryEntry { At = $"2026-10-2{i}T12:00:00Z", Outcome = "answered", Answered = ["ssh"], RttMs = i })
                .ToList();
            var doc = new InventoryDocument
            {
                GeneratedAt = "2026-10-25T21:04:00Z",
                Mode = "manual",
                Assets =
                [
                    new DiscoveredAsset
                    {
                        Id = "srv-01.example.com",
                        Names = ["srv-01.example.com"],
                        Addresses = ["192.0.2.10"],
                        State = AssetStates.Answering,
                        EverAnswered = true,
                        FirstSeen = "2026-10-21T12:00:00Z",
                        LastSeen = "2026-10-25T12:00:00Z",
                        History = history,
                    },
                ],
            };

            InventoryFile.Write(temp, doc, historyKeep: 3);
            var loaded = InventoryFile.LoadIfExists(temp);
            Assert.NotNull(loaded);
            Assert.Equal(Schemas.Inventory, loaded.Schema);
            Assert.Single(loaded.Assets);
            Assert.Equal(3, loaded.Assets[0].History.Count);
            Assert.Equal("2026-10-23T12:00:00Z", loaded.Assets[0].History[0].At);

            InventoryFile.RotateForFresh(temp);
            var prev = InventoryFile.LoadIfExists(temp, InventoryFile.PreviousRelativePath);
            Assert.NotNull(prev);
            Assert.Equal("srv-01.example.com", prev.Assets[0].Id);
        }
        finally
        {
            if (Directory.Exists(temp))
                Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void Lifecycle_RequiresBothScansAndDaysForLikelyGone_AndRespectsDegradedScan()
    {
        var staleness = new StalenessSettings { GoneAfterScans = 3, GoneAfterDays = 14 };
        var t0 = new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

        var asset = new DiscoveredAsset
        {
            Id = "ws-01.example.com",
            State = AssetStates.Pending,
        };

        // First answer -> answering
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Answered, ["smb"], BestRttMs: 4), ScanHealthStates.Ok, staleness, t0);
        Assert.Equal(AssetStates.Answering, asset.State);
        Assert.True(asset.EverAnswered);
        Assert.Equal(0, asset.Misses);

        // Miss 1 on day 1 -> not-answering
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), ScanHealthStates.Ok, staleness, t0.AddDays(1));
        Assert.Equal(AssetStates.NotAnswering, asset.State);
        Assert.Equal(1, asset.Misses);

        // Degraded scan on day 2 -> does NOT increment misses
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), ScanHealthStates.Degraded, staleness, t0.AddDays(2));
        Assert.Equal(AssetStates.NotAnswering, asset.State);
        Assert.Equal(1, asset.Misses);

        // Miss 2 and 3 within 5 days (< 14 days) -> still not-answering because days threshold not met
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), ScanHealthStates.Ok, staleness, t0.AddDays(3));
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), ScanHealthStates.Ok, staleness, t0.AddDays(5));
        Assert.Equal(3, asset.Misses);
        Assert.Equal(AssetStates.NotAnswering, asset.State);

        // Miss 4 after 15 days (>= 14 days from MissingSince on day 1) -> likely-gone
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), ScanHealthStates.Ok, staleness, t0.AddDays(16));
        Assert.Equal(AssetStates.LikelyGone, asset.State);

        // Answers again -> answering, flaps + 1, misses reset to 0
        asset = Lifecycle.Transition(asset, new ProbeAttemptOutcome(ProbeOutcomeKind.Answered, ["smb"]), ScanHealthStates.Ok, staleness, t0.AddDays(17));
        Assert.Equal(AssetStates.Answering, asset.State);
        Assert.Equal(0, asset.Misses);
        Assert.Null(asset.MissingSince);
        Assert.Equal(1, asset.Flaps);
    }
}
