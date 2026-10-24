using System.Net;
using System.Text;
using Keeper.Contracts;
using Keeper.Discover.Probes;

namespace Keeper.Discover.Tests;

public sealed class SnmpApproveTests
{
    private static readonly SnmpCredential Cred = new(
        Id: "snmp-legacy", AuthKind: "snmp-v2c", Scope: IPNetwork.Parse("192.0.2.0/24"), Community: "public-ro");

    private static async Task<List<byte[]>> PacketsSent(IReadOnlyList<ApproveRule> approve)
    {
        var dialer = new FakeDialer();
        var sent = new List<byte[]>();
        dialer.MapUdp("192.0.2.25", 161, payload =>
        {
            sent.Add(payload);
            return new UdpDialResult(DialStates.Filtered, 3, null);
        });
        var targets = new DiscoveryTargets
        {
            Schema = Schemas.DiscoveryTargets,
            Mode = "manual",
            Targets = [TargetEntry.ForNetwork(IPNetwork.Parse("192.0.2.0/24"))],
            Approve = approve,
            Snmp = new SnmpSettings { V2c = ["snmp-legacy"], AllowCleartext = true },
        };
        using var gate = new ProbeGate(dialer, targets);
        await SnmpProbe.ProbeHostAsync(gate, IPAddress.Parse("192.0.2.25"), null, targets.Snmp, [Cred],
            fetchNeighbours: false, cancellationToken: CancellationToken.None);
        return sent;
    }

    private static bool CommunitySent(List<byte[]> packets) =>
        packets.Any(p => Encoding.ASCII.GetString(p).Contains("public-ro", StringComparison.Ordinal));

    [Fact]
    public async Task The_community_is_not_sent_when_no_approve_rule_exists()
    {
        Assert.False(CommunitySent(await PacketsSent([])));
    }

    [Fact]
    public async Task The_community_is_not_sent_to_an_address_outside_the_approved_range()
    {
        var approve = new ApproveRule(IPNetwork.Parse("192.0.2.0/28"), ["snmp"], "snmp-legacy");
        Assert.False(CommunitySent(await PacketsSent([approve])));
    }

    [Fact]
    public async Task The_community_is_not_sent_under_another_integrations_approval()
    {
        var approve = new ApproveRule(IPNetwork.Parse("192.0.2.0/24"), ["snmp"], "some-other-integration");
        Assert.False(CommunitySent(await PacketsSent([approve])));
    }

    [Fact]
    public async Task The_community_is_sent_when_an_approve_rule_covers_address_integration_and_protocol()
    {
        var approve = new ApproveRule(IPNetwork.Parse("192.0.2.0/24"), ["snmp"], "snmp-legacy");
        Assert.True(CommunitySent(await PacketsSent([approve])));
    }
}
