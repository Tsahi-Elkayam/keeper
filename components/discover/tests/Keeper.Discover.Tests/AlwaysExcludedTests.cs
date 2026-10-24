using System.Net;
using Keeper.Discover.Probes;

namespace Keeper.Discover.Tests;

public sealed class AlwaysExcludedTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.254")]
    [InlineData("169.254.10.20")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public void Loopback_and_link_local_addresses_are_never_probed(string address)
    {
        Assert.True(Addresses.IsAlwaysExcluded(IPAddress.Parse(address), out var reason));
        Assert.NotNull(reason);
    }

    [Theory]
    [InlineData("192.0.2.10")]
    [InlineData("10.1.2.3")]
    [InlineData("2001:db8::1")]
    public void Ordinary_addresses_are_not_always_excluded(string address)
    {
        Assert.False(Addresses.IsAlwaysExcluded(IPAddress.Parse(address), out _));
    }

    [Fact]
    public void The_probe_never_sends_a_bulk_request()
    {
        Assert.DoesNotContain(SnmpProbe.GetBulkRequestPduTag, SnmpProbe.AllowedOutboundPduTags);
    }
}
