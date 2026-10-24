using Keeper.Runners.Cim;

namespace Keeper.Runners.Tests;

public sealed class TransportChainTests
{
    private static Func<string, (Reach, string?)> Replies(List<string> asked, params (string Transport, Reach Reach, string? Why)[] script) =>
        transport =>
        {
            asked.Add(transport);
            var (_, reach, why) = script.Single(s => s.Transport == transport);
            return (reach, why);
        };

    [Fact]
    public void The_first_transport_that_answers_is_used_and_the_rest_are_never_tried()
    {
        var asked = new List<string>();

        var result = TransportChain.Resolve(["wsman", "dcom"], Replies(asked, ("wsman", Reach.Answered, null), ("dcom", Reach.Answered, null)));

        Assert.Equal("wsman", result.Transport);
        Assert.Equal(["wsman"], asked);
    }

    [Fact]
    public void A_transport_nobody_listens_on_falls_through_to_the_next()
    {
        var asked = new List<string>();

        var result = TransportChain.Resolve(["wsman", "dcom"], Replies(asked, ("wsman", Reach.Unreachable, "no listener on 5985"), ("dcom", Reach.Answered, null)));

        Assert.Equal("dcom", result.Transport);
        Assert.Equal(["wsman", "dcom"], asked);
    }

    [Fact]
    public void A_host_that_answers_and_refuses_stops_the_chain_so_a_wrong_password_is_not_tried_twice()
    {
        var asked = new List<string>();

        var result = TransportChain.Resolve(["wsman", "dcom"], Replies(asked, ("wsman", Reach.Refused, "access denied"), ("dcom", Reach.Answered, null)));

        Assert.Equal("wsman", result.Transport);
        Assert.Equal(["wsman"], asked);
    }

    [Fact]
    public void When_nothing_answers_there_is_no_transport_and_the_first_reason_is_kept()
    {
        var asked = new List<string>();

        var result = TransportChain.Resolve(["wsman", "dcom"], Replies(asked, ("wsman", Reach.Unreachable, "no listener on 5985"), ("dcom", Reach.Unreachable, "RPC server unavailable")));

        Assert.Null(result.Transport);
        Assert.Equal("no listener on 5985", result.FirstReason);
        Assert.Equal(["wsman", "dcom"], result.Tried);
    }

    [Fact]
    public void The_order_given_is_the_order_tried()
    {
        var asked = new List<string>();

        TransportChain.Resolve(["dcom", "wsman"], Replies(asked, ("wsman", Reach.Answered, null), ("dcom", Reach.Unreachable, "x")));

        Assert.Equal(["dcom", "wsman"], asked);
    }

    [Fact]
    public void An_empty_chain_is_a_mistake_not_a_scan_of_nothing()
    {
        Assert.Throws<ArgumentException>(() => TransportChain.Resolve([], _ => (Reach.Answered, null)));
    }
}
