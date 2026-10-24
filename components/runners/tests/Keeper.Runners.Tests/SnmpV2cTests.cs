using System.Net;
using Keeper.Runners.Printer;

namespace Keeper.Runners.Tests;

public sealed class SnmpV2cTests
{
    private static readonly TimeSpan Quick = TimeSpan.FromMilliseconds(400);

    private static FakeSnmpAgent Agent(string community = "public") => new(community, new()
    {
        ["1.3.6.1.2.1.1.1.0"] = "HP LaserJet Pro M404",
        ["1.3.6.1.2.1.43.11.1.1.9.1.1"] = 80L,
        ["1.3.6.1.2.1.43.11.1.1.9.1.2"] = 15L,
        ["1.3.6.1.2.1.43.11.1.1.9.1.3"] = 4L,
        ["1.3.6.1.2.1.43.10.2.1.4.1.1"] = 4_000_000_123L,       // a Counter32 beyond the signed range
        ["1.3.6.1.2.1.43.5.1.1.17.1"] = new byte[] { 0x00, 0x01, 0x02 },
        ["1.3.6.1.2.1.99.1.1.0"] = "outside the subtree",
    });

    private static IPEndPoint At(FakeSnmpAgent agent) => new(IPAddress.Loopback, agent.Port);

    [Fact]
    public async Task A_walk_returns_the_rows_under_a_subtree_in_order_and_stops_at_its_end()
    {
        using var agent = Agent();

        var walk = await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.43.11.1.1.9", 100, Quick, CancellationToken.None);

        Assert.True(walk.Complete);
        Assert.Equal(["1.3.6.1.2.1.43.11.1.1.9.1.1", "1.3.6.1.2.1.43.11.1.1.9.1.2", "1.3.6.1.2.1.43.11.1.1.9.1.3"], walk.Rows.Select(r => r.Oid));
        Assert.Equal([80L, 15L, 4L], walk.Rows.Select(r => (long)r.Value!));
    }

    [Fact]
    public async Task Text_numbers_beyond_the_signed_range_and_raw_bytes_each_come_back_as_what_they_are()
    {
        using var agent = Agent();

        var description = (await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.1.1", 10, Quick, CancellationToken.None)).Rows.Single();
        var pages = (await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.43.10.2.1.4", 10, Quick, CancellationToken.None)).Rows.Single();
        var serial = (await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.43.5.1.1.17", 10, Quick, CancellationToken.None)).Rows.Single();

        Assert.Equal("HP LaserJet Pro M404", SnmpV2c.AsText(description.Value));
        Assert.Equal(4_000_000_123L, (long)pages.Value!);
        Assert.Equal(new byte[] { 0, 1, 2 }, (byte[])serial.Value!);
    }

    [Fact]
    public async Task A_wrong_community_gets_no_answer_and_the_walk_says_so_rather_than_returning_an_empty_pass()
    {
        using var agent = Agent("secret-community");

        var walk = await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.1", 10, Quick, CancellationToken.None);

        Assert.False(walk.Complete);
        Assert.Empty(walk.Rows);
        Assert.Contains("no answer", walk.Problem!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_walk_that_hits_its_row_limit_says_it_is_incomplete()
    {
        using var agent = Agent();

        var walk = await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.43.11.1.1.9", 2, Quick, CancellationToken.None);

        Assert.False(walk.Complete);
        Assert.Equal(2, walk.Rows.Count);
    }

    [Fact]
    public async Task An_answer_with_the_wrong_request_id_is_ignored_and_the_right_one_still_counts()
    {
        using var agent = Agent();
        agent.SendStaleAnswerFirst = true;

        var walk = await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.1.1", 10, Quick, CancellationToken.None);

        Assert.True(walk.Complete);
        Assert.Equal("HP LaserJet Pro M404", SnmpV2c.AsText(walk.Rows.Single().Value));
    }

    [Fact]
    public async Task Only_get_and_getnext_requests_ever_reach_the_device()
    {
        using var agent = Agent();

        await SnmpV2c.WalkAsync(At(agent), "public", "1.3.6.1.2.1.43.11.1.1.9", 100, Quick, CancellationToken.None);
        await SnmpV2c.GetAsync(At(agent), "public", "1.3.6.1.2.1.1.1.0", Quick, CancellationToken.None);

        Assert.All(agent.PduTags, tag => Assert.Contains(tag, new byte[] { 0xA0, 0xA1 }));
        Assert.NotEmpty(agent.PduTags);
    }

    [Theory]
    [InlineData(0xA3)]   // SetRequest
    [InlineData(0xA5)]   // GetBulkRequest
    [InlineData(0xA6)]   // InformRequest
    public void A_request_of_any_other_kind_cannot_be_built(int tag)
    {
        Assert.Throws<InvalidOperationException>(() => SnmpV2c.BuildRequest((byte)tag, "public", 1, "1.3.6.1.2.1.1.1.0"));
    }

    [Fact]
    public async Task A_get_returns_the_value_or_says_there_is_none()
    {
        using var agent = Agent();

        Assert.Equal("HP LaserJet Pro M404", SnmpV2c.AsText((await SnmpV2c.GetAsync(At(agent), "public", "1.3.6.1.2.1.1.1.0", Quick, CancellationToken.None))!.Value.Value));
        Assert.Null(await SnmpV2c.GetAsync(At(agent), "public", "1.3.6.1.2.1.77.77.0", Quick, CancellationToken.None));
    }

    [Theory]
    [InlineData(new byte[] { 0x48, 0x50 }, "HP")]
    [InlineData(new byte[] { 0x00, 0x01, 0xFF }, "0001FF")]     // not text: shown as hex, never garbled
    public void Bytes_that_are_text_read_as_text_and_the_rest_as_hex(byte[] bytes, string expected)
    {
        Assert.Equal(expected, SnmpV2c.AsText(bytes));
    }

    [Fact]
    public void An_oid_must_be_numbers_and_a_community_is_never_empty()
    {
        Assert.Throws<ArgumentException>(() => SnmpV2c.BuildRequest(0xA0, "public", 1, "not.an.oid"));
        Assert.Throws<ArgumentException>(() => SnmpV2c.BuildRequest(0xA0, "", 1, "1.3.6.1.2.1.1.1.0"));
    }
}
