using Keeper.Contracts;

namespace Keeper.Discover.Tests;

public sealed class HealthTests
{
    private static IReadOnlyList<DiscoveredAsset> Answering(int count) =>
        Enumerable.Range(1, count).Select(i => new DiscoveredAsset { Id = $"host{i}", State = AssetStates.Answering }).ToList();

    private static IReadOnlySet<string> Answered(int count) =>
        Enumerable.Range(1, count).Select(i => $"host{i}").ToHashSet();

    [Fact]
    public void A_big_drop_among_enough_hosts_is_a_degraded_run()
    {
        var (health, _) = Lifecycle.EvaluateHealth(Answering(4), Answered(1));
        Assert.Equal(ScanHealthStates.Degraded, health);
    }

    // With fewer than 4 hosts to compare against, one retired machine would keep every later run degraded
    // and nothing could ever age out: the outage guard needs a baseline of at least 4.
    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    [InlineData(3, 0)]
    public void A_small_baseline_never_makes_the_run_degraded(int before, int now)
    {
        var (health, _) = Lifecycle.EvaluateHealth(Answering(before), Answered(now));
        Assert.Equal(ScanHealthStates.Ok, health);
    }

    [Fact]
    public void Four_hosts_is_enough_to_judge_an_outage()
    {
        var (health, reason) = Lifecycle.EvaluateHealth(Answering(4), Answered(0));
        Assert.Equal(ScanHealthStates.Degraded, health);
        Assert.NotNull(reason);
    }
}
