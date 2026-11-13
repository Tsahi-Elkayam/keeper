namespace Keeper.Contracts.Tests;

public sealed class FindingKeyTests
{
    [Fact]
    public void Same_problem_on_same_target_keeps_its_key_whatever_the_case()
    {
        Assert.Equal(FindingKey.For("ad-main", "AD-001", "dc1"), FindingKey.For("AD-MAIN", "ad-001", "DC1"));
    }

    [Fact]
    public void Different_target_or_instance_gets_a_different_key()
    {
        Assert.NotEqual(FindingKey.For("ad-main", "AD-001", "dc1"), FindingKey.For("ad-main", "AD-001", "dc2"));
        Assert.NotEqual(FindingKey.For("ad-main", "AD-001", "dc1"), FindingKey.For("ad-other", "AD-001", "dc1"));
    }

    [Fact]
    public void Key_is_lower_case_sha256_hex()
    {
        var key = FindingKey.For("ad-main", "AD-001", "-");

        Assert.Equal(64, key.Length);
        Assert.Equal(key.ToLowerInvariant(), key);
    }
}
