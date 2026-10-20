namespace Keeper.Common.Tests;

public sealed class CliArgsTests
{
    [Fact]
    public void Reads_positional_words_options_and_flags()
    {
        var cli = new CliArgs(["migrate", "--apply", "--settings", "x.json"], flags: ["apply"]);

        Assert.Equal(new[] { "migrate" }, cli.Positional);
        Assert.True(cli.Has("apply"));
        Assert.Equal("x.json", cli.Get("settings"));
    }

    [Fact]
    public void Reads_name_equals_value()
    {
        var cli = new CliArgs(["broken", "--system=SYS1"]);

        Assert.Equal("SYS1", cli.Get("SYSTEM"));
    }

    [Fact]
    public void Option_without_a_value_is_refused()
    {
        Assert.Throws<ArgumentException>(() => new CliArgs(["broken", "--system"]));
    }
}
