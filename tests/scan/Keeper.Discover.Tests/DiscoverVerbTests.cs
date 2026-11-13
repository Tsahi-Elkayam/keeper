using Keeper.Common;
using Keeper.Home;

namespace Keeper.Discover.Tests;

public sealed class DiscoverVerbTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "keeper-discover-verb-" + Guid.NewGuid().ToString("N"));
    private readonly string _settings;
    private readonly string _targets;

    public DiscoverVerbTests()
    {
        var settingsDir = Path.Combine(_root, "settings");
        Directory.CreateDirectory(settingsDir);
        Directory.CreateDirectory(Path.Combine(_root, "data"));
        _settings = Path.Combine(settingsDir, "settings.json");
        File.WriteAllText(_settings, """{ "tenantName": "example", "dataPath": "../data" }""");
        _targets = Path.Combine(settingsDir, "discovery.yaml");
        File.WriteAllText(_targets, "schema: keeper.discovery/1\nmode: manual\nscope: [192.0.2.0/24]\ntargets: [192.0.2.10]\n");
        HomeSecurity.MakePrivate(_root);
        HomeSecurity.MakePrivate(settingsDir);
        HomeSecurity.MakePrivate(Path.Combine(_root, "data"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    /// <summary>A dialer that fails the test if the verb tries to send anything.</summary>
    private sealed class NoDialer : IDialer
    {
        public Task<TcpDialResult> ConnectTcpAsync(System.Net.IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("a mistyped command must not reach the network");

        public Task<UdpDialResult> ExchangeUdpAsync(System.Net.IPAddress address, int port, ReadOnlyMemory<byte> request, TimeSpan timeout, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("a mistyped command must not reach the network");
    }

    private Task<int> Run(params string[] extra) =>
        DiscoverVerb.RunAsync(["--settings", _settings, "--targets", _targets, .. extra], new NoDialer());

    [Fact]
    public async Task A_correct_dry_run_works_with_this_home()
    {
        // Control: the home and targets file are valid, so a usage error below can only come from the arguments.
        Assert.Equal(ExitCodes.Ok, await Run("--dry-run"));
    }

    // The documented-but-missing names, a stray word, and a flag that swallows the next flag:
    // each must be a usage error, never a live scan.
    [Theory]
    [InlineData("status")]
    [InlineData("--plan")]
    [InlineData("--test")]
    [InlineData("--now")]
    [InlineData("--plan", "--fresh")]
    [InlineData("--dry-runn")]
    public async Task A_mistyped_command_is_a_usage_error_and_sends_nothing(params string[] extra)
    {
        Assert.Equal(ExitCodes.Usage, await Run(extra));
    }
}
