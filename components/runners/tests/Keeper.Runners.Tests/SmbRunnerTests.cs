using System.Text.Json.Nodes;
using Keeper.Runners.Smb;

namespace Keeper.Runners.Tests;

public sealed class SmbRunnerTests
{
    [Theory]
    [InlineData(@"C$\ProgramData\App", true)]
    [InlineData(@"SYSVOL\example.org\Policies", true)]
    [InlineData(@"\\other-host\C$", false)]          // another host
    [InlineData(@"C:\Windows", false)]               // a drive letter
    [InlineData(@"C$\..\..\x", false)]               // a step up
    [InlineData(@"C$\a\\b", false)]
    [InlineData(@"C$/Windows", false)]
    [InlineData(@"C$\file?.txt", false)]
    public void A_path_is_share_and_folder_on_the_target_host_only(string path, bool allowed) =>
        Assert.Equal(allowed, SmbRunner.PathProblem(path) is null);

    [Fact]
    public void Each_read_names_what_it_needs()
    {
        var runner = new SmbRunner();

        Assert.Empty(runner.Validate(Context.Query("smb", "name", ("read", "shares"))));
        Assert.NotEmpty(runner.Validate(Context.Query("smb", "name", ("read", "share-acl"))));
        Assert.Empty(runner.Validate(Context.Query("smb", "name", ("read", "share-acl"), ("share", "Finance$"))));
        Assert.NotEmpty(runner.Validate(Context.Query("smb", "name", ("read", "ntfs"))));
        Assert.NotEmpty(runner.Validate(Context.Query("smb", "name", ("read", "write"))));
    }

    [Fact]
    public async Task A_read_as_another_account_than_the_one_keeper_runs_as_is_refused()
    {
        var result = await new SmbRunner().RunAsync(Context.Query("smb", "name", ("read", "shares")),
            Context.For(new FakeConnection("pc01.example.org"), "pc01.example.org"), CancellationToken.None);

        Assert.Equal("failed", result.State);   // the fake is bearer: only negotiate (this process's own Windows user) reads shares
        Assert.Contains("negotiate", result.Reason, StringComparison.Ordinal);
    }
}
