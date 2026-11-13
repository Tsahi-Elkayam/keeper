namespace Keeper.Home.Tests;

public sealed class HomeSecurityTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void A_folder_made_private_passes_the_check()
    {
        var home = Path.Combine(_dir, "home");

        HomeSecurity.MakePrivate(home);

        Assert.Null(HomeSecurity.Problem(home));
        HomeSecurity.EnsurePrivate(home, "The Keeper home");
    }
}
