namespace Keeper.Home.Tests;

public sealed class KeeperHomeTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Accepts_a_folder_outside_any_source_tree()
    {
        KeeperHome.EnsureOutsideCode(Path.Combine(_dir, "data"), "The data folder");
    }

    [Fact]
    public void Rejects_a_folder_inside_a_git_repo()
    {
        Directory.CreateDirectory(Path.Combine(_dir, ".git"));

        var ex = Assert.Throws<SettingsException>(() => KeeperHome.EnsureOutsideCode(Path.Combine(_dir, "build", "data"), "The data folder"));
        Assert.Contains(_dir, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_folder_inside_the_keeper_solution()
    {
        File.WriteAllText(Path.Combine(_dir, "Keeper.slnx"), "<Solution />");

        Assert.Throws<SettingsException>(() => KeeperHome.EnsureOutsideCode(Path.Combine(_dir, "settings", "settings.json"), "The settings file"));
    }

    [Fact]
    public void Rejects_a_folder_beside_the_binaries()
    {
        Assert.Throws<SettingsException>(() => KeeperHome.EnsureOutsideCode(Path.Combine(AppContext.BaseDirectory, "data"), "The data folder"));
    }

    [Fact]
    public void Keeper_home_variable_wins_over_the_default()
    {
        var before = Environment.GetEnvironmentVariable(KeeperHome.EnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(KeeperHome.EnvironmentVariable, _dir);
            Assert.Equal(Path.GetFullPath(_dir), KeeperHome.Resolve());
            Assert.Equal(Path.Combine(Path.GetFullPath(_dir), "settings", "settings.json"), KeeperPaths.DefaultSettingsFile);
        }
        finally
        {
            Environment.SetEnvironmentVariable(KeeperHome.EnvironmentVariable, before);
        }
    }
}
