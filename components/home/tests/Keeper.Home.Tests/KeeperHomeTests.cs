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

    [Theory]
    [InlineData("home")]
    [InlineData("demo")]
    public void Accepts_the_top_level_home_or_demo_folder_of_a_source_tree_when_git_ignores_it(string folder)
    {
        Directory.CreateDirectory(Path.Combine(_dir, ".git"));
        File.WriteAllText(Path.Combine(_dir, ".gitignore"), "build/\n/home/\n/demo/\n");

        KeeperHome.EnsureOutsideCode(Path.Combine(_dir, folder, "data"), "The data folder");
        KeeperHome.EnsureOutsideCode(Path.Combine(_dir, folder, "settings", "settings.json"), "The settings file");
    }

    [Fact]
    public void Rejects_the_home_folder_when_git_does_not_ignore_it()
    {
        Directory.CreateDirectory(Path.Combine(_dir, ".git"));
        File.WriteAllText(Path.Combine(_dir, ".gitignore"), "build/\n");

        Assert.Throws<SettingsException>(() => KeeperHome.EnsureOutsideCode(Path.Combine(_dir, "home", "data"), "The data folder"));
        Assert.Throws<SettingsException>(() => KeeperHome.EnsureOutsideCode(Path.Combine(_dir, "components", "home", "data"), "The data folder"));
    }

    [Fact]
    public void Without_the_variable_a_build_inside_the_source_tree_uses_its_home_folder()
    {
        var before = Environment.GetEnvironmentVariable(KeeperHome.EnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(KeeperHome.EnvironmentVariable, null);
            var tree = KeeperHome.SourceTreeAbove(AppContext.BaseDirectory);
            Assert.NotNull(tree);   // the tests run from bin\ inside the repo
            Assert.Equal(Path.Combine(tree, "home"), KeeperHome.Resolve());
        }
        finally
        {
            Environment.SetEnvironmentVariable(KeeperHome.EnvironmentVariable, before);
        }
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
