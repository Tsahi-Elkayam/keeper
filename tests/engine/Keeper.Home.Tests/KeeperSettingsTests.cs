namespace Keeper.Home.Tests;

public sealed class KeeperSettingsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteSettings(string json)
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void Loads_valid_settings_with_comments()
    {
        var path = WriteSettings("""
            {
              // comments are allowed
              "tenantName": "example",
              "dataPath": "../data"
            }
            """);

        var settings = SettingsLoader.Load(path);

        Assert.Equal("example", settings.TenantName);
        Assert.Equal("../data", settings.DataPath);
    }

    [Fact]
    public void Rejects_anything_beyond_the_bootstrap()
    {
        var path = WriteSettings("""{ "tenantName": "example", "integrations": [ { "type": "sccm" } ] }""");

        Assert.Throws<SettingsException>(() => SettingsLoader.Load(path));
    }

    [Fact]
    public void Requires_tenant_name()
    {
        var path = WriteSettings("""{ "dataPath": "../data" }""");

        Assert.Throws<SettingsException>(() => SettingsLoader.Load(path));
    }

    [Fact]
    public void Resolves_data_path_relative_to_the_settings_file()
    {
        var path = WriteSettings("""{ "tenantName": "example", "dataPath": "../data" }""");

        var settings = SettingsLoader.Load(path);

        Assert.Equal(Path.GetFullPath(Path.Combine(_dir, "..", "data")), SettingsLoader.ResolveDataPath(settings, path));
    }
}
