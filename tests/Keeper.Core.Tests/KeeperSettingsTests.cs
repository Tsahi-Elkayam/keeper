namespace Keeper.Core.Tests;

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
              "connectors": [
                { "type": "sccm", "enabled": true, "baseUrl": "https://sccm.example.org/AdminService", "credentialName": "keeper-sccm" }
              ]
            }
            """);

        var settings = SettingsLoader.Load(path);

        Assert.Equal("example", settings.TenantName);
        var connector = Assert.Single(settings.Connectors);
        Assert.True(connector.Enabled);
        Assert.Equal("keeper-sccm", connector.CredentialName);
    }

    [Fact]
    public void Rejects_unknown_fields_so_a_pasted_secret_stops_startup()
    {
        var path = WriteSettings("""{ "tenantName": "example", "connectors": [ { "type": "sccm", "password": "x" } ] }""");

        Assert.Throws<SettingsException>(() => SettingsLoader.Load(path));
    }

    [Fact]
    public void Requires_tenant_name()
    {
        var path = WriteSettings("""{ "connectors": [] }""");

        Assert.Throws<SettingsException>(() => SettingsLoader.Load(path));
    }

    [Fact]
    public void Requires_connector_type()
    {
        var path = WriteSettings("""{ "tenantName": "example", "connectors": [ { "enabled": true } ] }""");

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
