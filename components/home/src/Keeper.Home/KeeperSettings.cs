using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keeper.Home;

/// <summary>
/// One tenant's bootstrap settings: which tenant this Keeper home belongs to and where its data lives.
/// Lives in the Keeper home (settings\settings.json) - never in the repo and never beside the binaries.
/// Integrations and their credentials are not configured here; they live in the store.
/// </summary>
public sealed record KeeperSettings
{
    public string TenantName { get; init; } = "";

    /// <summary>Relative paths resolve against the settings file's folder.</summary>
    public string DataPath { get; init; } = "../data";
}

public sealed class SettingsException(string message) : Exception(message);

public static class SettingsLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        // Unknown fields fail loudly: anything beyond the bootstrap does not belong in this file.
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static KeeperSettings Load(string path)
    {
        if (!File.Exists(path))
            throw new SettingsException($"Settings file not found: {path}");

        KeeperSettings? settings;
        try
        {
            settings = JsonSerializer.Deserialize<KeeperSettings>(File.ReadAllText(path), Options);
        }
        catch (JsonException ex)
        {
            throw new SettingsException($"Settings file is not valid: {path}: {ex.Message}");
        }

        if (settings is null)
            throw new SettingsException($"Settings file is empty: {path}");
        if (string.IsNullOrWhiteSpace(settings.TenantName))
            throw new SettingsException($"tenantName is required: {path}");

        return settings;
    }

    public static string ResolveDataPath(KeeperSettings settings, string settingsPath) =>
        Path.GetFullPath(settings.DataPath, Path.GetDirectoryName(Path.GetFullPath(settingsPath))!);
}
