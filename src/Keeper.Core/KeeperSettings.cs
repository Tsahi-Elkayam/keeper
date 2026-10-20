using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keeper.Core;

/// <summary>
/// One tenant's settings. Lives in the Keeper home (settings\settings.json) - never in the repo and
/// never beside the binaries. Holds pointers to credentials, never the credentials themselves.
/// </summary>
public sealed record KeeperSettings
{
    public string TenantName { get; init; } = "";

    /// <summary>Relative paths resolve against the settings file's folder.</summary>
    public string DataPath { get; init; } = "../data";

    public IReadOnlyList<ConnectorSettings> Connectors { get; init; } = [];
}

public sealed record ConnectorSettings
{
    public string Type { get; init; } = "";
    public bool Enabled { get; init; }
    public string BaseUrl { get; init; } = "";

    /// <summary>Name of a Windows Credential Manager entry. Empty = interactive sign-in.</summary>
    public string CredentialName { get; init; } = "";
}

public sealed class SettingsException(string message) : Exception(message);

public static class SettingsLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        // Unknown fields fail loudly - a typo or a pasted secret must not be silently ignored.
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
        if (settings.Connectors.Any(c => string.IsNullOrWhiteSpace(c.Type)))
            throw new SettingsException($"Every connector needs a type: {path}");

        return settings;
    }

    public static string ResolveDataPath(KeeperSettings settings, string settingsPath) =>
        Path.GetFullPath(settings.DataPath, Path.GetDirectoryName(Path.GetFullPath(settingsPath))!);
}
