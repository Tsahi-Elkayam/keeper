using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Keeper.Common;
using Keeper.Contracts;

namespace Keeper.Discover;

public static class AssetStates
{
    public const string Pending = "pending";
    public const string Answering = "answering";
    public const string NotAnswering = "not-answering";
    public const string LikelyGone = "likely-gone";
    public const string Unresolved = "unresolved";
    public const string Excluded = "excluded";
    public const string OutOfScope = "out-of-scope";
}

public static class ScanHealthStates
{
    public const string Ok = "ok";
    public const string Degraded = "degraded";
    public const string Partial = "partial";
}

public sealed record AssetSource
{
    public required string Kind { get; init; }
    public required string FirstListed { get; init; }
    public required string LastListed { get; init; }
}

public sealed record AssetService
{
    public required int Port { get; init; }
    public required string Transport { get; init; }
    public required string Service { get; init; }
    public required string State { get; init; }
    public int? RttMs { get; init; }
    public JsonObject? Detail { get; init; }
}

public sealed record SnmpInfo
{
    public required string Version { get; init; }
    public bool V3Supported { get; init; }
    public bool V2cSupported { get; init; }
    public string? EngineId { get; init; }
    public int? EngineBoots { get; init; }
    public int? EngineTime { get; init; }
    public string? SysName { get; init; }
    public string? SysDescr { get; init; }
    public string? SysObjectId { get; init; }
    public long? SysUpTimeCs { get; init; }
}

public sealed record AssetHistoryEntry
{
    public required string At { get; init; }
    public required string Outcome { get; init; }
    public IReadOnlyList<string> Answered { get; init; } = [];
    public int? RttMs { get; init; }
}

public sealed record DiscoveredAsset
{
    public required string Id { get; init; }
    public IReadOnlyList<string> Names { get; init; } = [];
    public IReadOnlyList<string> Addresses { get; init; } = [];
    public IReadOnlyList<AssetSource> Sources { get; init; } = [];
    public required string State { get; init; }
    public bool EverAnswered { get; init; }
    public string? FirstSeen { get; init; }
    public string? LastSeen { get; init; }
    public int Misses { get; init; }
    public string? MissingSince { get; init; }
    public int Flaps { get; init; }
    public string Kind { get; init; } = "unknown";
    public string? KindWhy { get; init; }
    public string? Note { get; init; }
    public IReadOnlyList<string> Answered { get; init; } = [];
    public IReadOnlyList<AssetService> Services { get; init; } = [];
    public SnmpInfo? Snmp { get; init; }
    public IReadOnlyList<JsonObject> Tls { get; init; } = [];
    public IReadOnlyList<AssetHistoryEntry> History { get; init; } = [];
}

public sealed record DiscoveryCoverageEntry
{
    public required string Scope { get; init; }
    public required string Item { get; init; }
    public required string State { get; init; }
    public int Count { get; init; }
    public string? Reason { get; init; }
}

public sealed record DiscoveryCoverageSummary
{
    public int TotalCandidates { get; init; }
    public int Attempted { get; init; }
    public int Answering { get; init; }
    public int NotAnswering { get; init; }
    public int LikelyGone { get; init; }
    public int Unresolved { get; init; }
    public int Excluded { get; init; }
    public int OutOfScope { get; init; }
    public int WithManagementProtocol { get; init; }
    public int WidenedAddresses { get; init; }
}

public sealed record DiscoveryCoverage
{
    public IReadOnlyList<DiscoveryCoverageEntry> Sources { get; init; } = [];
    public DiscoveryCoverageSummary Summary { get; init; } = new();
}

public sealed record InventoryDocument
{
    public string Schema { get; init; } = Schemas.Inventory;
    public required string GeneratedAt { get; init; }
    public required string Mode { get; init; }
    public string ScanHealth { get; init; } = ScanHealthStates.Ok;
    public IReadOnlyList<string> Notes { get; init; } = [];
    public DiscoveryCoverage Coverage { get; init; } = new();
    public IReadOnlyList<DiscoveredAsset> Assets { get; init; } = [];
}

/// <summary>
/// Reads and atomically writes data/imports/discovery/inventory.json.
/// Enforces PathGuard under imports/, verifies schema, caps per-asset history, and backs up on --fresh.
/// </summary>
public static class InventoryFile
{
    public const string RelativePath = "discovery/inventory.json";
    public const string PreviousRelativePath = "discovery/inventory.previous.json";

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition. Never,
    };

    public static string ResolvePath(string importsDir, string relativePath = RelativePath) =>
        PathGuard.Resolve(importsDir, relativePath);

    public static InventoryDocument? LoadIfExists(string importsDir, string relativePath = RelativePath)
    {
        var path = ResolvePath(importsDir, relativePath);
        return File.Exists(path) ? LoadFile(path) : null;
    }

    public static InventoryDocument LoadFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new ArgumentException($"Inventory file not found: {path}");
        if (info.LinkTarget is not null)
            throw new ArgumentException($"Inventory file '{path}' is a symbolic link; links are not followed.");

        InventoryDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<InventoryDocument>(File.ReadAllText(path, Encoding.UTF8), Options);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"Inventory file '{path}' is not valid JSON: {ex.Message}");
        }

        if (doc is null)
            throw new ArgumentException($"Inventory file '{path}' is empty.");
        if (doc.Schema != Schemas.Inventory)
            throw new ArgumentException($"Inventory file '{path}' has unsupported schema '{doc.Schema}' (expected '{Schemas.Inventory}').");

        return doc;
    }

    /// <summary>Rotates the current inventory to inventory.previous.json when starting --fresh.</summary>
    public static void RotateForFresh(string importsDir)
    {
        var current = ResolvePath(importsDir, RelativePath);
        if (!File.Exists(current))
            return;
        var previous = ResolvePath(importsDir, PreviousRelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(previous)!);
        File.Copy(current, previous + ".tmp", overwrite: true);
        File.Move(previous + ".tmp", previous, overwrite: true);
    }

    /// <summary>Atomically writes the inventory file after capping each asset's history to <paramref name="historyKeep"/>.</summary>
    public static string Write(string importsDir, InventoryDocument document, int historyKeep = 20, string relativePath = RelativePath)
    {
        if (document.Schema != Schemas.Inventory)
            throw new ArgumentException($"Unsupported inventory schema '{document.Schema}'.");
        if (historyKeep < 1)
            throw new ArgumentOutOfRangeException(nameof(historyKeep));

        var path = ResolvePath(importsDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var cappedAssets = document.Assets
            .OrderBy(a => a.Id, StringComparer.Ordinal)
            .Select(a => a.History.Count <= historyKeep
                ? a
                : a with { History = a.History.Skip(a.History.Count - historyKeep).ToList() })
            .ToList();

        var normalized = document with { Assets = cappedAssets };
        var tmp = path + ".tmp";
        var json = JsonSerializer.Serialize(normalized, Options) + "\n";
        File.WriteAllText(tmp, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(tmp, path, overwrite: true);
        return path;
    }
}
