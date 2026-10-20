using System.Text.Json.Nodes;

namespace Keeper.Contracts;

public static class Schemas
{
    public const string Row = "keeper.row/1";
    public const string Result = "keeper.result/1";
    public const string Finding = "keeper.finding/1";
    public const string Coverage = "keeper.coverage/1";
    public const string Run = "keeper.run/1";
}

/// <summary>One entity as a query returned it. Rows are what Keeper has seen: the inventory.</summary>
public sealed record RowRecord
{
    public string Schema { get; init; } = Schemas.Row;
    public required string Instance { get; init; }
    public required string System { get; init; }
    public required string Query { get; init; }
    public required string EntityType { get; init; }
    public required string EntityKey { get; init; }
    public string? EntityName { get; init; }
    public string? Target { get; init; }
    public required JsonObject Attrs { get; init; }
    public required string ObservedAt { get; init; }
}

/// <summary>The outcome of one rule on one entity (or on the whole system for count rules).</summary>
public sealed record ResultRecord
{
    public string Schema { get; init; } = Schemas.Result;
    public required string Instance { get; init; }
    public required string System { get; init; }
    public required string RuleId { get; init; }
    public required string EntityType { get; init; }
    public required string EntityKey { get; init; }
    public required string State { get; init; }
    public string? Value { get; init; }
    public string? Operand { get; init; }
    public string? Why { get; init; }
    public required int TtlMinutes { get; init; }
    public required string At { get; init; }
}

/// <summary>One problem on one target, as a scan or an imported tool reported it.</summary>
public sealed record FindingRecord
{
    public string Schema { get; init; } = Schemas.Finding;
    public required string FindingKey { get; init; }
    public required string Instance { get; init; }
    public required string System { get; init; }
    public required string RuleId { get; init; }

    /// <summary>The rule id, or for an imported tool its own check id (e.g. PC-A-Krbtgt).</summary>
    public required string CheckId { get; init; }
    public required string EntityType { get; init; }

    /// <summary>The entity key; "-" for a finding about the whole system.</summary>
    public required string Target { get; init; }
    public string? EntityName { get; init; }
    public required string Kind { get; init; }
    public required string Lens { get; init; }
    public required string Category { get; init; }
    public required string Severity { get; init; }
    public bool Security { get; init; }
    public required string Title { get; init; }
    public string? Evidence { get; init; }
    public string? Why { get; init; }
    public string? Fix { get; init; }
    public IReadOnlyList<string> Refs { get; init; } = [];

    /// <summary>Date (yyyy-MM-dd) by which it breaks or falls due; null if none.</summary>
    public string? Deadline { get; init; }
    public required string ObservedAt { get; init; }
}

/// <summary>What a scan could and could not see. A source that writes no coverage counts as failed.</summary>
public sealed record CoverageRecord
{
    public string Schema { get; init; } = Schemas.Coverage;
    public required string Instance { get; init; }
    public required string System { get; init; }
    public required string Scope { get; init; }
    public required string Item { get; init; }
    public required string State { get; init; }
    public string? Reason { get; init; }
    public int? Count { get; init; }
    public required string ObservedAt { get; init; }
}

public sealed record RunFile(string Name, string Sha256, long Bytes);

/// <summary>run.json: what produced a run folder, and the hash of every file in it.</summary>
public sealed record RunManifest
{
    public string Schema { get; init; } = Schemas.Run;
    public required string RunId { get; init; }
    public required string Instance { get; init; }
    public required string System { get; init; }
    public string? Identity { get; init; }
    public string? Host { get; init; }
    public required string StartedAt { get; init; }
    public required string FinishedAt { get; init; }

    /// <summary>ok, partial or failed.</summary>
    public required string Status { get; init; }
    public IReadOnlyList<RunFile> Files { get; init; } = [];
    public IReadOnlyDictionary<string, int> Counts { get; init; } = new Dictionary<string, int>();
    public IReadOnlyList<string> Notes { get; init; } = [];
}
