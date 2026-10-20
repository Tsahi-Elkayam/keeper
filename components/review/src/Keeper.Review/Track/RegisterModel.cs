namespace Keeper.Review.Track;

/// <summary>What keeper-track hands to the queue manager: the register after one pipeline run.</summary>
public sealed record RegisterFile
{
    public required string BuildId { get; init; }
    public required string At { get; init; }
    public IReadOnlyList<FindingRow> Findings { get; init; } = [];
    public IReadOnlyList<EventRow> Events { get; init; } = [];
    public IReadOnlyList<EntityRow> Entities { get; init; } = [];
    public IReadOnlyDictionary<string, int> Counts { get; init; } = new Dictionary<string, int>();
}

public sealed record FindingRow
{
    public required string FindingKey { get; init; }
    public required string Instance { get; init; }
    public required string System { get; init; }
    public required string SystemId { get; init; }
    public required string RuleId { get; init; }
    public required string CheckId { get; init; }
    public required string EntityType { get; init; }
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
    public string? Deadline { get; init; }
    public required string Status { get; init; }
    public required string Lifecycle { get; init; }
    public required string FirstSeen { get; init; }
    public required string LastSeen { get; init; }
    public string? ResolvedAt { get; init; }
    public string? RunId { get; init; }
}

public sealed record EventRow(string FindingKey, string At, string Event, string? RunId, string? Actor, string? Note);

public sealed record EntityRow
{
    public required string Instance { get; init; }
    public required string EntityType { get; init; }
    public required string EntityKey { get; init; }
    public string? EntityName { get; init; }
    public required string SystemId { get; init; }
    public required string MappedBy { get; init; }
    public required string FirstSeen { get; init; }
    public required string LastSeen { get; init; }
    public string? GoneSince { get; init; }
}
