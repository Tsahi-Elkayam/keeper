using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Rules;

/// <summary>
/// How a rule gets its rows: the protocol, its protocol-specific fields, and the row fields that identify
/// the entity. Rules with the same query share one fetch.
/// </summary>
public sealed record QuerySpec(string Protocol, JsonObject Fields, string Key, string? Name)
{
    /// <summary>Stable short id: the same protocol, fields and key always give the same id.</summary>
    public string Id { get; } = Fingerprint(Protocol, Fields, Key);

    public string? Text(string field) => Fields[field] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    public IReadOnlyList<string> List(string field) =>
        Fields[field] switch
        {
            JsonArray a => a.Select(n => n?.ToString() ?? "").Where(s => s.Length > 0).ToList(),
            JsonValue v when v.TryGetValue<string>(out var s) => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            _ => [],
        };

    public int? Int(string field) => int.TryParse(Text(field), out var n) ? n : null;

    private static string Fingerprint(string protocol, JsonObject fields, string key)
    {
        var canonical = $"{protocol}|{Canonical(fields)}|{key}";
        return "q-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..12];
    }

    private static string Canonical(JsonNode? node) => node switch
    {
        JsonObject o => "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}:{Canonical(p.Value)}")) + "}",
        JsonArray a => "[" + string.Join(",", a.Select(Canonical)) + "]",
        null => "null",
        _ => node.ToJsonString(),
    };
}

public abstract record Condition;

/// <summary>A row fails when <see cref="Op"/> holds for the value at <see cref="Field"/>.</summary>
public sealed record LeafCondition(string Field, string Op, JsonNode? Value, string? Threshold) : Condition;

public sealed record AllCondition(IReadOnlyList<Condition> Items) : Condition;

public sealed record AnyCondition(IReadOnlyList<Condition> Items) : Condition;

public sealed record NotCondition(Condition Item) : Condition;

/// <summary>"each: any": every row is a problem.</summary>
public sealed record AlwaysCondition : Condition
{
    public static readonly AlwaysCondition Instance = new();
}

/// <summary>A rule over the number of rows: compare, "none" (no rows is the problem) or "some".</summary>
/// <param name="Where">Counts only the rows this holds for: "at least one enforced policy must exist" is
/// count lt 1 where enforced. A row the condition cannot judge (n/a) is not counted, so an unreadable
/// policy never satisfies a must-exist rule.</param>
public sealed record CountCondition(string Mode, string? Op, double Value, string? Threshold, Condition? Where = null);

public sealed record SeverityRange(double? Min, double? Max, string Value);

/// <summary>
/// Severity from a row: numeric ranges over a field (min, first match), ranges over the days left until a
/// date (max, first match), or a text-to-severity map. <see cref="Default"/> when nothing matches.
/// </summary>
public sealed record SeverityMap(string? Field, string? DaysLeft, IReadOnlyList<SeverityRange> Ranges,
    IReadOnlyDictionary<string, string> Values, string Default);

/// <summary>For rows that already are verdicts (an imported tool's results): the tool's own id, title and severity.</summary>
public sealed record Emit(string? Check, string? Title, string? Kind, string? Category, SeverityMap? Severity);

/// <summary>For per-host protocols: which hosts to scan.</summary>
public sealed record TargetSpec(string? Entity, Condition? Where, string? Field, IReadOnlyList<string> List);

public sealed record Rule
{
    public required string Id { get; init; }
    public required string System { get; init; }
    public required string Title { get; init; }
    public required string Kind { get; init; }
    public required string Lens { get; init; }
    public required string Category { get; init; }
    public required string Severity { get; init; }
    public required string EntityType { get; init; }
    public string? Why { get; init; }
    public string? Fix { get; init; }
    public IReadOnlyList<string> Refs { get; init; } = [];
    public required TimeSpan Refresh { get; init; }
    public required QuerySpec Query { get; init; }
    public Condition? Each { get; init; }
    public CountCondition? Count { get; init; }
    public string? Evidence { get; init; }

    /// <summary>A date field: the finding's deadline (when it breaks or falls due).</summary>
    public string? Deadline { get; init; }
    public SeverityMap? SeverityBy { get; init; }
    public Emit? Emit { get; init; }
    public required string Source { get; init; }
    public required int Line { get; init; }

    /// <summary>A result older than three refresh periods is stale.</summary>
    public int TtlMinutes => (int)Math.Max(1, Refresh.TotalMinutes * 3);
}

public sealed record RuleFile(string System, string Name, string Integration, TargetSpec? Targets, IReadOnlyList<Rule> Rules,
    string Path, string Origin, string Sha256);

public sealed class RuleSet(IReadOnlyList<RuleFile> files)
{
    public IReadOnlyList<RuleFile> Files { get; } = files;

    public IEnumerable<Rule> Rules => Files.SelectMany(f => f.Rules);

    public IReadOnlyList<RuleFile> ForSystem(string system) =>
        Files.Where(f => f.System.Equals(system, StringComparison.OrdinalIgnoreCase)).ToList();

    public IReadOnlyList<string> Systems => Files.Select(f => f.System).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToList();
}

public sealed class RuleException(IReadOnlyList<string> errors)
    : Exception(errors.Count == 1 ? errors[0] : $"{errors.Count} problems in rule files:{Environment.NewLine}{string.Join(Environment.NewLine, errors)}")
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
