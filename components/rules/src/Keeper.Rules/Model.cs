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

    /// <summary>
    /// Fewer rows than this (per target, for per-host protocols) makes the read partial, never a clean
    /// empty answer: for queries that always return something, such as every user or the domain object.
    /// </summary>
    public int? MinRows { get; init; }

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
public sealed record LeafCondition(string Field, string Op, JsonNode? Value, string? Threshold) : Condition
{
    /// <summary>
    /// The threshold has no meaningful default (a tenant's own list of names): until the tenant sets it the
    /// rule is not configured - never a pass that nothing was compared with.
    /// </summary>
    public bool Required { get; init; }

    /// <summary>How the field writes a date, when the automatic reading would miss it: ole, unix, unix-ms or a custom format.</summary>
    public string? Format { get; init; }
}

public sealed record AllCondition(IReadOnlyList<Condition> Items) : Condition;

public sealed record AnyCondition(IReadOnlyList<Condition> Items) : Condition;

public sealed record NotCondition(Condition Item) : Condition;

/// <summary>
/// The condition held by one element of an array - assignments[] where target and intent are of the same
/// assignment, not one each. Any (default) fires when some element fires; All when every element does.
/// </summary>
public sealed record ElementCondition(string Of, bool All, Condition Where) : Condition;

/// <summary>"each: any": every row is a problem.</summary>
public sealed record AlwaysCondition : Condition
{
    public static readonly AlwaysCondition Instance = new();
}

/// <summary>A rule over the number of rows: compare, "none" (no rows is the problem) or "some".</summary>
/// <param name="Where">Counts only the rows this holds for: "at least one enforced policy must exist" is
/// count lt 1 where enforced. A row the condition cannot judge (n/a) is not counted, so an unreadable
/// policy never satisfies a must-exist rule.</param>
public sealed record CountCondition(string Mode, string? Op, double Value, string? Threshold, Condition? Where = null)
{
    /// <summary>Counts per value of this field: one result (and finding) per group - "more than one admin per site".</summary>
    public string? By { get; init; }

    /// <summary>Counts the distinct values of this field among the rows counted, not the rows.</summary>
    public string? Distinct { get; init; }

    /// <summary>The count is the share of the judged rows that match, in percent - "more than 20% of devices".</summary>
    public bool Percent { get; init; }
}

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

    /// <summary>
    /// Fields whose values never leave the scan: the rows it keeps and the results and evidence it writes show
    /// "set" (or nothing) instead. Conditions still read the real value.
    /// </summary>
    public IReadOnlyList<string> Mask { get; init; } = [];

    /// <summary>The thresholds this rule cannot be judged without (conditions marked required); an hour of the day needs the time zone.</summary>
    public IReadOnlyList<string> RequiredSettings => [.. AllLeaves.Where(l => l.Required && l.Threshold is not null).Select(l => l.Threshold!)
        .Concat(AllLeaves.Any(l => l.Op.StartsWith("hour-", StringComparison.Ordinal)) ? [TimeZoneSetting] : [])
        .Distinct(StringComparer.Ordinal)];

    /// <summary>The setting (threshold.time-zone) that names the organisation's time zone: Asia/Jerusalem, or a Windows id.</summary>
    public const string TimeZoneSetting = "time-zone";

    /// <summary>The rule compares a row with the entity's row in the last clean read (op changed, field _new or _previous).</summary>
    public bool ComparesWithPrevious => AllLeaves.Any(l => l.Op == "changed" || IsPreviousField(l.Field));

    public static bool IsPreviousField(string field) =>
        field.Equals("_new", StringComparison.OrdinalIgnoreCase) || field.Equals("_previous_at", StringComparison.OrdinalIgnoreCase)
        || field.Equals("_previous", StringComparison.OrdinalIgnoreCase) || field.StartsWith("_previous.", StringComparison.OrdinalIgnoreCase);

    private IEnumerable<LeafCondition> AllLeaves => Leaves(Each).Concat(Leaves(Count?.Where));

    /// <summary>Whether the rule's conditions read a field that is, holds or sits inside one of these (masked) fields.</summary>
    public bool Reads(IReadOnlyList<string> fields) => fields.Count > 0 && FieldsOf(Each).Concat(FieldsOf(Count?.Where)).Any(f => fields.Any(m => Overlap(f, m)));

    /// <summary>Two field paths are the same field, or one holds the other (a.b and a; items[].key and items).</summary>
    public static bool Overlap(string a, string b)
    {
        static string Bare(string path) => path.Replace("[]", "", StringComparison.Ordinal);
        var (x, y) = (Bare(a), Bare(b));
        return x.Equals(y, StringComparison.OrdinalIgnoreCase)
               || x.StartsWith(y + ".", StringComparison.OrdinalIgnoreCase) || y.StartsWith(x + ".", StringComparison.OrdinalIgnoreCase);
    }

    // An element's own conditions are relative to the array: the array's path stands for them.
    private static IEnumerable<string> FieldsOf(Condition? condition) => condition switch
    {
        LeafCondition { Value: JsonObject reference } leaf when Values.Text(reference["field"]) is { } other => [leaf.Field, other],
        LeafCondition leaf => [leaf.Field],
        AllCondition all => all.Items.SelectMany(FieldsOf),
        AnyCondition any => any.Items.SelectMany(FieldsOf),
        NotCondition not => FieldsOf(not.Item),
        ElementCondition element => [element.Of],
        _ => [],
    };

    private static IEnumerable<LeafCondition> Leaves(Condition? condition) => condition switch
    {
        LeafCondition leaf => [leaf],
        AllCondition all => all.Items.SelectMany(Leaves),
        AnyCondition any => any.Items.SelectMany(Leaves),
        NotCondition not => Leaves(not.Item),
        ElementCondition element => Leaves(element.Where),
        _ => [],
    };
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
