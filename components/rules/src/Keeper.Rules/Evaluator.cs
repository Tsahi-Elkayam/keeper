using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Keeper.Rules;

/// <summary>A row's verdict: fails (true), passes (false) or cannot tell (null = n/a).</summary>
public sealed record Verdict(bool? Fails, string? Value, string? Operand, string? Why)
{
    public string State => Fails switch { true => "fail", false => "pass", null => "n-a" };
}

/// <summary>
/// Evaluates rule conditions. Fail-when semantics: a condition that holds means the row is a problem.
/// Three-valued: a comparison on a missing field is n/a, never a pass.
/// </summary>
public sealed class Evaluator(Func<string, string?> threshold, DateTimeOffset now)
{
    public static readonly IReadOnlySet<string> Ops = new HashSet<string>(StringComparer.Ordinal)
    {
        "eq", "ne", "gt", "ge", "lt", "le", "in", "notin", "contains", "notcontains", "match", "notmatch",
        "exists", "absent", "empty", "notempty", "age-gt", "age-lt", "until-lt", "flag", "noflag",
        "size-gt", "size-lt", "size-eq", "status",
    };

    public static readonly IReadOnlySet<string> OpsWithoutValue = new HashSet<string>(StringComparer.Ordinal)
    {
        "exists", "absent", "empty", "notempty", "status",
    };

    private static readonly HashSet<string> ArrayOps = new(StringComparer.Ordinal) { "size-gt", "size-lt", "size-eq", "empty", "notempty", "contains", "notcontains" };
    private static readonly string[] FailWords = ["fail", "failed", "false", "noncompliant", "non-compliant"];
    private static readonly string[] PassWords = ["pass", "passed", "ok", "true", "compliant", "success", "succeeded"];
    private static readonly ConcurrentDictionary<string, Regex> RegexCache = new(StringComparer.Ordinal);

    public Verdict Each(Condition condition, JsonNode? row) => condition switch
    {
        AlwaysCondition => new Verdict(true, null, null, null),
        LeafCondition leaf => Leaf(leaf, row),
        AllCondition all => Combine(all.Items.Select(c => Each(c, row)).ToList(), any: false),
        AnyCondition any => Combine(any.Items.Select(c => Each(c, row)).ToList(), any: true),
        NotCondition not => Invert(Each(not.Item, row)),
        _ => throw new InvalidOperationException($"Unknown condition {condition.GetType().Name}."),
    };

    public Verdict Count(CountCondition condition, int count)
    {
        var value = count.ToString(CultureInfo.InvariantCulture);
        switch (condition.Mode)
        {
            case "none":
                return new Verdict(count == 0, value, "none", count == 0 ? "no rows: something that should exist was not found" : null);
            case "some":
                return new Verdict(count > 0, value, "some", null);
        }

        var operand = Operand(condition.Threshold, condition.Value.ToString(CultureInfo.InvariantCulture));
        if (!Values.TryNumber(operand, out var limit))
            return new Verdict(null, value, operand, $"threshold '{operand}' is not a number");
        var fails = condition.Op switch
        {
            "gt" => count > limit,
            "ge" => count >= limit,
            "lt" => count < limit,
            "le" => count <= limit,
            "eq" => Math.Abs(count - limit) < 1e-9,
            "ne" => Math.Abs(count - limit) >= 1e-9,
            _ => throw new InvalidOperationException($"Unknown count op {condition.Op}."),
        };
        return new Verdict(fails, value, operand, null);
    }

    private string? Operand(string? thresholdName, string? literal) =>
        thresholdName is not null && threshold(thresholdName) is { Length: > 0 } fromTenant ? fromTenant : literal;

    private static Verdict Combine(List<Verdict> verdicts, bool any)
    {
        if (any)
        {
            var hit = verdicts.FirstOrDefault(v => v.Fails == true);
            if (hit is not null)
                return hit;
            return verdicts.Any(v => v.Fails is null)
                ? new Verdict(null, null, null, verdicts.First(v => v.Fails is null).Why)
                : new Verdict(false, null, null, null);
        }

        var miss = verdicts.FirstOrDefault(v => v.Fails == false);
        if (miss is not null)
            return miss;
        if (verdicts.Any(v => v.Fails is null))
            return new Verdict(null, null, null, verdicts.First(v => v.Fails is null).Why);
        return new Verdict(true, string.Join("; ", verdicts.Select(v => v.Value).Where(v => v is not null)), null, null);
    }

    private static Verdict Invert(Verdict v) => v with { Fails = v.Fails is null ? null : !v.Fails };

    private Verdict Leaf(LeafCondition leaf, JsonNode? row)
    {
        var nodes = FieldPath.Resolve(row, leaf.Field);
        if (!ArrayOps.Contains(leaf.Op))
            nodes = nodes.SelectMany(n => n is JsonArray a ? a.ToList() : [n]).ToList();
        var present = nodes.Where(n => n is not null && Values.Text(n) is not null).ToList();

        switch (leaf.Op)
        {
            case "exists": return new Verdict(present.Count > 0, Values.Text(present.FirstOrDefault()), null, null);
            case "absent": return new Verdict(present.Count == 0, null, null, null);
            case "empty": return new Verdict(IsEmpty(present), null, null, null);
            case "notempty": return new Verdict(!IsEmpty(present), Values.Text(present.FirstOrDefault()), null, null);
        }

        if (present.Count == 0)
            return new Verdict(null, null, null, $"{leaf.Field} not present");

        var operandText = Operand(leaf.Threshold, Values.Text(leaf.Value));

        if (leaf.Op is "size-gt" or "size-lt" or "size-eq")
        {
            var size = present[0] is JsonArray array ? array.Count : present.Count;
            if (!Values.TryNumber(operandText, out var limit))
                return new Verdict(null, size.ToString(CultureInfo.InvariantCulture), operandText, "operand is not a number");
            var fails = leaf.Op switch { "size-gt" => size > limit, "size-lt" => size < limit, _ => Math.Abs(size - limit) < 1e-9 };
            return new Verdict(fails, size.ToString(CultureInfo.InvariantCulture), operandText, null);
        }
        if (leaf.Op is "contains" or "notcontains")
        {
            var found = present.Any(n => Contains(n, operandText));
            return new Verdict(leaf.Op == "contains" ? found : !found, Values.Text(present[0]), operandText, null);
        }

        // Any element that fires makes the row fail; otherwise n/a beats pass.
        Verdict? unknown = null;
        Verdict? pass = null;
        foreach (var node in present)
        {
            var verdict = Scalar(leaf, Values.Text(node)!, operandText);
            if (verdict.Fails == true)
                return verdict;
            if (verdict.Fails is null)
                unknown ??= verdict;
            else
                pass ??= verdict;
        }
        return unknown ?? pass!;
    }

    private static bool IsEmpty(List<JsonNode?> present) =>
        present.Count == 0 || present.All(n => n is JsonArray { Count: 0 } || (n is JsonValue && Values.Text(n) is ""));

    private static bool Contains(JsonNode? node, string? operand)
    {
        if (operand is null)
            return false;
        if (node is JsonArray array)
            return array.Any(e => string.Equals(Values.Text(e), operand, StringComparison.OrdinalIgnoreCase));
        return Values.Text(node)?.Contains(operand, StringComparison.OrdinalIgnoreCase) == true;
    }

    private Verdict Scalar(LeafCondition leaf, string value, string? operand)
    {
        bool? fails;
        switch (leaf.Op)
        {
            case "eq":
            case "ne":
                var equal = Values.TryNumber(value, out var a) && Values.TryNumber(operand, out var b)
                    ? Math.Abs(a - b) < 1e-9
                    : string.Equals(value.Trim(), operand?.Trim(), StringComparison.OrdinalIgnoreCase);
                fails = leaf.Op == "eq" ? equal : !equal;
                break;
            case "gt":
            case "ge":
            case "lt":
            case "le":
                if (!Values.TryNumber(value, out var x) || !Values.TryNumber(operand, out var y))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not a number");
                fails = leaf.Op switch { "gt" => x > y, "ge" => x >= y, "lt" => x < y, _ => x <= y };
                break;
            case "in":
            case "notin":
                var list = ListOf(leaf.Value, operand);
                var member = list.Contains(value.Trim(), StringComparer.OrdinalIgnoreCase);
                fails = leaf.Op == "in" ? member : !member;
                break;
            case "match":
            case "notmatch":
                try
                {
                    var matched = RegexFor(operand ?? "").IsMatch(value);
                    fails = leaf.Op == "match" ? matched : !matched;
                }
                catch (RegexMatchTimeoutException)
                {
                    return new Verdict(null, value, operand, "the pattern timed out");
                }
                break;
            case "age-gt":
            case "age-lt":
            case "until-lt":
                if (!Values.TryDate(value, out var date))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not a date");
                if (!Values.TryNumber(operand, out var days))
                    return new Verdict(null, value, operand, "operand is not a number of days");
                fails = leaf.Op switch
                {
                    "age-gt" => Values.AgeDays(date, now) > days,
                    "age-lt" => Values.AgeDays(date, now) < days,
                    _ => Values.DaysLeft(date, now) < days,
                };
                break;
            case "flag":
            case "noflag":
                if (!Values.TryLong(value, out var bits) || !Values.TryLong(operand, out var flag))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not an integer");
                fails = leaf.Op == "flag" ? (bits & flag) == flag : (bits & flag) == 0;
                break;
            case "status":
                var word = value.Trim().ToLowerInvariant();
                var failWords = operand is { Length: > 0 } ? operand.Split(',', StringSplitOptions.TrimEntries) : FailWords;
                if (failWords.Contains(word, StringComparer.OrdinalIgnoreCase))
                    fails = true;
                else if (PassWords.Contains(word))
                    fails = false;
                else
                    return new Verdict(null, value, operand, $"verdict '{value}' is neither pass nor fail");
                break;
            default:
                throw new InvalidOperationException($"Unknown op {leaf.Op}.");
        }
        return new Verdict(fails, value, operand, null);
    }

    private static IReadOnlyList<string> ListOf(JsonNode? literal, string? operand) =>
        literal is JsonArray array && operand == Values.Text(literal)
            ? array.Select(n => Values.Text(n)?.Trim() ?? "").ToList()
            : (operand ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    public static Regex RegexFor(string pattern) =>
        RegexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));

    /// <summary>Severity for a row from a severity map; the map's default when nothing matches.</summary>
    public string Severity(SeverityMap map, JsonNode? row)
    {
        if (map.DaysLeft is not null)
        {
            if (Values.TryDate(Values.Text(FieldPath.First(row, map.DaysLeft)), out var date))
            {
                var left = Values.DaysLeft(date, now);
                foreach (var range in map.Ranges)
                {
                    if (range.Max is { } max && left <= max)
                        return range.Value;
                }
            }
            return map.Default;
        }

        var text = Values.Text(FieldPath.First(row, map.Field!));
        if (text is null)
            return map.Default;
        if (map.Values.Count > 0)
            return map.Values.TryGetValue(text.Trim(), out var mapped) ? mapped : map.Default;
        if (Values.TryNumber(text, out var number))
        {
            foreach (var range in map.Ranges)
            {
                if ((range.Min is null || number >= range.Min) && (range.Max is null || number <= range.Max))
                    return range.Value;
            }
        }
        return map.Default;
    }
}
