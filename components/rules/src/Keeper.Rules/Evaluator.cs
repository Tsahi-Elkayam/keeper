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
        "version-lt", "version-le", "version-gt", "version-ge", "in-cidr", "notin-cidr", "duration-gt", "duration-lt",
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
        ElementCondition element => Element(element, row),
        _ => throw new InvalidOperationException($"Unknown condition {condition.GetType().Name}."),
    };

    /// <summary>
    /// One element at a time: any - fires when some element fires (n/a when none fires and one cannot be
    /// judged); all - fires when every element fires. An empty array fires neither; a missing one, or a null
    /// element, cannot be judged.
    /// </summary>
    private Verdict Element(ElementCondition element, JsonNode? row)
    {
        var found = FieldPath.Resolve(row, element.Of);
        if (found.Count == 0 || found.All(n => n is null))
            return new Verdict(null, null, null, $"{element.Of} not present");
        var elements = found.SelectMany(n => n is JsonArray a ? a.ToList() : [n]).ToList();
        if (elements.Count == 0)
            return new Verdict(false, "0 elements", null, null);
        var verdicts = elements.Select(e => e is null ? new Verdict(null, null, null, $"an element of {element.Of} is null") : Each(element.Where, e)).ToList();
        if (element.All)
        {
            if (verdicts.FirstOrDefault(v => v.Fails == false) is { } miss)
                return miss;
            if (verdicts.FirstOrDefault(v => v.Fails is null) is { } unknown)
                return new Verdict(null, null, null, unknown.Why);
            return new Verdict(true, $"all {verdicts.Count} elements", null, null);
        }
        if (verdicts.FirstOrDefault(v => v.Fails == true) is { } hit)
            return hit;
        return verdicts.FirstOrDefault(v => v.Fails is null) is { } open
            ? new Verdict(null, null, null, open.Why)
            : new Verdict(false, null, null, null);
    }

    public Verdict Count(CountCondition condition, double count)
    {
        var value = Math.Round(count, 2).ToString(CultureInfo.InvariantCulture);
        switch (condition.Mode)
        {
            case "none":
                return new Verdict(count == 0, value, "none", count == 0 ? "nothing matched: something that should exist was not found" : null);
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

        string? literal;
        if (leaf.Value is JsonObject reference)
        {
            // Another field of the same row, optionally scaled: a missing or non-numeric one cannot be judged.
            var other = Values.Text(FieldPath.First(row, Values.Text(reference["field"])!));
            if (other is null)
                return new Verdict(null, Values.Text(present[0]), null, $"{Values.Text(reference["field"])} not present");
            if (reference["times"] is not null || reference["plus"] is not null)
            {
                if (!Values.TryNumber(other, out var number))
                    return new Verdict(null, Values.Text(present[0]), other, $"{Values.Text(reference["field"])} is not a number");
                Values.TryNumber(Values.Text(reference["times"]) ?? "1", out var times);
                Values.TryNumber(Values.Text(reference["plus"]) ?? "0", out var plus);
                other = (number * times + plus).ToString(CultureInfo.InvariantCulture);
            }
            literal = other;
        }
        else
        {
            literal = Values.Text(leaf.Value);
        }
        var operandText = Operand(leaf.Threshold, literal);

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
                catch (ArgumentException)
                {
                    // A tenant's pattern setting that is not a valid expression: the row cannot be judged.
                    return new Verdict(null, value, operand, $"'{operand}' is not a valid regular expression (check the threshold setting)");
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
            case "version-lt":
            case "version-le":
            case "version-gt":
            case "version-ge":
                if (!Values.TryVersion(value, out var have))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not a version");
                if (!Values.TryVersion(operand, out var limitVersion))
                    return new Verdict(null, value, operand, "operand is not a version");
                if (have.PreRelease && limitVersion.PreRelease
                    && Values.CompareVersions(have with { PreRelease = false }, limitVersion with { PreRelease = false }) == 0)
                    return new Verdict(null, value, operand, "two pre-releases of one version cannot be ordered");
                var order = Values.CompareVersions(have, limitVersion);   // a pre-release is below its release
                fails = leaf.Op switch { "version-lt" => order < 0, "version-le" => order <= 0, "version-gt" => order > 0, _ => order >= 0 };
                break;
            case "in-cidr":
            case "notin-cidr":
                // Only an address written as one: 5, 192.168.1 or 3232235777 also parse, as 0.0.0.5 and the like.
                if (!IsAddress(value.Trim(), out var address))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not an IP address");
                var inside = false;
                foreach (var range in ListOf(leaf.Value, operand))
                {
                    if (!System.Net.IPNetwork.TryParse(range, out var network))
                        return new Verdict(null, value, operand, $"'{range}' is not a network (CIDR)");
                    inside |= network.Contains(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);
                }
                fails = leaf.Op == "in-cidr" ? inside : !inside;
                break;
            case "duration-gt":
            case "duration-lt":
                if (!Values.TryDays(value, out var length))
                    return new Verdict(null, value, operand, $"{leaf.Field} is not a duration");
                if (!Values.TryNumber(operand, out var limitDays))
                    return new Verdict(null, value, operand, "operand is not a number of days");
                fails = leaf.Op == "duration-gt" ? length > limitDays : length < limitDays;
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

    /// <summary>An IPv4 address in its four dotted parts, or an IPv6 address.</summary>
    private static bool IsAddress(string text, out System.Net.IPAddress address)
    {
        address = System.Net.IPAddress.None;
        if (text.Contains(':', StringComparison.Ordinal))
            return System.Net.IPAddress.TryParse(text, out address!) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        return text.Split('.') is { Length: 4 } parts && parts.All(p => p.Length is > 0 and <= 3 && p.All(char.IsAsciiDigit))
               && System.Net.IPAddress.TryParse(text, out address!);
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
