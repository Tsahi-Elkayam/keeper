using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;

namespace Keeper.Runners;

/// <summary>
/// Dates a request can name relative to the scan: {NOW}, {TODAY}, {DAYS_AGO:n}, {DAYS_AHEAD:n} - so a Graph
/// $filter can ask for "the provisioning events of the last 7 days" without a date in the rule file. The days
/// can be the tenant's own: {DAYS_AGO:threshold.ad.stale-days|90} takes that setting, else 90.
/// </summary>
public static partial class RequestMacros
{
    [GeneratedRegex(@"\{(NOW|TODAY|DAYS_AGO:(\d{1,4}|threshold\.[a-z0-9.-]{1,80}\|\d{1,4})|DAYS_AHEAD:(\d{1,4}|threshold\.[a-z0-9.-]{1,80}\|\d{1,4}))\}",
        RegexOptions.CultureInvariant)]
    private static partial Regex Macro();

    public static string Expand(string text, DateTimeOffset now) => Expand(text, now, _ => null);

    public static string Expand(string text, RunnerContext context) => Expand(text, context.Now, context.Threshold);

    public static string Expand(string text, DateTimeOffset now, Func<string, string?> threshold) =>
        Macro().Replace(text, m => m.Groups[1].Value switch
        {
            "NOW" => Iso(now),
            "TODAY" => now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            _ when m.Groups[2].Success => Iso(now.AddDays(-Days(m.Groups[2].Value, threshold))),
            _ => Iso(now.AddDays(Days(m.Groups[3].Value, threshold))),
        });

    /// <summary>"30", or "threshold.name|30": the tenant's whole number of days, else the default.</summary>
    private static int Days(string text, Func<string, string?> threshold)
    {
        if (!text.StartsWith("threshold.", StringComparison.Ordinal))
            return int.Parse(text, CultureInfo.InvariantCulture);
        var bar = text.IndexOf('|', StringComparison.Ordinal);
        return int.TryParse(threshold(text["threshold.".Length..bar]), NumberStyles.None, CultureInfo.InvariantCulture, out var days) && days <= 9999
            ? days
            : int.Parse(text[(bar + 1)..], CultureInfo.InvariantCulture);
    }

    public static bool IsMacro(string name) => Macro().IsMatch("{" + name + "}");

    /// <summary>Every string in a request body (or GraphQL variables), expanded. Changes and returns the node.</summary>
    public static JsonNode? ExpandAll(JsonNode? node, RunnerContext context) => ExpandAll(node, context.Now, context.Threshold);

    public static JsonNode? ExpandAll(JsonNode? node, DateTimeOffset now, Func<string, string?>? threshold = null)
    {
        threshold ??= _ => null;
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).ToList())
                {
                    if (o[name] is JsonValue v && v.TryGetValue<string>(out var s))
                        o[name] = Expand(s, now, threshold);
                    else
                        ExpandAll(o[name], now, threshold);
                }
                return o;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue v && v.TryGetValue<string>(out var s))
                        a[i] = Expand(s, now, threshold);
                    else
                        ExpandAll(a[i], now, threshold);
                }
                return a;
            case JsonValue v when v.TryGetValue<string>(out var s):
                return JsonValue.Create(Expand(s, now, threshold));
            default:
                return node;
        }
    }

    private static string Iso(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}

/// <summary>
/// for_each: one request per object of another list - /servicePrincipals/{id}/synchronization/jobs for every
/// service principal the for_each query returns. The list is fetched first through the same runner and
/// integration - or given: values (a fixed list) or threshold (the tenant's comma-separated list). Each
/// object's fields fill the {placeholders} of the path and of the params, and every row it returns carries
/// that object as "parent". Capped (max, default 200), and an id that is not a plain id is never put in a request.
/// </summary>
public static partial class PerObject
{
    private const int DefaultMax = 200;
    private const int Parallel = 4;

    [GeneratedRegex(@"\{([A-Za-z_][A-Za-z0-9_.]{0,63})\}", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"^[A-Za-z0-9._:\-]{1,200}$", RegexOptions.CultureInvariant)]
    private static partial Regex PlainId();

    public static IEnumerable<string> Validate(QuerySpec query)
    {
        if (query.Fields["for_each"] is null)
            yield break;
        if (query.Fields["for_each"] is not JsonObject each)
        {
            yield return "for_each must be a mapping: the query that lists the objects, plus field";
            yield break;
        }
        if (each["for_each"] is not null)
            yield return "for_each cannot be nested";
        if (each["missing"] is not null)
            yield return "for_each's own list cannot take missing: a list that answers 404 has a wrong path";
        if (Values.Text(each["field"]) is not { Length: > 0 } field)
            yield return "for_each.field is required: the field of each object that goes into the request";
        else if (!(query.Text("path") ?? "").Contains("{" + field + "}", StringComparison.Ordinal)
                 && !(query.Fields["params"]?.ToJsonString() ?? "").Contains("{" + field + "}", StringComparison.Ordinal))
            yield return $"the path or a param must use {{{field}}} so each object gets its own request";
        var given = each["values"] is not null || each["threshold"] is not null;
        if (each["values"] is not (null or JsonArray))
            yield return "for_each.values must be a list";
        if (each["threshold"] is { } name && Values.Text(name) is not { Length: > 0 })
            yield return "for_each.threshold must name a setting (threshold.<name>) that holds a comma-separated list";
        if (!given && HttpPaths.Problem(Values.Text(each["path"])) is { } problem)
            yield return $"for_each.{problem}";
        if (Values.Text(each["max"]) is { } max && (!int.TryParse(max, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n is < 1 or > 2000))
            yield return "for_each.max must be 1 to 2000";
    }

    public static async Task<RunnerResult> RunAsync(IRunner runner, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var each = (JsonObject)query.Fields["for_each"]!.DeepClone();
        var field = Values.Text(each["field"])!;
        var max = int.TryParse(Values.Text(each["max"]), NumberStyles.None, CultureInfo.InvariantCulture, out var m) ? m : DefaultMax;
        each.Remove("field");
        each.Remove("max");

        RunnerResult list;
        if (each["values"] is JsonArray values)
            list = RunnerResult.Ok([.. values.Where(v => v is not null).Select(v => new JsonObject { [field] = v!.DeepClone() })]);
        else if (Values.Text(each["threshold"]) is { } setting)
            list = RunnerResult.Ok([.. (context.Threshold(setting) ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(v => new JsonObject { [field] = v })]);
        else
            list = await runner.RunAsync(new QuerySpec(query.Protocol, each, field, null), context, cancellationToken).ConfigureAwait(false);
        if (list.State == "failed")
            return RunnerResult.Failed($"the list for for_each failed: {list.Reason}");

        var parents = list.Rows.Take(max).ToList();
        var template = query.Text("path")!;
        var childFields = (JsonObject)query.Fields.DeepClone();
        childFields.Remove("for_each");

        using var gate = new SemaphoreSlim(Parallel);
        var results = await Task.WhenAll(parents.Select(async parent =>
        {
            if (Path(template, parent) is not { } path || Params(childFields["params"], parent) is not { } parameters)
                return (Parent: parent, Result: RunnerResult.Failed($"{Values.Text(FieldPath.First(parent, field)) ?? "?"}: not a plain id; skipped"));
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var fields = (JsonObject)childFields.DeepClone();
                fields["path"] = path;
                if (parameters.Count > 0)
                    fields["params"] = parameters;
                return (Parent: parent, Result: await runner.RunAsync(new QuerySpec(query.Protocol, fields, query.Key, query.Name), context, cancellationToken).ConfigureAwait(false));
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        var rows = new List<JsonObject>();
        foreach (var (parent, result) in results)
        {
            foreach (var row in result.Rows)
            {
                row["parent"] = parent.DeepClone();
                rows.Add(row);
            }
        }

        var failed = results.Where(r => r.Result.State == "failed").ToList();
        var partial = results.Where(r => r.Result.State == "partial").ToList();
        var absent = results.Count(r => r.Result.State == "ok" && r.Result.Reason == RunnerResult.NotFound);
        var notes = new List<string>();
        // Every object lacking the child is more likely a wrong path than a fact: not a clean answer.
        if (parents.Count > 0 && absent == parents.Count)
            return RunnerResult.Partial(rows, $"all {parents.Count} objects answered 404 - check the path");
        // Some objects lacking the child (users without a manager) is an answer, not a cut-short read.
        var info = absent > 0 ? $"{absent} of {parents.Count} objects have none (404)" : null;
        if (list.Rows.Count > max)
            notes.Add($"only the first {max} of {list.Rows.Count} objects (raise for_each.max)");
        if (failed.Count > 0)
            notes.Add($"{failed.Count} of {parents.Count} objects failed: {string.Join("; ", failed.Take(3).Select(f => f.Result.Reason))}");
        if (partial.Count > 0)
            notes.Add($"{partial.Count} of {parents.Count} objects were read only in part: {string.Join("; ", partial.Take(3).Select(p => p.Result.Reason))}");
        if (list.State == "partial")
            notes.Add($"the object list itself was partial: {list.Reason}");

        if (parents.Count > 0 && failed.Count == parents.Count)
            return RunnerResult.Failed(string.Join("; ", notes));
        if (notes.Count > 0)
            return RunnerResult.Partial(rows, string.Join("; ", info is null ? notes : [.. notes, info]));
        return new RunnerResult(rows, "ok", info);
    }

    /// <summary>The path with each {field} replaced by the object's value - only plain ids, escaped; date macros are left for the runner.</summary>
    public static string? Path(string template, JsonObject parent) => Fill(template, parent, escape: true);

    /// <summary>The params with each {field} replaced the same way (not escaped: the engine escapes parameters), or null.</summary>
    public static JsonObject? Params(JsonNode? template, JsonObject parent)
    {
        var filled = new JsonObject();
        if (template is not JsonObject map)
            return filled;
        foreach (var (name, value) in map)
        {
            if (Values.Text(value) is not { } text)
            {
                filled[name] = value?.DeepClone();
                continue;
            }
            // A name the object does not have stays as it is: braces in a param are not always a placeholder.
            if (Fill(text, parent, escape: false, keepUnknown: true) is not { } done)
                return null;
            filled[name] = done;
        }
        return filled;
    }

    private static string? Fill(string template, JsonObject parent, bool escape, bool keepUnknown = false)
    {
        var ok = true;
        var text = Placeholder().Replace(template, m =>
        {
            if (RequestMacros.IsMacro(m.Groups[1].Value))
                return m.Value;
            var value = Values.Text(FieldPath.First(parent, m.Groups[1].Value));
            if (value is null && keepUnknown)
                return m.Value;
            if (value is null || !PlainId().IsMatch(value))
            {
                ok = false;
                return m.Value;
            }
            return escape ? Uri.EscapeDataString(value) : value;
        });
        return ok ? text : null;
    }
}
