using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;

namespace Keeper.Runners;

/// <summary>
/// Dates a request can name relative to the scan: {NOW}, {TODAY}, {DAYS_AGO:n}, {DAYS_AHEAD:n} - so a Graph
/// $filter can ask for "the provisioning events of the last 7 days" without a date in the rule file.
/// </summary>
public static partial class RequestMacros
{
    [GeneratedRegex(@"\{(NOW|TODAY|DAYS_AGO:(\d{1,4})|DAYS_AHEAD:(\d{1,4}))\}", RegexOptions.CultureInvariant)]
    private static partial Regex Macro();

    public static string Expand(string text, DateTimeOffset now) =>
        Macro().Replace(text, m => m.Groups[1].Value switch
        {
            "NOW" => Iso(now),
            "TODAY" => now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            _ when m.Groups[2].Success => Iso(now.AddDays(-int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture))),
            _ => Iso(now.AddDays(int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture))),
        });

    public static bool IsMacro(string name) => Macro().IsMatch("{" + name + "}");

    private static string Iso(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}

/// <summary>
/// for_each: one request per object of another list - /servicePrincipals/{id}/synchronization/jobs for every
/// service principal the for_each query returns. The list is fetched first through the same runner and
/// integration; each object's fields fill the {placeholders} of the path, and every row it returns carries
/// that object as "parent". Capped (max, default 200), and an id that is not a plain id is never put in a path.
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
        if (Values.Text(each["field"]) is not { Length: > 0 } field)
            yield return "for_each.field is required: the field of each object that goes into the path";
        else if (!(query.Text("path") ?? "").Contains("{" + field + "}", StringComparison.Ordinal))
            yield return $"the path must use {{{field}}} so each object gets its own request";
        if (HttpPaths.Problem(Values.Text(each["path"])) is { } problem)
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

        var list = await runner.RunAsync(new QuerySpec(query.Protocol, each, field, null), context, cancellationToken).ConfigureAwait(false);
        if (list.State == "failed")
            return RunnerResult.Failed($"the list for for_each failed: {list.Reason}");

        var parents = list.Rows.Take(max).ToList();
        var template = query.Text("path")!;
        var childFields = (JsonObject)query.Fields.DeepClone();
        childFields.Remove("for_each");

        using var gate = new SemaphoreSlim(Parallel);
        var results = await Task.WhenAll(parents.Select(async parent =>
        {
            if (Path(template, parent) is not { } path)
                return (Parent: parent, Result: RunnerResult.Failed($"{Values.Text(FieldPath.First(parent, field)) ?? "?"}: not a plain id; skipped"));
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var fields = (JsonObject)childFields.DeepClone();
                fields["path"] = path;
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
        var notes = new List<string>();
        if (list.Rows.Count > max)
            notes.Add($"only the first {max} of {list.Rows.Count} objects (raise for_each.max)");
        if (failed.Count > 0)
            notes.Add($"{failed.Count} of {parents.Count} objects failed: {string.Join("; ", failed.Take(3).Select(f => f.Result.Reason))}");
        if (list.State == "partial")
            notes.Add($"the object list itself was partial: {list.Reason}");

        if (parents.Count > 0 && failed.Count == parents.Count)
            return RunnerResult.Failed(string.Join("; ", notes));
        return notes.Count > 0 ? RunnerResult.Partial(rows, string.Join("; ", notes)) : RunnerResult.Ok(rows);
    }

    /// <summary>The path with each {field} replaced by the object's value - only plain ids, escaped; date macros are left for the runner.</summary>
    public static string? Path(string template, JsonObject parent)
    {
        var ok = true;
        var path = Placeholder().Replace(template, m =>
        {
            if (RequestMacros.IsMacro(m.Groups[1].Value))
                return m.Value;
            var value = Values.Text(FieldPath.First(parent, m.Groups[1].Value));
            if (value is null || !PlainId().IsMatch(value))
            {
                ok = false;
                return m.Value;
            }
            return Uri.EscapeDataString(value);
        });
        return ok ? path : null;
    }
}
