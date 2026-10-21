using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;

namespace Keeper.Runners.Http;

/// <summary>
/// graphql: a GraphQL query (Wiz, monday, Rubrik). Mutations and subscriptions are refused before
/// anything is sent. Cursor paging: paging.cursor and paging.hasNext name fields in the response,
/// paging.variable the query variable that takes the cursor.
/// </summary>
public sealed partial class GraphQlRunner : IRunner
{
    private const int DefaultMaxPages = 100;

    public string Protocol => "graphql";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (Problem(query.Text("document")) is { } documentProblem)
            yield return documentProblem;
        if (query.Text("path") is { } path && HttpPaths.Problem(path) is { } pathProblem)
            yield return pathProblem;
        if (query.Fields["paging"] is JsonObject paging &&
            (Values.Text(paging["cursor"]) is null || Values.Text(paging["hasNext"]) is null || Values.Text(paging["variable"]) is null))
            yield return "paging needs cursor, hasNext and variable";
    }

    /// <summary>Why a document is not a plain query, or null.</summary>
    public static string? Problem(string? document)
    {
        if (string.IsNullOrWhiteSpace(document))
            return "document is required";
        var code = Comments().Replace(StringsPattern().Replace(document, "\"\""), "");
        if (Writes().IsMatch(code))
            return "only queries are allowed - mutations and subscriptions are refused";
        var trimmed = code.TrimStart();
        if (!(trimmed.StartsWith('{') || trimmed.StartsWith("query", StringComparison.Ordinal) || trimmed.StartsWith("fragment", StringComparison.Ordinal)))
            return "the document must start with a query";
        return null;
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (Problem(query.Text("document")) is { } problem)
            return RunnerResult.Failed(problem);

        try
        {
            using var engine = HttpEngine.Open(context);
            var uri = engine.Build(query.Text("path") ?? "/graphql");
            // Dates in the document and the variables ({DAYS_AGO:30}); a macro only ever becomes a date, never syntax.
            var document = RequestMacros.Expand(query.Text("document")!, context);
            var variables = query.Fields["variables"] is JsonObject v ? (JsonObject)RequestMacros.ExpandAll(v.DeepClone(), context)! : new JsonObject();
            var paging = query.Fields["paging"] as JsonObject;
            var maxPages = query.Int("maxPages") ?? DefaultMaxPages;
            var rows = new List<JsonObject>();

            for (var page = 1; ; page++)
            {
                var (body, _) = await engine.PostJsonAsync(uri, new JsonObject
                {
                    ["query"] = document,
                    ["variables"] = (JsonObject)JsonNode.Parse(variables.ToJsonString())!,
                }, cancellationToken).ConfigureAwait(false);

                if (body?["errors"] is JsonArray { Count: > 0 } errors)
                    return rows.Count == 0
                        ? RunnerResult.Failed($"GraphQL errors: {HttpEngine.Truncate(errors.ToJsonString(), 300)}")
                        : RunnerResult.Partial(rows, $"GraphQL errors on page {page}");

                rows.AddRange(RowValues.ItemsOf(body, query.Text("items")));
                if (paging is null)
                    break;
                var hasNext = Values.Text(FieldPath.First(body, Values.Text(paging["hasNext"])!));
                var cursor = Values.Text(FieldPath.First(body, Values.Text(paging["cursor"])!));
                if (hasNext != "true" || cursor is null)
                    break;
                if (page >= maxPages)
                    return RunnerResult.Partial(rows, $"stopped after {maxPages} pages");
                variables[Values.Text(paging["variable"])!] = cursor;
            }
            return RunnerResult.Ok(rows);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UnauthorizedAccessException or InvalidOperationException)
        {
            return RunnerResult.Failed(HttpEngine.Reason(ex));
        }
    }

    [GeneratedRegex("\"(?:[^\"\\\\]|\\\\.)*\"", RegexOptions.CultureInvariant)]
    private static partial Regex StringsPattern();

    [GeneratedRegex("#[^\\n]*", RegexOptions.CultureInvariant)]
    private static partial Regex Comments();

    [GeneratedRegex(@"\b(mutation|subscription)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Writes();
}
