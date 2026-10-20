using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Http;

/// <summary>
/// http: GET a JSON API relative to the integration's endpoint - SCCM AdminService, ServiceNow, vCenter,
/// Veeam, PRTG, Dynatrace, Azure Resource Manager. Paging: odata (@odata.nextLink), link (Link header),
/// offset (offsetParam/limitParam, e.g. ServiceNow's sysparm_offset/sysparm_limit), or none.
/// </summary>
public sealed class HttpRunner : IRunner
{
    private const int DefaultMaxPages = 200;
    private const int MaxRows = 500_000;

    public string Protocol => "http";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (HttpPaths.Problem(query.Text("path")) is { } problem)
            yield return problem;
        if (query.Text("paging") is { } paging && paging is not ("auto" or "odata" or "link" or "offset" or "none"))
            yield return "paging must be auto, odata, link, offset or none";
        if (query.Fields["params"] is not (null or JsonObject))
            yield return "params must be a mapping";
        if (query.Fields["headers"] is JsonObject headers && headers.Any(h => h.Key.Contains("auth", StringComparison.OrdinalIgnoreCase) || h.Key.Contains("cookie", StringComparison.OrdinalIgnoreCase)))
            yield return "headers must not carry credentials; the integration adds them";
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var engine = HttpEngine.Open(context);
            return await Fetch(engine, query, context, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UnauthorizedAccessException or InvalidOperationException)
        {
            return RunnerResult.Failed(HttpEngine.Reason(ex));
        }
    }

    internal static async Task<RunnerResult> Fetch(HttpEngine engine, QuerySpec query, RunnerContext context, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? extraHeaders = null, IEnumerable<KeyValuePair<string, string>>? extraParams = null)
    {
        var paging = query.Text("paging") ?? "auto";
        var items = query.Text("items");
        var maxPages = query.Int("maxPages") ?? DefaultMaxPages;
        var headers = (query.Fields["headers"] as JsonObject)?.ToDictionary(h => h.Key, h => Values.Text(h.Value) ?? "") ?? [];
        foreach (var (name, value) in extraHeaders ?? new Dictionary<string, string>())
            headers[name] = value;
        var parameters = HttpEngine.Parameters(query.Fields["params"]).Concat(extraParams ?? []).ToList();

        var offsetParam = query.Text("offsetParam") ?? "sysparm_offset";
        var limitParam = query.Text("limitParam") ?? "sysparm_limit";
        var pageSize = query.Int("pageSize") ?? 1000;
        if (paging == "offset")
            parameters.Add(KeyValuePair.Create(limitParam, pageSize.ToString(CultureInfo.InvariantCulture)));

        var rows = new List<JsonObject>();
        Uri? next = engine.Build(query.Text("path")!, paging == "offset"
            ? parameters.Append(KeyValuePair.Create(offsetParam, "0"))
            : parameters);
        for (var page = 1; next is not null; page++)
        {
            if (page > maxPages)
                return RunnerResult.Partial(rows, $"stopped after {maxPages} pages");
            if (!engine.IsOwn(next))
                return RunnerResult.Partial(rows, $"the next page is on another host ({next.Host}); refused");

            var (body, responseHeaders) = await engine.GetAsync(next, headers, cancellationToken).ConfigureAwait(false);
            var pageRows = RowValues.ItemsOf(body, items);
            rows.AddRange(pageRows);
            if (rows.Count > MaxRows)
                return RunnerResult.Partial(rows, $"stopped at {MaxRows} rows");

            next = paging switch
            {
                "none" => null,
                "link" => HttpEngine.NextLink(responseHeaders),
                "offset" => pageRows.Count < pageSize ? null : engine.Build(query.Text("path")!,
                    parameters.Append(KeyValuePair.Create(offsetParam, (page * pageSize).ToString(CultureInfo.InvariantCulture)))),
                _ => body is JsonObject o && Values.Text(o["@odata.nextLink"]) is { } link && Uri.TryCreate(link, UriKind.Absolute, out var u) ? u : null,
            };
        }
        return RunnerResult.Ok(rows);
    }
}
