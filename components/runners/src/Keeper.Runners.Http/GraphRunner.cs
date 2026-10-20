using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Http;

/// <summary>
/// graph: Microsoft Graph GET with OData paging. Builds $select, $filter, $expand, $top and $search from
/// the rule; consistency: eventual adds the ConsistencyLevel header and $count. The bearer token comes
/// from the integration (Entra sign-in or a certificate), never from the rule.
/// </summary>
public sealed class GraphRunner : IRunner
{
    public const string DefaultEndpoint = "https://graph.microsoft.com";

    public string Protocol => "graph";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (HttpPaths.Problem(query.Text("path")) is { } problem)
            yield return problem;
        if (query.Text("version") is { } version && version is not ("v1.0" or "beta"))
            yield return "version must be v1.0 or beta";
        if (query.Text("consistency") is { } consistency && consistency != "eventual")
            yield return "consistency can only be eventual";
        if (query.Text("search") is not null && query.Text("consistency") is null)
            yield return "search needs consistency: eventual";
        foreach (var perObject in PerObject.Validate(query))
            yield return perObject;
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (query.Fields["for_each"] is JsonObject)
            return await PerObject.RunAsync(this, query, context, cancellationToken).ConfigureAwait(false);
        try
        {
            using var engine = HttpEngine.Open(context, DefaultEndpoint);
            var parameters = new List<KeyValuePair<string, string>>();
            void Add(string name, string? value)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    parameters.Add(KeyValuePair.Create(name, value));
            }

            var select = query.List("select");
            Add("$select", select.Count > 0 ? string.Join(",", select) : null);
            Add("$filter", query.Text("filter") is { } filter ? RequestMacros.Expand(filter, context.Now) : null);
            Add("$expand", query.Text("expand"));
            // Only when the rule asks: some Graph endpoints refuse $top outright.
            Add("$top", query.Int("top")?.ToString(CultureInfo.InvariantCulture));
            Add("$search", query.Text("search"));
            var headers = new Dictionary<string, string>();
            if (query.Text("consistency") == "eventual")
            {
                headers["ConsistencyLevel"] = "eventual";
                Add("$count", "true");
            }

            var versioned = new QuerySpec("http",
                new JsonObject
                {
                    ["path"] = "/" + (query.Text("version") ?? "v1.0") + query.Text("path"),
                    ["paging"] = "odata",
                    ["items"] = query.Text("items") ?? "value",
                    ["maxPages"] = query.Text("maxPages"),
                },
                query.Key, query.Name);
            return await HttpRunner.Fetch(engine, versioned, context, cancellationToken, headers, parameters).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UnauthorizedAccessException or InvalidOperationException)
        {
            return RunnerResult.Failed(HttpEngine.Reason(ex));
        }
    }
}
