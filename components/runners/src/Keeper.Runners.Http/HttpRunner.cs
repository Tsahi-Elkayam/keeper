using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Http;

/// <summary>
/// http: read a JSON or XML API relative to the integration's endpoint - SCCM AdminService, ServiceNow, vCenter,
/// Veeam, PRTG, Dynatrace, Azure Resource Manager, Check Point. GET, or POST where the integration's type
/// answers a POST as a read (<see cref="IConnection.ReadPosts"/>). Paging: odata (@odata.nextLink or ARM's
/// nextLink), link (Link header), offset (offsetParam/limitParam), cursor (cursorField in the answer ->
/// cursorParam), body-offset (offsetField/limitField in a POST body), body-cursor (cursorField -> cursorBody),
/// or none.
/// </summary>
public sealed class HttpRunner : IRunner
{
    private const int DefaultMaxPages = 200;
    private const int MaxRows = 500_000;

    private static readonly string[] Pagings = ["auto", "odata", "link", "offset", "cursor", "body-offset", "body-cursor", "none"];

    public string Protocol => "http";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (HttpPaths.Problem(query.Text("path")) is { } problem)
            yield return problem;
        var method = query.Text("method") ?? "get";
        if (method is not ("get" or "post"))
            yield return "method must be get or post (post only where the integration type answers it as a read)";
        if (query.Fields["body"] is not (null or JsonObject))
            yield return "body must be a mapping (it is sent as JSON)";
        else if (query.Fields["body"] is not null && method != "post")
            yield return "body needs method: post";
        var paging = query.Text("paging") ?? "auto";
        if (!Pagings.Contains(paging))
            yield return $"paging must be {string.Join(", ", Pagings)}";
        if (paging is "body-offset" or "body-cursor" && method != "post")
            yield return $"paging {paging} needs method: post";
        if (paging is "cursor" or "body-cursor" && query.Text("cursorField") is null)
            yield return $"paging {paging} needs cursorField: where the answer gives the next cursor";
        if (paging == "cursor" && query.Text("cursorParam") is null)
            yield return "paging cursor needs cursorParam: the parameter the next request passes it in";
        if (paging == "body-cursor" && query.Text("cursorBody") is null)
            yield return "paging body-cursor needs cursorBody: where in the body the next request passes it";
        var format = query.Text("format") ?? "json";
        if (format is not ("json" or "xml"))
            yield return "format must be json or xml";
        else if (format == "xml" && string.IsNullOrWhiteSpace(query.Text("items")))
            yield return "format xml needs items: the XPath of the elements that are rows";
        if (query.Text("missing") is not (null or "empty" or "fail"))
            yield return "missing must be empty (a 404 is an answer with no rows) or fail (the default)";
        else if (query.Text("missing") == "empty" && query.Fields["for_each"] is null)
            yield return "missing: empty is for per-object reads (for_each), where an object may lack the child; a list that answers 404 has a wrong path";
        if (query.Fields["capture_headers"] is not (null or JsonArray))
            yield return "capture_headers must be a list of response header names";
        if (query.Text("map") is not (null or "true" or "false"))
            yield return "map must be true or false";
        else if (query.Text("map") == "true" && format == "xml")
            yield return "map works on JSON answers only";
        if (query.Fields["params"] is not (null or JsonObject))
            yield return "params must be a mapping";
        if (query.Fields["headers"] is JsonObject headers && headers.Any(h => h.Key.Contains("auth", StringComparison.OrdinalIgnoreCase) || h.Key.Contains("cookie", StringComparison.OrdinalIgnoreCase)))
            yield return "headers must not carry credentials; the integration adds them";
        // X-HTTP-Method-Override and its kin turn a GET or a read POST into a DELETE or a PATCH on servers that honour them.
        if (query.Fields["headers"] is JsonObject named && named.Any(h => h.Key.Contains("method", StringComparison.OrdinalIgnoreCase) || h.Key.Contains("override", StringComparison.OrdinalIgnoreCase)))
            yield return "headers must not change the request's method (X-HTTP-Method-Override and the like)";
        if (query.Fields["params"] is JsonObject parameters && parameters.Select(p => p.Key).FirstOrDefault(k =>
                k.Equals("_method", StringComparison.OrdinalIgnoreCase) || k.Equals("$method", StringComparison.OrdinalIgnoreCase)
                || k.Contains("method-override", StringComparison.OrdinalIgnoreCase) || k.Equals("x-http-method", StringComparison.OrdinalIgnoreCase)) is { } overriding)
            yield return $"param {overriding} would change the request's method; Keeper only reads";
        foreach (var perObject in PerObject.Validate(query))
            yield return perObject;
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (query.Fields["for_each"] is JsonObject)
            return await PerObject.RunAsync(this, query, context, cancellationToken).ConfigureAwait(false);
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
        var xml = query.Text("format") == "xml";
        var maxPages = query.Int("maxPages") ?? DefaultMaxPages;
        var headers = (query.Fields["headers"] as JsonObject)?.ToDictionary(h => h.Key, h => Values.Text(h.Value) ?? "") ?? [];
        foreach (var (name, value) in extraHeaders ?? new Dictionary<string, string>())
            headers[name] = value;
        var parameters = HttpEngine.Parameters(query.Fields["params"]).Concat(extraParams ?? [])
            .Select(p => KeyValuePair.Create(p.Key, RequestMacros.Expand(p.Value, context)))
            .ToList();
        var path = RequestMacros.Expand(query.Text("path")!, context);

        var method = query.Text("method") == "post" ? HttpMethod.Post : HttpMethod.Get;
        if (method == HttpMethod.Post && !ReadPost.Allow(context.Connection.ReadPosts, path))
            return RunnerResult.Failed($"POST {path.Split('?')[0]} is not a read the {context.Connection.Type} integration type allows; nothing was sent");
        var body = query.Fields["body"] is JsonObject template ? (JsonObject)RequestMacros.ExpandAll(template.DeepClone(), context)! : null;
        if (method == HttpMethod.Post && ReadPost.CommandProblem(context.Connection.ReadCommand, body) is { } refused)
            return RunnerResult.Failed($"{refused}; nothing was sent");
        var readPaths = context.Connection.ReadPaths;

        var offsetParam = query.Text("offsetParam") ?? "sysparm_offset";
        var limitParam = query.Text("limitParam") ?? "sysparm_limit";
        var pageSize = query.Int("pageSize") ?? 1000;
        if (paging == "offset")
            parameters.Add(KeyValuePair.Create(limitParam, pageSize.ToString(CultureInfo.InvariantCulture)));
        if (paging == "body-offset")
        {
            body ??= [];
            ReadPost.Set(body, query.Text("limitField") ?? "limit", pageSize);
            ReadPost.Set(body, query.Text("offsetField") ?? "offset", 0);
        }
        var cursorField = query.Text("cursorField");

        var rows = new List<JsonObject>();
        Uri? next = engine.Build(path, paging == "offset"
            ? parameters.Append(KeyValuePair.Create(offsetParam, "0"))
            : parameters);
        for (var page = 1; next is not null; page++)
        {
            if (page > maxPages)
                return RunnerResult.Partial(rows, $"stopped after {maxPages} pages");
            if (!engine.IsOwn(next))
                return RunnerResult.Partial(rows, $"the next page is on another host ({next.Host}); refused");
            // A next page the server names is checked like the rule's own path: a read POST never follows a link
            // to a path its integration type does not read.
            if (method == HttpMethod.Post && (engine.Relative(next) is not { } relative || !ReadPost.Allow(context.Connection.ReadPosts, relative)))
                return RunnerResult.Partial(rows, $"the next page POST {next.AbsolutePath} is not a read the {context.Connection.Type} integration type allows; refused");
            // A type that reads only some paths (Key Vault: lists and metadata, never a value) is held to them
            // on every page, as the request will actually go: the whole path on the host, built and normalised -
            // an endpoint with a path of its own must not shift what the rule's path means.
            if (readPaths.Count > 0 && !ReadPost.Allow(readPaths, next.AbsolutePath))
            {
                var refusedPath = $"{next.AbsolutePath} is not a path the {context.Connection.Type} integration type reads";
                return page == 1 ? RunnerResult.Failed(refusedPath + "; nothing was sent") : RunnerResult.Partial(rows, refusedPath + "; the next page was refused");
            }
            // Body paging changes the body between pages: what it runs is checked before every one.
            if (method == HttpMethod.Post && page > 1 && ReadPost.CommandProblem(context.Connection.ReadCommand, body) is { } changed)
                return RunnerResult.Partial(rows, $"{changed}; the next page was refused");

            string text;
            IReadOnlyDictionary<string, string> responseHeaders;
            try
            {
                (text, responseHeaders) = await engine.SendTextAsync(method, next, body, headers, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound && query.Text("missing") == "empty")
            {
                // The object has no such child (no manager, no policy): an answer with no rows - on the first page
                // only. A later page that vanishes is a cut-short read.
                return page == 1 ? new RunnerResult([], "ok", RunnerResult.NotFound) : RunnerResult.Partial(rows, $"page {page} answered 404");
            }
            JsonNode? json = null;
            System.Xml.Linq.XDocument? document = null;
            List<JsonObject> pageRows;
            if (xml)
            {
                document = text.Length == 0 ? null : XmlRows.Load(new StringReader(text), HttpEngine.MaxResponseBytes);
                pageRows = document is null ? [] : XmlRows.Select(document, items!);
                pageRows.ForEach(SecretProperties.Mask);
            }
            else
            {
                json = text.Length == 0 ? null : RowValues.Parse(text) ?? throw new HttpRequestException($"{engine.Endpoint.Host} did not answer with JSON.");
                pageRows = query.Text("map") == "true" ? [.. RowValues.EntriesOf(json, items)] : [.. RowValues.ItemsOf(json, items)];
            }
            if (query.Fields["capture_headers"] is JsonArray wanted)
            {
                // Response headers as fields (Strict-Transport-Security, Server): on every row, or one row of their own.
                var captured = new JsonObject();
                foreach (var name in wanted.Select(Values.Text).OfType<string>())
                    captured[name] = responseHeaders.GetValueOrDefault(name);
                if (pageRows.Count == 0 && page == 1)
                    pageRows.Add([]);
                foreach (var row in pageRows)
                    row["_headers"] = captured.DeepClone();
            }
            rows.AddRange(pageRows);
            if (rows.Count > MaxRows)
                return RunnerResult.Partial(rows, $"stopped at {MaxRows} rows");

            string? Cursor() => cursorField is null ? null
                : xml ? (document is null ? null : XmlRows.Value(document, cursorField))
                : Values.Text(FieldPath.First(json, cursorField)) is { Length: > 0 } c ? c : null;
            // A next link the answer names but that cannot be used is a cut-short read, never the last page.
            var malformed = false;
            var named = paging switch
            {
                "link" => HttpEngine.NextLink(responseHeaders.GetValueOrDefault("Link"), out malformed),
                "auto" or "odata" => json is JsonObject linked
                    ? (Values.Text(linked["@odata.nextLink"]) is { } odataLink && !string.IsNullOrWhiteSpace(odataLink) ? odataLink : Values.Text(linked["nextLink"]))
                    : null,
                _ => null,
            };
            if (malformed)
                return RunnerResult.Partial(rows, "the answer's Link header could not be read, so whether more pages follow is unknown");
            if (string.IsNullOrWhiteSpace(named))
                named = null;   // an empty next link is no next link
            if (named is not null && engine.Resolve(named) is null)
                return RunnerResult.Partial(rows, $"the answer's next page link could not be used: {HttpEngine.Truncate(named, 120)}");
            next = paging switch
            {
                "none" => null,
                "link" or "auto" or "odata" => engine.Resolve(named),
                "offset" => pageRows.Count < pageSize ? null : engine.Build(path,
                    parameters.Append(KeyValuePair.Create(offsetParam, (page * pageSize).ToString(CultureInfo.InvariantCulture)))),
                "cursor" => Cursor() is { } cursor ? engine.Build(path, parameters.Append(KeyValuePair.Create(query.Text("cursorParam")!, cursor))) : null,
                // A body page is the same request with the next offset or cursor in its body.
                "body-offset" => pageRows.Count < pageSize ? null : ReadPost.Set(body!, query.Text("offsetField") ?? "offset", page * pageSize, next),
                "body-cursor" => Cursor() is { } cursor ? ReadPost.Set(body ??= [], query.Text("cursorBody")!, cursor, next) : null,
                _ => null,
            };
        }
        return RunnerResult.Ok(rows);
    }
}
