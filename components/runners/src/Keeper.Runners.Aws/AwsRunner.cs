using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Keeper.Rules;

namespace Keeper.Runners.Aws;

/// <summary>
/// aws: one AWS API action, signed here (SigV4, no SDK), in every account the integration reads (through its
/// read-only role) and every region the query names. Rows carry _account and _region. Only reads
/// (<see cref="AwsServices"/>); an account or region that fails makes the result partial, never clean.
/// Fields: service, action, api (query | json | rest-json | rest-xml; known services need none), version,
/// target, path and method (REST), params, items, next ({ from, to }: where the answer gives the next token
/// and where the request passes it), regions (all | home | a list), accounts (all | own), maxPages, billed,
/// for_each (one request per object of a list, in that object's own account and region).
/// </summary>
public sealed class AwsRunner : IRunner
{
    private const int DefaultMaxPages = 100;
    private const int MaxRows = 200_000;
    private const int Parallel = 4;
    private const int DefaultMax = 200;
    private const long MaxResponseChars = 64L * 1024 * 1024;

    // S3 reads Keeper may make besides the bucket list: each bucket setting by its action's own subresource -
    // never an object.
    private static readonly Dictionary<string, string> S3Settings = new(StringComparer.Ordinal)
    {
        ["GetBucketAcl"] = "acl", ["GetBucketPolicy"] = "policy", ["GetBucketPolicyStatus"] = "policyStatus",
        ["GetBucketEncryption"] = "encryption", ["GetBucketVersioning"] = "versioning", ["GetBucketLogging"] = "logging",
        ["GetPublicAccessBlock"] = "publicAccessBlock", ["GetBucketOwnershipControls"] = "ownershipControls",
        ["GetBucketLifecycleConfiguration"] = "lifecycle", ["GetBucketReplication"] = "replication", ["GetBucketTagging"] = "tagging",
        ["GetBucketLocation"] = "location", ["GetBucketWebsite"] = "website", ["GetBucketCors"] = "cors",
        ["GetBucketNotificationConfiguration"] = "notification", ["GetObjectLockConfiguration"] = "object-lock",
    };

    // Fields that carry secrets in AWS answers under names no other API uses: instance user data, Lambda and
    // container environments, build variables.
    private static readonly HashSet<string> AwsSecrets = new(StringComparer.OrdinalIgnoreCase)
    {
        "UserData", "Environment", "environmentVariables", "exportedEnvironmentVariables", "SecretString", "SecretBinary",
        "Plaintext", "PasswordData", "MasterUserPassword", "DbPassword", "AuthToken", "SessionToken", "SecretAccessKey", "KeyMaterial",
        // A VPN connection's configuration for the customer's device: its tunnels' pre-shared keys, as XML.
        "CustomerGatewayConfiguration",
    };

    public string Protocol => "aws";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query) => Validate(query, nested: false);

    private IEnumerable<string> Validate(QuerySpec query, bool nested)
    {
        // Only the services Keeper knows: the table is the boundary - their APIs, and for REST each action's path.
        var serviceId = query.Text("service");
        if (serviceId is null || !AwsServices.Known.TryGetValue(serviceId, out var service))
        {
            yield return $"service must be one Keeper knows: {string.Join(", ", AwsServices.Known.Keys.Order(StringComparer.Ordinal))}";
            yield break;
        }
        if (query.Fields["api"] is not null || query.Fields["version"] is not null || query.Fields["target"] is not null)
            yield return "api, version and target come from Keeper's own table of services, never from a rule";
        var action = query.Text("action");
        if (AwsServices.ActionProblem(action) is { } actionProblem)
            yield return actionProblem;

        var method = query.Text("method") ?? "get";
        if (service.Api.StartsWith("rest-", StringComparison.Ordinal))
        {
            // A REST API names its operation by its path: the action must be one Keeper knows, at its own path.
            if (HttpPaths.Problem(query.Text("path")) is { } pathProblem)
                yield return pathProblem;
            else if (query.Text("path")!.Contains('?', StringComparison.Ordinal))
                yield return "path takes no query: put it in params";
            else if (action is not null)
            {
                var operation = AwsServices.Rest.TryGetValue(service.Id, out var operations) ? operations.GetValueOrDefault(action) : null;
                if (operation is null)
                    yield return $"{service.Id} {action} is not a REST read Keeper knows";
                else if (operation.Method != method || !AwsServices.IsPath(operation, query.Text("path")!))
                    yield return $"{service.Id} {action} is {operation.Method.ToUpperInvariant()} {operation.Path}";
            }
            if (service.Id == "s3" && S3Problem(query) is { } s3)
                yield return s3;
        }
        else if (query.Fields["path"] is not null || query.Fields["method"] is not null)
        {
            yield return $"a {service.Api} API takes no path or method: the action names the call";
        }

        if (query.Fields["params"] is not (null or JsonObject))
            yield return "params must be a mapping";
        else if (query.Fields["params"] is JsonObject given)
        {
            // The call is the action's: no param may name another, or sign itself.
            if (given.Select(p => p.Key).FirstOrDefault(Reserved) is { } reserved)
                yield return $"param {reserved} is the request's own; the action names the call";
            if (service.Api is "query" or "rest-xml" || (service.Api == "rest-json" && method == "get"))
            {
                if (given.Any(p => p.Value is JsonObject or JsonArray))
                    yield return "params of a query or GET are names and plain values (Filter.1.Name: tag:Owner)";
            }
            // A placeholder is filled in only at the top of params: one deeper would be sent as written.
            else if (given.Any(p => p.Value is JsonObject or JsonArray
                                    && System.Text.RegularExpressions.Regex.IsMatch(p.Value.ToJsonString(), @"\{[A-Za-z_][A-Za-z0-9_.]{0,63}\}")))
                yield return "a {placeholder} goes in a top-level param, where it is filled in; deeper it would be sent as written";
        }
        if (service.Api is "query" or "rest-xml" && string.IsNullOrWhiteSpace(query.Text("items")))
            yield return "an XML answer needs items: the XPath of the elements that are rows (//Users/member)";
        if (query.Fields["next"] is not null and not JsonObject)
            yield return "next must be a mapping: { from: where the answer gives the token, to: where the request passes it }";
        else if (query.Fields["next"] is JsonObject next && (Values.Text(next["from"]) is not { Length: > 0 } || Values.Text(next["to"]) is not { Length: > 0 } to
                     || !to.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') || Reserved(to)))
            yield return "next needs from and to (to: a plain parameter name, not the request's own Action or Version)";
        switch (query.Fields["regions"])
        {
            case null:
                break;
            case JsonValue v when Values.Text(v) is "all" or "home":
                break;
            case JsonArray list when list.Count > 0 && list.All(r => AwsServices.IsRegion(Values.Text(r))):
                break;
            default:
                yield return "regions must be all, home, or a list of region ids (eu-central-1)";
                break;
        }
        if (query.Text("accounts") is not (null or "all" or "own"))
            yield return "accounts must be all (every account the integration reads) or own";
        if (AwsServices.Billed.Contains(service.Id) && query.Text("billed") != "daily")
            yield return $"every {service.Id} call is billed: say billed: daily, and give the rule a refresh of a day or more";
        else if (query.Text("billed") is { } billed && billed != "daily")
            yield return "billed must be daily";
        if (query.Int("maxPages") is { } pages && pages is < 1 or > 1000)
            yield return "maxPages must be 1 to 1000";
        if (query.Text("missing") is not (null or "empty"))
            yield return "missing must be empty (a 404 or NoSuch... answer is an object without that setting)";
        else if (query.Text("missing") == "empty" && (query.Fields["for_each"] is null || nested))
            yield return "missing: empty is for per-object reads (for_each): a list that is not there has a wrong action";

        if (query.Fields["for_each"] is JsonObject each)
        {
            if (nested || each["for_each"] is not null)
                yield return "an aws for_each is one level only";
            else if (each["values"] is not null || each["threshold"] is not null)
                yield return "an aws for_each lists its objects with an action, in their own accounts and regions - not values or a threshold";
            else
                foreach (var problem in PerObject.Validate(query, list => Validate(list, nested: true)))
                    yield return problem;
        }
        else if (query.Fields["for_each"] is not null)
        {
            yield return "for_each must be a mapping: the query that lists the objects, plus field";
        }
    }

    private static string? S3Problem(QuerySpec query)
    {
        var path = query.Text("path") ?? "";
        if (query.Text("method") == "post")
            return "s3 is read with GET only";
        var segments = path.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length > 1)
            return "s3 reads the bucket list (/) or one bucket's settings (/{Name}) - never an object";
        var names = (query.Fields["params"] as JsonObject)?.Select(p => p.Key).ToList() ?? [];
        var action = query.Text("action") ?? "";
        if (action == "ListBuckets")
            return names.Count == 0 || names.All(n => n is "max-buckets" or "continuation-token" or "prefix") ? null : "the bucket list takes no params but max-buckets and continuation-token";
        if (!S3Settings.TryGetValue(action, out var setting))
            return null;   // not an s3 read Keeper knows: refused by the action's table
        return names.Count == 1 && names[0] == setting ? null : $"{action} reads one setting: params {{ {setting}: \"\" }}";
    }

    private static AwsService Service(QuerySpec query) => AwsServices.Known[query.Text("service")!];

    /// <summary>A parameter name that is the request's own: Action and Version, and anything X-Amz-.</summary>
    private static bool Reserved(string name) =>
        name.Equals("Action", StringComparison.OrdinalIgnoreCase) || name.Equals("Version", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("X-Amz-", StringComparison.OrdinalIgnoreCase);

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (context.Connection is not IAwsConnection aws)
            return RunnerResult.Failed($"the {context.Connection.Type} integration cannot sign AWS requests");
        using var client = new HttpClient(context.Connection.CreateHttpHandler()) { Timeout = context.Timeout };
        var call = new Caller(aws, client);
        return query.Fields["for_each"] is JsonObject
            ? await PerParent(call, query, cancellationToken).ConfigureAwait(false)
            : await Across(call, query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The action in every account and region the query names; each place is read on its own.</summary>
    private static async Task<RunnerResult> Across(Caller call, QuerySpec query, CancellationToken cancellationToken)
    {
        var service = Service(query)!;
        var accounts = query.Text("accounts") == "own" || call.Aws.AwsAccounts.Count == 0 ? [null] : call.Aws.AwsAccounts.Cast<string?>().ToList();
        var regions = Regions(query, service, call.Aws);
        if (regions.Count == 0)
            return RunnerResult.Failed("the integration names no regions (option regions)");
        var places = accounts.SelectMany(a => regions.Select(r => (Account: a, Region: r))).ToList();

        using var gate = new SemaphoreSlim(Parallel);
        var results = await Task.WhenAll(places.Select(async place =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return (place, Result: await call.ReadAsync(service, query, place.Account, place.Region, cancellationToken).ConfigureAwait(false));
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);
        return Combine(results.Select(r => ($"{r.place.Account ?? "own"}/{r.place.Region}", r.Result)).ToList(), "places");
    }

    /// <summary>
    /// One request per object of a list - each user's attached policies - in that object's own account and
    /// region (its _account and _region). Its fields fill the {placeholders} of the params and path; only plain
    /// ids are put in. The rows carry the object as parent.
    /// </summary>
    private static async Task<RunnerResult> PerParent(Caller call, QuerySpec query, CancellationToken cancellationToken)
    {
        var each = (JsonObject)query.Fields["for_each"]!.DeepClone();
        var field = Values.Text(each["field"])!;
        var max = int.TryParse(Values.Text(each["max"]), NumberStyles.None, CultureInfo.InvariantCulture, out var m) ? m : DefaultMax;
        each.Remove("field");
        each.Remove("max");
        var list = await Across(call, new QuerySpec("aws", each, field, null), cancellationToken).ConfigureAwait(false);
        if (list.State == "failed")
            return RunnerResult.Failed($"the list for for_each failed: {list.Reason}");

        var service = Service(query)!;
        var childFields = (JsonObject)query.Fields.DeepClone();
        childFields.Remove("for_each");
        var parents = list.Rows.Take(max).ToList();
        using var gate = new SemaphoreSlim(Parallel);
        var results = await Task.WhenAll(parents.Select(async parent =>
        {
            var account = Values.Text(parent["_account"]) is { } a && a != "own" ? a : null;
            // A bucket is read in its own region (ListBuckets names it); anything else where it was listed.
            var region = (service.Id == "s3" ? Values.Text(parent["BucketRegion"]) : null)
                         ?? Values.Text(parent["_region"]) ?? call.Aws.AwsRegions.FirstOrDefault() ?? "us-east-1";
            var path = childFields["path"] is null ? null : PerObject.Path(query.Text("path")!, parent);
            var parameters = PerObject.Params(childFields["params"], parent);
            var label = Values.Text(FieldPath.First(parent, field)) ?? "?";
            if ((childFields["path"] is not null && path is null) || parameters is null || !AwsServices.IsRegion(region))
                return (Parent: parent, Label: label, Result: RunnerResult.Failed($"{label}: not a plain id; skipped"));
            var fields = (JsonObject)childFields.DeepClone();
            if (path is not null)
                fields["path"] = path;
            fields["params"] = parameters;
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var child = await call.ReadAsync(service, new QuerySpec("aws", fields, query.Key, query.Name), account, region, cancellationToken).ConfigureAwait(false);
                return (Parent: parent, Label: label, Result: child);
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        var combined = Combine(results.Select(r =>
        {
            foreach (var row in r.Result.Rows)
                row["parent"] = r.Parent.DeepClone();
            return (r.Label, r.Result);
        }).ToList(), "objects");
        var notes = new List<string>();
        // Objects without the setting asked for (buckets without a policy) are an answer: a note, not a cut-short read.
        var absent = results.Count(r => r.Result.State == "ok" && r.Result.Reason == RunnerResult.NotFound);
        if (absent > 0 && combined.State == "ok" && list.Rows.Count <= max && list.State == "ok")
            return new RunnerResult(combined.Rows, "ok", $"{absent} of {parents.Count} objects have none");
        if (list.Rows.Count > max)
            notes.Add($"only the first {max} of {list.Rows.Count} objects (raise for_each.max)");
        if (list.State == "partial")
            notes.Add($"the object list itself was partial: {list.Reason}");
        return notes.Count == 0 ? combined
            : RunnerResult.Partial(combined.Rows, string.Join("; ", notes.Prepend(combined.Reason).OfType<string>()));
    }

    /// <summary>Every place read cleanly: ok. Some failed or were cut short: partial, saying which. All failed: failed.</summary>
    private static RunnerResult Combine(List<(string Label, RunnerResult Result)> results, string what)
    {
        var rows = results.SelectMany(r => r.Result.Rows).ToList();
        var failed = results.Where(r => r.Result.State == "failed").ToList();
        var partial = results.Where(r => r.Result.State == "partial").ToList();
        if (results.Count > 0 && failed.Count == results.Count)
            return RunnerResult.Failed(string.Join("; ", failed.Take(3).Select(f => $"{f.Label}: {f.Result.Reason}")));
        var notes = new List<string>();
        if (failed.Count > 0)
            notes.Add($"{failed.Count} of {results.Count} {what} failed: {string.Join("; ", failed.Take(3).Select(f => $"{f.Label}: {f.Result.Reason}"))}");
        if (partial.Count > 0)
            notes.Add($"{partial.Count} of {results.Count} {what} were read only in part: {string.Join("; ", partial.Take(3).Select(p => $"{p.Label}: {p.Result.Reason}"))}");
        if (rows.Count > MaxRows)
            return RunnerResult.Partial(rows.Take(MaxRows).ToList(), $"stopped at {MaxRows} rows");
        return notes.Count == 0 ? RunnerResult.Ok(rows) : RunnerResult.Partial(rows, string.Join("; ", notes));
    }

    /// <summary>
    /// Whether a field of an answer says more pages follow: any token, marker or continuation (NextToken,
    /// nextToken, NextMarker, Marker, NextPageToken, ContinuationToken, PaginationToken...), LastEvaluated...,
    /// or a truncated flag - unless it only echoes the token this request sent.
    /// </summary>
    private static bool SaysMore(string name, string? value, string? sent)
    {
        if (!IsPagingName(name) || string.IsNullOrEmpty(value) || value == "null")
            return false;
        if (name.Equals("IsTruncated", StringComparison.OrdinalIgnoreCase) || name.Equals("Truncated", StringComparison.OrdinalIgnoreCase))
            return value.Equals("true", StringComparison.OrdinalIgnoreCase);
        return value != sent;
    }

    /// <summary>
    /// A name a page uses for "more": NextToken, NextPageToken, PaginationToken, ContinuationToken, PageToken,
    /// Next...Token, any ...Marker, LastEvaluated..., IsTruncated. Not every token: a LockToken (WAF) or an
    /// ImportToken (KMS) is part of the answer.
    /// </summary>
    private static bool IsPagingName(string name) =>
        name.Equals("IsTruncated", StringComparison.OrdinalIgnoreCase) || name.Equals("Truncated", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("LastEvaluated", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith("Marker", StringComparison.OrdinalIgnoreCase)
        || name.Equals("PaginationToken", StringComparison.OrdinalIgnoreCase) || name.Equals("PageToken", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith("ContinuationToken", StringComparison.OrdinalIgnoreCase)
        || (name.StartsWith("Next", StringComparison.OrdinalIgnoreCase) && name.EndsWith("Token", StringComparison.OrdinalIgnoreCase));

    private static int Depth(System.Xml.Linq.XElement element)
    {
        var depth = 1;
        for (var parent = element.Parent; parent is not null; parent = parent.Parent)
            depth++;
        return depth;
    }

    private static List<string> Regions(QuerySpec query, AwsService service, IAwsConnection aws)
    {
        var home = aws.AwsRegions.FirstOrDefault();
        // The bucket list is the same in every region: read once, at home.
        if (service.Global || (service.Id == "s3" && query.Text("action") == "ListBuckets"))
            return home is null ? [] : [home];
        return query.Fields["regions"] switch
        {
            JsonArray list => [.. list.Select(Values.Text).OfType<string>()],
            JsonValue v when Values.Text(v) == "home" => home is null ? [] : [home],
            _ => [.. aws.AwsRegions],
        };
    }

    /// <summary>An error answer; Missing when it says the thing asked for does not exist (404, NoSuch..., ...NotFound).</summary>
    private sealed class AwsError(string message, bool missing) : HttpRequestException(message)
    {
        public bool Missing { get; } = missing;
    }

    /// <summary>One account and region: the action, page by page, signed for that place.</summary>
    private sealed class Caller(IAwsConnection aws, HttpClient client)
    {
        public IAwsConnection Aws => aws;

        public async Task<RunnerResult> ReadAsync(AwsService service, QuerySpec query, string? account, string region, CancellationToken cancellationToken)
        {
            AwsCredentials credentials;
            try
            {
                credentials = await aws.AwsCredentialsAsync(account, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return RunnerResult.Failed($"no credentials{(account is null ? "" : $" for {account}")}: {Keeper.Common.Redactor.Clean(ex.Message)}");
            }

            var action = query.Text("action")!;
            var (from, to) = Next(query, service);
            var maxPages = query.Int("maxPages") ?? DefaultMaxPages;
            var rows = new List<JsonObject>();
            string? token = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var page = 1; ; page++)
            {
                if (page > maxPages)
                    return RunnerResult.Partial(rows, $"stopped after {maxPages} pages");
                string text;
                try
                {
                    text = await SendAsync(service, query, action, region, credentials, to, token, cancellationToken).ConfigureAwait(false);
                }
                catch (AwsError ex) when (ex.Missing && query.Text("missing") == "empty")
                {
                    // The object has no such setting (a bucket without a policy): an answer with no rows - on the
                    // first page only. A later page that vanishes is a cut-short read.
                    return page == 1 ? new RunnerResult([], "ok", RunnerResult.NotFound) : RunnerResult.Partial(rows, $"page {page}: {ex.Message}");
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
                {
                    return page == 1 ? RunnerResult.Failed(ex.Message) : RunnerResult.Partial(rows, $"page {page}: {ex.Message}");
                }

                List<JsonObject> pageRows;
                string? nextToken;
                bool more;
                try
                {
                    if (service.Id == "s3" && text.TrimStart().StartsWith('{'))
                    {
                        // A bucket policy is the policy document itself, not XML: one row holding it.
                        pageRows = [new JsonObject { ["Policy"] = RowValues.Parse(text) ?? throw new InvalidOperationException("s3 answered a policy that is not JSON") }];
                        nextToken = null;
                        more = false;
                    }
                    else if (service.Api is "query" or "rest-xml")
                    {
                        var document = text.Length == 0 ? null : XmlRows.Load(new StringReader(text), MaxResponseChars);
                        pageRows = document is null ? [] : XmlRows.Select(document, query.Text("items")!);
                        nextToken = document is null || from is null ? null : XmlRows.Value(document, from);
                        // The answer's own fields, near its top (Response > Result > NextToken): not the items'.
                        more = document?.Root is { } root && root.DescendantsAndSelf()
                            .Where(e => !e.HasElements && Depth(e) <= 3)
                            .Any(e => SaysMore(e.Name.LocalName, e.Value, token));
                    }
                    else
                    {
                        var json = text.Length == 0 ? null : RowValues.Parse(text) ?? throw new InvalidOperationException($"{service.Id} did not answer with JSON");
                        pageRows = [.. RowValues.ItemsOf(json, query.Text("items"))];
                        nextToken = from is null ? null : Values.Text(FieldPath.First(json, from));
                        more = json is JsonObject o && o.Any(p => IsPagingName(p.Key) && p.Value is JsonValue or JsonObject && SaysMore(p.Key, Values.Text(p.Value), token));
                    }
                }
                catch (Exception ex) when (ex is System.Xml.XmlException or InvalidOperationException)
                {
                    return page == 1 ? RunnerResult.Failed($"{service.Id} answered what could not be read: {ex.Message}")
                        : RunnerResult.Partial(rows, $"page {page} could not be read: {ex.Message}");
                }
                foreach (var row in pageRows)
                {
                    Mask(row);
                    row["_account"] = account ?? "own";
                    row["_region"] = region;
                }
                rows.AddRange(pageRows);
                if (rows.Count > MaxRows)
                    return RunnerResult.Partial(rows, $"stopped at {MaxRows} rows");
                // A page that says more follow, without a token where the rule reads it (no next, or the wrong
                // name: EC2 writes nextToken), is a cut-short read - never the last page.
                if (string.IsNullOrEmpty(nextToken))
                    return more
                        ? RunnerResult.Partial(rows, from is null
                            ? "the answer has more pages, and the rule names no next to follow them"
                            : $"the answer says more pages follow, but gives no token at {from}")
                        : RunnerResult.Ok(rows);
                if (!seen.Add(nextToken))
                    return RunnerResult.Partial(rows, "the answer gave the same next token twice");
                token = nextToken;
            }
        }

        private async Task<string> SendAsync(AwsService service, QuerySpec query, string action, string region, AwsCredentials credentials,
            string? tokenParam, string? token, CancellationToken cancellationToken)
        {
            var host = AwsServices.Host(service, region);
            if (!AwsServices.IsRegion(region) || !host.EndsWith(".amazonaws.com", StringComparison.Ordinal))
                throw new HttpRequestException($"{host} is not an AWS host");
            // A REST path filled in from an answer is held to its action's method and path again, as it will be sent.
            if (service.Api.StartsWith("rest-", StringComparison.Ordinal)
                && !(AwsServices.Rest.TryGetValue(service.Id, out var operations) && operations.TryGetValue(action, out var operation)
                     && operation.Method == (query.Text("method") ?? "get") && AwsServices.IsPath(operation, query.Text("path") ?? "")))
                throw new HttpRequestException($"{service.Id} {action}: {query.Text("method") ?? "get"} {query.Text("path")} is not its own; nothing was sent");
            var parameters = (query.Fields["params"] as JsonObject)?.ToDictionary(p => p.Key, p => p.Value) ?? [];
            if (token is not null)
                parameters[tokenParam!] = token;

            for (var attempt = 1; ; attempt++)
            {
                using var request = Build(service, query, action, host, parameters, out var body);
                // Signed at the moment it is sent: AWS refuses a signature more than five minutes off.
                SigV4.Sign(request, body, credentials, AwsServices.SigningRegion(service, region), service.Signing, DateTimeOffset.UtcNow,
                    hashHeader: service.Id == "s3");
                using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
                var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                    return text;
                var (code, message) = ErrorOf(text);
                // REST APIs (Lambda, EKS, GuardDuty) name the error in a header: ResourceNotFoundException:http://...
                if (response.Headers.TryGetValues("x-amzn-ErrorType", out var errorType) && errorType.FirstOrDefault() is { Length: > 0 } typed)
                    code = typed.Split(':')[0].Trim();
                var throttled = (int)response.StatusCode is 429 or 503 || code is "Throttling" or "ThrottlingException" or "RequestLimitExceeded" or "TooManyRequestsException";
                if (throttled && attempt < 5)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, 2 * attempt * attempt)), cancellationToken).ConfigureAwait(false);
                    continue;
                }
                if ((int)response.StatusCode is >= 300 and < 400)
                    throw new HttpRequestException($"{host} answered {(int)response.StatusCode} (a redirect, not followed): " +
                        (response.Headers.TryGetValues("x-amz-bucket-region", out var bucketRegion)
                            ? $"the bucket is in {bucketRegion.FirstOrDefault()}, and ListBuckets did not say so (BucketRegion)"
                            : "the bucket or service is in another region"));
                // Missing only when the answer says what is missing (NoSuchBucketPolicy, ...NotFound): a bare 404 is
                // as likely a wrong path, and a wrong path must never read as "this object has none".
                throw new AwsError($"{host} answered {(int)response.StatusCode} {code}: {Keeper.Common.Redactor.Clean(Truncate(message, 300))}",
                    code.StartsWith("NoSuch", StringComparison.Ordinal) || code.EndsWith("NotFound", StringComparison.Ordinal)
                    || code.EndsWith("NotFoundError", StringComparison.Ordinal) || code.EndsWith("NotFoundException", StringComparison.Ordinal));
            }
        }

        private static HttpRequestMessage Build(AwsService service, QuerySpec query, string action, string host,
            Dictionary<string, JsonNode?> parameters, out byte[] body)
        {
            switch (service.Api)
            {
                case "query":
                {
                    var form = new List<string> { $"Action={SigV4.Encode(action)}", $"Version={SigV4.Encode(service.Version!)}" };
                    form.AddRange(parameters.Select(p => $"{SigV4.Encode(p.Key)}={SigV4.Encode(Values.Text(p.Value) ?? "")}"));
                    body = Encoding.UTF8.GetBytes(string.Join("&", form));
                    var request = new HttpRequestMessage(HttpMethod.Post, $"https://{host}/") { Content = new ByteArrayContent(body) };
                    request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded; charset=utf-8");
                    return request;
                }
                case "json":
                {
                    var json = new JsonObject(parameters.Select(p => KeyValuePair.Create(p.Key, p.Value?.DeepClone())));
                    body = Encoding.UTF8.GetBytes(json.ToJsonString());
                    var request = new HttpRequestMessage(HttpMethod.Post, $"https://{host}/") { Content = new ByteArrayContent(body) };
                    request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue($"application/x-amz-json-{service.JsonVersion}");
                    request.Headers.TryAddWithoutValidation("X-Amz-Target", $"{service.Target}.{action}");
                    return request;
                }
                default:
                {
                    var path = query.Text("path")!;
                    if (query.Text("method") == "post")
                    {
                        var json = new JsonObject(parameters.Select(p => KeyValuePair.Create(p.Key, p.Value?.DeepClone())));
                        body = Encoding.UTF8.GetBytes(json.ToJsonString());
                        var post = new HttpRequestMessage(HttpMethod.Post, $"https://{host}{path}") { Content = new ByteArrayContent(body) };
                        post.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                        return post;
                    }
                    body = [];
                    var queryString = string.Join("&", parameters.Select(p =>
                        Values.Text(p.Value) is { Length: > 0 } value ? $"{SigV4.Encode(p.Key)}={SigV4.Encode(value)}" : SigV4.Encode(p.Key)));
                    return new HttpRequestMessage(HttpMethod.Get, $"https://{host}{path}{(queryString.Length > 0 ? "?" + queryString : "")}");
                }
            }
        }

        /// <summary>Where the answer gives the next token and where the request passes it - the rule's, or the API's usual.</summary>
        private static (string? From, string? To) Next(QuerySpec query, AwsService service)
        {
            if (query.Fields["next"] is JsonObject next)
                return (Values.Text(next["from"]), Values.Text(next["to"]));
            // Each query API names its token its own way.
            return (service.Api, service.Id) switch
            {
                ("query", "iam" or "rds" or "redshift" or "elasticache") => ("//Marker", "Marker"),
                ("query", "ec2") => ("//nextToken", "NextToken"),
                ("query", "elasticloadbalancing") => ("//NextMarker", "Marker"),
                ("query", _) => ("//NextToken", "NextToken"),
                ("json", _) => ("NextToken", "NextToken"),
                _ => (null, null),
            };
        }

        private static (string Code, string Message) ErrorOf(string text)
        {
            if (text.TrimStart().StartsWith('<'))
            {
                try
                {
                    var document = XmlRows.Load(new StringReader(text), 1_000_000);
                    return (XmlRows.Value(document, "//Code") ?? "Error", XmlRows.Value(document, "//Message") ?? "");
                }
                catch (System.Xml.XmlException)
                {
                    return ("Error", text);
                }
            }
            if (RowValues.Parse(text) is JsonObject json)
            {
                var type = Values.Text(json["__type"]) ?? Values.Text(json["code"]) ?? Values.Text(json["Code"]) ?? "Error";
                return (type.Contains('#', StringComparison.Ordinal) ? type[(type.LastIndexOf('#') + 1)..] : type,
                    Values.Text(json["message"]) ?? Values.Text(json["Message"]) ?? "");
            }
            return ("Error", text);
        }

        private static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "...";
    }

    /// <summary>The runners' secret names, and AWS's own: user data, environments, build variables become "set".</summary>
    private static void Mask(JsonObject row)
    {
        SecretProperties.Mask(row);
        MaskAws(row);
    }

    private static void MaskAws(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).ToList())
                {
                    if (AwsSecrets.Contains(name) && o[name] is { } value && Values.Text(value) is { Length: > 0 })
                        o[name] = "set";
                    else if (Embedded(o[name], always: Events.Contains(name)) is { } parsed)
                        o[name] = parsed;
                    else
                        MaskAws(o[name]);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (Embedded(a[i], always: false) is { } parsed)
                        a[i] = parsed;
                    else
                        MaskAws(a[i]);
                }
                break;
        }
    }

    /// <summary>
    /// A string that is itself JSON - a CloudTrail event, a Config item's configuration - as the object it holds,
    /// masked like any other: an AssumeRole event's session token, a function's environment. Null otherwise.
    /// </summary>
    // Fields that are records in their own right, read as objects always so every row has one shape: a CloudTrail
    // event, a Config item's configuration.
    private static readonly HashSet<string> Events = new(StringComparer.Ordinal) { "CloudTrailEvent", "configuration", "supplementaryConfiguration" };

    private static JsonNode? Embedded(JsonNode? node, bool always)
    {
        if (node is not JsonValue value || !value.TryGetValue<string>(out var raw))
            return null;
        var text = raw.Trim();
        if (text.Length < 2 || !((text[0] == '{' && text[^1] == '}') || (text[0] == '[' && text[^1] == ']')))
            return null;
        var parsed = RowValues.Parse(text);
        if (parsed is not (JsonObject or JsonArray))
            return null;
        var before = parsed.ToJsonString();
        SecretProperties.Mask(parsed);
        MaskAws(parsed);
        // Kept as written unless something in it was a secret: a policy document stays the text rules match on.
        return always || parsed.ToJsonString() != before ? parsed : null;
    }
}
