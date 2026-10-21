using System.Net;
using System.Text.Json.Nodes;
using Keeper.Runners.Http;

namespace Keeper.Runners.Tests;

public sealed class HttpRunnerTests
{
    private static async Task<(RunnerResult Result, StubHandler Stub)> Run(IRunner runner, string endpoint,
        Func<HttpRequestMessage, HttpResponseMessage> respond, JsonObject? options, params (string, JsonNode?)[] fields)
    {
        var stub = new StubHandler(respond);
        var result = await runner.RunAsync(Context.Query(runner.Protocol, "id", fields), Context.For(new FakeConnection(endpoint, stub, options)), CancellationToken.None);
        return (result, stub);
    }

    [Fact]
    public async Task Odata_pages_are_followed_and_the_endpoint_path_kept()
    {
        var (result, stub) = await Run(new HttpRunner(), "https://cm.example.org/AdminService", request =>
            request.RequestUri!.Query.Contains("page=2", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "value": [ { "id": "b" } ] }""")
                : StubHandler.Json("""{ "value": [ { "id": "a" } ], "@odata.nextLink": "https://cm.example.org/AdminService/wmi/SMS_R_System?page=2" }"""),
            null, ("path", "/wmi/SMS_R_System"));

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "a", "b" }, result.Rows.Select(r => r["id"]!.ToString()));
        Assert.Equal("/AdminService/wmi/SMS_R_System", stub.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("Bearer", stub.Requests[0].Headers.Authorization!.Scheme);
    }

    /// <summary>Runs an http query against a stub, recording each request's method, path and query, and body.</summary>
    private static async Task<(RunnerResult Result, List<(string Method, string PathAndQuery, string? Body)> Sent)> RunPosting(
        string endpoint, IReadOnlyList<string> readPosts, Func<string, JsonNode?, HttpResponseMessage> respond, params (string, JsonNode?)[] fields)
    {
        var sent = new List<(string, string, string?)>();
        var stub = new StubHandler(request =>
        {
            var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
            sent.Add((request.Method.Method, request.RequestUri!.PathAndQuery, body));
            return respond(request.RequestUri!.PathAndQuery, body is null ? null : JsonNode.Parse(body));
        });
        var result = await new HttpRunner().RunAsync(Context.Query("http", "uid", fields),
            Context.For(new FakeConnection(endpoint, stub, null, readPosts)), CancellationToken.None);
        return (result, sent);
    }

    [Theory]
    [InlineData("/web_api/set-host")]          // a write
    [InlineData("/web_api/show-hosts/../x")]
    [InlineData("/web_api/publish")]
    public async Task A_post_is_refused_before_anything_is_sent_unless_the_integration_type_reads_that_path(string path)
    {
        var (result, sent) = await RunPosting("https://mgmt.example.org", ["/web_api/show-*"], (_, _) => StubHandler.Json("{}"),
            ("path", path), ("method", "post"), ("body", new JsonObject()));

        Assert.Equal("failed", result.State);
        Assert.Empty(sent);
    }

    [Fact]
    public async Task A_read_post_pages_by_the_offset_in_its_body()
    {
        // Check Point: show-hosts with offset/limit in the body, the answer's objects as rows.
        var (result, sent) = await RunPosting("https://mgmt.example.org", ["/web_api/show-*"], (_, body) =>
            (int)body!["offset"]! == 0
                ? StubHandler.Json("""{ "objects": [ { "uid": "h1" }, { "uid": "h2" } ], "from": 1, "to": 2, "total": 3 }""")
                : StubHandler.Json("""{ "objects": [ { "uid": "h3" } ], "from": 3, "to": 3, "total": 3 }"""),
            ("path", "/web_api/show-hosts"), ("method", "post"), ("body", new JsonObject { ["details-level"] = "standard" }),
            ("items", "objects"), ("paging", "body-offset"), ("pageSize", "2"));

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "h1", "h2", "h3" }, result.Rows.Select(r => r["uid"]!.ToString()));
        Assert.All(sent, s => Assert.Equal("POST", s.Method));
        Assert.Equal(new[] { 0, 2 }, sent.Select(s => (int)JsonNode.Parse(s.Body!)!["offset"]!));
        Assert.All(sent, s => Assert.Equal("standard", JsonNode.Parse(s.Body!)!["details-level"]!.ToString()));
    }

    [Fact]
    public async Task A_read_post_pages_by_the_cursor_the_answer_gives_back_into_the_body()
    {
        // Azure Resource Graph: data rows, and $skipToken back into options.$skipToken.
        var (result, sent) = await RunPosting("https://management.azure.com", ["/providers/Microsoft.ResourceGraph/resources"], (_, body) =>
            body!["options"]?["$skipToken"] is null
                ? StubHandler.Json("""{ "data": [ { "uid": "vm1" } ], "$skipToken": "t2" }""")
                : StubHandler.Json("""{ "data": [ { "uid": "vm2" } ] }"""),
            ("path", "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"), ("method", "post"),
            ("body", new JsonObject { ["query"] = "Resources | where type =~ 'microsoft.compute/virtualmachines'" }),
            ("items", "data"), ("paging", "body-cursor"), ("cursorField", "$skipToken"), ("cursorBody", "options.$skipToken"));

        Assert.Equal(new[] { "vm1", "vm2" }, result.Rows.Select(r => r["uid"]!.ToString()));
        Assert.Equal("t2", JsonNode.Parse(sent[1].Body!)!["options"]!["$skipToken"]!.ToString());
    }

    [Fact]
    public async Task An_xml_answer_with_a_default_namespace_is_rows_and_its_cursor_is_followed()
    {
        var (result, sent) = await RunPosting("https://ec2.example.org", [], (pathAndQuery, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(pathAndQuery.Contains("NextToken", StringComparison.Ordinal)
                    ? """<DescribeResponse xmlns="https://example.org/doc/"><set><item><uid>i-2</uid></item></set></DescribeResponse>"""
                    : """<DescribeResponse xmlns="https://example.org/doc/"><set><item><uid>i-1</uid><password>p-not-real</password></item></set><nextToken>n2</nextToken></DescribeResponse>""",
                    System.Text.Encoding.UTF8, "text/xml"),
            },
            ("path", "/?Action=Describe"), ("format", "xml"), ("items", "//set/item"),
            ("paging", "cursor"), ("cursorField", "//nextToken"), ("cursorParam", "NextToken"));

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "i-1", "i-2" }, result.Rows.Select(r => r["uid"]!.ToString()));
        Assert.Equal("set", result.Rows[0]["password"]!.ToString());   // masked like any other answer
        Assert.Contains("NextToken=n2", sent[1].PathAndQuery, StringComparison.Ordinal);
        Assert.All(sent, s => Assert.Equal("GET", s.Method));
    }

    [Fact]
    public async Task Arm_next_links_in_the_body_are_followed()
    {
        var (result, _) = await RunPosting("https://management.azure.com", [], (pathAndQuery, _) =>
            pathAndQuery.Contains("skiptoken", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "value": [ { "uid": "b" } ] }""")
                : StubHandler.Json("""{ "value": [ { "uid": "a" } ], "nextLink": "https://management.azure.com/subscriptions?api-version=2022-12-01&skiptoken=x" }"""),
            ("path", "/subscriptions?api-version=2022-12-01"));

        Assert.Equal(new[] { "a", "b" }, result.Rows.Select(r => r["uid"]!.ToString()));
    }

    [Fact]
    public async Task Dates_in_a_post_body_are_expanded()
    {
        var (_, sent) = await RunPosting("https://api.example.org", ["/search"], (_, _) => StubHandler.Json("[]"),
            ("path", "/search"), ("method", "post"), ("body", new JsonObject { ["since"] = "{DAYS_AGO:7}", ["nested"] = new JsonObject { ["at"] = new JsonArray("{TODAY}") } }));

        var body = JsonNode.Parse(sent[0].Body!)!;
        Assert.Equal("2026-10-13T00:00:00Z", body["since"]!.ToString());
        Assert.Equal("2026-10-20", body["nested"]!["at"]![0]!.ToString());
    }

    [Fact]
    public async Task A_missing_child_is_an_answer_with_no_rows_but_every_object_missing_it_is_not()
    {
        HttpResponseMessage Manager(string pathAndQuery, JsonNode? _) => pathAndQuery.StartsWith("/users/u1/", StringComparison.Ordinal)
            ? StubHandler.Json("""{ "uid": "boss" }""")
            : StubHandler.Json("""{ "error": "not found" }""", HttpStatusCode.NotFound);
        var perUser = ("for_each", (JsonNode?)new JsonObject { ["values"] = new JsonArray("u1", "u2"), ["field"] = "id" });
        var everyoneMissing = ("for_each", (JsonNode?)new JsonObject { ["values"] = new JsonArray("u2", "u3"), ["field"] = "id" });

        var (some, _) = await RunPosting("https://graph.example.org", [], Manager, ("path", "/users/{id}/manager"), ("missing", "empty"), perUser);
        var (none, _) = await RunPosting("https://graph.example.org", [], Manager, ("path", "/users/{id}/manager"), ("missing", "empty"), everyoneMissing);
        var (strict, _) = await RunPosting("https://graph.example.org", [], Manager, ("path", "/users/{id}/manager"), perUser);

        Assert.Equal(("ok", 1), (some.State, some.Rows.Count));
        Assert.Contains("1 of 2 objects have none", some.Reason, StringComparison.Ordinal);
        Assert.Equal("partial", none.State);   // every object lacking it: more likely a wrong path
        Assert.Equal("partial", strict.State);  // without missing: empty a 404 is a failed object
        Assert.Contains(new HttpRunner().Validate(Context.Query("http", "id", ("path", "/x"), ("missing", "empty"))), p => p.Contains("for_each", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_read_post_never_follows_a_next_link_to_a_path_its_type_does_not_read()
    {
        var (result, sent) = await RunPosting("https://mgmt.example.org", ["/web_api/show-*"], (_, _) =>
                StubHandler.Json("""{ "objects": [ { "uid": "h1" } ], "nextLink": "https://mgmt.example.org/web_api/delete-host" }"""),
            ("path", "/web_api/show-hosts"), ("method", "post"), ("body", new JsonObject()), ("items", "objects"));

        Assert.Equal("partial", result.State);
        Assert.Single(sent);   // the delete was never sent
        Assert.Contains("delete-host", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""<https://api.example.org/items?page=2&fields=a,b>; rel="next", <https://api.example.org/items?page=9>; rel="last" """, "https://api.example.org/items?page=2&fields=a,b")]
    [InlineData("""<https://api.example.org/items?page=9>; rel="last", </items?page=2>; rel="next" """, "/items?page=2")]
    [InlineData("""<https://api.example.org/items?page=9>; rel="last" """, null)]
    [InlineData("""<https://api.example.org/items?page=2>; rel="next last" """, "https://api.example.org/items?page=2")]
    [InlineData("""<https://api.example.org/items?page=2>;rel=next""", "https://api.example.org/items?page=2")]
    [InlineData("""<https://api.example.org/items?page=2>; related="next" """, null)]   // another parameter, not rel
    public void A_link_header_is_read_between_its_angle_brackets(string header, string? next)
    {
        Assert.Equal(next, HttpEngine.NextLink(header));
    }

    [Fact]
    public async Task A_link_header_that_cannot_be_read_is_a_cut_short_read_and_an_empty_next_link_is_none()
    {
        var (malformed, _) = await RunPosting("https://api.example.org", [], (_, _) =>
        {
            var response = StubHandler.Json("""[ { "uid": "a" } ]""");
            response.Headers.TryAddWithoutValidation("Link", "<https://api.example.org/items?page=2; rel=\"next\"");
            return response;
        }, ("path", "/items"), ("paging", "link"));
        var (empty, _) = await RunPosting("https://api.example.org", [], (_, _) =>
            StubHandler.Json("""{ "value": [ { "uid": "a" } ], "@odata.nextLink": "" }"""), ("path", "/items"));

        Assert.Equal("partial", malformed.State);
        Assert.Equal("ok", empty.State);
    }

    [Fact]
    public async Task A_relative_next_link_is_followed_and_one_that_cannot_be_used_is_a_cut_short_read()
    {
        var (relative, _) = await RunPosting("https://api.example.org", [], (pathAndQuery, _) => pathAndQuery.Contains("page=2", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "value": [ { "uid": "b" } ] }""")
                : StubHandler.Json("""{ "value": [ { "uid": "a" } ], "@odata.nextLink": "/items?page=2" }"""),
            ("path", "/items"));
        var (broken, _) = await RunPosting("https://api.example.org", [], (_, _) =>
                StubHandler.Json("""{ "value": [ { "uid": "a" } ], "@odata.nextLink": "javascript:alert(1)" }"""),
            ("path", "/items"));

        Assert.Equal(new[] { "a", "b" }, relative.Rows.Select(r => r["uid"]!.ToString()));
        Assert.Equal("partial", broken.State);
    }

    [Fact]
    public async Task A_blank_odata_next_link_falls_through_to_next_link()
    {
        var (result, _) = await RunPosting("https://api.example.org", [], (pathAndQuery, _) => pathAndQuery.Contains("page=2", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "value": [ { "uid": "b" } ] }""")
                : StubHandler.Json("""{ "value": [ { "uid": "a" } ], "@odata.nextLink": "  ", "nextLink": "/items?page=2" }"""),
            ("path", "/items"));

        Assert.Equal(new[] { "a", "b" }, result.Rows.Select(r => r["uid"]!.ToString()));
    }

    [Fact]
    public async Task A_read_post_next_link_outside_the_endpoints_own_path_is_refused()
    {
        var (result, sent) = await RunPosting("https://mgmt.example.org/mgmt", ["/web_api/show-*"], (_, _) =>
                StubHandler.Json("""{ "objects": [ { "uid": "h1" } ], "nextLink": "https://mgmt.example.org/web_api/show-hosts?page=2" }"""),
            ("path", "/web_api/show-hosts"), ("method", "post"), ("body", new JsonObject()), ("items", "objects"));

        Assert.Equal("partial", result.State);
        Assert.Single(sent);
    }

    [Theory]
    [InlineData("/web_api/show-hosts", true)]
    [InlineData("/web_api/v1.8/show-hosts", true)]
    [InlineData("/web_api/SHOW-hosts", false)]       // exact case
    [InlineData("/web_api/show-hosts\n", false)]
    [InlineData("/web_api/v1..8/show-hosts", false)]
    [InlineData("/web_api/show-hosts/x", false)]
    public void A_read_post_path_must_match_its_pattern_exactly(string path, bool allowed)
    {
        Assert.Equal(allowed, ReadPost.Allow(["/web_api/show-*", "/web_api/v*/show-*"], path));
    }

    [Fact]
    public async Task Captured_headers_include_the_contents_own()
    {
        var (result, _) = await RunPosting("https://app.example.org", [], (_, _) =>
        {
            var response = StubHandler.Json("""{ "uid": "x" }""");
            response.Content.Headers.TryAddWithoutValidation("Content-Security-Policy", "default-src 'self'");
            return response;
        }, ("path", "/"), ("capture_headers", new JsonArray("Content-Type", "Content-Security-Policy")));

        var headers = Assert.Single(result.Rows)["_headers"]!;
        Assert.StartsWith("application/json", headers["Content-Type"]!.ToString(), StringComparison.Ordinal);
        Assert.Equal("default-src 'self'", headers["Content-Security-Policy"]!.ToString());
    }

    [Fact]
    public async Task Response_headers_can_be_read_as_fields()
    {
        var (result, _) = await RunPosting("https://app.example.org", [], (_, _) =>
        {
            var response = StubHandler.Json("");
            response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
            return response;
        }, ("path", "/"), ("capture_headers", new JsonArray("Strict-Transport-Security", "X-Frame-Options")));

        var row = Assert.Single(result.Rows);
        Assert.Equal("max-age=31536000", row["_headers"]!["Strict-Transport-Security"]!.ToString());
        Assert.Null(row["_headers"]!["X-Frame-Options"]);
    }

    [Fact]
    public async Task A_map_answer_can_be_one_row_per_key()
    {
        var (result, _) = await RunPosting("https://api.example.org", [], (_, _) =>
                StubHandler.Json("""{ "protocols": { "smtp": { "enabled": true }, "pop3": { "enabled": false } } }"""),
            ("path", "/settings"), ("items", "protocols"), ("map", "true"));

        Assert.Equal(new[] { "smtp:true", "pop3:false" }, result.Rows.Select(r => $"{r["key"]}:{r["value"]!["enabled"]}"));
    }

    [Fact]
    public async Task For_each_takes_a_tenants_list_and_fills_params_too()
    {
        var sent = new List<string>();
        var stub = new StubHandler(request =>
        {
            sent.Add(request.RequestUri!.PathAndQuery);
            return StubHandler.Json("""{ "value": [ { "uid": "x" } ] }""");
        });
        var context = Context.For(new FakeConnection("https://api.example.org", stub)) with { Threshold = name => name == "app.sites" ? "site-a, site-b" : null };
        var query = Context.Query("http", "uid", ("path", "/sites/{site}/policies"), ("params", new JsonObject { ["owner"] = "{site}", ["literal"] = "{not.a.field}" }),
            ("for_each", new JsonObject { ["threshold"] = "app.sites", ["field"] = "site" }));

        Assert.Empty(new HttpRunner().Validate(query));
        var result = await new HttpRunner().RunAsync(query, context, CancellationToken.None);

        Assert.Equal(2, result.Rows.Count);
        Assert.Contains(sent, s => s.StartsWith("/sites/site-a/policies?", StringComparison.Ordinal) && s.Contains("owner=site-a", StringComparison.Ordinal));
        Assert.All(sent, s => Assert.Contains("literal=%7Bnot.a.field%7D", s, StringComparison.Ordinal));
        Assert.Equal("site-b", result.Rows.Single(r => r["parent"]!["site"]!.ToString() == "site-b")["parent"]!["site"]!.ToString());
    }

    [Fact]
    public async Task A_request_can_take_its_window_from_a_tenant_setting()
    {
        var sent = new List<string>();
        var stub = new StubHandler(request =>
        {
            sent.Add(Uri.UnescapeDataString(request.RequestUri!.Query));
            return StubHandler.Json("[]");
        });
        var context = Context.For(new FakeConnection("https://api.example.org", stub)) with { Threshold = name => name == "app.window-days" ? "30" : null };

        await new HttpRunner().RunAsync(Context.Query("http", "id", ("path", "/events"),
            ("params", new JsonObject { ["since"] = "{DAYS_AGO:threshold.app.window-days|90}", ["until"] = "{DAYS_AGO:threshold.unset|1}" })), context, CancellationToken.None);

        Assert.Contains("since=2026-09-20T00:00:00Z", sent[0], StringComparison.Ordinal);
        Assert.Contains("until=2026-10-19T00:00:00Z", sent[0], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("body", "get", null, "body needs method: post")]
    [InlineData("paging", "get", "body-offset", "needs method: post")]
    [InlineData("format", "get", "xml", "needs items")]
    [InlineData("paging", "get", "cursor", "cursorField")]
    [InlineData("method", "delete", null, "method must be get or post")]
    public void Http_queries_that_cannot_be_read_safely_are_refused_at_load(string what, string method, string? value, string problem)
    {
        var fields = new List<(string, JsonNode?)> { ("path", "/x"), ("method", method) };
        if (what == "body")
            fields.Add(("body", new JsonObject()));
        else if (value is not null)
            fields.Add((what, value));

        Assert.Contains(new HttpRunner().Validate(Context.Query("http", "id", [.. fields])), p => p.Contains(problem, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_graph_endpoint_that_returns_one_object_is_one_row_not_an_empty_answer()
    {
        var (result, _) = await Run(new GraphRunner(), "https://graph.microsoft.com", _ =>
            StubHandler.Json("""{ "id": "authorizationPolicy", "allowInvitesFrom": "everyone" }"""),
            null, ("path", "/policies/authorizationPolicy"));

        Assert.Equal("everyone", Assert.Single(result.Rows)["allowInvitesFrom"]!.ToString());
    }

    [Fact]
    public async Task A_next_page_on_another_host_is_refused()
    {
        var (result, stub) = await Run(new HttpRunner(), "https://api.example.org", _ =>
            StubHandler.Json("""{ "value": [ { "id": "a" } ], "@odata.nextLink": "https://collector.example.com/steal" }"""),
            null, ("path", "/items"));

        Assert.Equal("partial", result.State);
        Assert.Single(stub.Requests);
        Assert.Contains("another host", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_redirect_is_not_followed()
    {
        var (result, _) = await Run(new HttpRunner(), "https://api.example.org", _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri("https://evil.example.com/");
            return response;
        }, null, ("path", "/items"));

        Assert.Equal("failed", result.State);
        Assert.Contains("redirect", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Plain_http_is_refused_unless_the_integration_allows_it()
    {
        var (refused, refusedStub) = await Run(new HttpRunner(), "http://prtg.example.org", _ => StubHandler.Json("[]"), null, ("path", "/api/table.json"));
        var (allowed, _) = await Run(new HttpRunner(), "http://prtg.example.org", _ => StubHandler.Json("[]"),
            new JsonObject { ["allowHttp"] = "true" }, ("path", "/api/table.json"));

        Assert.Equal("failed", refused.State);
        Assert.Empty(refusedStub.Requests);
        Assert.Equal("ok", allowed.State);
    }

    [Fact]
    public async Task Offset_paging_stops_on_a_short_page()
    {
        var (result, stub) = await Run(new HttpRunner(), "https://servicenow.example.org", request =>
            request.RequestUri!.Query.Contains("sysparm_offset=0", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "result": [ { "id": "1" }, { "id": "2" } ] }""")
                : StubHandler.Json("""{ "result": [ { "id": "3" } ] }"""),
            null, ("path", "/api/now/table/incident"), ("items", "result"), ("paging", "offset"), ("pageSize", "2"));

        Assert.Equal(3, result.Rows.Count);
        Assert.Equal(2, stub.Requests.Count);
    }

    [Fact]
    public async Task Access_denied_says_so()
    {
        var (result, _) = await Run(new HttpRunner(), "https://api.example.org", _ => StubHandler.Json("{}", HttpStatusCode.Forbidden), null, ("path", "/items"));

        Assert.Equal("failed", result.State);
        Assert.Contains("access denied", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Graph_builds_its_odata_query()
    {
        var (result, stub) = await Run(new GraphRunner(), "https://graph.microsoft.com",
            _ => StubHandler.Json("""{ "value": [ { "id": "u1", "displayName": "User One" } ] }"""),
            null, ("path", "/users"), ("select", new JsonArray("id", "displayName")), ("filter", "accountEnabled eq true"), ("consistency", "eventual"));

        Assert.Equal("ok", result.State);
        var uri = stub.Requests[0].RequestUri!;
        Assert.Equal("/v1.0/users", uri.AbsolutePath);
        var query = Uri.UnescapeDataString(uri.Query);
        Assert.Contains("$select=id,displayName", query, StringComparison.Ordinal);
        Assert.Contains("$count=true", query, StringComparison.Ordinal);
        Assert.Equal("eventual", stub.Requests[0].Headers.GetValues("ConsistencyLevel").Single());
    }

    [Fact]
    public async Task Graphql_follows_its_cursor()
    {
        var (result, stub) = await Run(new GraphQlRunner(), "https://api.wiz.example.org", request =>
        {
            var body = request.Content!.ReadAsStringAsync().Result;
            return body.Contains("\"after\":\"c1\"", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "data": { "issues": { "nodes": [ { "id": "i2" } ], "pageInfo": { "hasNextPage": false, "endCursor": null } } } }""")
                : StubHandler.Json("""{ "data": { "issues": { "nodes": [ { "id": "i1" } ], "pageInfo": { "hasNextPage": true, "endCursor": "c1" } } } }""");
        }, null,
            ("document", "query($after: String) { issues(after: $after) { nodes { id } pageInfo { hasNextPage endCursor } } }"),
            ("items", "data.issues.nodes"),
            ("paging", new JsonObject { ["cursor"] = "data.issues.pageInfo.endCursor", ["hasNext"] = "data.issues.pageInfo.hasNextPage", ["variable"] = "after" }));

        Assert.Equal(new[] { "i1", "i2" }, result.Rows.Select(r => r["id"]!.ToString()));
        Assert.Equal(2, stub.Requests.Count);
        Assert.Equal(HttpMethod.Post, stub.Requests[0].Method);
    }
}
