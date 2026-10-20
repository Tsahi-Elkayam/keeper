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
