using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Tests;

public sealed class PerObjectTests
{
    /// <summary>Answers by path: the list of objects, then one request per object.</summary>
    private sealed class PathRunner : IRunner
    {
        public List<string> Paths { get; } = [];
        public string Protocol => "http";
        public bool PerTarget => false;
        public IEnumerable<string> Validate(QuerySpec query) => PerObject.Validate(query);

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            if (query.Fields["for_each"] is JsonObject)
                return PerObject.RunAsync(this, query, context, cancellationToken);
            var path = query.Text("path")!;
            lock (Paths)
                Paths.Add(path);
            return Task.FromResult(path switch
            {
                "/servicePrincipals" => RunnerResult.Ok([new() { ["id"] = "sp-1", ["name"] = "App one" }, new() { ["id"] = "sp-2" }, new() { ["id"] = "../../x" }, new() { ["id"] = ".." }]),
                "/servicePrincipals/sp-1/jobs" => RunnerResult.Ok([new() { ["status"] = "Quarantine" }]),
                "/sites" => RunnerResult.Ok([new() { ["id"] = "s1" }, new() { ["id"] = "s2" }]),
                "/sites/s1/lists" => RunnerResult.Ok([new() { ["id"] = "l1" }]),
                "/sites/s2/lists" => RunnerResult.Ok([new() { ["id"] = "l2" }, new() { ["id"] = "l3" }]),
                "/sites/s1/lists/l1/items" => RunnerResult.Ok([new() { ["title"] = "a" }]),
                "/sites/s2/lists/l2/items" => RunnerResult.Ok([new() { ["title"] = "b" }]),
                "/sites/s2/lists/l3/items" => RunnerResult.Ok([]),
                _ => RunnerResult.Failed($"{path}: 404"),
            });
        }
    }

    private static QuerySpec Query(string path, JsonObject? each) =>
        Context.Query("http", "status", ("path", path), ("for_each", each));

    [Fact]
    public async Task One_request_per_object_with_the_object_as_parent_and_failures_reported()
    {
        var runner = new PathRunner();
        var query = Query("/servicePrincipals/{id}/jobs", new JsonObject { ["path"] = "/servicePrincipals", ["field"] = "id" });

        Assert.Empty(runner.Validate(query));
        var result = await runner.RunAsync(query, Context.For(new FakeConnection("")), CancellationToken.None);

        var row = Assert.Single(result.Rows);
        Assert.Equal("Quarantine", row["status"]!.ToString());
        Assert.Equal("App one", row["parent"]!["name"]!.ToString());
        Assert.Equal("partial", result.State);                    // sp-2 failed, and two ids were not plain ids
        Assert.Contains("3 of 4 objects failed", result.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(runner.Paths, p => p.Contains("..", StringComparison.Ordinal) || p == "/servicePrincipals/jobs");
    }

    [Fact]
    public void A_path_without_the_placeholder_or_a_broken_inner_for_each_is_refused()
    {
        var runner = new PathRunner();

        Assert.NotEmpty(runner.Validate(Query("/servicePrincipals/jobs", new JsonObject { ["path"] = "/servicePrincipals", ["field"] = "id" })));
        Assert.NotEmpty(runner.Validate(Query("/x/{id}", new JsonObject { ["path"] = "/x", ["field"] = "id", ["for_each"] = new JsonObject() })));
    }

    private static JsonObject Lists(JsonObject? sites = null) =>
        new() { ["path"] = "/sites/{id}/lists", ["field"] = "id", ["for_each"] = sites ?? new JsonObject { ["path"] = "/sites", ["field"] = "id" } };

    [Fact]
    public async Task Two_levels_name_the_object_two_levels_up_as_parent_parent()
    {
        var runner = new PathRunner();
        var query = Query("/sites/{parent.id}/lists/{id}/items", Lists());

        Assert.Empty(runner.Validate(query));
        var result = await runner.RunAsync(query, Context.For(new FakeConnection("")), CancellationToken.None);

        Assert.Equal("ok", result.State);
        Assert.Equal(new[] { "a/l1/s1", "b/l2/s2" },
            result.Rows.Select(r => $"{r["title"]}/{r["parent"]!["id"]}/{r["parent"]!["parent"]!["id"]}").Order(StringComparer.Ordinal));
        Assert.Equal(1 + 2 + 3, runner.Paths.Count);   // the sites, each site's lists, each list's items
    }

    [Fact]
    public void Three_levels_are_refused()
    {
        var three = Lists(new JsonObject { ["path"] = "/sites/{id}", ["field"] = "id", ["for_each"] = new JsonObject { ["path"] = "/hubs", ["field"] = "id" } });

        Assert.Contains(new PathRunner().Validate(Query("/sites/{parent.id}/lists/{id}/items", three)), p => p.Contains("two levels", StringComparison.Ordinal));
    }

    [Fact]
    public void Date_macros_are_relative_to_the_scan()
    {
        var now = new DateTimeOffset(2026, 10, 20, 6, 0, 0, TimeSpan.Zero);

        Assert.Equal("activityDateTime ge 2026-10-13T06:00:00Z and x le 2026-10-20",
            RequestMacros.Expand("activityDateTime ge {DAYS_AGO:7} and x le {TODAY}", now));
        Assert.Equal("{id}", RequestMacros.Expand("{id}", now));
    }
}
