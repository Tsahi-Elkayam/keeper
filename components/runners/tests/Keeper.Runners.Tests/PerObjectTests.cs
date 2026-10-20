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
                "/servicePrincipals" => RunnerResult.Ok([new() { ["id"] = "sp-1", ["name"] = "App one" }, new() { ["id"] = "sp-2" }, new() { ["id"] = "../../x" }]),
                "/servicePrincipals/sp-1/jobs" => RunnerResult.Ok([new() { ["status"] = "Quarantine" }]),
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
        Assert.Equal("partial", result.State);                    // sp-2 failed, and one id was not a plain id
        Assert.Contains("2 of 3 objects failed", result.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(runner.Paths, p => p.Contains("..", StringComparison.Ordinal));
    }

    [Fact]
    public void A_path_without_the_placeholder_or_a_nested_for_each_is_refused()
    {
        var runner = new PathRunner();

        Assert.NotEmpty(runner.Validate(Query("/servicePrincipals/jobs", new JsonObject { ["path"] = "/servicePrincipals", ["field"] = "id" })));
        Assert.NotEmpty(runner.Validate(Query("/x/{id}", new JsonObject { ["path"] = "/x", ["field"] = "id", ["for_each"] = new JsonObject() })));
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
