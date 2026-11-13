using System.Net;
using System.Text.Json.Nodes;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Runners;
using Keeper.Store;

namespace Keeper.Push.Tests;

internal sealed class Recorder : HttpMessageHandler
{
    public List<(HttpMethod Method, Uri Uri, string Body)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method, request.RequestUri!, body));
        return new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent("""{ "result": { "sys_id": "abc123" } }""") };
    }
}

internal sealed class TrackerConnection(string endpoint, HttpMessageHandler handler) : IConnection
{
    public string Instance => "tickets";
    public string Type => "servicenow";
    public string Endpoint => endpoint;
    public string AuthKind => "basic";
    public string? Identity => "svc-keeper";
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => handler;
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class PushTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, PushComponent.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public PushTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
        Sql.Execute(connection,
            """
            INSERT INTO system (system_id, name, route, updated_by, updated_at) VALUES
                ('ROUTED', 'Routed to ServiceNow', 'servicenow', 'test', '2026-10-01T00:00:00Z'),
                ('LOCAL', 'Handled here', 'triage', 'test', '2026-10-01T00:00:00Z');
            """);
        foreach (var (key, system) in new[] { ("aaaa1111", "ROUTED"), ("bbbb2222", "ROUTED"), ("cccc3333", "LOCAL") })
        {
            Sql.Execute(connection,
                """
                INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, kind, lens,
                                     category, severity, title, status, lifecycle, first_seen, last_seen)
                VALUES (:k, 'ex', 'example', :s, 'R1', 'R1', 'host', 'host1.example.org', 'broken', 'both', 'HLT', 'high',
                        'Finding ' || :k, 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                """, null, (":k", key), (":s", system));
        }
        // aaaa1111 and cccc3333 are handed off; bbbb2222 is not.
        Sql.Execute(connection,
            """
            INSERT INTO triage (finding_key, decision, owner, actor, at, why) VALUES
                ('aaaa1111', 'delegate', 'server team', 'test', '2026-10-19T00:00:00Z', 'test'),
                ('cccc3333', 'delegate', 'desk', 'test', '2026-10-19T00:00:00Z', 'test');
            """);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string DataDir => Path.Combine(_dir, "data");

    private Database Db => new(Path.Combine(DataDir, "keeper.db"));

    private IReadOnlyList<PushItem> Plan(params string[] keys)
    {
        using var connection = Db.OpenReadOnly();
        return PushComponent.Plan(connection, "servicenow", keys);
    }

    [Fact]
    public void Only_handed_off_findings_on_systems_routed_to_the_tracker_are_planned()
    {
        Assert.Equal(new[] { "aaaa1111" }, Plan().Select(i => i.FindingKey));
        Assert.Equal("server team", Plan().Single().Owner);
    }

    [Fact]
    public void Asking_by_key_prefix_plans_exactly_those()
    {
        Assert.Equal(new[] { "bbbb2222" }, Plan("bbbb").Select(i => i.FindingKey));
    }

    [Fact]
    public void A_recorded_ticket_is_not_planned_again()
    {
        new RequestWriter(Path.Combine(DataDir, "spool")).Submit("push.record", "test", new
        {
            findingKey = "aaaa1111", tracker = "servicenow", integration = "tickets", extId = "abc123", status = "sent",
        });
        var report = new QueueManager(Db, Path.Combine(DataDir, "spool"), DataDir, Schemas, PushComponent.Handlers()).DrainOnce();

        Assert.Equal(1, report.Done);
        Assert.Empty(Plan());
    }

    [Fact]
    public async Task ServiceNow_gets_one_incident_correlated_by_the_finding_key_and_only_at_its_own_host()
    {
        var recorder = new Recorder();
        var tracker = new ServiceNowTracker(new TrackerConnection("https://tickets.example.org", recorder));

        var ticket = await tracker.OpenAsync(Plan().Single(), CancellationToken.None);

        Assert.Equal("abc123", ticket.ExtId);
        var (method, uri, body) = Assert.Single(recorder.Requests);
        Assert.Equal(HttpMethod.Post, method);
        Assert.Equal("https://tickets.example.org/api/now/table/incident", uri.ToString());
        Assert.Equal("aaaa1111", JsonNode.Parse(body)!["correlation_id"]!.ToString());
    }

    [Fact]
    public async Task A_tracker_endpoint_that_is_not_https_is_refused()
    {
        var tracker = new ServiceNowTracker(new TrackerConnection("http://tickets.example.org", new Recorder()));

        await Assert.ThrowsAsync<InvalidOperationException>(() => tracker.OpenAsync(Plan().Single(), CancellationToken.None));
    }
}
