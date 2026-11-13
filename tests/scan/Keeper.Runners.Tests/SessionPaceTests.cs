using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Aws;
using Keeper.Runners.Files;
using Keeper.Runners.Http;
using Keeper.Runners.Printer;
using Keeper.Runners.Tls;

namespace Keeper.Runners.Tests;

/// <summary>A connection that counts the HTTP handlers (so connections) it is asked to make, and the sign-ins its token would need.</summary>
internal class CountingConnection(string endpoint, Func<HttpRequestMessage, HttpResponseMessage> respond, string authKind = "bearer") : IConnection
{
    private int _handlers;

    public StubHandler Stub { get; } = new(respond);
    public int HandlersCreated => Volatile.Read(ref _handlers);
    public string Instance => "test";
    public string Type => "test";
    public string Endpoint => endpoint;
    public string AuthKind => authKind;
    public string? Identity => "reader@example.org";
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => "test-token";
    public NetworkCredential? WindowsCredential() => null;

    public HttpMessageHandler CreateHttpHandler()
    {
        Interlocked.Increment(ref _handlers);
        return Stub;
    }

    public virtual Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "test-token");
        return Task.CompletedTask;
    }
}

/// <summary>A session-token connection: it renews on request, at most as often as it is allowed to.</summary>
internal sealed class RenewingConnection(string endpoint, Func<HttpRequestMessage, HttpResponseMessage> respond, bool canRenew)
    : CountingConnection(endpoint, respond, "vcenter-session"), ISessionTokenConnection
{
    public int Renewals;

    public Task<bool> RenewSessionAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Renewals);
        return Task.FromResult(canRenew);
    }
}

public sealed class SessionPaceTests
{
    private static RunnerContext For(IConnection connection, IPace? pace = null, string? target = null, TimeSpan? timeout = null) =>
        Context.For(connection, target) with { Pace = pace ?? NoPace.Instance, Timeout = timeout ?? TimeSpan.FromSeconds(10) };

    private static QuerySpec Http(params (string, JsonNode?)[] fields) => Context.Query("http", "id", fields);

    // ------------------------------------------------------------------ HTTP: one client per scan

    [Fact]
    public async Task Many_queries_over_one_session_use_one_connection()
    {
        var connection = new CountingConnection("https://api.example.org", _ => StubHandler.Json("""{ "value": [ { "id": "a" } ] }"""));
        var runner = new HttpRunner();
        await using var session = await runner.OpenAsync(For(connection), CancellationToken.None);

        for (var i = 0; i < 5; i++)
            Assert.Equal("ok", (await runner.RunAsync(session, Http(("path", "/items/" + i)), For(connection), CancellationToken.None)).State);
        // Graph and graphql share the session: still the same client.
        await new GraphRunner().RunAsync(session, Context.Query("graph", "id", ("path", "/users")), For(connection), CancellationToken.None);

        Assert.Equal(1, connection.HandlersCreated);
        Assert.Equal(6, connection.Stub.Requests.Count);
        Assert.Equal(1, ((HttpSession)session).EnginesOpened);
    }

    [Fact]
    public async Task The_stateless_path_still_works_and_opens_a_connection_per_call()
    {
        var connection = new CountingConnection("https://api.example.org", _ => StubHandler.Json("""{ "value": [] }"""));
        var runner = new HttpRunner();

        await runner.RunAsync(Http(("path", "/a")), For(connection), CancellationToken.None);
        await runner.RunAsync(Http(("path", "/b")), For(connection), CancellationToken.None);

        Assert.Equal(2, connection.HandlersCreated);
    }

    [Fact]
    public async Task For_each_children_share_the_sessions_one_connection_and_each_waits_for_the_pace()
    {
        var connection = new CountingConnection("https://api.example.org", request =>
            request.RequestUri!.AbsolutePath == "/people"
                ? StubHandler.Json("""{ "value": [ { "id": "1" }, { "id": "2" }, { "id": "3" }, { "id": "4" }, { "id": "5" } ] }""")
                : StubHandler.Json("""{ "value": [ { "x": 1 } ] }"""));
        var pace = new CountingPace();
        var runner = new HttpRunner();
        await using var session = await runner.OpenAsync(For(connection, pace), CancellationToken.None);
        var query = Http(("path", "/people/{id}/roles"), ("for_each", new JsonObject { ["path"] = "/people", ["field"] = "id" }));

        var result = await runner.RunAsync(session, query, For(connection, pace), CancellationToken.None);

        Assert.Equal("ok", result.State);
        Assert.Equal(5, result.Rows.Count);
        Assert.Equal(1, connection.HandlersCreated);          // before: 1 + 5 clients
        Assert.Equal(6, connection.Stub.Requests.Count);
        Assert.Equal(5, pace.Waits);                          // the list is the query's first request; each child waits
    }

    [Fact]
    public async Task A_second_page_waits_for_the_pace_the_first_does_not()
    {
        var connection = new CountingConnection("https://api.example.org", request =>
            request.RequestUri!.Query.Contains("p=2", StringComparison.Ordinal)
                ? StubHandler.Json("""{ "value": [ { "id": "b" } ] }""")
                : StubHandler.Json("""{ "value": [ { "id": "a" } ], "@odata.nextLink": "https://api.example.org/things?p=2" }"""));
        var pace = new CountingPace();

        var result = await new HttpRunner().RunAsync(Http(("path", "/things")), For(connection, pace), CancellationToken.None);

        Assert.Equal(2, result.Rows.Count);
        Assert.Equal(1, pace.Waits);
    }

    // ------------------------------------------------------------------ HTTP: timeouts

    private sealed class Slow : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return StubHandler.Json("{}");
        }
    }

    [Fact]
    public async Task The_query_timeout_applies_per_request_and_is_reported_as_a_timeout()
    {
        var connection = new FixedHandlerConnection(new Slow());
        var runner = new HttpRunner();
        await using var session = await runner.OpenAsync(For(connection), CancellationToken.None);

        var started = DateTime.UtcNow;
        var result = await runner.RunAsync(session, Http(("path", "/slow")), For(connection, timeout: TimeSpan.FromMilliseconds(300)), CancellationToken.None);

        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(10));
        Assert.Equal("failed", result.State);
        Assert.Equal(FailureKind.Timeout, result.Failure);
        Assert.Contains("timed out", result.Reason, StringComparison.Ordinal);
        // The same session, a longer timeout for the next query: the client was not fixed to the first one's.
        Assert.Equal(FailureKind.Timeout, (await runner.RunAsync(session, Http(("path", "/slow")), For(connection, timeout: TimeSpan.FromMilliseconds(100)), CancellationToken.None)).Failure);
    }

    [Fact]
    public async Task A_caller_cancelling_is_not_reported_as_a_timeout()
    {
        var connection = new FixedHandlerConnection(new Slow());
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new HttpRunner().RunAsync(Http(("path", "/slow")), For(connection, timeout: TimeSpan.FromSeconds(20)), cancel.Token));
    }

    private sealed class FixedHandlerConnection(HttpMessageHandler handler) : IConnection
    {
        public string Instance => "test";
        public string Type => "test";
        public string Endpoint => "https://api.example.org";
        public string AuthKind => "none";
        public string? Identity => null;
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => handler;
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    // ------------------------------------------------------------------ HTTP: retries and Retry-After

    [Fact]
    public void Retry_after_is_honoured_as_seconds_or_as_a_date_and_is_never_less_than_a_second()
    {
        var now = new DateTimeOffset(2026, 11, 13, 9, 0, 0, TimeSpan.Zero);
        static System.Net.Http.Headers.RetryConditionHeaderValue? Header(string? text) =>
            text is null ? null : System.Net.Http.Headers.RetryConditionHeaderValue.Parse(text);

        Assert.Equal(TimeSpan.FromSeconds(7), HttpEngine.RetryDelay(Header("7"), now, 1));
        Assert.Equal(TimeSpan.FromSeconds(1), HttpEngine.RetryDelay(Header("0"), now, 1));
        Assert.Equal(TimeSpan.FromSeconds(5), HttpEngine.RetryDelay(Header("Fri, 13 Nov 2026 09:00:05 GMT"), now, 1));
        Assert.Equal(TimeSpan.FromSeconds(1), HttpEngine.RetryDelay(Header("Fri, 13 Nov 2026 08:00:00 GMT"), now, 1));   // a date in the past
        Assert.Equal(TimeSpan.FromSeconds(60), HttpEngine.RetryDelay(Header("3600"), now, 1));
        Assert.Equal(TimeSpan.FromSeconds(4), HttpEngine.RetryDelay(null, now, 2));
    }

    [Fact]
    public async Task A_429_is_retried_after_a_pace_wait_and_reported_to_the_pace_as_throttled()
    {
        var calls = 0;
        var connection = new CountingConnection("https://api.example.org", _ =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                var busy = StubHandler.Json("{}", HttpStatusCode.TooManyRequests);
                busy.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero);   // 0: still at least a second
                return busy;
            }
            return StubHandler.Json("""{ "value": [ { "id": "a" } ] }""");
        });
        var pace = new CountingPace();
        var started = DateTime.UtcNow;

        var result = await new HttpRunner().RunAsync(Http(("path", "/things")), For(connection, pace), CancellationToken.None);

        Assert.Equal("ok", result.State);
        Assert.True(DateTime.UtcNow - started >= TimeSpan.FromMilliseconds(900));
        Assert.Equal(1, pace.Throttled);
        Assert.Equal(1, pace.Waits);         // the retry waits for the pace; the first request did not
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, FailureKind.Refused)]
    [InlineData(HttpStatusCode.Forbidden, FailureKind.Denied)]
    public async Task Http_failures_carry_their_kind(HttpStatusCode status, FailureKind kind)
    {
        var connection = new CountingConnection("https://api.example.org", _ => StubHandler.Json("""{ "error": "no" }""", status));

        var result = await new HttpRunner().RunAsync(Http(("path", "/x")), For(connection), CancellationToken.None);

        Assert.Equal(kind, result.Failure);
    }

    [Fact]
    public async Task A_session_that_expired_is_renewed_once_and_a_second_401_is_a_refusal()
    {
        var calls = 0;
        var renewing = new RenewingConnection("https://vc.example.org", _ => Interlocked.Increment(ref calls) == 1
            ? StubHandler.Json("{}", HttpStatusCode.Unauthorized)
            : StubHandler.Json("""{ "value": [ { "id": "a" } ] }"""), canRenew: true);

        var ok = await new HttpRunner().RunAsync(Http(("path", "/vcenter/vm")), For(renewing), CancellationToken.None);
        Assert.Equal("ok", ok.State);
        Assert.Equal(1, renewing.Renewals);

        var always401 = new RenewingConnection("https://vc.example.org", _ => StubHandler.Json("{}", HttpStatusCode.Unauthorized), canRenew: true);
        var refused = await new HttpRunner().RunAsync(Http(("path", "/vcenter/vm")), For(always401), CancellationToken.None);
        Assert.Equal(FailureKind.Refused, refused.Failure);
        Assert.Equal(1, always401.Renewals);                   // once, not again
        Assert.Equal(2, always401.Stub.Requests.Count);

        var cannot = new RenewingConnection("https://vc.example.org", _ => StubHandler.Json("{}", HttpStatusCode.Unauthorized), canRenew: false);
        Assert.Equal(FailureKind.Refused, (await new HttpRunner().RunAsync(Http(("path", "/x")), For(cannot), CancellationToken.None)).Failure);
        Assert.Single(cannot.Stub.Requests);
    }

    // ------------------------------------------------------------------ for_each circuit breaker

    private static string People(int count) =>
        "{ \"value\": [" + string.Join(",", Enumerable.Range(1, count).Select(i => $"{{ \"id\": \"p{i}\" }}")) + "] }";

    [Fact]
    public async Task For_each_stops_sending_after_the_first_refusal()
    {
        var connection = new CountingConnection("https://api.example.org", request =>
            request.RequestUri!.AbsolutePath == "/people" ? StubHandler.Json(People(40)) : StubHandler.Json("""{ "error": "bad credentials" }""", HttpStatusCode.Unauthorized));
        var query = Http(("path", "/people/{id}/roles"), ("for_each", new JsonObject { ["path"] = "/people", ["field"] = "id" }));

        var result = await new HttpRunner().RunAsync(query, For(connection), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Equal(FailureKind.Refused, result.Failure);
        Assert.Contains("not sent", result.Reason, StringComparison.Ordinal);
        Assert.Equal(2, connection.Stub.Requests.Count);       // the list, and the first child alone: never four refused at once
    }

    [Fact]
    public async Task For_each_stops_after_three_denied_in_a_row()
    {
        var connection = new CountingConnection("https://api.example.org", request =>
            request.RequestUri!.AbsolutePath == "/people" ? StubHandler.Json(People(40)) : StubHandler.Json("""{ "error": "forbidden" }""", HttpStatusCode.Forbidden));
        var query = Http(("path", "/people/{id}/roles"), ("for_each", new JsonObject { ["path"] = "/people", ["field"] = "id" }));

        var result = await new HttpRunner().RunAsync(query, For(connection), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Equal(FailureKind.Denied, result.Failure);
        Assert.Contains("objects were not sent", result.Reason, StringComparison.Ordinal);
        Assert.True(connection.Stub.Requests.Count <= 1 + 3 + 3, $"sent {connection.Stub.Requests.Count}");   // list + 3 + the ones in flight
    }

    [Fact]
    public async Task For_each_keeps_going_when_a_few_objects_are_denied_among_good_ones()
    {
        var connection = new CountingConnection("https://api.example.org", request =>
            request.RequestUri!.AbsolutePath == "/people" ? StubHandler.Json(People(10))
            : request.RequestUri.AbsolutePath.Contains("p3/", StringComparison.Ordinal) || request.RequestUri.AbsolutePath.Contains("p7/", StringComparison.Ordinal)
                ? StubHandler.Json("{}", HttpStatusCode.Forbidden)
                : StubHandler.Json("""{ "value": [ { "x": 1 } ] }"""));
        var query = Http(("path", "/people/{id}/roles"), ("for_each", new JsonObject { ["path"] = "/people", ["field"] = "id" }));

        var result = await new HttpRunner().RunAsync(query, For(connection), CancellationToken.None);

        Assert.Equal("partial", result.State);
        Assert.Equal(8, result.Rows.Count);
        Assert.Equal(11, connection.Stub.Requests.Count);
    }

    // ------------------------------------------------------------------ GraphQL errors

    [Theory]
    [InlineData("""{ "errors": [ { "message": "Unauthenticated", "extensions": { "code": "UNAUTHENTICATED" } } ] }""", FailureKind.Refused)]
    [InlineData("""{ "errors": [ { "message": "You are not allowed to see this", "extensions": { "code": "FORBIDDEN" } } ] }""", FailureKind.Denied)]
    [InlineData("""{ "errors": [ { "message": "Field x not found" } ] }""", FailureKind.Error)]
    public async Task Graphql_errors_in_a_200_body_are_classified(string body, FailureKind kind)
    {
        var connection = new CountingConnection("https://api.example.org", _ => StubHandler.Json(body));

        var result = await new GraphQlRunner().RunAsync(Context.Query("graphql", "id", ("document", "{ me { id } }")), For(connection), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Equal(kind, result.Failure);
    }

    // ------------------------------------------------------------------ AWS

    private sealed class CountingAws(Func<HttpRequestMessage, string, HttpResponseMessage> respond, IReadOnlyList<string> regions) : IConnection, IAwsConnection
    {
        private int _handlers;
        public int HandlersCreated => Volatile.Read(ref _handlers);
        public int Requests;
        public string Instance => "aws-test";
        public string Type => "aws";
        public string Endpoint => "eu-central-1";
        public string AuthKind => "aws-access-key";
        public string? Identity => "AKIDEXAMPLE";
        public JsonObject Options { get; } = [];
        public IReadOnlyList<string> AwsAccounts => [];
        public IReadOnlyList<string> AwsRegions => regions;
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<AwsCredentials> AwsCredentialsAsync(string? account, CancellationToken cancellationToken) =>
            Task.FromResult(new AwsCredentials("AKIDEXAMPLE", SigV4Tests.ExampleSecret, null));

        public HttpMessageHandler CreateHttpHandler()
        {
            Interlocked.Increment(ref _handlers);
            return new StubHandler(request =>
            {
                Interlocked.Increment(ref Requests);
                return respond(request, request.Content?.ReadAsStringAsync().GetAwaiter().GetResult() ?? "");
            });
        }
    }

    private const string Users = """<ListUsersResponse><ListUsersResult><Users><member><UserName>a</UserName></member></Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>""";

    private static QuerySpec Iam(params (string, JsonNode?)[] extra) =>
        Context.Query("aws", "id", [("service", "iam"), ("action", "ListUsers"), ("items", "//Users/member"), .. extra]);

    [Fact]
    public async Task Aws_reads_over_a_session_use_one_client_and_every_place_after_the_first_waits()
    {
        var aws = new CountingAws((_, _) => FakeAws.Xml("""<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>"""), ["eu-central-1", "eu-west-1", "us-east-1"]);
        var pace = new CountingPace();
        var runner = new AwsRunner();
        await using var session = await runner.OpenAsync(For(aws, pace), CancellationToken.None);

        for (var i = 0; i < 3; i++)
        {
            var query = Context.Query("aws", "id", ("service", "ec2"), ("action", "DescribeInstances"), ("items", "//instancesSet/item"));
            Assert.Equal("ok", (await runner.RunAsync(session, query, For(aws, pace), CancellationToken.None)).State);
        }

        Assert.Equal(1, aws.HandlersCreated);        // before: one client per query
        Assert.Equal(9, aws.Requests);               // 3 queries x 3 regions
        Assert.Equal(6, pace.Waits);                 // the first request of each query is the scanner's
    }

    [Theory]
    [InlineData("AccessDenied", HttpStatusCode.Forbidden, FailureKind.Denied)]
    [InlineData("UnauthorizedOperation", HttpStatusCode.Forbidden, FailureKind.Denied)]
    [InlineData("InvalidClientTokenId", HttpStatusCode.Forbidden, FailureKind.Refused)]
    [InlineData("SignatureDoesNotMatch", HttpStatusCode.Forbidden, FailureKind.Refused)]
    [InlineData("ExpiredToken", HttpStatusCode.BadRequest, FailureKind.Refused)]
    public async Task Aws_errors_are_classified_in_the_home_region(string code, HttpStatusCode status, FailureKind kind)
    {
        var aws = new CountingAws((_, _) => FakeAws.Xml($"<ErrorResponse><Error><Code>{code}</Code><Message>no</Message></Error></ErrorResponse>", status), ["eu-central-1"]);

        var result = await new AwsRunner().RunAsync(Iam(), For(aws), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Equal(kind, result.Failure);
    }

    [Fact]
    public async Task A_key_aws_does_not_know_in_a_region_that_is_not_home_does_not_stop_the_credential_everywhere()
    {
        // An opt-in region that is not enabled answers InvalidClientTokenId to a good key: Denied there, not Refused.
        var aws = new CountingAws((request, _) => request.RequestUri!.Host.Contains("eu-south-1", StringComparison.Ordinal)
            ? FakeAws.Xml("<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>no</Message></Error></ErrorResponse>", HttpStatusCode.Forbidden)
            : FakeAws.Xml("""<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>"""), ["eu-central-1", "eu-south-1"]);

        var result = await new AwsRunner().RunAsync(
            Context.Query("aws", "id", ("service", "ec2"), ("action", "DescribeInstances"), ("items", "//instancesSet/item")), For(aws), CancellationToken.None);

        Assert.Equal("partial", result.State);
    }

    [Fact]
    public async Task An_aws_throttle_is_retried_and_reported_to_the_pace()
    {
        var calls = 0;
        var aws = new CountingAws((_, _) => Interlocked.Increment(ref calls) == 1
            ? FakeAws.Xml("<ErrorResponse><Error><Code>Throttling</Code><Message>slow</Message></Error></ErrorResponse>", HttpStatusCode.BadRequest)
            : FakeAws.Xml(Users), ["eu-central-1"]);
        var pace = new CountingPace();

        var result = await new AwsRunner().RunAsync(Iam(), For(aws, pace), CancellationToken.None);

        Assert.Equal("ok", result.State);
        Assert.Equal(1, pace.Throttled);
        Assert.Equal(1, pace.Waits);
    }

    // ------------------------------------------------------------------ Printer

    [Fact]
    public async Task A_silent_printer_is_asked_once_in_the_scan_not_once_per_query()
    {
        // A device that listens and never answers, and counts what it was sent.
        using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var received = 0;
        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    await silent.ReceiveAsync();
                    Interlocked.Increment(ref received);
                }
            }
            catch (ObjectDisposedException)
            {
            }
        });
        var port = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;
        var runner = new PrinterRunner();
        var connection = new PrinterFakeConnection();
        var context = For(connection, target: "127.0.0.1", timeout: TimeSpan.FromMilliseconds(250));
        await using var session = await runner.OpenAsync(context, CancellationToken.None);
        RunnerResult[] results = new RunnerResult[4];

        string[] reads = ["info", "supplies", "alerts", "info"];
        for (var i = 0; i < reads.Length; i++)
            results[i] = await runner.RunAsync(session, Context.Query("printer", "host", ("read", "snmp"), ("what", reads[i]), ("port", port)), context, CancellationToken.None);

        Assert.All(results, r => Assert.Equal("failed", r.State));
        Assert.Equal(FailureKind.Timeout, results[0].Failure);          // the one real silence
        Assert.Contains("not asked again", results[1].Reason, StringComparison.Ordinal);
        await Task.Delay(100);
        Assert.Equal(2, Volatile.Read(ref received));                   // one request, sent twice (its one retry) - not 4 x 2
    }

    [Fact]
    public async Task Snmp_reads_over_a_session_use_one_socket_and_wait_for_the_pace_between_datagrams()
    {
        using var agent = new FakeSnmpAgent("s3cret-community", new()
        {
            ["1.3.6.1.2.1.1.1.0"] = "HP LaserJet Pro M404",
            ["1.3.6.1.2.1.1.5.0"] = "REC-PRN-01",
            ["1.3.6.1.2.1.43.11.1.1.6.1.1"] = "Black Toner",
            ["1.3.6.1.2.1.43.11.1.1.5.1.1"] = 3L,
            ["1.3.6.1.2.1.43.11.1.1.8.1.1"] = 100L,
            ["1.3.6.1.2.1.43.11.1.1.9.1.1"] = 50L,
        });
        var pace = new CountingPace();
        var context = For(new PrinterFakeConnection(), pace, "127.0.0.1");
        var runner = new PrinterRunner();
        await using var session = await runner.OpenAsync(context, CancellationToken.None);

        var result = await runner.RunAsync(session, Context.Query("printer", "host", ("read", "snmp"), ("what", "supplies"), ("port", agent.Port)), context, CancellationToken.None);

        Assert.Equal("ok", result.State);
        var datagrams = agent.PduTags.Count;
        Assert.True(datagrams > 3);
        Assert.Equal(datagrams - 1, pace.Waits);        // every datagram after the query's first
    }

    [Fact]
    public async Task The_ports_read_connects_four_at_a_time_and_waits_between_batches()
    {
        var running = 0;
        var peak = 0;
        var total = 0;
        var runner = new PrinterRunner(async (_, _, _) =>
        {
            var now = Interlocked.Increment(ref running);
            Interlocked.Increment(ref total);
            lock (runner_lock)
                peak = Math.Max(peak, now);
            await Task.Delay(20);
            Interlocked.Decrement(ref running);
            return false;
        });
        var pace = new CountingPace();
        var extra = new JsonArray(Enumerable.Range(7000, 20).Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());

        var result = await runner.RunAsync(Context.Query("printer", "host", ("read", "ports"), ("ports", extra)),
            For(new PrinterFakeConnection(), pace, "127.0.0.1"), CancellationToken.None);

        Assert.Equal("ok", result.State);
        Assert.Equal(30, total);
        Assert.True(peak <= PrinterRunner.PortsAtOnce, $"peak {peak}");
        Assert.Equal(7, pace.Waits);                    // 8 batches of up to 4
    }

    private static readonly object runner_lock = new();

    // ------------------------------------------------------------------ TLS and local runners

    [Fact]
    public void Tls_failures_are_classified_without_calling_a_cut_off_handshake_a_refused_credential()
    {
        Assert.Equal(FailureKind.Unreachable, TlsRunner.Classify(new SocketException((int)SocketError.ConnectionRefused)));
        Assert.Equal(FailureKind.Unreachable, TlsRunner.Classify(new SocketException((int)SocketError.HostUnreachable)));
        Assert.Equal(FailureKind.Throttled, TlsRunner.Classify(new IOException("read failed", new SocketException((int)SocketError.ConnectionReset))));
        Assert.Equal(FailureKind.Timeout, TlsRunner.Classify(new SocketException((int)SocketError.TimedOut)));
        // .NET words a handshake the other side cut off as "Authentication failed ...": that phrase must not read as Refused.
        Assert.Equal(FailureKind.Throttled,
            TlsRunner.Classify(new AuthenticationException("Authentication failed because the remote party has closed the transport stream.")));
        Assert.Equal(FailureKind.Error, TlsRunner.Classify(new AuthenticationException("The remote certificate is invalid.")));
    }

    [Fact]
    public async Task A_tls_read_of_a_port_nobody_listens_on_is_unreachable()
    {
        var free = new TcpListener(IPAddress.Loopback, 0);
        free.Start();
        var port = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();

        var result = await new TlsRunner().RunAsync(Context.Query("tls", "endpoint", ("port", port)), For(new PrinterFakeConnection(), target: "127.0.0.1"), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Equal(FailureKind.Unreachable, result.Failure);
    }

    [Fact]
    public void Local_runners_are_not_remote()
    {
        var connection = new PrinterFakeConnection();

        Assert.False(new FileRunner().IsRemote(connection));
        Assert.False(new StoreRunner().IsRemote(connection));
        Assert.True(((IRunner)new HttpRunner()).IsRemote(connection));
    }
}
