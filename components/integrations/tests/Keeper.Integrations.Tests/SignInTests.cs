using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Queue;
using Keeper.Runners;
using Keeper.Store;
using Keeper.Vault;

namespace Keeper.Integrations.Tests;

/// <summary>
/// Token and session sign-ins under a scan: a refused credential is remembered once (and classified Refused), a busy or
/// silent service is retried a little and never remembered. Every answer comes from a fake handler.
/// </summary>
public sealed class SignInTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-signin-").FullName;
    private readonly Vault.Vault _vault;

    public SignInTests()
    {
        var protector = KeyProtectors.Default(_dir);
        var (keyId, wrapped) = Vault.Vault.NewKey(protector);
        var db = new Database(Path.Combine(_dir, "keeper.db"));
        using var connection = db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, [Vault.Vault.Schema]);
        Sql.Execute(connection, "INSERT INTO vault_key (key_id, protector, wrapped, created_by, created_at) VALUES ($k, $p, $w, 'test', '2026-11-13T00:00:00Z');",
            null, ("$k", keyId), ("$p", protector.Kind), ("$w", wrapped));
        _vault = Vault.Vault.Load(connection, protector);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Answers each request with the next response of the script (the last one repeats); counts the requests.</summary>
    private sealed class Script(params Func<HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        public int Requests;
        public System.Collections.Concurrent.ConcurrentQueue<string> Sent { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent.Enqueue($"{request.Method} {request.RequestUri!.AbsolutePath} {(request.Headers.TryGetValues("vmware-api-session-id", out var id) ? id.First() : "")}".TrimEnd());
            var index = Math.Min(Interlocked.Increment(ref Requests) - 1, responses.Length - 1);
            return Task.FromResult(responses[index]());
        }
    }

    private static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Token(string token = "tok-1") => Json($$"""{ "access_token": "{{token}}", "expires_in": 3600 }""");

    private IntegrationConnection OAuth(Script script, string kind = "oauth-client-credentials", TimeSpan? cooldown = null)
    {
        var binding = IntegrationStore.Binding("app", kind == "vcenter-session" ? "password" : "clientSecret", "https://app.example.org");
        var name = kind == "vcenter-session" ? "password" : "clientSecret";
        var record = new IntegrationRecord("app", "http", "https://app.example.org", kind, "reader",
            new JsonObject { ["tokenUrl"] = "https://login.example.org/token" }, true,
            new Dictionary<string, StoredSecret>
            {
                [name] = new(name, _vault.Seal("not-a-real-secret", binding), binding, "2026-11-13T00:00:00Z", null),
            });
        return new IntegrationConnection(record, _vault) { SignInHandler = script, SignInBackoff = TimeSpan.FromMilliseconds(1), SessionRenewGrace = TimeSpan.Zero, BusyCooldown = cooldown ?? TimeSpan.Zero };
    }

    private static async Task<string?> BearerOf(IntegrationConnection connection)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://app.example.org/api/x");
        await connection.AuthorizeAsync(request, CancellationToken.None);
        return request.Headers.Authorization?.Parameter ?? request.Headers.GetValues("vmware-api-session-id").FirstOrDefault();
    }

    [Fact]
    public async Task A_busy_service_is_retried_at_sign_in_and_the_token_is_kept()
    {
        var script = new Script(() => Json("{}", HttpStatusCode.ServiceUnavailable), () => Json("{}", HttpStatusCode.TooManyRequests), () => Token());
        using var connection = OAuth(script);

        Assert.Equal("tok-1", await BearerOf(connection));
        Assert.Equal("tok-1", await BearerOf(connection));   // cached: no further sign-in
        Assert.Equal(3, script.Requests);
    }

    [Fact]
    public async Task A_service_that_stays_busy_fails_as_throttled_and_is_not_remembered_as_a_refusal()
    {
        var script = new Script(() => Json("{}", HttpStatusCode.ServiceUnavailable));
        using var connection = OAuth(script);

        var failure = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        Assert.Equal(FailureKind.Throttled, Failures.Classify(failure));
        Assert.Equal(3, script.Requests);          // one try and two more, no more

        // The next read signs in again - the service has recovered - instead of repeating the old failure.
        var recovered = new Script(() => Token("tok-2"));
        using var later = OAuth(recovered);
        Assert.Equal("tok-2", await BearerOf(later));
    }

    [Fact]
    public async Task A_transient_failure_is_asked_again_on_the_next_query_not_cached()
    {
        var calls = 0;
        var script = new Script(() => ++calls <= 3 ? Json("{}", HttpStatusCode.BadGateway) : Token("tok-3"));
        using var connection = OAuth(script);

        await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        Assert.Equal("tok-3", await BearerOf(connection));     // the second query signs in afresh and gets in
    }

    [Fact]
    public async Task A_timeout_at_sign_in_is_a_timeout_that_is_not_remembered()
    {
        var script = new TimingOut();
        var binding = IntegrationStore.Binding("app", "clientSecret", "https://app.example.org");
        var record = new IntegrationRecord("app", "http", "https://app.example.org", "oauth-client-credentials", "reader",
            new JsonObject { ["tokenUrl"] = "https://login.example.org/token" }, true,
            new Dictionary<string, StoredSecret> { ["clientSecret"] = new("clientSecret", _vault.Seal("not-a-real-secret", binding), binding, "2026-11-13T00:00:00Z", null) });
        using var connection = new IntegrationConnection(record, _vault) { SignInHandler = script, SignInBackoff = TimeSpan.FromMilliseconds(1), BusyCooldown = TimeSpan.Zero };

        var failure = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        Assert.Equal(FailureKind.Timeout, Failures.Classify(failure));
        await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        Assert.Equal(6, script.Requests);          // asked again by the second query once the cool-down is over: 3 tries each
    }

    [Fact]
    public async Task A_sign_in_that_stays_busy_is_not_sent_again_for_every_read()
    {
        // A service that answers a locked account with 503 must not get three sign-ins per read until the host stops.
        var script = new Script(() => Json("{}", HttpStatusCode.ServiceUnavailable));
        using var connection = OAuth(script, cooldown: TimeSpan.FromMinutes(1));

        for (var read = 0; read < 5; read++)
        {
            var failure = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
            Assert.Equal(FailureKind.Throttled, Failures.Classify(failure));
        }
        Assert.Equal(3, script.Requests);          // one round of tries; the other reads fail as it did
    }

    private sealed class TimingOut : HttpMessageHandler
    {
        public int Requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Requests);
            throw new TaskCanceledException("the request timed out");
        }
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "")]
    [InlineData(HttpStatusCode.BadRequest, """{ "error": "invalid_grant" }""")]
    [InlineData(HttpStatusCode.BadRequest, """{ "error": "invalid_client" }""")]
    public async Task A_refused_credential_is_refused_once_for_the_scan_and_classified_refused(HttpStatusCode status, string body)
    {
        var script = new Script(() => Json(body.Length == 0 ? "{}" : body, status));
        using var connection = OAuth(script);

        var first = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        var second = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        var third = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));

        Assert.Equal(FailureKind.Refused, Failures.Classify(first));
        Assert.Same(first, second);
        Assert.Same(first, third);
        Assert.Equal(1, script.Requests);          // one try; a refusal is never repeated (it counts towards a lockout)
    }

    [Fact]
    public async Task A_wrong_url_that_answers_something_else_is_remembered_but_is_not_a_refused_credential()
    {
        var script = new Script(() => Json("{}", HttpStatusCode.NotFound));
        using var connection = OAuth(script);

        var first = await Assert.ThrowsAsync<IntegrationException>(() => BearerOf(connection));
        Assert.Same(first, await Assert.ThrowsAsync<IntegrationException>(() => BearerOf(connection)));
        Assert.Equal(1, script.Requests);
        Assert.NotEqual(FailureKind.Refused, Failures.Classify(first));
    }

    [Fact]
    public async Task A_vcenter_session_that_expired_mid_scan_signs_in_once_more_and_a_refusal_then_is_final()
    {
        var script = new Script(() => Json("\"session-1\""), () => Json("\"session-2\""), () => Json("{}", HttpStatusCode.Unauthorized));
        using var connection = OAuth(script, "vcenter-session");

        Assert.Equal("session-1", await BearerOf(connection));
        Assert.True(await connection.RenewSessionAsync(CancellationToken.None));
        Assert.Equal("session-2", await BearerOf(connection));
        Assert.Equal(2, script.Requests);

        // The next renewal is refused: the account is not allowed in. That is remembered; nothing signs in again.
        Assert.False(await connection.RenewSessionAsync(CancellationToken.None));
        var refusal = await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        Assert.Equal(FailureKind.Refused, Failures.Classify(refusal));
        Assert.Equal(3, script.Requests);
    }

    [Fact]
    public async Task A_vcenter_session_is_ended_after_the_scan_and_nothing_is_sent_when_none_was_opened()
    {
        var script = new Script(() => Json("\"session-1\""), () => Json("{}", HttpStatusCode.NoContent));
        using var connection = OAuth(script, "vcenter-session");

        await connection.SignOutAsync(CancellationToken.None);       // no session yet: nothing to end
        Assert.Equal(0, script.Requests);

        await BearerOf(connection);
        await connection.SignOutAsync(CancellationToken.None);
        await connection.SignOutAsync(CancellationToken.None);       // once only
        Assert.Equal(["POST /api/session", "DELETE /api/session session-1"], script.Sent);
    }

    [Fact]
    public async Task A_session_login_product_is_signed_out_through_its_logout_path()
    {
        var script = new Script(() => Json("""{ "sid": "s-1" }"""), () => Json("{}"));
        var binding = IntegrationStore.Binding("fw", "password", "https://fw.example.org");
        var record = new IntegrationRecord("fw", "http", "https://fw.example.org", "session-login", "reader",
            new JsonObject { ["loginPath"] = "/web_api/login", ["logoutPath"] = "/web_api/logout", ["tokenField"] = "sid", ["header"] = "X-chkp-sid" }, true,
            new Dictionary<string, StoredSecret> { ["password"] = new("password", _vault.Seal("not-a-real-secret", binding), binding, "2026-11-13T00:00:00Z", null) });
        using var connection = new IntegrationConnection(record, _vault) { SignInHandler = script };
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://fw.example.org/web_api/show-hosts");
        await connection.AuthorizeAsync(request, CancellationToken.None);

        await connection.SignOutAsync(CancellationToken.None);

        Assert.Equal(["POST /web_api/login", "POST /web_api/logout"], script.Sent);
    }

    [Fact]
    public async Task A_busy_sign_in_is_tried_again_once_the_cool_down_is_over()
    {
        var calls = 0;
        var script = new Script(() => ++calls <= 3 ? Json("{}", HttpStatusCode.ServiceUnavailable) : Token("tok-4"));
        using var connection = OAuth(script, cooldown: TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));
        await Assert.ThrowsAsync<SignInException>(() => BearerOf(connection));   // within the cool-down: nothing sent
        Assert.Equal(3, script.Requests);
        await Task.Delay(300);
        Assert.Equal("tok-4", await BearerOf(connection));
    }

    [Fact]
    public async Task Reads_that_fail_together_share_one_new_session()
    {
        var script = new Script(() => Json("\"session-1\""), () => Json("\"session-2\""));
        var binding = IntegrationStore.Binding("app", "password", "https://app.example.org");
        var record = new IntegrationRecord("app", "http", "https://app.example.org", "vcenter-session", "reader", [], true,
            new Dictionary<string, StoredSecret> { ["password"] = new("password", _vault.Seal("not-a-real-secret", binding), binding, "2026-11-13T00:00:00Z", null) });
        using var connection = new IntegrationConnection(record, _vault) { SignInHandler = script };   // the default grace of 30 s

        await BearerOf(connection);
        var renewals = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => connection.RenewSessionAsync(CancellationToken.None)));

        Assert.All(renewals, Assert.True);
        Assert.Equal(1, script.Requests);           // the token was fresh: the four reads retry with it, no new sign-in
    }

    [Fact]
    public async Task A_token_that_is_not_json_is_remembered_rather_than_signing_in_for_every_query()
    {
        var script = new Script(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>login page</html>") });
        using var connection = OAuth(script);

        var first = await Assert.ThrowsAsync<IntegrationException>(() => BearerOf(connection));
        Assert.Same(first, await Assert.ThrowsAsync<IntegrationException>(() => BearerOf(connection)));
        Assert.Equal(1, script.Requests);
    }
}
