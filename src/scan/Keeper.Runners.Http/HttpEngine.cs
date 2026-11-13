using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Runners.Http;

/// <summary>
/// The HTTP plumbing every web runner shares. Requests only ever go to the integration's own host
/// (pinned), redirects are never followed, plain http needs the integration to allow it explicitly,
/// responses are size-capped, and 429/503 are retried after the server's Retry-After.
/// </summary>
public sealed class HttpEngine : IDisposable
{
    public const long MaxResponseBytes = 64L * 1024 * 1024;
    private const int MaxRetries = 3;

    private readonly HttpClient _client;

    private HttpEngine(Uri endpoint, HttpClient client)
    {
        Endpoint = endpoint;
        _client = client;
    }

    public Uri Endpoint { get; }

    /// <summary>Opens the engine, or explains why the endpoint is not acceptable.</summary>
    public static HttpEngine Open(RunnerContext context, string? defaultEndpoint = null)
    {
        var text = string.IsNullOrWhiteSpace(context.Connection.Endpoint) ? defaultEndpoint : context.Connection.Endpoint;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var endpoint) || endpoint.Scheme is not ("https" or "http"))
            throw new HttpRequestException($"The integration endpoint '{text}' is not an http(s) URL.");
        if (endpoint.Scheme == "http" && context.Connection.Options["allowHttp"]?.ToString() != "true")
            throw new HttpRequestException($"{endpoint.Host}: plain http would send credentials in the clear; set the integration option allowHttp to true to accept that.");
        if (!string.IsNullOrEmpty(endpoint.UserInfo))
            throw new HttpRequestException("The integration endpoint must not carry credentials in the URL.");

        // One client for the whole scan of this endpoint, so TLS and NTLM/Negotiate are negotiated once. Its own
        // timeout is off: each request carries the timeout of the query that sends it (see SendAsync), because the
        // client is shared by queries whose timeouts may differ and cannot be changed after the first request.
        var client = new HttpClient(new HostPinningHandler(endpoint, context.Connection.CreateHttpHandler()))
        {
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = MaxResponseBytes,
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Keeper", "1"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.5));
        return new HttpEngine(endpoint, client);
    }

    /// <summary>The endpoint's own path, then the rule's path: https://host/AdminService + /wmi/SMS_R_System.</summary>
    public Uri Build(string path, IEnumerable<KeyValuePair<string, string>>? parameters = null)
    {
        var basePath = Endpoint.AbsolutePath.TrimEnd('/');
        var builder = new UriBuilder(Endpoint) { Path = basePath + path.Split('?')[0] };
        var query = new List<string>();
        if (path.Contains('?'))
            query.Add(path[(path.IndexOf('?') + 1)..]);
        foreach (var (name, value) in parameters ?? [])
            query.Add($"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}");
        builder.Query = string.Join("&", query.Where(q => q.Length > 0));
        return builder.Uri;
    }

    /// <summary>True when <paramref name="uri"/> is on the integration's own scheme, host and port.</summary>
    public bool IsOwn(Uri uri) =>
        uri.Scheme.Equals(Endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
        && uri.Host.Equals(Endpoint.Host, StringComparison.OrdinalIgnoreCase)
        && uri.Port == Endpoint.Port;

    public Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> GetAsync(RunnerContext context, bool pace, Uri uri,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken) =>
        JsonAsync(context, pace, () => new HttpRequestMessage(HttpMethod.Get, uri), headers, cancellationToken);

    /// <summary>POST is only for protocols whose reads are POSTs (GraphQL queries).</summary>
    public Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> PostJsonAsync(RunnerContext context, bool pace, Uri uri, JsonObject body,
        CancellationToken cancellationToken) =>
        JsonAsync(context, pace, () => new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        }, null, cancellationToken);

    /// <summary>
    /// The answer as text, with every header it carried (the content's too): a GET, or a POST with a JSON body.
    /// The caller has checked that the POST is a read its integration type allows (<see cref="IConnection.ReadPosts"/>).
    /// </summary>
    public Task<(string Text, IReadOnlyDictionary<string, string> Headers)> SendTextAsync(RunnerContext context, bool pace, HttpMethod method, Uri uri,
        JsonObject? body, IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken) =>
        SendAsync(context, pace, () => new HttpRequestMessage(method, uri)
        {
            Content = body is null ? null : new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        }, headers, cancellationToken);

    /// <summary>
    /// A URL's path relative to the endpoint's own path - what a rule names and an allow-list matches - or null
    /// when the URL is outside the endpoint's path altogether (https://host/mgmt has nothing at /web_api).
    /// </summary>
    public string? Relative(Uri uri)
    {
        var basePath = Endpoint.AbsolutePath.TrimEnd('/');
        if (basePath.Length == 0)
            return uri.AbsolutePath;
        return uri.AbsolutePath.StartsWith(basePath + "/", StringComparison.Ordinal) ? uri.AbsolutePath[basePath.Length..] : null;
    }

    /// <summary>A next-page URL as an answer gives it: absolute, or relative to the endpoint. Null when it is neither.</summary>
    public Uri? Resolve(string? link) =>
        string.IsNullOrWhiteSpace(link) ? null
        : Uri.TryCreate(link, UriKind.Absolute, out var absolute) && absolute.Scheme is "https" or "http" ? absolute
        : Uri.TryCreate(Endpoint, link, out var relative) ? relative
        : null;

    private async Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> JsonAsync(RunnerContext context, bool pace, Func<HttpRequestMessage> create,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken)
    {
        var (text, responseHeaders) = await SendAsync(context, pace, create, headers, cancellationToken).ConfigureAwait(false);
        return (text.Length == 0 ? null : RowValues.Parse(text) ?? throw new HttpRequestException($"{Endpoint.Host} did not answer with JSON."), responseHeaders);
    }

    /// <summary>
    /// One request, with its retries. <paramref name="pace"/> is false only for the first request of a query (the
    /// scanner has already waited for it); every further request - another page, a for_each child, a retry - waits
    /// for the host's pace first. The query's timeout applies to each request on its own.
    /// </summary>
    private async Task<(string Text, IReadOnlyDictionary<string, string> Headers)> SendAsync(RunnerContext context, bool pace,
        Func<HttpRequestMessage> create, IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken)
    {
        var renewed = false;
        for (var attempt = 1; ; attempt++)
        {
            if (pace || attempt > 1 || renewed)
                await context.Pace.WaitAsync(cancellationToken).ConfigureAwait(false);

            using var request = create();
            foreach (var (name, value) in headers ?? new Dictionary<string, string>())
                request.Headers.TryAddWithoutValidation(name, value);
            await context.Connection.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);

            // The timeout belongs to this request, not to the shared client. A caller's cancellation is not a timeout:
            // only our own timer firing becomes a TimeoutException.
            using var timer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timer.CancelAfter(context.Timeout);
            HttpResponseMessage response;
            try
            {
                response = await _client.SendAsync(request, timer.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"{Endpoint.Host} did not answer within {context.Timeout.TotalSeconds:0} s.");
            }
            using (response)
            {
                var status = (int)response.StatusCode;

                if (status is 429 or 503 && attempt < MaxRetries)
                {
                    var wait = RetryDelay(response.Headers.RetryAfter, DateTimeOffset.UtcNow, attempt);
                    context.Log($"{Endpoint.Host}: {status}, retrying in {wait.TotalSeconds:0} s");
                    context.Pace.Signal(FailureKind.Throttled);
                    await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                // A 401 on a session token (the session expired mid-scan) signs in once more; a second 401 is a refusal.
                if (status == 401 && !renewed && context.Connection is ISessionTokenConnection session
                    && await session.RenewSessionAsync(cancellationToken).ConfigureAwait(false))
                {
                    renewed = true;
                    attempt--;
                    continue;
                }
                if (status is >= 300 and < 400)
                    throw new HttpRequestException($"{Endpoint.Host} answered {status} (redirect to {response.Headers.Location}); redirects are not followed.");
                if (!response.IsSuccessStatusCode)
                {
                    var detail = await ReadAsync(response, timer, cancellationToken).ConfigureAwait(false);
                    throw new HttpRequestException(
                        $"{Endpoint.Host} answered {status} {response.ReasonPhrase}: {Keeper.Common.Redactor.Clean(Truncate(detail, 300))}",
                        null, response.StatusCode);
                }

                var all = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var (name, values) in response.Headers.Concat(response.Content.Headers))
                    all[name] = string.Join(", ", values);
                return (await ReadAsync(response, timer, cancellationToken).ConfigureAwait(false), all);
            }
        }
    }

    private async Task<string> ReadAsync(HttpResponseMessage response, CancellationTokenSource timer, CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadAsStringAsync(timer.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"{Endpoint.Host} did not finish its answer in time.");
        }
    }

    /// <summary>
    /// How long to wait after a 429 or 503: the server's Retry-After (seconds or an HTTP date), else 2 s times the
    /// attempt. At least 1 s - a "Retry-After: 0" is still a request to slow down - and at most 60 s.
    /// </summary>
    public static TimeSpan RetryDelay(System.Net.Http.Headers.RetryConditionHeaderValue? retryAfter, DateTimeOffset now, int attempt)
    {
        var wait = retryAfter?.Delta ?? (retryAfter?.Date is { } date ? date - now : TimeSpan.FromSeconds(2 * attempt));
        if (wait < TimeSpan.FromSeconds(1))
            wait = TimeSpan.FromSeconds(1);
        return wait > TimeSpan.FromSeconds(60) ? TimeSpan.FromSeconds(60) : wait;
    }

    /// <summary>
    /// The rel="next" target of a Link header (RFC 8288), as written: &lt;url&gt;; rel="next", ... - the URL is
    /// read between its angle brackets, so a comma inside it does not split it. Null when there is no next link.
    /// </summary>
    public static string? NextLink(string? link) => NextLink(link, out _);

    /// <param name="malformed">The header could not be read (an unclosed &lt;): the caller cannot tell whether a next page exists.</param>
    public static string? NextLink(string? link, out bool malformed)
    {
        malformed = false;
        if (string.IsNullOrEmpty(link))
            return null;
        for (var start = link.IndexOf('<', StringComparison.Ordinal); start >= 0;)
        {
            var end = link.IndexOf('>', start + 1);
            if (end < 0)
            {
                malformed = true;
                return null;
            }
            var target = link[(start + 1)..end];
            var next = link.IndexOf('<', end + 1);
            var parameters = next < 0 ? link[(end + 1)..] : link[(end + 1)..next];
            // rel is a list of tokens: rel="next last" names the next page too.
            if (parameters.Split(';', StringSplitOptions.TrimEntries)
                .Select(p => p.Trim(',', ' '))
                .Where(p => p.Contains('=', StringComparison.Ordinal) && p[..p.IndexOf('=', StringComparison.Ordinal)].Trim().Equals("rel", StringComparison.OrdinalIgnoreCase))
                .Select(p => p[(p.IndexOf('=', StringComparison.Ordinal) + 1)..].Trim().Trim('"'))
                .Any(value => value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("next", StringComparer.OrdinalIgnoreCase)))
                return target;
            start = next;
        }
        return null;
    }

    public static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "...";

    public static string Reason(Exception ex) => ex switch
    {
        HttpRequestException { StatusCode: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden } h =>
            $"access denied ({(int)h.StatusCode!}): the integration's identity lacks a permission. {h.Message}",
        TimeoutException => $"timed out: {ex.Message}",
        TaskCanceledException => "timed out",
        _ => ex.Message,
    };

    /// <summary>The failed result for an exception a read met: its message, and the kind <see cref="Failures.Classify"/> reads from it.</summary>
    public static RunnerResult Failure(Exception ex) => RunnerResult.Failed(Reason(ex), ex);

    /// <summary>The exceptions a read turns into a failed result. A caller's cancellation is never one of them.</summary>
    public static bool IsReadFailure(Exception ex, CancellationToken cancellationToken) =>
        !cancellationToken.IsCancellationRequested
        && ex is HttpRequestException or TimeoutException or TaskCanceledException or UnauthorizedAccessException or InvalidOperationException or RunnerFailureException;

    public void Dispose() => _client.Dispose();

    public static IEnumerable<KeyValuePair<string, string>> Parameters(JsonNode? node) =>
        node is JsonObject map
            ? map.Where(p => p.Value is not null).Select(p => KeyValuePair.Create(p.Key, Convert.ToString(Keeper.Rules.Values.Text(p.Value), CultureInfo.InvariantCulture) ?? ""))
            : [];
}

/// <summary>
/// The session of the http, graph and graphql runners: one <see cref="HttpEngine"/> per endpoint of one
/// integration for the whole scan, so the connection, TLS and any NTLM/Negotiate handshake are made once and
/// every query - and every for_each child - goes over it. Opening a session sends nothing; the engine is made
/// by the first query that names its endpoint.
/// </summary>
public sealed class HttpSession : IRunnerSession
{
    private readonly Dictionary<string, HttpEngine> _engines = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private bool _disposed;

    /// <summary>How many engines (HTTP clients) this session made: one per endpoint, however many queries ran.</summary>
    public int EnginesOpened
    {
        get
        {
            lock (_lock)
                return _engines.Count;
        }
    }

    /// <summary>The engine for the integration's endpoint (or the runner's default when none is set), made on first use.</summary>
    public HttpEngine Engine(RunnerContext context, string? defaultEndpoint = null)
    {
        var key = string.IsNullOrWhiteSpace(context.Connection.Endpoint) ? defaultEndpoint ?? "" : context.Connection.Endpoint;
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_engines.TryGetValue(key, out var engine))
                _engines[key] = engine = HttpEngine.Open(context, defaultEndpoint);
            return engine;
        }
    }

    public static HttpSession Of(IRunnerSession session) =>
        session as HttpSession ?? throw new InvalidOperationException("this runner was given a session that is not an http session");

    public ValueTask DisposeAsync()
    {
        lock (_lock)
        {
            _disposed = true;
            foreach (var engine in _engines.Values)
                engine.Dispose();
            _engines.Clear();
        }
        return ValueTask.CompletedTask;
    }
}
