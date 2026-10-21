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
    private readonly RunnerContext _context;

    private HttpEngine(Uri endpoint, RunnerContext context, HttpClient client)
    {
        Endpoint = endpoint;
        _context = context;
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

        var client = new HttpClient(new HostPinningHandler(endpoint, context.Connection.CreateHttpHandler()))
        {
            Timeout = context.Timeout,
            MaxResponseContentBufferSize = MaxResponseBytes,
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Keeper", "1"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.5));
        return new HttpEngine(endpoint, context, client);
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

    public Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> GetAsync(Uri uri, IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken) =>
        JsonAsync(() => new HttpRequestMessage(HttpMethod.Get, uri), headers, cancellationToken);

    /// <summary>POST is only for protocols whose reads are POSTs (GraphQL queries).</summary>
    public Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> PostJsonAsync(Uri uri, JsonObject body, CancellationToken cancellationToken) =>
        JsonAsync(() => new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        }, null, cancellationToken);

    /// <summary>
    /// The answer as text, with every header it carried (the content's too): a GET, or a POST with a JSON body.
    /// The caller has checked that the POST is a read its integration type allows (<see cref="IConnection.ReadPosts"/>).
    /// </summary>
    public Task<(string Text, IReadOnlyDictionary<string, string> Headers)> SendTextAsync(HttpMethod method, Uri uri, JsonObject? body,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken) =>
        SendAsync(() => new HttpRequestMessage(method, uri)
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

    private async Task<(JsonNode? Body, IReadOnlyDictionary<string, string> Headers)> JsonAsync(Func<HttpRequestMessage> create,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken)
    {
        var (text, responseHeaders) = await SendAsync(create, headers, cancellationToken).ConfigureAwait(false);
        return (text.Length == 0 ? null : RowValues.Parse(text) ?? throw new HttpRequestException($"{Endpoint.Host} did not answer with JSON."), responseHeaders);
    }

    private async Task<(string Text, IReadOnlyDictionary<string, string> Headers)> SendAsync(Func<HttpRequestMessage> create,
        IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var request = create();
            foreach (var (name, value) in headers ?? new Dictionary<string, string>())
                request.Headers.TryAddWithoutValidation(name, value);
            await _context.Connection.AuthorizeAsync(request, cancellationToken).ConfigureAwait(false);

            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var status = (int)response.StatusCode;

            if (status is 429 or 503 && attempt < MaxRetries)
            {
                var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(2 * attempt);
                if (wait > TimeSpan.FromSeconds(60))
                    wait = TimeSpan.FromSeconds(60);
                _context.Log($"{Endpoint.Host}: {status}, retrying in {wait.TotalSeconds:0} s");
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (status is >= 300 and < 400)
                throw new HttpRequestException($"{Endpoint.Host} answered {status} (redirect to {response.Headers.Location}); redirects are not followed.");
            if (!response.IsSuccessStatusCode)
            {
                var detail = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                throw new HttpRequestException(
                    $"{Endpoint.Host} answered {status} {response.ReasonPhrase}: {Keeper.Common.Redactor.Clean(Truncate(detail, 300))}",
                    null, response.StatusCode);
            }

            var all = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, values) in response.Headers.Concat(response.Content.Headers))
                all[name] = string.Join(", ", values);
            return (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false), all);
        }
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
        TaskCanceledException => "timed out",
        _ => ex.Message,
    };

    public void Dispose() => _client.Dispose();

    public static IEnumerable<KeyValuePair<string, string>> Parameters(JsonNode? node) =>
        node is JsonObject map
            ? map.Where(p => p.Value is not null).Select(p => KeyValuePair.Create(p.Key, Convert.ToString(Keeper.Rules.Values.Text(p.Value), CultureInfo.InvariantCulture) ?? ""))
            : [];
}
