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

    public Task<(JsonNode? Body, HttpResponseHeaders Headers)> GetAsync(Uri uri, IReadOnlyDictionary<string, string>? headers, CancellationToken cancellationToken) =>
        SendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri), headers, cancellationToken);

    /// <summary>POST is only for protocols whose reads are POSTs (GraphQL queries).</summary>
    public Task<(JsonNode? Body, HttpResponseHeaders Headers)> PostJsonAsync(Uri uri, JsonObject body, CancellationToken cancellationToken) =>
        SendAsync(() => new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        }, null, cancellationToken);

    private async Task<(JsonNode? Body, HttpResponseHeaders Headers)> SendAsync(Func<HttpRequestMessage> create,
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

            var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return (text.Length == 0 ? null : RowValues.Parse(text) ?? throw new HttpRequestException($"{Endpoint.Host} did not answer with JSON."), response.Headers);
        }
    }

    public static Uri? NextLink(HttpResponseHeaders headers)
    {
        if (!headers.TryGetValues("Link", out var values))
            return null;
        foreach (var part in values.SelectMany(v => v.Split(',')))
        {
            var pieces = part.Split(';', StringSplitOptions.TrimEntries);
            if (pieces.Length > 1 && pieces.Skip(1).Any(p => p.Replace(" ", "", StringComparison.Ordinal).Equals("rel=\"next\"", StringComparison.OrdinalIgnoreCase))
                && Uri.TryCreate(pieces[0].Trim('<', '>'), UriKind.Absolute, out var next))
                return next;
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
