using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Tests;

/// <summary>Serves canned responses by URL; records every request it saw.</summary>
internal sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return Task.FromResult(respond(request));
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}

internal sealed class FakeConnection(string endpoint, HttpMessageHandler? handler = null, JsonObject? options = null,
    IReadOnlyList<string>? readPosts = null, IReadOnlyList<string>? readPaths = null, ReadCommand? readCommand = null) : IConnection
{
    public string Instance => "test";
    public string Type => "test";
    public IReadOnlyList<string> ReadPosts => readPosts ?? [];
    public IReadOnlyList<string> ReadPaths => readPaths ?? [];
    public ReadCommand? ReadCommand => readCommand;
    public string Endpoint => endpoint;
    public string AuthKind => "bearer";
    public string? Identity => "reader@example.org";
    public JsonObject Options { get; } = options ?? [];
    public string? Secret(string name) => name == "token" ? "test-token" : null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => handler ?? new HttpClientHandler { AllowAutoRedirect = false };

    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "test-token");
        return Task.CompletedTask;
    }
}

internal static class Context
{
    public static readonly DateTimeOffset Now = new(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

    public static RunnerContext For(IConnection connection, string? target = null, string? imports = null, string? store = null) =>
        new(connection, target, imports ?? Path.GetTempPath(), store, Now, TimeSpan.FromSeconds(10), _ => { });

    public static QuerySpec Query(string protocol, string key, params (string Name, JsonNode? Value)[] fields)
    {
        var json = new JsonObject();
        foreach (var (name, value) in fields)
            json[name] = value?.Parent is null ? value : value.DeepClone();
        return new QuerySpec(protocol, json, key, null);
    }
}
