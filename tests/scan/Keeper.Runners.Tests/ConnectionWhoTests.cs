using System.Net;

namespace Keeper.Runners.Tests;

public sealed class ConnectionWhoTests
{
    private sealed class Connection(string auth, string? identity) : IConnection
    {
        public string Instance => "x";
        public string Type => "graph";
        public string Endpoint => "https://graph.microsoft.com";
        public string AuthKind => auth;
        public string? Identity => identity;
        public System.Text.Json.Nodes.JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    [Theory]
    [InlineData("entra-certificate", null, "the app registration")]
    [InlineData("entra-interactive", null, "the current user")]
    [InlineData("negotiate", null, "the current user")]
    [InlineData("entra-certificate", "keeper-reader", "keeper-reader")]
    public void A_message_names_who_signs_in(string auth, string? identity, string expected) =>
        Assert.Equal(expected, ((IConnection)new Connection(auth, identity)).Who);
}
