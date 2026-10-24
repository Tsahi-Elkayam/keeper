using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Http;

namespace Keeper.Scan.Tests;

public sealed class KubernetesPackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-k8s-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class Answers(Func<string, string?> respond) : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            var body = respond(request.RequestUri.AbsolutePath);
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private sealed class Cluster(HttpMessageHandler handler) : IConnection
    {
        public string Instance => "prod-cluster";
        public string Type => "kubernetes";
        public string Endpoint => "https://k8s.example.org:6443";
        public string AuthKind => "bearer";
        public string? Identity => null;
        public IReadOnlyList<string>? Protocols => IntegrationTypes.Find("kubernetes")!.Protocols;
        public IReadOnlyList<string> ReadPaths => IntegrationTypes.Find("kubernetes")!.ReadPaths;
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => name == "token" ? "service-account-token" : null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => handler;

        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "service-account-token");
            return Task.CompletedTask;
        }
    }

    private static string List(params object[] items) => new JsonObject { ["kind"] = "List", ["metadata"] = new JsonObject(), ["items"] = JsonSerializer(items) }.ToJsonString();

    private static JsonNode JsonSerializer(object[] items) => JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(items))!;

    private static object Pod(string name, string ns, object? container = null, object? spec = null, object[]? volumes = null) => new
    {
        metadata = new { uid = "uid-" + name, name, @namespace = ns },
        spec = new Dictionary<string, object?>
        {
            ["containers"] = new[] { container ?? Good() },
            ["volumes"] = volumes ?? [],
            ["hostNetwork"] = (spec as Dictionary<string, object>)?.GetValueOrDefault("hostNetwork"),
        },
    };

    private static Dictionary<string, object?> Good() => new()
    {
        ["name"] = "app", ["image"] = "registry.example.org:5000/team/app@sha256:0123456789abcdef",
        ["resources"] = new { limits = new { memory = "128Mi" } },
    };

    private static Dictionary<string, object?> With(string key, object? value, string? image = null)
    {
        var container = Good();
        container[key] = value;
        if (image is not null)
            container["image"] = image;
        return container;
    }

    private string Respond(string path) => path switch
    {
        "/api/v1/pods" => List(
            Pod("good", "app"),
            Pod("priv", "app", With("securityContext", new { privileged = true })),
            Pod("priv-system", "kube-system", With("securityContext", new { privileged = true })),
            Pod("hostnet", "app", spec: new Dictionary<string, object> { ["hostNetwork"] = true }),
            Pod("sock", "app", volumes: [new { name = "d", hostPath = new { path = "/var/run/docker.sock" } }]),
            Pod("hostpath", "app", volumes: [new { name = "d", hostPath = new { path = "/data" } }]),
            Pod("caps", "app", With("securityContext", new { capabilities = new { add = new[] { "NET_BIND_SERVICE", "SYS_ADMIN" } } })),
            Pod("harmless-cap", "app", With("securityContext", new { capabilities = new { add = new[] { "NET_BIND_SERVICE" } } })),
            Pod("root", "app", With("securityContext", new { runAsUser = 0 })),
            Pod("latest", "app", With("name", "app", "nginx:latest")),
            Pod("untagged", "app", With("name", "app", "registry.example.org:5000/team/app")),
            Pod("tagged", "app", With("name", "app", "registry.example.org:5000/team/app:1.4.2")),
            Pod("nolimit", "app", With("resources", new { }))),
        "/api/v1/nodes" => List(
            new { metadata = new { uid = "uid-n1", name = "n1" }, status = new { conditions = new[] { new { type = "Ready", status = "True" } } } },
            new { metadata = new { uid = "uid-n2", name = "n2" }, status = new { conditions = new[] { new { type = "Ready", status = "False" } } } }),
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" => List(
            new { metadata = new { uid = "uid-crb-default", name = "cluster-admin" }, roleRef = new { name = "cluster-admin" }, subjects = new[] { new { kind = "Group", name = "system:masters" } } },
            new { metadata = new { uid = "uid-crb-kubeadm", name = "kubeadm:cluster-admins" }, roleRef = new { name = "cluster-admin" }, subjects = new[] { new { kind = "Group", name = "kubeadm:cluster-admins" } } },
            new { metadata = new { uid = "uid-crb-dev", name = "dev-admins" }, roleRef = new { name = "cluster-admin" }, subjects = new[] { new { kind = "Group", name = "developers" } } },
            new { metadata = new { uid = "uid-crb-anon", name = "open-view" }, roleRef = new { name = "view" }, subjects = new[] { new { kind = "User", name = "system:unauthenticated" } } },
            new { metadata = new { uid = "uid-crb-public", name = "system:public-info-viewer" }, roleRef = new { name = "system:public-info-viewer" }, subjects = new[] { new { kind = "Group", name = "system:unauthenticated" } } }),
        "/apis/rbac.authorization.k8s.io/v1/clusterroles" => List(
            new { metadata = new { uid = "uid-cr-star", name = "everything" }, rules = new[] { new { verbs = new[] { "*" }, resources = new[] { "*" } } } },
            new { metadata = new { uid = "uid-cr-admin", name = "cluster-admin" }, rules = new[] { new { verbs = new[] { "*" }, resources = new[] { "*" } } } },
            new { metadata = new { uid = "uid-cr-reader", name = "reader" }, rules = new[] { new { verbs = new[] { "get", "list" }, resources = new[] { "pods" } } } }),
        _ => throw new InvalidOperationException("Keeper asked for " + path),
    };

    private async Task<(List<FindingRecord> Findings, Answers Answers, string Status)> Scan()
    {
        var answers = new Answers(path => Respond(path));
        var registry = new RunnerRegistry([new HttpRunner()]);
        var file = RuleLoader.LoadFile(Path.Combine(FindRepoRoot(), "rules", "kubernetes.yaml"), "builtin", registry.Validators);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [file],
            Connection = new Cluster(answers),
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
        }, CancellationToken.None);
        var findingsFile = Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings);
        return (File.Exists(findingsFile) ? JsonLines.Read<FindingRecord>(findingsFile).ToList() : [], answers, report.Manifest.Status);
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private static string[] Flagged(List<FindingRecord> findings, string rule) =>
        [.. findings.Where(f => f.RuleId == rule).Select(f => f.Target ?? "").Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Every_rule_flags_what_it_should_and_leaves_the_rest_alone()
    {
        var (findings, _, status) = await Scan();

        Assert.Equal("ok", status);
        Assert.Equal(["uid-priv"], Flagged(findings, "K8S-POD-PRIVILEGED"));                       // not the kube-system one
        Assert.Equal(["uid-hostnet"], Flagged(findings, "K8S-POD-HOST-NAMESPACE"));
        Assert.Equal(["uid-sock"], Flagged(findings, "K8S-POD-RUNTIME-SOCKET"));
        Assert.Equal(["uid-hostpath"], Flagged(findings, "K8S-POD-HOSTPATH"));                     // the socket pod is the socket rule's
        Assert.Equal(["uid-caps"], Flagged(findings, "K8S-POD-DANGEROUS-CAPABILITIES"));           // NET_BIND_SERVICE alone is harmless
        Assert.Equal(["uid-root"], Flagged(findings, "K8S-POD-RUNS-AS-ROOT"));
        Assert.Equal(["uid-latest", "uid-untagged"], Flagged(findings, "K8S-POD-IMAGE-NOT-PINNED")); // a tag with a registry port, or a digest, is pinned
        Assert.Equal(["uid-nolimit"], Flagged(findings, "K8S-POD-NO-MEMORY-LIMIT"));
        Assert.Equal(["uid-n2"], Flagged(findings, "K8S-NODE-NOT-READY"));
        Assert.Equal(["uid-crb-dev"], Flagged(findings, "K8S-RBAC-CLUSTER-ADMIN-BINDING"));        // not the built-in or kubeadm ones
        Assert.Equal(["uid-crb-anon"], Flagged(findings, "K8S-RBAC-ANONYMOUS-ACCESS"));           // not public-info-viewer
        Assert.Equal(["uid-cr-star"], Flagged(findings, "K8S-RBAC-WILDCARD-ROLE"));                // not cluster-admin
    }

    [Fact]
    public async Task Keeper_only_ever_reads_the_allowed_lists_and_never_asks_for_secrets()
    {
        var (_, answers, _) = await Scan();

        var allowed = IntegrationTypes.Find("kubernetes")!.ReadPaths;
        Assert.NotEmpty(answers.Paths);
        Assert.All(answers.Paths, p => Assert.Contains(p, allowed));
        Assert.DoesNotContain(answers.Paths, p => p.Contains("secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task A_rule_that_asks_for_secrets_is_refused_before_anything_is_sent()
    {
        var answers = new Answers(_ => "{\"items\":[]}");
        var registry = new RunnerRegistry([new HttpRunner()]);
        var result = await new HttpRunner().RunAsync(
            new QuerySpec("http", new JsonObject { ["path"] = "/api/v1/secrets", ["items"] = "items" }, "metadata.uid", null),
            new RunnerContext(new Cluster(answers), null, _dir, null, DateTimeOffset.UtcNow, TimeSpan.FromSeconds(10), _ => { }), CancellationToken.None);

        Assert.Equal("failed", result.State);
        Assert.Empty(answers.Paths);
        _ = registry;
    }
}
