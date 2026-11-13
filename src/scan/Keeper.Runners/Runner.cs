using System.Net;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners;

/// <summary>What one query returned: rows, and whether the runner could see everything it asked for.</summary>
public sealed record RunnerResult(IReadOnlyList<JsonObject> Rows, string State, string? Reason)
{
    /// <summary>For a failed read: what kind of failure, so the scan can slow down, skip a host or stop using a credential.</summary>
    public FailureKind Failure { get; init; }

    /// <summary>
    /// The host answered as the account - a registry provider's return code, a bind that succeeded before a search
    /// was refused - so the sign-in itself was accepted, whatever this read's outcome. It proves the credential.
    /// </summary>
    public bool SignedIn { get; init; }

    public static RunnerResult Ok(IReadOnlyList<JsonObject> rows) => new(rows, "ok", null);

    /// <summary>
    /// What an optional read (optional: true) reads is not on this host - no sshd_config, no Docker, no CUPS: no rows,
    /// and nothing to judge. A count rule ("fewer than 1 line that switches passwords off") says nothing about such a
    /// host, where an empty answer from something that IS there would still count.
    /// </summary>
    public bool Absent { get; init; }

    public static RunnerResult NotHere() => new([], "ok", null) { Absent = true };

    public static RunnerResult Partial(IReadOnlyList<JsonObject> rows, string reason) => new(rows, "partial", reason);

    public static RunnerResult Failed(string reason, FailureKind failure = FailureKind.Error) => new([], "failed", reason) { Failure = failure };

    /// <summary>A failed read whose kind is read from the exception that caused it.</summary>
    public static RunnerResult Failed(string reason, Exception cause) => Failed(reason, Failures.Classify(cause));

    /// <summary>The note on an ok answer that was a 404 under missing: empty; for_each counts them.</summary>
    public const string NotFound = "not found (404)";
}

/// <summary>The body field (dotted path) that names the command a POST runs, and the names allowed ('*' within a name).</summary>
public sealed record ReadCommand(string Field, IReadOnlyList<string> Allowed)
{
    /// <summary>Where the body gives the command's parameters (dotted path), for <see cref="DeniedParameters"/>.</summary>
    public string? ParametersField { get; init; }

    /// <summary>
    /// Parameters that make a read command do more than read - mail a log, show an export's credential - and so
    /// are never sent, whatever the case.
    /// </summary>
    public IReadOnlyList<string> DeniedParameters { get; init; } = [];
}

/// <summary>
/// What a runner may use to reach its system: one integration's endpoint and credentials - never
/// another's. Secrets are decrypted on demand and must never be logged.
/// </summary>
public interface IConnection
{
    /// <summary>The integration id, e.g. ad-main.</summary>
    string Instance { get; }

    /// <summary>The integration type, e.g. ldap, graph, servicenow.</summary>
    string Type { get; }

    /// <summary>The endpoint as configured: a URL, a host, or a domain name.</summary>
    string Endpoint { get; }

    string AuthKind { get; }

    /// <summary>The account or application the integration reads as. Not a secret.</summary>
    string? Identity { get; }

    /// <summary>
    /// Who the system actually saw, once known: the account a token was issued to, or the Windows user a
    /// negotiate sign-in runs as. Null until known, or when it is simply <see cref="Identity"/>.
    /// </summary>
    string? SignedInAs => null;

    /// <summary>
    /// Who signs in, as a message names it: the identity, else the app registration (a certificate sign-in reads as
    /// the app, never as a person), else the user Keeper runs as. Wording only; nothing is recorded under it.
    /// </summary>
    string Who => Identity ?? (AuthKind == "entra-certificate" ? "the app registration" : "the current user");

    /// <summary>
    /// Paths (relative to the endpoint, '*' within one segment) where this integration's type answers a POST
    /// as a read - Check Point's show- commands, Azure Resource Graph queries. Nowhere else does a rule POST.
    /// </summary>
    IReadOnlyList<string> ReadPosts => [];

    /// <summary>
    /// When not empty, the only paths (same patterns, the whole path on the host) a rule may read through this
    /// integration at all - Key Vault's lists and metadata, never the path that returns a secret's value.
    /// </summary>
    IReadOnlyList<string> ReadPaths => [];

    /// <summary>
    /// For an API whose POSTs run named commands (Exchange Online's InvokeCommand): the body field that names
    /// the command and the names it may be ('*' within the name) - Get-* only. Null: the type runs no commands.
    /// </summary>
    ReadCommand? ReadCommand => null;

    /// <summary>The protocols the integration's type offers, or null when it says nothing (a test's fake).</summary>
    IReadOnlyList<string>? Protocols => null;

    /// <summary>
    /// Why this integration's endpoint may not be used as it is stored, or null - a guarded type's endpoint with
    /// a path its type does not allow, saved before the check existed or by another route.
    /// </summary>
    string? EndpointProblem => null;

    /// <summary>Non-secret options (scopes, header names, TLS mode, targets).</summary>
    JsonObject Options { get; }

    /// <summary>A stored secret, decrypted now. Null when not set.</summary>
    string? Secret(string name);

    /// <summary>A stored Windows credential, or null to use the current user (Kerberos/NTLM).</summary>
    NetworkCredential? WindowsCredential();

    /// <summary>An HTTP handler for this integration: no automatic redirects, and Windows credentials when the auth needs them.</summary>
    HttpMessageHandler CreateHttpHandler();

    /// <summary>Adds the integration's credentials to a request: bearer token, API key, session.</summary>
    Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken);
}

public sealed record RunnerContext(
    IConnection Connection,
    string? Target,
    string ImportsDir,
    string? StoreFile,
    DateTimeOffset Now,
    TimeSpan Timeout,
    Action<string> Log)
{
    /// <summary>A tenant threshold by name (setting threshold.&lt;name&gt;), for requests that name one: {DAYS_AGO:threshold.x|90}.</summary>
    public Func<string, string?> Threshold { get; init; } = _ => null;

    /// <summary>The host's pace: await it before each network request, and signal what answers said. No pacing outside a scan.</summary>
    public IPace Pace { get; init; } = NoPace.Instance;
}

/// <summary>A read-only way to get rows from one kind of system. Runners never write.</summary>
public interface IRunner
{
    string Protocol { get; }

    /// <summary>True when the runner reads one host at a time (targets).</summary>
    bool PerTarget { get; }

    /// <summary>Whether a query through this integration reads one host at a time; usually what <see cref="PerTarget"/> says.</summary>
    bool IsPerTarget(IConnection connection) => PerTarget;

    /// <summary>Whether a query through this integration goes over the network, so the scan's pace applies. False for local files and the store.</summary>
    bool IsRemote(IConnection connection) => true;

    /// <summary>
    /// Whether "access denied" from this runner can be a wrong password. Over DCOM it can: a bad logon comes back as
    /// plain access denied. Elsewhere (HTTP 403, LDAP 50, SQL 229) the sign-in was accepted and one object is closed.
    /// </summary>
    bool DeniedMayBeSignIn => false;

    /// <summary>Checks a query's protocol-specific fields when the rule file is loaded.</summary>
    IEnumerable<string> Validate(QuerySpec query);

    Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken);
}

public sealed class RunnerRegistry
{
    private readonly Dictionary<string, IRunner> _runners = new(StringComparer.Ordinal);

    public RunnerRegistry(IEnumerable<IRunner> runners)
    {
        foreach (var runner in runners)
        {
            if (!_runners.TryAdd(runner.Protocol, runner))
                throw new ArgumentException($"Two runners for '{runner.Protocol}'.");
        }
    }

    public IRunner Get(string protocol) =>
        _runners.TryGetValue(protocol, out var runner) ? runner : throw new KeyNotFoundException($"No runner for '{protocol}'.");

    public IReadOnlyDictionary<string, QueryValidator> Validators =>
        _runners.ToDictionary(r => r.Key, r => (QueryValidator)r.Value.Validate, StringComparer.Ordinal);

    public IReadOnlyCollection<string> Protocols => _runners.Keys;
}
