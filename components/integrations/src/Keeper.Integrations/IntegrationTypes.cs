using System.Text.RegularExpressions;

namespace Keeper.Integrations;

/// <summary>
/// A kind of system Keeper reads: the protocols its rules may use, the ways it may authenticate, and -
/// for SaaS - the hosts its endpoint may point at, so a stored credential can only ever go there.
/// </summary>
public sealed record IntegrationType(
    string Id,
    string Description,
    IReadOnlyList<string> Protocols,
    IReadOnlyList<string> AuthKinds,
    IReadOnlyList<string> AllowedHosts,
    string? DefaultEndpoint = null)
{
    /// <summary>Paths (relative to the endpoint, '*' within a segment) where this type's API answers a POST as a read.</summary>
    public IReadOnlyList<string> ReadPosts { get; init; } = [];

    /// <summary>When not empty, the only paths a rule may read at all, whole paths on the host (Key Vault: lists and metadata, never a value).</summary>
    public IReadOnlyList<string> ReadPaths { get; init; } = [];

    /// <summary>
    /// The path an endpoint may have ('*' for one segment), for a type that limits what is read or POSTed: no
    /// path (null), or Exchange's /adminapi/beta/&lt;tenant&gt;. Its read lists are relative to it, so it is fixed.
    /// </summary>
    public string? EndpointPath { get; init; }

    /// <summary>Whether the type limits its reads, so its endpoint's path is held to <see cref="EndpointPath"/>.</summary>
    public bool Guarded => ReadPosts.Count > 0 || ReadPaths.Count > 0 || ReadCommand is not null;

    public bool AllowsEndpointPath(string path)
    {
        var segments = path.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var expected = (EndpointPath ?? "").Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length == expected.Length && segments.Zip(expected).All(p => p.Second == "*"
            ? p.First.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_') && p.First.Trim('.').Length > 0
            : p.First.Equals(p.Second, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>For an API whose POSTs run named commands: where the body names it, and the names allowed.</summary>
    public Keeper.Runners.ReadCommand? ReadCommand { get; init; }

    /// <summary>
    /// The Entra resource its tokens are for, when that is not the endpoint's own host: Defender's regional
    /// hosts share one, Key Vault's vaults share one, Power Platform's admin APIs use service.powerapps.com.
    /// </summary>
    public string? Resource { get; init; }

    /// <summary>The tenant file that added this type; null for a built-in type.</summary>
    public string? Source { get; init; }

    public bool AllowsHost(string host) =>
        AllowedHosts.Count == 0 || AllowedHosts.Any(pattern =>
            pattern.StartsWith("*.", StringComparison.Ordinal)
                ? host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase) && host.Length > pattern.Length - 1
                : host.Equals(pattern, StringComparison.OrdinalIgnoreCase));
}

public static partial class IntegrationTypes
{
    /// <summary>Auth kinds and the secrets each one needs.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> SecretsFor = new Dictionary<string, IReadOnlyList<string>>
    {
        ["none"] = [],
        ["negotiate"] = [],
        ["windows-credential"] = ["password"],
        ["basic"] = ["password"],
        ["bearer"] = ["token"],
        ["api-key-header"] = ["token"],
        ["api-key-query"] = ["token"],
        ["oauth-client-credentials"] = ["clientSecret"],
        ["oauth-password"] = ["password"],
        ["vcenter-session"] = ["password"],
        ["session-login"] = ["password"],
        ["entra-interactive"] = [],
        ["entra-certificate"] = [],
        ["aws-access-key"] = ["secretAccessKey"],
        ["aws-assume-role"] = ["secretAccessKey"],
        ["gcp-service-account"] = ["privateKey"],
        ["snmp-v3"] = ["authPassword", "privPassword"],
        ["snmp-v2c"] = ["community"],
        ["ssh-key"] = ["privateKey", "passphrase"],
        ["ssh-password"] = ["password"],
    };

    private static readonly Lazy<IReadOnlyList<IntegrationType>> BuiltInTypes = new(IntegrationTypeCatalog.BuiltIn);
    private static IReadOnlyList<IntegrationType> _tenant = [];

    /// <summary>The built-in types (integration-types.yaml), then the tenant's own.</summary>
    public static IReadOnlyList<IntegrationType> BuiltIn => BuiltInTypes.Value;

    public static IReadOnlyList<IntegrationType> All => [.. BuiltInTypes.Value, .. _tenant];

    public static IntegrationType? Find(string id) => All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Adds the types a tenant defines in <paramref name="folder"/> (settings/integration-types/*.yaml), replacing those
    /// a folder gave before. A missing folder adds none. A file that is not valid stops the command: an integration of
    /// a type that half-loaded could read more than its author meant.
    /// </summary>
    public static void UseTenantFolder(string folder) =>
        _tenant = IntegrationTypeFiles.Validate(IntegrationTypeFiles.In(folder).Select(file => (file, File.ReadAllText(file))));

    /// <summary>
    /// Whether an integration of type <paramref name="integrationType"/> can run rules written for <paramref name="ruleType"/>.
    /// Rules for the host protocol read the local machine, or each target host of an ssh integration.
    /// </summary>
    public static bool Satisfies(string ruleType, string integrationType) =>
        ruleType.Equals(integrationType, StringComparison.OrdinalIgnoreCase)
        || ruleType.Equals("host", StringComparison.OrdinalIgnoreCase) && integrationType.Equals("ssh", StringComparison.OrdinalIgnoreCase);

    /// <summary>Types that need no configuration: their single implicit instance has the type's own name.</summary>
    public static bool IsImplicit(string id) => id is "files" or "keeper" or "host";

    public static bool IsValidId(string id) => Id().IsMatch(id) && id.Length <= 60;

    [GeneratedRegex("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Id();
}
