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
    };

    private static readonly string[] Windows = ["negotiate", "windows-credential"];
    private static readonly string[] Entra = ["entra-interactive", "entra-certificate"];

    public static readonly IReadOnlyList<IntegrationType> All =
    [
        new("ldap", "Active Directory or another LDAP directory", ["ldap"], Windows, []),
        new("graph", "Microsoft Graph: Entra ID, Intune, Microsoft 365", ["graph"], Entra,
            ["graph.microsoft.com", "graph.microsoft.us", "dod-graph.microsoft.us", "microsoftgraph.chinacloudapi.cn"], "https://graph.microsoft.com"),
        new("azure", "Azure Resource Manager", ["http"], Entra,
            ["management.azure.com", "management.usgovcloudapi.net", "management.chinacloudapi.cn"], "https://management.azure.com"),
        new("sccm", "SCCM AdminService (or the site database)", ["http", "sql"], [.. Windows, "basic"], []),
        new("cim", "Windows hosts: WMI over WinRM, the registry (read-only) and event logs", ["cim", "registry", "eventlog"], Windows, []),
        new("sql", "SQL Server instances", ["sql"], ["negotiate", "basic"], []),
        new("tls", "TLS endpoints", ["tls"], ["none"], []),
        new("vcenter", "VMware vCenter REST API", ["http"], ["vcenter-session"], []),
        new("veeam", "Veeam Backup & Replication REST API", ["http"], ["oauth-password"], []),
        new("prtg", "PRTG API", ["http"], ["api-key-query", "basic"], []),
        new("dynatrace", "Dynatrace API", ["http"], ["api-key-header"], ["*.live.dynatrace.com", "*.apps.dynatrace.com", "*.dynatrace-managed.com"]),
        new("servicenow", "ServiceNow Table API", ["http"], ["basic", "bearer", "oauth-client-credentials"], ["*.service-now.com", "*.servicenowservices.com"]),
        new("monday", "monday.com GraphQL API", ["graphql"], ["api-key-header"], ["api.monday.com"], "https://api.monday.com/v2"),
        new("wiz", "Wiz GraphQL API", ["graphql"], ["oauth-client-credentials"], ["*.app.wiz.io", "*.app.wiz.us"]),
        new("rubrik", "Rubrik Security Cloud GraphQL API", ["graphql", "http"], ["oauth-client-credentials"], ["*.my.rubrik.com"]),
        new("files", "Reports other tools wrote into imports\\", ["file"], ["none"], []),
        new("keeper", "Keeper's own registers", ["store"], ["none"], []),
        new("http", "Any other JSON API", ["http"], ["none", "negotiate", "basic", "bearer", "api-key-header", "api-key-query", "oauth-client-credentials", "session-login"], []),
    ];

    public static IntegrationType? Find(string id) => All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Types that need no configuration: their single implicit instance has the type's own name.</summary>
    public static bool IsImplicit(string id) => id is "files" or "keeper";

    public static bool IsValidId(string id) => Id().IsMatch(id) && id.Length <= 60;

    [GeneratedRegex("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Id();
}
