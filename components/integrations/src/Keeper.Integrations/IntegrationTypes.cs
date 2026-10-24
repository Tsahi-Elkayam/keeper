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

    private static readonly string[] Windows = ["negotiate", "windows-credential"];
    private static readonly string[] Entra = ["entra-interactive", "entra-certificate"];

    // Dataverse's regional hosts (crm, crm2 ... crm22): not every *.dynamics.com. The US government clouds sign in
    // elsewhere than Entra's public cloud, which is all Keeper signs in to so far.
    private static readonly string[] DataverseHosts = ["*.crm.dynamics.com", .. Enumerable.Range(2, 21).Select(n => $"*.crm{n}.dynamics.com")];

    // Get- cmdlets read - except with a parameter that mails a log (Get-MobileDeviceStatistics -GetMailboxLog)
    // or shows an export's credential (Get-ComplianceSearchAction -IncludeCredential).
    private static readonly Keeper.Runners.ReadCommand GetCmdlets = new("CmdletInput.CmdletName", ["Get-*"])
    {
        ParametersField = "CmdletInput.Parameters",
        DeniedParameters = ["GetMailboxLog", "NotificationEmailAddresses", "IncludeCredential"],
    };

    public static readonly IReadOnlyList<IntegrationType> All =
    [
        new("ldap", "Active Directory or another LDAP directory, and its Group Policy objects in SYSVOL", ["ldap", "gpo"], Windows, []),
        new("graph", "Microsoft Graph: Entra ID, Intune, Microsoft 365", ["graph"], Entra,
            ["graph.microsoft.com", "graph.microsoft.us", "dod-graph.microsoft.us", "microsoftgraph.chinacloudapi.cn"], "https://graph.microsoft.com"),
        new("azure", "Azure Resource Manager", ["http"], Entra,
            ["management.azure.com", "management.usgovcloudapi.net", "management.chinacloudapi.cn"], "https://management.azure.com")
        {
            // Resource Graph takes its KQL as a POST; the query is the rule's own text, and Resource Graph only reads.
            ReadPosts = ["/providers/Microsoft.ResourceGraph/resources"],
        },
        // Microsoft APIs whose tokens are for another resource than Graph: one integration each, all through the
        // same Entra app (its own permissions per API), each held to its own hosts.
        new("power-platform", "Power Platform admin: environments, DLP policies (api.bap.microsoft.com)", ["http"], Entra,
            ["api.bap.microsoft.com"], "https://api.bap.microsoft.com") { Resource = "https://service.powerapps.com/" },
        new("power-apps", "Power Apps admin: apps and connections (api.powerapps.com)", ["http"], Entra,
            ["api.powerapps.com"], "https://api.powerapps.com") { Resource = "https://service.powerapps.com/" },
        new("power-automate", "Power Automate admin: flows (api.flow.microsoft.com)", ["http"], Entra,
            ["api.flow.microsoft.com"], "https://api.flow.microsoft.com") { Resource = "https://service.flow.microsoft.com/" },
        new("power-platform-api", "Power Platform API (api.powerplatform.com)", ["http"], Entra,
            ["api.powerplatform.com"], "https://api.powerplatform.com") { Resource = "https://api.powerplatform.com" },
        // The token is for the environment's own URL, so a token for one environment never opens another.
        new("dataverse", "One Dataverse environment's Web API (https://<org>.crm<n>.dynamics.com)", ["http"], Entra, DataverseHosts),
        new("power-bi", "Power BI admin REST API", ["http"], Entra,
            ["api.powerbi.com"], "https://api.powerbi.com") { Resource = "https://analysis.windows.net/powerbi/api" },
        new("defender-endpoint", "Microsoft Defender for Endpoint API (machines, vulnerabilities, advanced hunting)", ["http"], Entra,
            // Its regional hosts (api-eu, api-us, ...) share the one resource. api.security.microsoft.com is
            // Defender XDR's own API, with another resource: not this type.
            ["api.securitycenter.microsoft.com", "*.securitycenter.microsoft.com"], "https://api.securitycenter.microsoft.com")
        {
            Resource = "https://api.securitycenter.microsoft.com",
            // Advanced hunting takes its KQL as a POST; KQL only reads.
            ReadPosts = ["/api/advancedqueries/run"],
        },
        new("cloud-apps", "Microsoft Defender for Cloud Apps API (https://<tenant>.<region>.portal.cloudappsecurity.com)", ["http"], Entra,
            ["*.portal.cloudappsecurity.com"])
        {
            Resource = "05a65629-4c1b-48c1-a78b-804c4abdd4af",
            // Its lists take their filters as a POST; closing or dismissing an alert is another path.
            ReadPosts = ["/api/v1/alerts/", "/api/v1/activities/", "/api/v1/entities/", "/api/v1/files/", "/api/v1/discovery/discovered_apps/"],
        },
        new("key-vault", "One Azure Key Vault's metadata (https://<vault>.vault.azure.net; not Managed HSM): names, dates, policies - never a secret's value", ["http"], Entra,
            ["*.vault.azure.net"])
        {
            Resource = "https://vault.azure.net",
            // GET /secrets/<name> answers with the value: it is not here. Lists, versions, keys' public parts,
            // certificates and their policies are.
            ReadPaths =
            [
                "/secrets", "/secrets/*/versions", "/keys", "/keys/*", "/keys/*/versions", "/certificates", "/certificates/*",
                "/certificates/*/versions", "/certificates/*/policy", "/deletedsecrets", "/deletedkeys", "/deletedcertificates",
            ],
        },
        // The REST endpoint the Exchange Online module itself calls: one POST per cmdlet, Get- cmdlets only.
        new("exchange-online", "Exchange Online through its module's REST endpoint (https://outlook.office365.com/adminapi/beta/<tenant id>), Get- cmdlets only", ["http"], Entra,
            ["outlook.office365.com"], null)
        {
            EndpointPath = "/adminapi/beta/*",
            ReadPosts = ["/InvokeCommand"],
            ReadCommand = GetCmdlets,
        },
        new("purview", "Security & Compliance (Purview) through the same REST endpoint (https://<region>.ps.compliance.protection.outlook.com/adminapi/beta/<tenant id>), Get- cmdlets only", ["http"], Entra,
            ["ps.compliance.protection.outlook.com", "*.ps.compliance.protection.outlook.com"], null)
        {
            Resource = "https://ps.compliance.protection.outlook.com",
            EndpointPath = "/adminapi/beta/*",
            ReadPosts = ["/InvokeCommand"],
            ReadCommand = GetCmdlets,
        },
        // The endpoint is the home region. Hosts are never configured: the runner builds them under amazonaws.com.
        new("aws", "Amazon Web Services: read-only actions, signed in-process; every account through its read-only role", ["aws"],
            ["aws-access-key", "aws-assume-role"], []),
        // Google Cloud through Cloud Asset Inventory: every resource's configuration, IAM policies and organisation
        // policies, from one host and one read (ListAssets). The endpoint names the scope - an organisation, a folder
        // or a project - and its token has the read-only scope, so it cannot change anything whatever its roles.
        new("gcp", "Google Cloud: Cloud Asset Inventory over an organisation, folder or project (https://cloudasset.googleapis.com/v1/organizations/<n>), read-only token", ["http"],
            ["gcp-service-account"], ["cloudasset.googleapis.com"], null)
        {
            EndpointPath = "/v1/*/*",
            ReadPaths = ["/v1/*/*/assets"],
        },
        // The cluster's own API server, read with a service account that holds only the "view" kind of access. What a
        // rule may read is a short, explicit list: workloads, nodes, RBAC and network policy. Never secrets, config maps
        // (which hold secrets in practice), logs, exec, proxy, port-forward or a service account's token.
        new("kubernetes", "A Kubernetes cluster's API server (https://<host>:6443), read-only: workloads, nodes, RBAC and network policy - never secrets, config maps, logs or exec; option caCertificate trusts the cluster's own CA", ["http"], ["bearer"], [])
        {
            ReadPaths =
            [
                "/version", "/api/v1/namespaces", "/api/v1/nodes", "/api/v1/pods", "/api/v1/services", "/api/v1/serviceaccounts",
                "/api/v1/resourcequotas", "/api/v1/limitranges", "/api/v1/persistentvolumes", "/api/v1/persistentvolumeclaims",
                "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets", "/apis/apps/v1/statefulsets", "/apis/apps/v1/replicasets",
                "/apis/batch/v1/cronjobs", "/apis/batch/v1/jobs", "/apis/autoscaling/v2/horizontalpodautoscalers",
                "/apis/rbac.authorization.k8s.io/v1/clusterroles", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                "/apis/rbac.authorization.k8s.io/v1/roles", "/apis/rbac.authorization.k8s.io/v1/rolebindings",
                "/apis/networking.k8s.io/v1/networkpolicies", "/apis/networking.k8s.io/v1/ingresses",
                "/apis/policy/v1/poddisruptionbudgets", "/apis/storage.k8s.io/v1/storageclasses",
                "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
                "/apis/certificates.k8s.io/v1/certificatesigningrequests",
            ],
        },
        // FortiOS REST. Reading is GET only; what a rule may read is the configuration tables its checks judge and the
        // system status - never a configuration backup (which holds keys), API users, certificates or licence data.
        new("fortigate", "A FortiGate firewall's REST API (https://<host>), read-only: the configuration tables its rules judge and system status - never a configuration backup, certificate or key; option caCertificate trusts a device certificate", ["http"], ["bearer"], [])
        {
            ReadPaths =
            [
                "/api/v2/monitor/system/status", "/api/v2/monitor/vpn/ipsec",
                "/api/v2/cmdb/system/global", "/api/v2/cmdb/system/interface", "/api/v2/cmdb/system/admin", "/api/v2/cmdb/system/accprofile",
                "/api/v2/cmdb/system/snmp/community", "/api/v2/cmdb/system/ntp", "/api/v2/cmdb/system/dns",
                "/api/v2/cmdb/firewall/policy", "/api/v2/cmdb/firewall/address",
                "/api/v2/cmdb/vpn.ipsec/phase1-interface", "/api/v2/cmdb/vpn.ipsec/phase2-interface",
                "/api/v2/cmdb/log.syslogd/setting",
            ],
        },
        new("checkpoint", "Check Point management API (show- commands only, on a read-only session)", ["http"], ["session-login"], [])
        {
            ReadPosts = ["/web_api/show-*", "/web_api/v*/show-*"],
        },
        new("sccm", "SCCM AdminService (or the site database)", ["http", "sql"], [.. Windows, "basic"], []),
        new("cim", "Windows hosts: WMI over WinRM, the registry (read-only), event logs, file shares and NTFS permissions", ["cim", "registry", "eventlog", "smb"], Windows, []),
        new("sql", "SQL Server instances", ["sql"], ["negotiate", "basic"], []),
        new("tls", "TLS endpoints", ["tls"], ["none"], []),
        new("snmp", "SNMP devices (UDP 161): read-only GET/GETNEXT; the endpoint is the CIDR range the credential may be used in", ["snmp"], ["snmp-v3", "snmp-v2c"], []),
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
        new("ssh", "Unix hosts over SSH, read-only: the same configuration-file and command reads as the local host type; the endpoint lists where the credential may be used (CIDR ranges, host names, *.suffix), the targets option lists the hosts, and the hostKeys option pins their host keys", ["host"], ["ssh-key", "ssh-password"], []),
        new("printer", "Network printers and multifunction devices, read-only: which services answer (connect only), IPP attributes, and the Printer-MIB over SNMP (page count, supplies, alerts); the endpoint lists where it may talk (CIDR ranges, host names, *.suffix) and the targets option lists the printers", ["printer"], ["none", "snmp-v2c"], []),
        new("host", "The machine Keeper runs on: configuration files and a fixed set of read-only commands", ["host"], ["none"], []),
        new("http", "Any other JSON API", ["http"], ["none", "negotiate", "basic", "bearer", "api-key-header", "api-key-query", "oauth-client-credentials", "session-login"], []),
    ];

    public static IntegrationType? Find(string id) => All.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Types that need no configuration: their single implicit instance has the type's own name.</summary>
    /// <summary>
    /// Whether an integration of type <paramref name="integrationType"/> can run rules written for <paramref name="ruleType"/>.
    /// Rules for the host protocol read the local machine, or each target host of an ssh integration.
    /// </summary>
    public static bool Satisfies(string ruleType, string integrationType) =>
        ruleType.Equals(integrationType, StringComparison.OrdinalIgnoreCase)
        || ruleType.Equals("host", StringComparison.OrdinalIgnoreCase) && integrationType.Equals("ssh", StringComparison.OrdinalIgnoreCase);

    public static bool IsImplicit(string id) => id is "files" or "keeper" or "host";

    public static bool IsValidId(string id) => Id().IsMatch(id) && id.Length <= 60;

    [GeneratedRegex("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Id();
}
