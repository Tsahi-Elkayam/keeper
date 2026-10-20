using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Ldap;

/// <summary>
/// ldap: a paged LDAP search - Active Directory or any directory. Kerberos/NTLM (Negotiate) with signing
/// and sealing on ldap://, TLS on ldaps://; the current user, or the integration's stored credential.
/// Secret attributes are never requested or returned. Search only - nothing is ever modified.
/// </summary>
public sealed class LdapRunner : IRunner
{
    private const int DefaultPageSize = 500;
    private const int MaxRows = 500_000;

    public string Protocol => "ldap";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (string.IsNullOrWhiteSpace(query.Text("filter")))
            yield return "filter is required";
        else if (!Balanced(query.Text("filter")!))
            yield return "filter has unbalanced parentheses";
        if (query.Text("scope") is { } scope && scope is not ("subtree" or "onelevel" or "base"))
            yield return "scope must be subtree, onelevel or base";
        foreach (var secret in SecretAttributes.In(query.List("attributes")))
            yield return $"attribute {secret} holds a secret and is never read; read its expiry time instead";
        if (query.Int("pageSize") is { } size && size is < 1 or > 5000)
            yield return "pageSize must be 1 to 5000";
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken) =>
        Task.Run(() => Run(query, context, cancellationToken), cancellationToken);

    private static RunnerResult Run(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var connection = Connect(context);
            var contexts = NamingContexts(connection);
            var schemaCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            bool SchemaHas(string attribute)
            {
                if (!schemaCache.TryGetValue(attribute, out var has))
                {
                    var response = (SearchResponse)connection.SendRequest(new SearchRequest(contexts["schema"],
                        $"(lDAPDisplayName={Escape(attribute)})", SearchScope.OneLevel, "lDAPDisplayName"));
                    has = response.Entries.Count > 0;
                    schemaCache[attribute] = has;
                }
                return has;
            }

            var filter = LdapMacros.Expand(query.Text("filter")!, context.Now, contexts, SchemaHas);
            var baseDn = Base(query.Text("base") ?? "domain", contexts, context.Now);
            var scope = (query.Text("scope") ?? "subtree") switch { "base" => SearchScope.Base, "onelevel" => SearchScope.OneLevel, _ => SearchScope.Subtree };
            var attributes = query.List("attributes").Where(a => !SecretAttributes.IsSecret(a))
                .Append("distinguishedName").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            var request = new SearchRequest(baseDn, filter, scope, attributes);
            var paging = new PageResultRequestControl(query.Int("pageSize") ?? DefaultPageSize);
            request.Controls.Add(paging);

            var rows = new List<JsonObject>();
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var response = (SearchResponse)connection.SendRequest(request, context.Timeout);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    rows.Add(Row(entry));
                    if (rows.Count >= MaxRows)
                        return RunnerResult.Partial(rows, $"stopped at {MaxRows} entries");
                }
                var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                if (cookie is null || cookie.Length == 0)
                    break;
                paging.Cookie = cookie;
            }
            context.Log($"{rows.Count} entries");
            return RunnerResult.Ok(rows);
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException or FormatException or TimeoutException)
        {
            return RunnerResult.Failed(Reason(ex));
        }
    }

    private static LdapConnection Connect(RunnerContext context)
    {
        var (server, port, ssl) = Endpoint(context.Connection.Endpoint);
        var connection = new LdapConnection(new LdapDirectoryIdentifier(server, port, fullyQualifiedDnsHostName: false, connectionless: false))
        {
            AuthType = AuthType.Negotiate,
            Timeout = context.Timeout,
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (ssl)
        {
            connection.SessionOptions.SecureSocketLayer = true;
        }
        else
        {
            // Kerberos/NTLM integrity and confidentiality on a plain LDAP port.
            connection.SessionOptions.Signing = true;
            connection.SessionOptions.Sealing = true;
        }

        var credential = context.Connection.WindowsCredential();
        if (credential is null)
            connection.Bind();
        else
            connection.Bind(credential);
        return connection;
    }

    /// <summary>ldap://host:389, ldaps://host:636, or a bare domain/host name (DC locator, port 389).</summary>
    public static (string Server, int Port, bool Ssl) Endpoint(string endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && uri.Scheme is "ldap" or "ldaps")
        {
            var ssl = uri.Scheme == "ldaps";
            return (uri.Host, uri.IsDefaultPort || uri.Port <= 0 ? (ssl ? 636 : 389) : uri.Port, ssl);
        }
        return (endpoint.Trim(), 389, false);
    }

    private static Dictionary<string, string> NamingContexts(LdapConnection connection)
    {
        var response = (SearchResponse)connection.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base,
            "defaultNamingContext", "configurationNamingContext", "schemaNamingContext", "rootDomainNamingContext"));
        var root = response.Entries[0];
        string Read(string name) => root.Attributes.Contains(name) ? (string)root.Attributes[name][0] : "";
        return new Dictionary<string, string>
        {
            ["domain"] = Read("defaultNamingContext"),
            ["config"] = Read("configurationNamingContext"),
            ["schema"] = Read("schemaNamingContext"),
            ["root"] = Read("rootDomainNamingContext"),
        };
    }

    private static string Base(string text, IReadOnlyDictionary<string, string> contexts, DateTimeOffset now) => text switch
    {
        "domain" or "config" or "schema" or "root" => contexts[text],
        _ => LdapMacros.Expand(text, now, contexts, _ => false),
    };

    private static JsonObject Row(SearchResultEntry entry)
    {
        var row = new JsonObject { ["distinguishedName"] = entry.DistinguishedName };
        foreach (DirectoryAttribute attribute in entry.Attributes.Values)
        {
            if (SecretAttributes.IsSecret(attribute.Name))
                continue;
            var values = new List<object>();
            for (var i = 0; i < attribute.Count; i++)
                values.Add(attribute[i]);
            row[attribute.Name] = LdapValues.Convert(attribute.Name, values);
        }
        return row;
    }

    private static bool Balanced(string filter)
    {
        var depth = 0;
        foreach (var c in filter)
        {
            depth += c switch { '(' => 1, ')' => -1, _ => 0 };
            if (depth < 0)
                return false;
        }
        return depth == 0;
    }

    private static string Escape(string value) =>
        string.Concat(value.Select(c => c switch
        {
            '\\' => "\\5c",
            '*' => "\\2a",
            '(' => "\\28",
            ')' => "\\29",
            '\0' => "\\00",
            _ => c.ToString(),
        }));

    private static string Reason(Exception ex) => ex switch
    {
        LdapException { ErrorCode: 49 } => "the directory refused the credentials (invalid credentials)",
        LdapException { ErrorCode: 81 } => "the directory server is unreachable",
        LdapException l => $"LDAP error {l.ErrorCode.ToString(CultureInfo.InvariantCulture)}: {l.Message}",
        DirectoryOperationException d => $"the search was refused: {d.Message}",
        _ => ex.Message,
    };
}
