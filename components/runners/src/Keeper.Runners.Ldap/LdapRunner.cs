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
                    rows.Add(Row(entry, connection, context.Timeout));
                    if (rows.Count >= MaxRows)
                        return RunnerResult.Partial(rows, $"stopped at {MaxRows} entries");
                }
                var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                if (cookie is null || cookie.Length == 0)
                    break;
                paging.Cookie = cookie;
            }
            context.Log($"{rows.Count} entries");
            return new RunnerResult(rows, "ok", Notes(WhoAmI(connection, context.Timeout), query.List("attributes"), rows));
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

    /// <summary>Who the directory says this connection is bound as (the LDAP "Who am I?" operation), or null.</summary>
    private static string? WhoAmI(LdapConnection connection, TimeSpan timeout)
    {
        try
        {
            var response = (ExtendedResponse)connection.SendRequest(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"), timeout);
            // An empty answer is the anonymous identity: the directory showed only what anyone may see.
            return response.ResponseValue is { Length: > 0 } value ? AuthzId(System.Text.Encoding.UTF8.GetString(value)) : "anonymous";
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
        {
            return null;   // a directory without the operation still answered the search
        }
    }

    /// <summary>"u:EXAMPLE\reader" -> EXAMPLE\reader; "dn:CN=..." -> CN=...</summary>
    public static string AuthzId(string value) =>
        value.StartsWith("u:", StringComparison.Ordinal) ? value[2..] : value.StartsWith("dn:", StringComparison.Ordinal) ? value[3..] : value;

    /// <summary>
    /// What to know about an answer that is still complete: who read it, and attributes no entry returned.
    /// A directory leaves out an attribute nobody has set and one this account may not read alike, so a
    /// rule on such an attribute deserves a look before its pass is trusted.
    /// </summary>
    public static string? Notes(string? boundAs, IReadOnlyList<string> requested, IReadOnlyList<JsonObject> rows)
    {
        var notes = new List<string>();
        if (boundAs is not null)
            notes.Add($"bound as {boundAs}");
        if (rows.Count > 0)
        {
            var absent = requested
                .Where(a => !a.Equals("distinguishedName", StringComparison.OrdinalIgnoreCase) && !SecretAttributes.IsSecret(a))
                .Where(a => !rows.Any(r => r.Any(p => p.Key.Equals(a, StringComparison.OrdinalIgnoreCase))))
                .ToList();
            if (absent.Count > 0)
                notes.Add($"no entry returned {string.Join(", ", absent)} (unset everywhere, or hidden from this account)");
        }
        return notes.Count == 0 ? null : string.Join("; ", notes);
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

    private static JsonObject Row(SearchResultEntry entry, LdapConnection connection, TimeSpan timeout)
    {
        var row = new JsonObject { ["distinguishedName"] = entry.DistinguishedName };
        foreach (DirectoryAttribute attribute in entry.Attributes.Values)
        {
            var name = attribute.Name;
            var values = Values(attribute, LdapValues.IsBinary(RangeOf(name)?.Attribute ?? name));
            // A value list longer than the server's limit (1,500 members in AD) comes back as
            // member;range=0-1499. Reading only that page would make a member rule pass on a partial list.
            if (RangeOf(name) is { } range)
            {
                name = range.Attribute;
                values.AddRange(RestOfRange(connection, entry.DistinguishedName, range, timeout));
            }
            if (SecretAttributes.IsSecret(name))
                continue;
            row[name] = LdapValues.Convert(name, values);
        }
        return row;
    }

    private static List<object> Values(DirectoryAttribute attribute, bool binary = false)
    {
        if (binary)
            return [.. attribute.GetValues(typeof(byte[]))];
        var values = new List<object>();
        for (var i = 0; i < attribute.Count; i++)
            values.Add(attribute[i]);
        return values;
    }

    public sealed record Range(string Attribute, long? High);

    /// <summary>"member;range=0-1499" -> (member, 1499); "member;range=1500-*" -> (member, null = the last page).</summary>
    public static Range? RangeOf(string name)
    {
        var at = name.IndexOf(";range=", StringComparison.OrdinalIgnoreCase);
        if (at <= 0)
            return null;
        var bounds = name[(at + ";range=".Length)..].Split('-');
        if (bounds.Length != 2)
            return null;
        return new Range(name[..at], bounds[1] == "*" ? null : long.Parse(bounds[1], NumberStyles.None, CultureInfo.InvariantCulture));
    }

    private static IEnumerable<object> RestOfRange(LdapConnection connection, string dn, Range first, TimeSpan timeout)
    {
        var range = first;
        for (var page = 0; range.High is { } high && page < 10_000; page++)
        {
            var response = (SearchResponse)connection.SendRequest(
                new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, $"{range.Attribute};range={high + 1}-*"), timeout);
            var next = response.Entries.Count == 0 ? null : response.Entries[0].Attributes.Values.Cast<DirectoryAttribute>()
                .FirstOrDefault(a => RangeOf(a.Name)?.Attribute.Equals(range.Attribute, StringComparison.OrdinalIgnoreCase) == true);
            if (next is null)
                throw new FormatException($"{dn}: the server stopped returning {range.Attribute} after value {high}");
            foreach (var value in Values(next, LdapValues.IsBinary(range.Attribute)))
                yield return value;
            range = RangeOf(next.Name)!;
        }
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
