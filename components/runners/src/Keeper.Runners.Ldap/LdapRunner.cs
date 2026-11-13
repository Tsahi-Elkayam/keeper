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
/// A scan binds once per integration and runs every query over that connection (see <see cref="LdapSession"/>):
/// a directory that counts failed or repeated binds is asked once.
/// </summary>
public sealed class LdapRunner : ISessionRunner
{
    private const int DefaultPageSize = 500;
    private const int MaxRows = 500_000;

    public string Protocol => "ldap";

    public bool PerTarget => false;

    public string SessionFamily => "ldap";

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

    /// <summary>Runs one query on its own connection: opens a session, runs, closes. A scan uses the session overload instead.</summary>
    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        LdapSession session;
        try
        {
            session = (LdapSession)await OpenAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (RunnerFailureException ex)
        {
            return RunnerResult.Failed(ex.Message, ex.Kind);
        }
        catch (Exception ex) when (ex is FormatException or TimeoutException)
        {
            return RunnerResult.Failed(ex.Message, ex);
        }
        await using (session.ConfigureAwait(false))
            return await RunAsync(session, query, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Binds once. A refused bind throws with kind Refused; the scanner never tries this credential again.</summary>
    public Task<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken cancellationToken) =>
        Task.Run<IRunnerSession>(() =>
        {
            try
            {
                return new LdapSession(Connect(context));
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
            {
                throw new RunnerFailureException(Reason(ex), ClassifyException(ex), ex);
            }
        }, cancellationToken);

    public Task<RunnerResult> RunAsync(IRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken) =>
        Task.Run(() => RunSerial((LdapSession)session, query, context, cancellationToken), cancellationToken);

    /// <summary>The connection is used by one query at a time: whether it is safe to share between threads is not documented.</summary>
    private static RunnerResult RunSerial(LdapSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        session.Gate.Wait(cancellationToken);
        try
        {
            var result = Run(session, query, context, cancellationToken);
            // A connection that worked and then dropped (an idle timeout, a DC failing over) is bound again once: the
            // credential is known to work, so this is not a lockout risk - and every later query would fail otherwise.
            if (result.State == "failed" && result.Failure == FailureKind.Unreachable && session.Worked && !session.Rebound)
            {
                session.Rebound = true;
                try
                {
                    session.Replace(Connect(context));
                }
                catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
                {
                    // A bind refused now (the password changed, the account locked meanwhile) is a refusal, not the drop.
                    var kind = ClassifyException(ex);
                    return kind == FailureKind.Refused
                        ? RunnerResult.Failed($"ldap: binding again after the connection dropped was refused: {ex.Message}", kind)
                        : result;
                }
                result = Run(session, query, context, cancellationToken);
            }
            if (result.State != "failed")
                session.Worked = true;
            return result;
        }
        finally
        {
            session.Gate.Release();
        }
    }

    private static RunnerResult Run(LdapSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            var wire = new Wire(session, context, cancellationToken);
            var contexts = NamingContexts(wire, session);
            bool SchemaHas(string attribute)
            {
                if (!session.SchemaCache.TryGetValue(attribute, out var has))
                {
                    var response = (SearchResponse)wire.Send(new SearchRequest(contexts["schema"],
                        $"(lDAPDisplayName={Escape(attribute)})", SearchScope.OneLevel, "lDAPDisplayName"));
                    has = response.Entries.Count > 0;
                    session.SchemaCache[attribute] = has;
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
            // The security descriptor without its SACL: owner, group and DACL are what any user may read. Asked
            // for whole, the server would leave the attribute out for everyone but an auditor.
            if (attributes.Contains(LdapValues.SecurityDescriptor, StringComparer.OrdinalIgnoreCase))
                request.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl));

            var rows = new List<JsonObject>();
            while (true)
            {
                var response = (SearchResponse)wire.Send(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    rows.Add(Row(entry, wire));
                    if (rows.Count >= MaxRows)
                        return RunnerResult.Partial(rows, $"stopped at {MaxRows} entries");
                }
                var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                if (cookie is null || cookie.Length == 0)
                    break;
                paging.Cookie = cookie;
            }
            context.Log($"{rows.Count} entries");
            // An object whose descriptor did not come back (no right to read it) or could not be read would pass
            // every rule over its DACL by having none: the read is partial, never clean.
            if (attributes.Contains(LdapValues.SecurityDescriptor, StringComparer.OrdinalIgnoreCase)
                && rows.Where(r => FieldPath.First(r, LdapValues.SecurityDescriptor) is not JsonObject).ToList() is { Count: > 0 } unread)
                return RunnerResult.Partial(rows, $"{unread.Count} of {rows.Count} entries came back without a readable security descriptor " +
                    $"(as {WhoAmI(wire, session) ?? "this account"}), such as " +
                    string.Join("; ", unread.Take(3).Select(r => Keeper.Rules.Values.Text(r["distinguishedName"]))));
            return new RunnerResult(rows, "ok", Notes(WhoAmI(wire, session), query.List("attributes"), rows));
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException or FormatException or TimeoutException)
        {
            return RunnerResult.Failed(Reason(ex), ClassifyException(ex));
        }
    }

    /// <summary>
    /// The one place a request leaves for the directory: always with this query's timeout (the connection's own
    /// timeout is only the one the bind used), and after a pace wait - except the first request of a query, which
    /// the scanner's wait before the query already covers.
    /// </summary>
    private sealed class Wire(LdapSession session, RunnerContext context, CancellationToken cancellationToken)
    {
        private bool _sent;

        public DirectoryResponse Send(DirectoryRequest request)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_sent)
                context.Pace.WaitAsync(cancellationToken).GetAwaiter().GetResult();
            _sent = true;
            return session.Connection.SendRequest(request, context.Timeout);
        }
    }

    /// <summary>A connection bound once and the lookups that do not change during a scan; one query at a time uses it.</summary>
    public sealed class LdapSession(LdapConnection connection) : IRunnerSession
    {
        internal LdapConnection Connection { get; private set; } = connection;

        /// <summary>A query was read over this session: the bind works.</summary>
        internal bool Worked { get; set; }

        /// <summary>The connection was bound again once after it dropped; a second drop is the answer.</summary>
        internal bool Rebound { get; set; }

        internal void Replace(LdapConnection fresh)
        {
            Connection.Dispose();
            Connection = fresh;
        }

        internal SemaphoreSlim Gate { get; } = new(1, 1);

        internal Dictionary<string, string>? Contexts { get; set; }

        internal Dictionary<string, bool> SchemaCache { get; } = new(StringComparer.OrdinalIgnoreCase);

        internal bool WhoAmIKnown { get; set; }

        internal string? WhoAmIValue { get; set; }

        public ValueTask DisposeAsync()
        {
            Connection.Dispose();
            Gate.Dispose();
            return ValueTask.CompletedTask;
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
        try
        {
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
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Who the directory says this connection is bound as (the LDAP "Who am I?" operation), or null. Asked once per session.</summary>
    private static string? WhoAmI(Wire wire, LdapSession session)
    {
        if (session.WhoAmIKnown)
            return session.WhoAmIValue;
        try
        {
            var response = (ExtendedResponse)wire.Send(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"));
            // An empty answer is the anonymous identity: the directory showed only what anyone may see.
            session.WhoAmIValue = response.ResponseValue is { Length: > 0 } value ? AuthzId(System.Text.Encoding.UTF8.GetString(value)) : "anonymous";
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
        {
            session.WhoAmIValue = null;   // a directory without the operation still answered the search
        }
        session.WhoAmIKnown = true;
        return session.WhoAmIValue;
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

    /// <summary>The rootDSE naming contexts, read on the session's first query and kept for the scan.</summary>
    private static Dictionary<string, string> NamingContexts(Wire wire, LdapSession session)
    {
        if (session.Contexts is { } known)
            return known;
        var response = (SearchResponse)wire.Send(new SearchRequest("", "(objectClass=*)", SearchScope.Base,
            "defaultNamingContext", "configurationNamingContext", "schemaNamingContext", "rootDomainNamingContext"));
        var root = response.Entries[0];
        string Read(string name) => root.Attributes.Contains(name) ? (string)root.Attributes[name][0] : "";
        return session.Contexts = new Dictionary<string, string>
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

    private static JsonObject Row(SearchResultEntry entry, Wire wire)
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
                values.AddRange(RestOfRange(wire, entry.DistinguishedName, range));
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

    private static IEnumerable<object> RestOfRange(Wire wire, string dn, Range first)
    {
        var range = first;
        for (var page = 0; range.High is { } high && page < MaxRangePages; page++)
        {
            var response = (SearchResponse)wire.Send(
                new SearchRequest(dn, "(objectClass=*)", SearchScope.Base, $"{range.Attribute};range={high + 1}-*"));
            var next = response.Entries.Count == 0 ? null : response.Entries[0].Attributes.Values.Cast<DirectoryAttribute>()
                .FirstOrDefault(a => RangeOf(a.Name)?.Attribute.Equals(range.Attribute, StringComparison.OrdinalIgnoreCase) == true);
            if (next is null)
                throw new FormatException($"{dn}: the server stopped returning {range.Attribute} after value {high}");
            foreach (var value in Values(next, LdapValues.IsBinary(range.Attribute)))
                yield return value;
            range = RangeOf(next.Name)!;
        }
        // Stopping at the cap must not look like the end of the list: a member rule would judge part of a group.
        if (range.High is { } stoppedAt)
            throw new FormatException($"{dn}: {range.Attribute} has more than {stoppedAt + 1} values; Keeper stops reading at {MaxRangePages} pages");
    }

    /// <summary>Pages of one ranged attribute read at most (1,500 values a page on AD): a bound, never a silent end.</summary>
    private const int MaxRangePages = 10_000;

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
        LdapException l => Describe(l.ErrorCode, l.ServerErrorMessage, l.Message),
        DirectoryOperationException d => $"the search was refused: {d.Message}",
        _ => ex.Message,
    };

    /// <summary>The kind of a failed LDAP call, from its exception.</summary>
    public static FailureKind ClassifyException(Exception ex) => ex switch
    {
        LdapException l => Classify(l.ErrorCode, l.ServerErrorMessage),
        DirectoryOperationException { Response: { } response } => Classify((int)response.ResultCode, response.ErrorMessage),
        _ => Failures.Classify(ex),
    };

    /// <summary>
    /// The kind of an LDAP result code. 49 (invalid credentials) is always the credential itself - whatever AD says
    /// in its sub-code (bad password, locked, expired, disabled, logon hours, workstation), presenting it again can
    /// only count towards a lockout. 50 is a signed-in account that may not read this; 51 and 52 are a busy or
    /// unavailable server; 81 and 91 are no server to talk to; 85 is no answer in time.
    /// </summary>
    public static FailureKind Classify(int errorCode, string? serverMessage) => errorCode switch
    {
        49 => FailureKind.Refused,
        50 => FailureKind.Denied,
        51 or 52 => FailureKind.Throttled,
        81 or 91 => FailureKind.Unreachable,
        85 => FailureKind.Timeout,
        _ => Failures.SaysRefused(serverMessage) ? FailureKind.Refused : FailureKind.Error,
    };

    /// <summary>What an Active Directory bind failure means: the sub-code after "data " in the server's message.</summary>
    public static string? AdMeaning(string? serverMessage)
    {
        if (serverMessage is null)
            return null;
        var at = serverMessage.IndexOf("data ", StringComparison.OrdinalIgnoreCase);
        if (at < 0)
            return null;
        var code = new string(serverMessage[(at + 5)..].TakeWhile(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        return code switch
        {
            "52e" => "the user name or password is wrong (52e)",
            "525" => "the user does not exist (525)",
            "530" => "the account may not sign in at this time of day (530)",
            "531" => "the account may not sign in from this workstation (531)",
            "532" or "773" => "the password has expired or must be changed (" + code + ")",
            "533" => "the account is disabled (533)",
            "701" => "the account has expired (701)",
            "775" => "the account is locked out (775)",
            _ => null,
        };
    }

    /// <summary>The words for a failed LDAP call, with the Active Directory meaning when the server gave one.</summary>
    public static string Describe(int errorCode, string? serverMessage, string message) => errorCode switch
    {
        49 => "the directory refused the credentials (invalid credentials" + (AdMeaning(serverMessage) is { } meaning ? $": {meaning}" : "") + ")",
        50 => "the directory denied access (insufficient access rights)",
        51 => "the directory is busy",
        52 => "the directory is unavailable",
        81 => "the directory server is unreachable",
        91 => "the directory server could not be connected to",
        85 => "the directory did not answer in time",
        _ => $"LDAP error {errorCode.ToString(CultureInfo.InvariantCulture)}: {message}",
    };
}
