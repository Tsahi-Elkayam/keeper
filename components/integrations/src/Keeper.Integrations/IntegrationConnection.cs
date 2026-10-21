using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Runners;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace Keeper.Integrations;

/// <summary>
/// The connection a runner gets: one integration's endpoint and credentials. Secrets are opened from the
/// vault only when used, and only this integration's. Tokens are cached for the life of the process.
/// </summary>
public sealed partial class IntegrationConnection : IConnection, IDisposable
{
    private readonly IntegrationRecord _record;
    private readonly Keeper.Vault.Vault? _vault;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _token;
    private DateTimeOffset _tokenExpires;
    private string? _signedInAs;
    private IntegrationException? _tokenError;

    public IntegrationConnection(IntegrationRecord record, Keeper.Vault.Vault? vault)
    {
        _record = record;
        _vault = vault;
    }

    public string Instance => _record.Id;
    public string Type => _record.Type;
    public string Endpoint => _record.Endpoint;
    public string AuthKind => _record.AuthKind;
    public string? Identity => _record.Identity;
    public JsonObject Options => _record.Options;

    /// <summary>The account an Entra token was issued to; for negotiate, the Windows user this process runs as.</summary>
    public string? SignedInAs => _signedInAs ?? (_record.AuthKind == "negotiate" ? $"{Environment.UserDomainName}\\{Environment.UserName}" : null);

    public IReadOnlyList<string> ReadPosts => IntegrationTypes.Find(_record.Type)?.ReadPosts ?? [];

    /// <summary>Sign in to Entra again even when a cached token is valid: right after a PIM activation, so the new role is in it.</summary>
    public bool FreshSignIn { get; init; }

    public string? Secret(string name)
    {
        if (!_record.Secrets.TryGetValue(name, out var stored))
            return null;
        var vault = _vault ?? throw new IntegrationException("The vault is not available to open secrets.");
        return vault.Open(stored.Sealed, IntegrationStore.Binding(_record.Id, name, _record.Endpoint));
    }

    private string RequiredSecret(string name) =>
        Secret(name) ?? throw new IntegrationException($"Integration {_record.Id} needs its {name} set: keeper integration set-secret {_record.Id} {name}");

    public NetworkCredential? WindowsCredential()
    {
        if (_record.AuthKind != "windows-credential")
            return null;   // negotiate: the current Windows user (Kerberos/NTLM)
        var identity = _record.Identity ?? throw new IntegrationException($"Integration {_record.Id} needs an identity (DOMAIN\\user).");
        var slash = identity.IndexOf('\\');
        return slash > 0
            ? new NetworkCredential(identity[(slash + 1)..], RequiredSecret("password"), identity[..slash])
            : new NetworkCredential(identity, RequiredSecret("password"));
    }

    public HttpMessageHandler CreateHttpHandler()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        handler.Credentials = _record.AuthKind switch
        {
            "negotiate" => CredentialCache.DefaultCredentials,
            "windows-credential" => WindowsCredential(),
            _ => null,
        };
        return handler;
    }

    public async Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_record.Options["headers"] is JsonObject staticHeaders)
        {
            foreach (var (name, value) in staticHeaders)
                request.Headers.TryAddWithoutValidation(name, value?.ToString());
        }

        switch (_record.AuthKind)
        {
            case "none":
            case "negotiate":
            case "windows-credential":
                return;
            case "basic":
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_record.Identity}:{RequiredSecret("password")}")));
                return;
            case "bearer":
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", RequiredSecret("token"));
                return;
            case "api-key-header":
                var header = _record.Options["header"]?.ToString() ?? "Authorization";
                request.Headers.TryAddWithoutValidation(header, (_record.Options["prefix"]?.ToString() ?? "") + RequiredSecret("token"));
                return;
            case "api-key-query":
                var parameter = _record.Options["param"]?.ToString() ?? "apitoken";
                var builder = new UriBuilder(request.RequestUri!);
                var separator = string.IsNullOrEmpty(builder.Query) ? "" : builder.Query.TrimStart('?') + "&";
                builder.Query = separator + $"{Uri.EscapeDataString(parameter)}={Uri.EscapeDataString(RequiredSecret("token"))}";
                request.RequestUri = builder.Uri;
                return;
            case "oauth-client-credentials":
            case "oauth-password":
            case "vcenter-session":
            case "session-login":
            case "entra-interactive":
            case "entra-certificate":
                var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
                if (_record.AuthKind == "vcenter-session")
                    request.Headers.TryAddWithoutValidation("vmware-api-session-id", token);
                else if (_record.AuthKind == "session-login")
                    request.Headers.TryAddWithoutValidation(_record.Options["header"]?.ToString() ?? "Authorization",
                        (_record.Options["prefix"]?.ToString() ?? "") + token);
                else
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return;
            default:
                throw new IntegrationException($"Unknown auth kind {_record.AuthKind}.");
        }
    }

    private async Task<string> TokenAsync(CancellationToken cancellationToken)
    {
        await _tokenLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // A refused sign-in is refused for the whole scan: asking again for every query would open a
            // sign-in window per query, or repeat a wrong password until the account locks.
            if (_tokenError is not null)
                throw _tokenError;
            if (_token is not null && DateTimeOffset.UtcNow < _tokenExpires.AddMinutes(-2))
                return _token;
            try
            {
                (_token, _tokenExpires) = _record.AuthKind switch
                {
                    "oauth-client-credentials" => await OAuthAsync(ClientCredentialsForm(), TokenUrl(), cancellationToken).ConfigureAwait(false),
                    "oauth-password" => await OAuthAsync(PasswordForm(), TokenUrl("/api/oauth2/token"), cancellationToken).ConfigureAwait(false),
                    "vcenter-session" => await VCenterSessionAsync(cancellationToken).ConfigureAwait(false),
                    "session-login" => await SessionLoginAsync(cancellationToken).ConfigureAwait(false),
                    "entra-interactive" => await EntraInteractiveAsync(cancellationToken).ConfigureAwait(false),
                    _ => await EntraCertificateAsync(cancellationToken).ConfigureAwait(false),
                };
            }
            catch (IntegrationException ex)
            {
                _tokenError = ex;
                throw;
            }
            return _token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    // ---- OAuth (ServiceNow, Wiz, Rubrik) and Veeam's password grant ------------------

    private Uri TokenUrl(string? defaultPath = null)
    {
        var text = _record.Options["tokenUrl"]?.ToString();
        if (text is null && defaultPath is not null && Uri.TryCreate(_record.Endpoint, UriKind.Absolute, out var endpoint))
            return new Uri(endpoint, defaultPath);
        if (text is null || !Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != "https")
            throw new IntegrationException($"Integration {_record.Id} needs the option tokenUrl (https).");
        return uri;
    }

    private Dictionary<string, string> ClientCredentialsForm()
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _record.Identity ?? throw new IntegrationException($"Integration {_record.Id} needs its client id as the identity."),
            ["client_secret"] = RequiredSecret("clientSecret"),
        };
        if (_record.Options["scope"]?.ToString() is { } scope)
            form["scope"] = scope;
        if (_record.Options["audience"]?.ToString() is { } audience)
            form["audience"] = audience;
        return form;
    }

    private Dictionary<string, string> PasswordForm() => new()
    {
        ["grant_type"] = "password",
        ["username"] = _record.Identity ?? throw new IntegrationException($"Integration {_record.Id} needs a user name as the identity."),
        ["password"] = RequiredSecret("password"),
    };

    private async Task<(string, DateTimeOffset)> OAuthAsync(Dictionary<string, string> form, Uri tokenUrl, CancellationToken cancellationToken)
    {
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl) { Content = new FormUrlEncodedContent(form) };
        if (_record.Options["headers"] is JsonObject staticHeaders)
        {
            foreach (var (name, value) in staticHeaders)
                request.Headers.TryAddWithoutValidation(name, value?.ToString());
        }
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new IntegrationException($"{tokenUrl.Host} refused the sign-in ({(int)response.StatusCode}).");
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        var token = body?["access_token"]?.ToString() ?? throw new IntegrationException($"{tokenUrl.Host} returned no access token.");
        var seconds = int.TryParse(body?["expires_in"]?.ToString(), out var s) ? s : 3600;
        return (token, DateTimeOffset.UtcNow.AddSeconds(seconds));
    }

    private async Task<(string, DateTimeOffset)> VCenterSessionAsync(CancellationToken cancellationToken)
    {
        var endpoint = new Uri(_record.Endpoint);
        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint, "/api/session"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_record.Identity}:{RequiredSecret("password")}")));
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new IntegrationException($"vCenter refused the sign-in ({(int)response.StatusCode}).");
        var token = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim().Trim('"');
        return (token, DateTimeOffset.UtcNow.AddMinutes(25));
    }

    /// <summary>
    /// session-login: products that sign in with a POST and then want the session token in a header (a
    /// firewall manager's /web_api/login and its X-chkp-sid, say). The login goes to a path on the
    /// integration's own endpoint - never another host - with the user and password as JSON (or a form);
    /// the token is read from the answer by a field path. Options: loginPath (required), userField
    /// (user), passwordField (password), body (json|form), tokenField (token), header, prefix,
    /// lifetimeMinutes (25), plus any fixed loginFields.* the product needs.
    /// </summary>
    public static Uri LoginUri(string endpoint, string? loginPath)
    {
        if (loginPath is null || !loginPath.StartsWith('/') || loginPath.StartsWith("//", StringComparison.Ordinal) || loginPath.Contains("://", StringComparison.Ordinal))
            throw new IntegrationException("session-login needs the option loginPath: a path on the integration's endpoint, such as /web_api/login.");
        var root = new Uri(endpoint);
        if (root.Scheme != "https")
            throw new IntegrationException("session-login needs an https endpoint.");
        return new Uri(root, loginPath);
    }

    private async Task<(string, DateTimeOffset)> SessionLoginAsync(CancellationToken cancellationToken)
    {
        var uri = LoginUri(_record.Endpoint, _record.Options["loginPath"]?.ToString());
        var user = _record.Identity ?? throw new IntegrationException($"Integration {_record.Id} needs a user name as the identity.");
        var fields = new Dictionary<string, string>
        {
            [_record.Options["userField"]?.ToString() ?? "user"] = user,
            [_record.Options["passwordField"]?.ToString() ?? "password"] = RequiredSecret("password"),
        };
        var extras = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, value) in _record.Options.Where(o => o.Key.StartsWith("loginFields.", StringComparison.Ordinal)))
        {
            fields[name["loginFields.".Length..]] = value?.ToString() ?? "";
            extras.Add(name["loginFields.".Length..]);
        }

        using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = _record.Options["body"]?.ToString() == "form"
                ? new FormUrlEncodedContent(fields)
                // A configured login field of true / false goes as a JSON boolean: Check Point's login takes
                // "read-only": true for a session that cannot change anything. The user and password never do.
                : new StringContent(new JsonObject(fields.Select(f => KeyValuePair.Create(f.Key, extras.Contains(f.Key) && f.Value is "true" or "false"
                    ? (JsonNode?)JsonValue.Create(f.Value == "true")
                    : JsonValue.Create(f.Value)))).ToJsonString(), Encoding.UTF8, "application/json"),
        };
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new IntegrationException($"{uri.Host} refused the sign-in ({(int)response.StatusCode}).");
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        var tokenField = _record.Options["tokenField"]?.ToString() ?? "token";
        var token = Keeper.Rules.FieldPath.First(body, tokenField)?.ToString();
        if (string.IsNullOrEmpty(token))
            throw new IntegrationException($"{uri.Host} answered the sign-in without {tokenField}.");
        var minutes = int.TryParse(_record.Options["lifetimeMinutes"]?.ToString(), out var m) && m > 0 ? m : 25;
        return (token, DateTimeOffset.UtcNow.AddMinutes(minutes));
    }

    // ---- Entra: interactive through the Windows broker (WAM), or an app certificate ----

    private IReadOnlyList<string> Scopes()
    {
        if (_record.Options["scopes"] is JsonArray list)
            return list.Select(s => s?.ToString() ?? "").Where(s => s.Length > 0).ToList();
        if (_record.Options["scopes"]?.ToString() is { Length: > 0 } text)
            return text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var resource = Uri.TryCreate(_record.Endpoint, UriKind.Absolute, out var uri) ? $"{uri.Scheme}://{uri.Host}" : "https://graph.microsoft.com";
        return [$"{resource}/.default"];
    }

    private (string ClientId, string TenantId) EntraApp() =>
        (_record.Options["clientId"]?.ToString() ?? throw new IntegrationException($"Integration {_record.Id} needs the option clientId (an app registration)."),
         _record.Options["tenantId"]?.ToString() ?? throw new IntegrationException($"Integration {_record.Id} needs the option tenantId."));

    private async Task<(string, DateTimeOffset)> EntraInteractiveAsync(CancellationToken cancellationToken)
    {
        var (clientId, tenantId) = EntraApp();
        var builder = PublicClientApplicationBuilder.Create(clientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithDefaultRedirectUri();
        if (OperatingSystem.IsWindows())
        {
            builder = builder
                .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows) { Title = "Keeper" })
                .WithParentActivityOrWindow(GetConsoleWindow);
        }
        var app = builder.Build();
        var scopes = Scopes();
        // The account this integration reads as, typically an admin account. Null: whoever is signed in.
        var wanted = _record.Identity;

        try
        {
            var accounts = await app.GetAccountsAsync().ConfigureAwait(false);
            var account = wanted is null
                ? accounts.FirstOrDefault()
                : accounts.FirstOrDefault(a => string.Equals(a.Username, wanted, StringComparison.OrdinalIgnoreCase));

            AuthenticationResult? result = null;
            // With an identity, never the Windows account: it is usually not the admin account, and a scan
            // through it reads less while looking complete. A fresh sign-in skips the cache altogether: a
            // token minted before a PIM activation does not carry the new role.
            if ((account is not null || wanted is null) && !FreshSignIn)
            {
                try
                {
                    var silent = account is null
                        ? app.AcquireTokenSilent(scopes, PublicClientApplication.OperatingSystemAccount)
                        : app.AcquireTokenSilent(scopes, account);
                    result = await silent.ExecuteAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (MsalUiRequiredException)
                {
                    // Falls through to the interactive sign-in.
                }
            }
            if (result is null)
            {
                if (!Environment.UserInteractive || Console.IsInputRedirected)
                    throw new IntegrationException($"Integration {_record.Id} needs an interactive sign-in{(wanted is null ? "" : $" as {wanted}")}, and this run has no desktop. Run the scan from your own window once, or use entra-certificate.");
                var interactive = app.AcquireTokenInteractive(scopes);
                if (wanted is not null)
                    interactive = interactive.WithLoginHint(wanted);
                result = await interactive.ExecuteAsync(cancellationToken).ConfigureAwait(false);
            }

            _signedInAs = SignedInAccount(_record.Id, wanted, result.Account?.Username);
            return (result.AccessToken, result.ExpiresOn);
        }
        catch (MsalException ex)
        {
            throw new IntegrationException($"Entra sign-in failed: {ex.ErrorCode}: {ex.Message}");
        }
    }

    /// <summary>
    /// The account a token was issued to, when it is the one the integration reads as. A token for anyone
    /// else - picked in the account chooser, or the Windows account - would make a scan that reads less and
    /// still looks complete, so it is refused.
    /// </summary>
    public static string? SignedInAccount(string integration, string? wanted, string? issuedTo)
    {
        if (wanted is not null && !string.Equals(issuedTo, wanted, StringComparison.OrdinalIgnoreCase))
            throw new IntegrationException(
                $"Integration {integration} reads as {wanted}, but the sign-in returned {issuedTo ?? "an unknown account"}. " +
                (wanted.Contains('@', StringComparison.Ordinal)
                    ? $"Sign in as {wanted} (activate its PIM role first if it needs one)."
                    : $"The identity must be the account's sign-in name (user@domain): keeper integration set {integration} --identity <user@domain> --reason \"...\"."));
        return issuedTo;
    }

    private async Task<(string, DateTimeOffset)> EntraCertificateAsync(CancellationToken cancellationToken)
    {
        var (clientId, tenantId) = EntraApp();
        var thumbprint = _record.Options["certificateThumbprint"]?.ToString()
            ?? throw new IntegrationException($"Integration {_record.Id} needs the option certificateThumbprint (a certificate in CurrentUser\\My).");
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false).FirstOrDefault()
            ?? throw new IntegrationException($"Certificate {thumbprint} is not in CurrentUser\\My.");

        var app = ConfidentialClientApplicationBuilder.Create(clientId)
            .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
            .WithCertificate(certificate)
            .Build();
        try
        {
            var result = await app.AcquireTokenForClient(Scopes()).ExecuteAsync(cancellationToken).ConfigureAwait(false);
            return (result.AccessToken, result.ExpiresOn);
        }
        catch (MsalException ex)
        {
            throw new IntegrationException($"Entra sign-in failed: {ex.ErrorCode}: {ex.Message}");
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetConsoleWindow();

    public void Dispose() => _tokenLock.Dispose();
}
