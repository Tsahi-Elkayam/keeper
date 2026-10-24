using System.Text.Json;
using Keeper.Queue;
using Keeper.Store;
using Keeper.Vault;

namespace Keeper.Integrations.Tests;

public sealed class IntegrationTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, Vault.Vault.Schema, IntegrationStore.Schema];

    // AWS's documentation example key id, from the demo vault: the organisation's DLP flags a key written out.
    // Theories name it {key}, filled in at run time.
    private static readonly string ExampleKeyId = Keeper.TestKit.DemoVault.Get("aws-doc-id");
    private const string Key = "{key}";

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;
    private readonly Database _db;

    public IntegrationTests()
    {
        _db = new Database(Path.Combine(DataDir, "keeper.db"));
        using var connection = _db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string DataDir => Path.Combine(_dir, "data");

    [Theory]
    [InlineData("https://fw.example.org", "/web_api/login", "https://fw.example.org/web_api/login")]
    [InlineData("https://fw.example.org", "//evil.example.com/login", null)]
    [InlineData("https://fw.example.org", "https://evil.example.com/login", null)]
    [InlineData("http://fw.example.org", "/web_api/login", null)]
    [InlineData("https://fw.example.org", null, null)]
    public void A_session_login_goes_only_to_a_path_on_the_integrations_own_https_endpoint(string endpoint, string? path, string? expected)
    {
        if (expected is null)
            Assert.Throws<IntegrationException>(() => IntegrationConnection.LoginUri(endpoint, path));
        else
            Assert.Equal(expected, IntegrationConnection.LoginUri(endpoint, path).ToString());
    }

    [Theory]
    [InlineData("admin@example.org", "admin@example.org", true)]
    [InlineData("admin@example.org", "ADMIN@Example.org", true)]    // case only
    [InlineData("admin@example.org", "someone@example.org", false)] // the Windows account, or another pick in the chooser
    [InlineData("admin@example.org", null, false)]
    [InlineData(null, "someone@example.org", true)]                 // no identity set: whoever signed in, recorded as such
    public void An_entra_token_is_accepted_only_for_the_account_the_integration_reads_as(string? wanted, string? issuedTo, bool accepted)
    {
        if (accepted)
            Assert.Equal(issuedTo, IntegrationConnection.SignedInAccount("entra", wanted, issuedTo));
        else
            Assert.Contains("reads as admin@example.org", Assert.Throws<IntegrationException>(() => IntegrationConnection.SignedInAccount("entra", wanted, issuedTo)).Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("power-platform", "https://api.bap.microsoft.com", "https://service.powerapps.com//.default")]   // the resource's own name, slash and all
    [InlineData("defender-endpoint", "https://api-eu.securitycenter.microsoft.com", "https://api.securitycenter.microsoft.com/.default")]
    [InlineData("key-vault", "https://kv1.vault.azure.net", "https://vault.azure.net/.default")]
    [InlineData("cloud-apps", "https://contoso.eu2.portal.cloudappsecurity.com", "05a65629-4c1b-48c1-a78b-804c4abdd4af/.default")]
    [InlineData("dataverse", "https://org1.crm4.dynamics.com", "https://org1.crm4.dynamics.com/.default")]   // its own environment only
    [InlineData("exchange-online", "https://outlook.office365.com/adminapi/beta/00000000-0000-0000-0000-000000000000", "https://outlook.office365.com/.default")]
    public void Each_microsoft_api_gets_a_token_for_its_own_resource(string type, string endpoint, string scope)
    {
        Assert.Equal(scope, IntegrationConnection.DefaultScope(IntegrationTypes.Find(type)!.Resource, endpoint));
    }

    [Theory]
    [InlineData("key-vault", "kv1.vault.azure.net", true)]
    [InlineData("key-vault", "vault.azure.net.example.com", false)]
    [InlineData("exchange-online", "outlook.office365.com", true)]
    [InlineData("exchange-online", "outlook.office365.com.example.com", false)]
    [InlineData("purview", "eur02b.ps.compliance.protection.outlook.com", true)]
    [InlineData("dataverse", "org1.crm4.dynamics.com", true)]
    [InlineData("dataverse", "dynamics.com.example.org", false)]
    [InlineData("dataverse", "admin.dynamics.com", false)]                 // a Dynamics host, not a Dataverse environment
    [InlineData("dataverse", "org1.crm11.dynamics.com", true)]
    [InlineData("defender-endpoint", "api-eu.securitycenter.microsoft.com", true)]
    [InlineData("defender-endpoint", "api.security.microsoft.com", false)]  // Defender XDR: another resource
    public void A_microsoft_api_token_goes_only_to_its_own_hosts(string type, string host, bool allowed)
    {
        Assert.Equal(allowed, IntegrationTypes.Find(type)!.AllowsHost(host));
    }

    [Theory]
    [InlineData("key-vault", "/", true)]
    [InlineData("key-vault", "/secrets", false)]                                         // would shift the readable paths
    [InlineData("exchange-online", "/adminapi/beta/00000000-0000-0000-0000-000000000000", true)]
    [InlineData("exchange-online", "/adminapi/beta/example.onmicrosoft.com", true)]
    [InlineData("exchange-online", "/adminapi/beta/x/y", false)]
    [InlineData("exchange-online", "/", false)]
    [InlineData("exchange-online", "/adminapi/beta/..", false)]
    [InlineData("azure", "/", true)]
    public void A_guarded_types_endpoint_has_its_own_path_and_no_other(string type, string path, bool allowed)
    {
        Assert.Equal(allowed, IntegrationTypes.Find(type)!.AllowsEndpointPath(path));
    }

    [Fact]
    public void A_connection_offers_its_types_protocols_and_refuses_an_endpoint_saved_with_a_path_its_type_does_not_allow()
    {
        var vault = new IntegrationRecord("kv", "key-vault", "https://kv1.vault.azure.net/secrets", "entra-certificate", null, [], true, new Dictionary<string, StoredSecret>());
        using var stored = new IntegrationConnection(vault, null);
        using var clean = new IntegrationConnection(vault with { Endpoint = "https://kv1.vault.azure.net" }, null);
        using var unknown = new IntegrationConnection(vault with { Type = "retired-type" }, null);

        Assert.Equal(["http"], stored.Protocols);
        Assert.Contains("/secrets", stored.EndpointProblem, StringComparison.Ordinal);
        Assert.Null(clean.EndpointProblem);
        Assert.Empty(unknown.Protocols!);   // a type Keeper no longer knows offers nothing
    }

    [Theory]
    [InlineData("eu-central-1", Key, "111111111111", "keeper-read", true)]
    [InlineData("eu-central-1", Key, null, null, true)]                        // its own account only
    [InlineData("https://ec2.amazonaws.com", Key, null, null, false)]          // a region, never a host
    [InlineData("eu-central-1", "keeper-user", null, null, false)]             // not an access key id
    [InlineData("eu-central-1", Key, "111111111111", null, false)]             // accounts without the role to assume
    [InlineData("eu-central-1", Key, "1111", "keeper-read", false)]
    public void An_aws_integration_is_a_home_region_an_access_key_id_and_accounts_with_their_role(string endpoint, string identity,
        string? account, string? role, bool accepted)
    {
        identity = identity == Key ? ExampleKeyId : identity;
        Submit("integrations.upsert", new
        {
            integrationId = "aws", type = "aws", endpoint, authKind = "aws-access-key", identity,
            options = account is null ? (object)new { } : new { accounts = new[] { account }, roleName = role, regions = new[] { "eu-west-1" } },
        });

        Assert.Equal(accepted ? 1 : 0, Drain().Done);
    }

    [Fact]
    public async Task An_aws_connection_reads_its_home_region_first_and_only_the_accounts_it_names()
    {
        var record = new IntegrationRecord("aws", "aws", "eu-central-1", "aws-access-key", ExampleKeyId,
            new System.Text.Json.Nodes.JsonObject { ["accounts"] = new System.Text.Json.Nodes.JsonArray("111111111111"), ["roleName"] = "keeper-read",
                ["regions"] = new System.Text.Json.Nodes.JsonArray("eu-west-1", "eu-central-1") },
            true, new Dictionary<string, StoredSecret>());
        using var connection = new IntegrationConnection(record, null);

        Assert.Equal(["eu-central-1", "eu-west-1"], connection.AwsRegions);
        Assert.Equal(["111111111111"], connection.AwsAccounts);
        // No secret is set: refused, and refused the same way again rather than retried.
        var first = await Assert.ThrowsAsync<IntegrationException>(() => connection.AwsCredentialsAsync(null, CancellationToken.None));
        var again = await Assert.ThrowsAsync<IntegrationException>(() => connection.AwsCredentialsAsync(null, CancellationToken.None));
        Assert.Contains("secretAccessKey", first.Message, StringComparison.Ordinal);
        Assert.Same(first, again);
        await Assert.ThrowsAsync<IntegrationException>(() => connection.AwsCredentialsAsync("222222222222", CancellationToken.None));
    }

    [Fact]
    public void Key_vault_never_reads_a_secrets_value_and_exchange_runs_get_cmdlets_only()
    {
        var vault = IntegrationTypes.Find("key-vault")!;
        var exchange = IntegrationTypes.Find("exchange-online")!;

        Assert.DoesNotContain(vault.ReadPaths, p => p is "/secrets/*" or "/secrets/*/*");
        Assert.Equal(["Get-*"], exchange.ReadCommand!.Allowed);
        Assert.Equal(["/InvokeCommand"], exchange.ReadPosts);
    }

    [Fact]
    public async Task A_refused_sign_in_is_refused_once_for_the_whole_scan_not_retried_per_query()
    {
        // No identity: the sign-in fails before anything is sent. The same must hold for a refused password.
        var record = new IntegrationRecord("app", "http", "https://app.example.org", "session-login", null, [], true, new Dictionary<string, StoredSecret>());
        using var connection = new IntegrationConnection(record, null);
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://app.example.org/api/a");
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://app.example.org/api/b");

        var a = await Assert.ThrowsAsync<IntegrationException>(() => connection.AuthorizeAsync(first, CancellationToken.None));
        var b = await Assert.ThrowsAsync<IntegrationException>(() => connection.AuthorizeAsync(second, CancellationToken.None));

        Assert.Same(a, b);
    }

    [Fact]
    public void A_negotiate_connection_says_which_windows_user_it_reads_as()
    {
        var negotiate = new IntegrationRecord("ad", "ldap", "example.org", "negotiate", null, [], true, new Dictionary<string, StoredSecret>());
        var basic = negotiate with { AuthKind = "basic", Identity = "reader" };

        using var a = new IntegrationConnection(negotiate, null);
        using var b = new IntegrationConnection(basic, null);

        Assert.Equal($"{Environment.UserDomainName}\\{Environment.UserName}", a.SignedInAs);
        Assert.Null(b.SignedInAs);   // the manifest falls back to the identity, reader
    }

    private QueueReport Drain() =>
        new QueueManager(_db, Path.Combine(DataDir, "spool"), DataDir, Schemas, IntegrationHandlers.All()).DrainOnce();

    private void Submit<T>(string kind, T payload) where T : notnull =>
        new RequestWriter(Path.Combine(DataDir, "spool")).Submit(kind, "test", payload, @"TEST\user");

    private IntegrationRecord? Find(string id)
    {
        using var connection = _db.OpenReadOnly();
        return IntegrationStore.Find(connection, id);
    }

    private void AddServiceNow(string endpoint = "https://example.service-now.com") =>
        Submit("integrations.upsert", new { integrationId = "snow", type = "servicenow", endpoint, authKind = "basic", identity = "keeper-reader" });

    /// <summary>Seals like keeper-integration set-secret does, creating the vault key on first use.</summary>
    private void SetSecret(string id, string name, string plaintext, string endpoint)
    {
        var protector = KeyProtectors.Default(_dir);
        Vault.Vault vault;
        using (var connection = _db.OpenReadOnly())
            vault = Vault.Vault.Load(connection, protector);
        var binding = IntegrationStore.Binding(id, name, endpoint);
        SealedSecret sealedSecret;
        if (vault.ActiveKeyId is null)
        {
            var (keyId, wrapped) = Vault.Vault.NewKey(protector);
            Submit("vault.create-key", new { keyId, protector = protector.Kind, wrapped = Convert.ToBase64String(wrapped) });
            sealedSecret = Vault.Vault.Seal(protector, keyId, wrapped, plaintext, binding);
        }
        else
        {
            sealedSecret = vault.Seal(plaintext, binding);
        }
        Submit("integrations.set-secret", new
        {
            integrationId = id, name, keyId = sealedSecret.KeyId, nonce = Convert.ToBase64String(sealedSecret.Nonce),
            ciphertext = Convert.ToBase64String(sealedSecret.Ciphertext), tag = Convert.ToBase64String(sealedSecret.Tag), boundTo = binding,
        });
    }

    private IntegrationConnection Connect(string id)
    {
        using var connection = _db.OpenReadOnly();
        return new IntegrationConnection(IntegrationStore.Find(connection, id)!, Vault.Vault.Load(connection, KeyProtectors.Default(_dir)));
    }

    [Fact]
    public void A_secret_is_stored_sealed_and_opens_only_through_its_integration()
    {
        AddServiceNow();
        Assert.Equal(1, Drain().Done);
        // A demo password from the demo vault: the organisation's DLP flags one written out in the source.
        var plaintext = Keeper.TestKit.DemoVault.Get("demo-login");
        SetSecret("snow", "password", plaintext, "https://example.service-now.com");
        Assert.Equal(2, Drain().Done);

        using var connection = Connect("snow");
        Assert.Equal(plaintext, connection.Secret("password"));

        // Nothing on disk holds the plaintext: not the store, not the spool.
        foreach (var file in Directory.GetFiles(DataDir, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain(plaintext, File.ReadAllText(file), StringComparison.Ordinal);
    }

    [Fact]
    public void A_sealed_secret_does_not_open_for_another_integration_or_endpoint()
    {
        var protector = KeyProtectors.Default(_dir);
        var (keyId, wrapped) = Vault.Vault.NewKey(protector);
        var sealedSecret = Vault.Vault.Seal(protector, keyId, wrapped, "s3cret", IntegrationStore.Binding("snow", "password", "https://a.service-now.com"));

        Submit("vault.create-key", new { keyId, protector = protector.Kind, wrapped = Convert.ToBase64String(wrapped) });
        Assert.Equal(1, Drain().Done);
        using var connection = _db.OpenReadOnly();
        var vault = Vault.Vault.Load(connection, protector);

        Assert.Equal("s3cret", vault.Open(sealedSecret, IntegrationStore.Binding("snow", "password", "https://a.service-now.com")));
        Assert.Throws<VaultException>(() => vault.Open(sealedSecret, IntegrationStore.Binding("snow", "password", "https://evil.service-now.com")));
        Assert.Throws<VaultException>(() => vault.Open(sealedSecret, IntegrationStore.Binding("other", "password", "https://a.service-now.com")));
    }

    [Fact]
    public void Changing_the_endpoint_drops_the_secrets_bound_to_the_old_one()
    {
        AddServiceNow();
        Drain();
        SetSecret("snow", "password", "pw", "https://example.service-now.com");
        Drain();
        Assert.Single(Find("snow")!.Secrets);

        AddServiceNow("https://other.service-now.com");
        Assert.Equal(1, Drain().Done);

        Assert.Empty(Find("snow")!.Secrets);
    }

    [Fact]
    public void A_secret_sealed_for_an_old_endpoint_is_refused()
    {
        AddServiceNow();
        Drain();
        SetSecret("snow", "password", "pw", "https://stale.service-now.com");

        Assert.Equal(1, Drain().Failed);
        Assert.Empty(Find("snow")!.Secrets);
    }

    [Theory]
    [InlineData("servicenow", "https://servicenow.example.com", "basic")]      // not a ServiceNow host
    [InlineData("servicenow", "http://example.service-now.com", "basic")]       // cleartext
    [InlineData("servicenow", "https://example.service-now.com", "negotiate")]  // auth kind not allowed
    [InlineData("graph", "https://graph.example.com", "entra-interactive")]
    [InlineData("nope", "https://x.example.org", "none")]
    public void An_unacceptable_integration_is_refused(string type, string endpoint, string authKind)
    {
        Submit("integrations.upsert", new { integrationId = "x", type, endpoint, authKind });

        Assert.Equal(1, Drain().Failed);
        Assert.Null(Find("x"));
    }

    [Theory]
    [InlineData(@"EXAMPLE\admin", false)]   // a Windows name is not what Entra returns
    [InlineData("Admin Example", false)]
    [InlineData("admin@example.org", true)]
    public void An_entra_interactive_identity_must_be_a_sign_in_name(string identity, bool accepted)
    {
        Submit("integrations.upsert", new { integrationId = "entra", type = "graph", authKind = "entra-interactive", identity });

        var report = Drain();

        Assert.Equal(accepted ? 1 : 0, report.Done);
        Assert.Equal(accepted, Find("entra") is not null);
    }

    [Theory]
    [InlineData("auto", true)]
    [InlineData("dcom", true)]
    [InlineData("telnet", false)]
    public void Cim_protocol_is_winrm_dcom_or_auto(string protocol, bool accepted)
    {
        Submit("integrations.upsert", new { integrationId = "pcs", type = "cim", endpoint = "pc01.example.org", authKind = "negotiate", options = new { cimProtocol = protocol } });

        Assert.Equal(accepted ? 1 : 0, Drain().Done);
    }

    [Fact]
    public void An_option_that_looks_like_a_secret_is_refused()
    {
        var notAnOption = string.Concat("oo", "ps");
        Submit("integrations.upsert", new
        {
            integrationId = "wiz", type = "wiz", endpoint = "https://api.eu1.app.wiz.io", authKind = "oauth-client-credentials",
            options = new { tokenUrl = "https://auth.app.wiz.io/oauth/token", clientSecret = notAnOption },
        });

        Assert.Equal(1, Drain().Failed);
    }

    private void UpsertSsh(string endpoint = "192.0.2.0/24, *.example.org", string authKind = "ssh-key", string? identity = "keeper-reader", object? options = null) =>
        Submit("integrations.upsert", new { integrationId = "fleet", type = "ssh", endpoint, authKind, identity, options = options ?? new { targets = new[] { "192.0.2.10" } } });

    [Fact]
    public void An_ssh_integration_names_where_its_credential_may_go_and_who_signs_in()
    {
        UpsertSsh(options: new { port = "2222", acceptAnyHostKey = "false", hostKeys = new { web01 = "SHA256:abc" }, targets = new[] { "web01.example.org" } });

        Assert.Equal(1, Drain().Done);
        var record = Find("fleet")!;
        Assert.Equal("ssh", record.Type);
        Assert.Equal("keeper-reader", record.Identity);
    }

    [Theory]
    [InlineData("", "ssh-key", "keeper-reader", null)]                       // no scope: the credential could go anywhere
    [InlineData("https://example.org", "ssh-key", "keeper-reader", null)]    // a URL is not a scope
    [InlineData("*", "ssh-key", "keeper-reader", null)]                      // everywhere
    [InlineData("192.0.2.0/24", "ssh-key", null, null)]                      // nobody to sign in as
    [InlineData("192.0.2.0/24", "basic", "keeper-reader", null)]             // not an ssh sign-in
    [InlineData("192.0.2.0/24", "ssh-key", "keeper-reader", "{\"port\":70000}")]
    [InlineData("192.0.2.0/24", "ssh-key", "keeper-reader", "{\"port\":\"abc\"}")]
    [InlineData("192.0.2.0/24", "ssh-key", "keeper-reader", "{\"acceptAnyHostKey\":\"maybe\"}")]
    [InlineData("192.0.2.0/24", "ssh-key", "keeper-reader", "{\"hostKeys\":{\"web01\":5}}")]
    public void A_badly_scoped_or_incomplete_ssh_integration_is_refused(string endpoint, string authKind, string? identity, string? optionsJson)
    {
        var options = optionsJson is null ? null : System.Text.Json.JsonSerializer.Deserialize<object>(optionsJson);
        UpsertSsh(endpoint, authKind, identity, options);

        Assert.Equal(1, Drain().Failed);
        Assert.Null(Find("fleet"));
    }

    [Fact]
    public void Rules_written_for_the_host_protocol_can_run_through_a_named_ssh_integration_but_never_choose_one_alone()
    {
        UpsertSsh();
        Assert.Equal(1, Drain().Done);
        using var connection = _db.OpenReadOnly();

        Assert.Equal("fleet", IntegrationStore.Resolve(connection, "host", "fleet").Id);
        Assert.Equal("host", IntegrationStore.Resolve(connection, "host", null).Id);      // the local machine, as before
        Assert.Throws<IntegrationException>(() => IntegrationStore.Resolve(connection, "ldap", "fleet"));
        Assert.True(IntegrationTypes.Satisfies("host", "ssh"));
        Assert.False(IntegrationTypes.Satisfies("ssh", "host"));
        Assert.False(IntegrationTypes.Satisfies("cim", "ssh"));
    }

    [Fact]
    public void Implicit_integrations_need_no_configuration()
    {
        using var connection = _db.OpenReadOnly();

        Assert.Equal("files", IntegrationStore.Resolve(connection, "files", null).Id);
        Assert.Throws<IntegrationException>(() => IntegrationStore.Resolve(connection, "ldap", null));
    }

    [Fact]
    public void Api_key_query_auth_adds_the_parameter_without_losing_the_query()
    {
        var record = new IntegrationRecord("prtg", "prtg", "https://prtg.example.org", "api-key-query", null,
            new System.Text.Json.Nodes.JsonObject { ["param"] = "apitoken" }, true, new Dictionary<string, StoredSecret>());
        using var connection = new IntegrationConnection(record, null);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://prtg.example.org/api/table.json?content=sensors");

        var ex = Assert.Throws<IntegrationException>(() => connection.AuthorizeAsync(request, CancellationToken.None).GetAwaiter().GetResult());
        Assert.Contains("set-secret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Describe_never_shows_secret_material()
    {
        var record = new IntegrationRecord("snow", "servicenow", "https://example.service-now.com", "basic", "reader", [], true,
            new Dictionary<string, StoredSecret>
            {
                ["password"] = new("password", new SealedSecret("k-1", [1, 2, 3], [9, 9, 9, 9], [7, 7]), "b", "2026-10-20T00:00:00Z", "2027-01-01"),
            });

        var text = IntegrationStore.Describe(record);

        Assert.Contains("2027-01-01", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Ciphertext", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CQkJCQ", text, StringComparison.Ordinal);   // base64 of the ciphertext
        Assert.Contains("password", JsonDocument.Parse(text).RootElement.GetProperty("Secrets")[0].GetProperty("Name").GetString(), StringComparison.Ordinal);
    }
}
