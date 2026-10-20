using System.Text.Json;
using Keeper.Queue;
using Keeper.Store;
using Keeper.Vault;

namespace Keeper.Integrations.Tests;

public sealed class IntegrationTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, Vault.Vault.Schema, IntegrationStore.Schema];

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
        var protector = KeyProtectors.Default();
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
        return new IntegrationConnection(IntegrationStore.Find(connection, id)!, Vault.Vault.Load(connection, KeyProtectors.Default()));
    }

    [Fact]
    public void A_secret_is_stored_sealed_and_opens_only_through_its_integration()
    {
        if (!OperatingSystem.IsWindows())
            return;
        AddServiceNow();
        Assert.Equal(1, Drain().Done);
        SetSecret("snow", "password", "Hunter2-not-real", "https://example.service-now.com");
        Assert.Equal(2, Drain().Done);

        using var connection = Connect("snow");
        Assert.Equal("Hunter2-not-real", connection.Secret("password"));

        // Nothing on disk holds the plaintext: not the store, not the spool.
        foreach (var file in Directory.GetFiles(DataDir, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain("Hunter2-not-real", File.ReadAllText(file), StringComparison.Ordinal);
    }

    [Fact]
    public void A_sealed_secret_does_not_open_for_another_integration_or_endpoint()
    {
        if (!OperatingSystem.IsWindows())
            return;
        var protector = KeyProtectors.Default();
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
        if (!OperatingSystem.IsWindows())
            return;
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
        if (!OperatingSystem.IsWindows())
            return;
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

    [Fact]
    public void An_option_that_looks_like_a_secret_is_refused()
    {
        Submit("integrations.upsert", new
        {
            integrationId = "wiz", type = "wiz", endpoint = "https://api.eu1.app.wiz.io", authKind = "oauth-client-credentials",
            options = new { tokenUrl = "https://auth.app.wiz.io/oauth/token", clientSecret = "oops" },
        });

        Assert.Equal(1, Drain().Failed);
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
