using System.Text.Json.Nodes;
using Keeper.Queue;
using Keeper.Review.Config;
using Keeper.Store;

namespace Keeper.Review.Tests;

/// <summary>
/// The integrations config family, mirroring SettingsConfigTests. These exercise only the file reader and
/// writer (no store), so they hold the deterministic-round-trip and malformed-file guarantees.
/// </summary>
public sealed class IntegrationsConfigTests
{
    private static readonly IntegrationRecord[] Sample =
    [
        new("ad-main", "ldap", "ldaps://dc.example.org", "windows-credential", "reader", true, new JsonObject(), ["password"]),
        new("snow", "servicenow", "https://example.service-now.com", "basic", "Alex O'Brien", false,   // a quote, to exercise quoting
            new JsonObject { ["headers"] = new JsonObject { ["x-note"] = "hi, Dana" } }, []),
        new("wiz", "wiz", "https://api.eu1.app.wiz.io", "oauth-client-credentials", null, true,
            new JsonObject { ["tokenUrl"] = "https://auth.app.wiz.io/oauth/token", ["scopes"] = new JsonArray("read:a", "read:b") },
            ["clientSecret"]),
    ];

    [Fact]
    public void Write_then_read_then_write_is_byte_stable()
    {
        var yaml1 = IntegrationsConfig.Write("acme", Sample);
        var records = IntegrationsConfig.Read(yaml1, "mem", out var client);
        var yaml2 = IntegrationsConfig.Write(client, records);

        Assert.Equal("acme", client);
        Assert.Equal(yaml1, yaml2);
    }

    [Fact]
    public void Read_recovers_every_field_ordered_by_id()
    {
        var byId = IntegrationsConfig.Read(IntegrationsConfig.Write(null, Sample), "mem", out _)
            .ToDictionary(i => i.Id, StringComparer.Ordinal);

        Assert.Equal(["ad-main", "snow", "wiz"], byId.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("ldap", byId["ad-main"].Type);
        Assert.Equal("windows-credential", byId["ad-main"].AuthKind);
        Assert.Equal(["password"], byId["ad-main"].Secrets);
        Assert.False(byId["snow"].Enabled);
        Assert.Null(byId["wiz"].Identity);
        Assert.Equal(["clientSecret"], byId["wiz"].Secrets);
        // Options survive: a nested headers map, and an array of scopes.
        Assert.Equal("hi, Dana", (string?)byId["snow"].Options["headers"]!["x-note"]);
        Assert.Equal("read:a", (string?)byId["wiz"].Options["scopes"]![0]);
    }

    [Fact]
    public void A_well_formed_empty_file_reads_as_no_integrations()
    {
        Assert.Empty(IntegrationsConfig.Read("schema: keeper.config/1\nintegrations: []\n", "mem", out _));
    }

    [Theory]
    [InlineData("this: is: not: valid: yaml")]                                                            // unparseable
    [InlineData("schema: wrong/9\nintegrations: []")]                                                     // wrong schema
    [InlineData("client: 'x'\nintegrations: []")]                                                         // missing schema
    [InlineData("schema: keeper.config/1")]                                                               // missing integrations
    [InlineData("schema: keeper.config/1\nintegrations:\n  - type: 'ldap'\n    auth: 'basic'")]           // missing id
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    auth: 'basic'")]                // missing type
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'")]                 // missing auth
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'Bad Id'\n    type: 'ldap'\n    auth: 'basic'")] // bad id
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n    bogus: 1")] // unknown field
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n    enabled: maybe")] // bad enabled
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n    options: 'x'")] // options not a mapping
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n    secrets: 'x'")] // secrets not a list
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n    secrets: ['s', 's']")] // duplicate secret
    [InlineData("schema: keeper.config/1\nintegrations:\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'\n  - id: 'a'\n    type: 'ldap'\n    auth: 'basic'")] // duplicate id
    public void A_malformed_file_throws_config_exception(string yaml)
    {
        var ex = Assert.Throws<ConfigException>(() => IntegrationsConfig.Read(yaml, "bad.yaml", out _));
        Assert.NotEmpty(ex.Errors);
    }
}

/// <summary>
/// The secret-safety proof and the store round-trips. These seed a real integration store and vault and drive
/// the real integration request handlers (the one-writer path), exactly as keeper-config does, so they prove
/// the security-critical guarantee: no secret value - plaintext or ciphertext - ever reaches the config file,
/// and import never reads, writes or requires a secret (the vault is untouched).
/// </summary>
public sealed class IntegrationsConfigStoreTests : IDisposable
{
    private static readonly MigrationSet[] Schemas =
        [QueueSchema.Migrations, Keeper.Vault.Vault.Schema, Keeper.Integrations.IntegrationStore.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-cfgtest-").FullName;
    private readonly Database _db;

    public IntegrationsConfigStoreTests()
    {
        _db = new Database(Path.Combine(DataDir, "keeper.db"));
        using var connection = _db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string DataDir => Path.Combine(_dir, "data");
    private string Spool => Path.Combine(DataDir, "spool");

    [Fact]
    public void Export_records_the_secret_name_but_never_its_value_or_ciphertext()
    {
        Submit("integrations.upsert", new { integrationId = "snow", type = "servicenow", endpoint = "https://example.service-now.com", authKind = "basic", identity = "keeper-reader" });
        Assert.Equal(1, Drain().Done);

        // A DLP-safe demo value (password-shaped text in the source is flagged by the organisation's DLP).
        var plaintext = Keeper.TestKit.DemoVault.Get("demo-login");
        var ciphertextBase64 = SetSecret("snow", "password", plaintext, "https://example.service-now.com");
        Assert.Equal(2, Drain().Done);   // vault.create-key + integrations.set-secret

        var yaml = IntegrationsConfig.Write("acme", ReadStore());

        // The NAME is present; neither the plaintext nor the stored ciphertext (base64 as queued, or re-read
        // straight from the store) appears anywhere in the file.
        Assert.Contains("secrets: ['password']", yaml, StringComparison.Ordinal);
        Assert.DoesNotContain(plaintext, yaml, StringComparison.Ordinal);
        Assert.DoesNotContain(ciphertextBase64, yaml, StringComparison.Ordinal);
        var storedCiphertext = Convert.ToBase64String((byte[])Rows("SELECT ciphertext FROM integration_secret;").Single()["ciphertext"]!);
        Assert.DoesNotContain(storedCiphertext, yaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Export_import_export_through_the_store_is_byte_identical_idempotent_and_leaves_the_vault_untouched()
    {
        Submit("integrations.upsert", new { integrationId = "snow", type = "servicenow", endpoint = "https://example.service-now.com", authKind = "basic", identity = "keeper-reader" });
        Submit("integrations.upsert", new
        {
            integrationId = "wiz", type = "wiz", endpoint = "https://api.eu1.app.wiz.io", authKind = "oauth-client-credentials",
            options = new { tokenUrl = "https://auth.app.wiz.io/oauth/token", scopes = new[] { "read:a", "read:b" } },
        });
        Assert.Equal(2, Drain().Done);
        SetSecret("wiz", "clientSecret", Keeper.TestKit.DemoVault.Get("demo-login"), "https://api.eu1.app.wiz.io");
        Assert.Equal(2, Drain().Done);

        var yaml1 = IntegrationsConfig.Write("acme", ReadStore());
        var vaultBefore = VaultSnapshot();

        // Import exactly as keeper-config does: compare-first, upsert only what differs.
        var fromFile = IntegrationsConfig.Read(yaml1, "file", out var client);
        var inStore = ReadStore().ToDictionary(e => e.Id, StringComparer.Ordinal);
        var queued = 0;
        foreach (var e in fromFile)
        {
            if (inStore.TryGetValue(e.Id, out var current) && IntegrationsConfig.SameConfig(current, e))
                continue;
            Submit("integrations.upsert", UpsertPayload(e));
            queued++;
        }
        Assert.Equal(0, queued);            // every config already matches: idempotent, nothing to queue
        Assert.Equal(0, Drain().Done);

        var yaml2 = IntegrationsConfig.Write(client, ReadStore());
        Assert.Equal(yaml1, yaml2);         // byte-identical round-trip
        Assert.Equal(vaultBefore, VaultSnapshot());   // import touched neither the vault key nor the sealed secret
    }

    [Fact]
    public void Import_applies_config_into_a_fresh_store_without_reading_or_creating_any_secret()
    {
        // A file that declares an integration WITH an expected secret name but, of course, no value.
        var file = IntegrationsConfig.Write("acme",
        [
            new IntegrationRecord("snow", "servicenow", "https://example.service-now.com", "basic", "keeper-reader", true, new JsonObject(), ["password"]),
        ]);
        var fromFile = IntegrationsConfig.Read(file, "file", out _);

        foreach (var e in fromFile)
            Submit("integrations.upsert", UpsertPayload(e));
        Assert.Equal(1, Drain().Done);

        var stored = Assert.Single(ReadStore());
        Assert.Equal("snow", stored.Id);
        Assert.Empty(stored.Secrets);                                           // import did NOT create the named secret
        Assert.Equal(0L, (long)Rows("SELECT COUNT(*) AS n FROM integration_secret;").Single()["n"]!);
        Assert.Equal(0L, (long)Rows("SELECT COUNT(*) AS n FROM vault_key;").Single()["n"]!);   // the vault was never touched
    }

    // Helpers --------------------------------------------------------------------

    private List<IntegrationRecord> ReadStore()
    {
        using var connection = _db.OpenReadOnly();
        return Keeper.Integrations.IntegrationStore.All(connection).Select(i => new IntegrationRecord(
            i.Id, i.Type, i.Endpoint, i.AuthKind, i.Identity, i.Enabled,
            IntegrationsConfig.Normalize(i.Options),
            i.Secrets.Keys.Order(StringComparer.Ordinal).ToList())).ToList();
    }

    private static object UpsertPayload(IntegrationRecord e) => new
    {
        integrationId = e.Id, type = e.Type, endpoint = e.Endpoint, authKind = e.AuthKind,
        identity = e.Identity, options = e.Options, enabled = e.Enabled,
    };

    /// <summary>Seals and stores a secret the way keeper-integration set-secret does, creating the key on first use.</summary>
    private string SetSecret(string id, string name, string plaintext, string endpoint)
    {
        var protector = Keeper.Vault.KeyProtectors.Default(_dir);
        Keeper.Vault.Vault vault;
        using (var connection = _db.OpenReadOnly())
            vault = Keeper.Vault.Vault.Load(connection, protector);
        var binding = Keeper.Integrations.IntegrationStore.Binding(id, name, endpoint);
        Keeper.Vault.SealedSecret sealedSecret;
        if (vault.ActiveKeyId is null)
        {
            var (keyId, wrapped) = Keeper.Vault.Vault.NewKey(protector);
            Submit("vault.create-key", new { keyId, protector = protector.Kind, wrapped = Convert.ToBase64String(wrapped) });
            sealedSecret = Keeper.Vault.Vault.Seal(protector, keyId, wrapped, plaintext, binding);
        }
        else
        {
            sealedSecret = vault.Seal(plaintext, binding);
        }
        var ciphertext = Convert.ToBase64String(sealedSecret.Ciphertext);
        Submit("integrations.set-secret", new
        {
            integrationId = id, name, keyId = sealedSecret.KeyId, nonce = Convert.ToBase64String(sealedSecret.Nonce),
            ciphertext, tag = Convert.ToBase64String(sealedSecret.Tag), boundTo = binding,
        });
        return ciphertext;
    }

    private string VaultSnapshot()
    {
        var keys = string.Join("|", Rows("SELECT key_id, protector, hex(wrapped) AS w FROM vault_key ORDER BY key_id;")
            .Select(r => $"{r["key_id"]}/{r["protector"]}/{r["w"]}"));
        var secrets = string.Join("|", Rows("SELECT integration_id, name, key_id, hex(nonce) AS n, hex(ciphertext) AS c, hex(tag) AS t, bound_to FROM integration_secret ORDER BY integration_id, name;")
            .Select(r => $"{r["integration_id"]}/{r["name"]}/{r["key_id"]}/{r["n"]}/{r["c"]}/{r["t"]}/{r["bound_to"]}"));
        return keys + "||" + secrets;
    }

    private QueueReport Drain() =>
        new QueueManager(_db, Spool, DataDir, Schemas, Keeper.Integrations.IntegrationHandlers.All()).DrainOnce();

    private void Submit<T>(string kind, T payload) where T : notnull =>
        new RequestWriter(Spool).Submit(kind, "test", payload, @"TEST\user");

    private List<Dictionary<string, object?>> Rows(string sql)
    {
        using var connection = _db.OpenReadOnly();
        return Sql.Rows(connection, sql);
    }
}
