using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Store;
using Keeper.Vault;
using Microsoft.Data.Sqlite;

namespace Keeper.Integrations;

public sealed class IntegrationException(string message) : Exception(message)
{
    /// <summary>The service was busy or unreachable, not refusing: worth asking again, never kept as a refusal.</summary>
    public bool Transient { get; init; }
}

public sealed record IntegrationRecord(
    string Id,
    string Type,
    string Endpoint,
    string AuthKind,
    string? Identity,
    JsonObject Options,
    bool Enabled,
    IReadOnlyDictionary<string, StoredSecret> Secrets)
{
    public IntegrationType TypeInfo => IntegrationTypes.Find(Type) ?? throw new IntegrationException($"Unknown integration type '{Type}'.");
}

public sealed record StoredSecret(string Name, SealedSecret Sealed, string BoundTo, string SetAt, string? ExpiresOn);

/// <summary>Reads integrations from the store. Secrets come back sealed; only a connection opens them, on use.</summary>
public static class IntegrationStore
{
    public static MigrationSet Schema { get; } =
        MigrationSet.FromResources("integrations", typeof(IntegrationStore).Assembly, "integrations/", "vault");

    public static IReadOnlyList<IntegrationRecord> All(SqliteConnection connection)
    {
        var secrets = Sql.Rows(connection, "SELECT * FROM integration_secret;")
            .GroupBy(r => (string)r["integration_id"]!)
            .ToDictionary(g => g.Key, g => (IReadOnlyDictionary<string, StoredSecret>)g.ToDictionary(
                r => (string)r["name"]!,
                r => new StoredSecret((string)r["name"]!,
                    new SealedSecret((string)r["key_id"]!, (byte[])r["nonce"]!, (byte[])r["ciphertext"]!, (byte[])r["tag"]!),
                    (string)r["bound_to"]!, (string)r["set_at"]!, r["expires_on"] as string),
                StringComparer.Ordinal));

        return Sql.Rows(connection, "SELECT * FROM integration ORDER BY integration_id;")
            .Select(r => new IntegrationRecord(
                (string)r["integration_id"]!,
                (string)r["type"]!,
                (string)r["endpoint"]!,
                (string)r["auth_kind"]!,
                r["identity"] as string,
                JsonNode.Parse((string)r["options"]!) as JsonObject ?? [],
                r["enabled"] is long e && e == 1,
                secrets.TryGetValue((string)r["integration_id"]!, out var s) ? s : new Dictionary<string, StoredSecret>()))
            .ToList();
    }

    public static IntegrationRecord? Find(SqliteConnection connection, string id) =>
        All(connection).FirstOrDefault(i => i.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The integration a rule file should read through: the one named, or the single enabled one of the
    /// file's type. Types that need no configuration (files, keeper) have an implicit instance.
    /// </summary>
    public static IntegrationRecord Resolve(SqliteConnection connection, string type, string? id)
    {
        if (id is null && IntegrationTypes.IsImplicit(type))
            return new IntegrationRecord(type, type, "", "none", null, [], true, new Dictionary<string, StoredSecret>());

        var all = All(connection);
        if (id is not null)
        {
            var named = all.FirstOrDefault(i => i.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                ?? throw new IntegrationException($"No integration '{id}'. 'keeper integration list' shows them.");
            if (!IntegrationTypes.Satisfies(type, named.Type))
                throw new IntegrationException($"Integration '{id}' is of type {named.Type}; these rules need {type}.");
            if (!named.Enabled)
                throw new IntegrationException($"Integration '{id}' is disabled.");
            return named;
        }

        var candidates = all.Where(i => i.Enabled && IntegrationTypes.Satisfies(type, i.Type)).ToList();
        return candidates.Count switch
        {
            1 => candidates[0],
            0 => throw new IntegrationException($"No enabled {type} integration. Add one: keeper integration add <id> --type {type} ..."),
            _ => throw new IntegrationException($"{candidates.Count} {type} integrations ({string.Join(", ", candidates.Select(c => c.Id))}); name one with --integration."),
        };
    }

    /// <summary>What a secret is bound to: its integration, name and endpoint. A changed endpoint cannot open an old secret.</summary>
    public static string Binding(string integrationId, string name, string endpoint) =>
        $"keeper/integration/{integrationId.ToLowerInvariant()}/{name}/{EndpointFingerprint(endpoint)}";

    public static string EndpointFingerprint(string endpoint) =>
        Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && uri.IsAbsoluteUri && !string.IsNullOrEmpty(uri.Host)
            ? $"{uri.Scheme}://{uri.Host}:{uri.Port}".ToLowerInvariant()
            : endpoint.Trim().ToLowerInvariant();

    public static string Describe(IntegrationRecord record) =>
        JsonSerializer.Serialize(new
        {
            record.Id,
            record.Type,
            record.Endpoint,
            record.AuthKind,
            record.Identity,
            record.Enabled,
            Options = record.Options,
            Secrets = record.Secrets.Values.Select(s => new { s.Name, s.SetAt, s.ExpiresOn }),
        }, new JsonSerializerOptions { WriteIndented = true });
}
