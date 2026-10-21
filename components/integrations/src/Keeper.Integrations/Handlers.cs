using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Queue;

namespace Keeper.Integrations;

/// <summary>
/// integrations.upsert: { "integrationId", "type", "endpoint", "authKind", "identity", "options": {...}, "enabled" }.
/// Validates the type, the auth kind it allows, the endpoint's scheme and allowed hosts, and refuses options
/// that look like secrets. Changing the endpoint drops the stored secrets - they were bound to the old one.
/// </summary>
public sealed partial class UpsertHandler : IRequestHandler
{
    private static readonly string[] SecretLike = ["password", "secret", "token", "apikey", "api-key", "credential", "key"];

    public string Kind => "integrations.upsert";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var id = Payload.Required(payload, "integrationId");
        if (!IntegrationTypes.IsValidId(id))
            throw new RequestException("payload.integrationId must be lower-case letters, digits and dashes.");

        var type = IntegrationTypes.Find(Payload.Required(payload, "type"))
            ?? throw new RequestException($"Unknown integration type. Known: {string.Join(", ", IntegrationTypes.All.Select(t => t.Id))}.");
        if (IntegrationTypes.IsImplicit(type.Id))
            throw new RequestException($"{type.Id} needs no integration; its rules run without one.");

        var authKind = Payload.Required(payload, "authKind");
        if (!type.AuthKinds.Contains(authKind))
            throw new RequestException($"{type.Id} allows auth: {string.Join(", ", type.AuthKinds)}.");
        // A scan refuses a token issued to anyone but this account, and Entra names the account by its sign-in name.
        if (authKind == "entra-interactive" && Payload.Text(payload, "identity") is { } account && !account.Contains('@', StringComparison.Ordinal))
            throw new RequestException("payload.identity for entra-interactive must be the account's sign-in name (user@domain), or empty for whoever signs in.");

        var endpoint = Payload.Text(payload, "endpoint") ?? type.DefaultEndpoint ?? "";
        CheckEndpoint(type, endpoint, payload);

        var options = payload.TryGetProperty("options", out var raw) && raw.ValueKind == JsonValueKind.Object
            ? JsonNode.Parse(raw.GetRawText())!.AsObject()
            : [];
        var text = options.ToJsonString();
        if (text.Length > 8000)
            throw new RequestException("payload.options is too large.");
        foreach (var (name, _) in options)
        {
            var lower = name.ToLowerInvariant();
            if (SecretLike.Any(s => lower == s || (s.Length > 5 && lower.Contains(s, StringComparison.Ordinal))))
                throw new RequestException($"Option '{name}' looks like a secret. Secrets are set with set-secret, never as options.");
        }
        if (options["tokenUrl"] is JsonValue tokenUrl
            && (!Uri.TryCreate(tokenUrl.ToString(), UriKind.Absolute, out var tu) || tu.Scheme != "https"))
            throw new RequestException("Option tokenUrl must be an https URL.");
        if (options["cimProtocol"] is { } cimProtocol && cimProtocol.ToString() is not ("auto" or "wsman" or "dcom"))
            throw new RequestException("Option cimProtocol must be auto (WinRM, then DCOM), wsman or dcom.");
        // A fixed header on every request must not turn a read into a write on a server that honours it.
        if (options["headers"] is JsonObject fixedHeaders && fixedHeaders.Select(h => h.Key).FirstOrDefault(h =>
                h.Contains("method", StringComparison.OrdinalIgnoreCase) || h.Contains("override", StringComparison.OrdinalIgnoreCase)) is { } methodHeader)
            throw new RequestException($"Option headers.{methodHeader} would change the request's method; Keeper only reads.");

        var existing = context.Scalar("SELECT endpoint FROM integration WHERE integration_id = :id;", (":id", id)) as string;
        context.Execute(
            """
            INSERT INTO integration (integration_id, type, endpoint, auth_kind, identity, options, enabled, changed_by, changed_at, why)
            VALUES (:id, :type, :endpoint, :auth, :identity, :options, :enabled, :by, :at, :why)
            ON CONFLICT (integration_id) DO UPDATE SET
                type = excluded.type, endpoint = excluded.endpoint, auth_kind = excluded.auth_kind, identity = excluded.identity,
                options = excluded.options, enabled = excluded.enabled, changed_by = excluded.changed_by,
                changed_at = excluded.changed_at, why = excluded.why;
            """,
            (":id", id), (":type", type.Id), (":endpoint", endpoint), (":auth", authKind),
            (":identity", Payload.Text(payload, "identity")), (":options", text),
            (":enabled", Payload.Bool(payload, "enabled") == false ? 0 : 1),
            (":by", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));

        if (existing is not null && IntegrationStore.EndpointFingerprint(existing) != IntegrationStore.EndpointFingerprint(endpoint))
            context.Execute("DELETE FROM integration_secret WHERE integration_id = :id;", (":id", id));
    }

    /// <summary>
    /// aws: the endpoint is the home region; the identity an access key id; accounts are 12-digit ids read
    /// through roleName in each; aws-assume-role names the role the key assumes first (roleArn).
    /// </summary>
    private static void CheckAws(string endpoint, JsonElement payload)
    {
        if (!AwsRegion().IsMatch(endpoint))
            throw new RequestException("aws endpoints are the home region, such as eu-central-1.");
        if (Payload.Text(payload, "identity") is not { } key || !AccessKeyId().IsMatch(key))
            throw new RequestException("aws needs a long-term access key id as the identity (AKIA...); its secret is set with set-secret secretAccessKey.");
        if (!payload.TryGetProperty("options", out var options) || options.ValueKind != JsonValueKind.Object)
            options = default;
        string? Option(string name) => options.ValueKind == JsonValueKind.Object && options.TryGetProperty(name, out var v) ? v.ToString() : null;
        List<string> Options(string name) => options.ValueKind == JsonValueKind.Object && options.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? [.. v.EnumerateArray().Select(e => e.ToString())]
            : Option(name) is { } text ? [.. text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)] : [];
        if (Options("accounts") is { Count: > 0 } accounts)
        {
            if (accounts.FirstOrDefault(a => !AccountId().IsMatch(a)) is { } bad)
                throw new RequestException($"Option accounts: '{bad}' is not a 12-digit account id.");
            if (Option("roleName") is not { } role || !RoleName().IsMatch(role))
                throw new RequestException("Option accounts needs roleName: the read-only role each account has for Keeper (SecurityAudit, ReadOnlyAccess).");
        }
        if (Options("regions").FirstOrDefault(r => !AwsRegion().IsMatch(r)) is { } region)
            throw new RequestException($"Option regions: '{region}' is not a region id.");
        if (Payload.Text(payload, "authKind") == "aws-assume-role" && (Option("roleArn") is not { } arn || !RoleArn().IsMatch(arn)))
            throw new RequestException("aws-assume-role needs the option roleArn (arn:aws:iam::<account>:role/<name>).");
    }

    // \z, never $: "$" would let a trailing newline through into a host name.
    [System.Text.RegularExpressions.GeneratedRegex(@"\A[a-z]{2}(-[a-z]+)+-[0-9]{1,2}\z")]
    private static partial System.Text.RegularExpressions.Regex AwsRegion();

    // A long-term key: a temporary one (ASIA...) needs its session token, which Keeper does not take.
    [System.Text.RegularExpressions.GeneratedRegex(@"\AAKIA[A-Z0-9]{16}\z")]
    private static partial System.Text.RegularExpressions.Regex AccessKeyId();

    [System.Text.RegularExpressions.GeneratedRegex(@"\A[0-9]{12}\z")]
    private static partial System.Text.RegularExpressions.Regex AccountId();

    [System.Text.RegularExpressions.GeneratedRegex(@"\A[\w+=,.@-]{1,64}\z")]
    private static partial System.Text.RegularExpressions.Regex RoleName();

    [System.Text.RegularExpressions.GeneratedRegex(@"\Aarn:aws:iam::[0-9]{12}:role/[\w+=,.@/-]{1,128}\z")]
    private static partial System.Text.RegularExpressions.Regex RoleArn();

    private static void CheckEndpoint(IntegrationType type, string endpoint, JsonElement payload)
    {
        if (type.Protocols.Any(p => p is "http" or "graph" or "graphql"))
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
                throw new RequestException($"{type.Id} needs an https endpoint URL.");
            if (!string.IsNullOrEmpty(uri.UserInfo))
                throw new RequestException("The endpoint must not carry credentials.");
            var allowHttp = payload.TryGetProperty("options", out var o) && o.ValueKind == JsonValueKind.Object
                && o.TryGetProperty("allowHttp", out var a) && a.ToString() == "true";
            if (uri.Scheme == "http" && !allowHttp)
                throw new RequestException("Plain http sends credentials in the clear; use https, or set the option allowHttp to true.");
            if (!type.AllowsHost(uri.Host))
                throw new RequestException($"{type.Id} endpoints must be on: {string.Join(", ", type.AllowedHosts)}.");
            if (type.Guarded && (!type.AllowsEndpointPath(uri.AbsolutePath) || uri.Query.Length > 0))
                throw new RequestException(type.EndpointPath is null
                    ? $"{type.Id} endpoints have no path: https://<host> (what it reads is checked against the host's own paths)."
                    : $"{type.Id} endpoints have the path {type.EndpointPath}, and no query.");
        }
        else if (type.Id == "aws")
        {
            CheckAws(endpoint, payload);
        }
        else if (type.Id == "ldap" && endpoint.Length > 0 && endpoint.Contains("://", StringComparison.Ordinal)
                 && !endpoint.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase) && !endpoint.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase))
        {
            throw new RequestException("ldap endpoints are ldap://, ldaps:// or a domain name.");
        }
    }
}

/// <summary>
/// integrations.set-secret: { "integrationId", "name", "keyId", "nonce", "ciphertext", "tag", "boundTo", "expiresOn" } -
/// ciphertext only (base64). Refused when the integration's endpoint is no longer the one it was sealed for.
/// </summary>
public sealed class SetSecretHandler : IRequestHandler
{
    public string Kind => "integrations.set-secret";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var id = Payload.Required(payload, "integrationId");
        var name = Payload.Required(payload, "name");
        var row = Keeper.Store.Sql.Rows(context.Connection, "SELECT endpoint, auth_kind FROM integration WHERE integration_id = :id;", context.Transaction, (":id", id))
            .FirstOrDefault() ?? throw new RequestException($"No integration {id}.");

        var authKind = (string)row["auth_kind"]!;
        if (!IntegrationTypes.SecretsFor.TryGetValue(authKind, out var allowed) || !allowed.Contains(name))
            throw new RequestException($"Auth {authKind} takes secrets: {string.Join(", ", allowed ?? [])}.");
        var boundTo = Payload.Required(payload, "boundTo");
        if (boundTo != IntegrationStore.Binding(id, name, (string)row["endpoint"]!))
            throw new RequestException("The integration's endpoint changed after the secret was sealed; set the secret again.");
        var keyId = Payload.Required(payload, "keyId");
        if (context.Scalar("SELECT 1 FROM vault_key WHERE key_id = :k AND retired_at IS NULL;", (":k", keyId)) is null)
            throw new RequestException($"Vault key {keyId} is not active.");

        byte[] Bytes(string field)
        {
            try
            {
                return Convert.FromBase64String(Payload.Required(payload, field));
            }
            catch (FormatException)
            {
                throw new RequestException($"payload.{field} must be base64.");
            }
        }

        context.Execute(
            """
            INSERT INTO integration_secret (integration_id, name, key_id, nonce, ciphertext, tag, bound_to, set_by, set_at, expires_on)
            VALUES (:id, :name, :key, :nonce, :ct, :tag, :bound, :by, :at, :expires)
            ON CONFLICT (integration_id, name) DO UPDATE SET
                key_id = excluded.key_id, nonce = excluded.nonce, ciphertext = excluded.ciphertext, tag = excluded.tag,
                bound_to = excluded.bound_to, set_by = excluded.set_by, set_at = excluded.set_at, expires_on = excluded.expires_on;
            """,
            (":id", id), (":name", name), (":key", keyId), (":nonce", Bytes("nonce")), (":ct", Bytes("ciphertext")), (":tag", Bytes("tag")),
            (":bound", boundTo), (":by", context.Request.SubmittedBy), (":at", context.NowText), (":expires", Payload.Date(payload, "expiresOn")));
    }
}

/// <summary>integrations.remove: { "integrationId" } - the integration and its secrets.</summary>
public sealed class RemoveHandler : IRequestHandler
{
    public string Kind => "integrations.remove";

    public void Apply(RequestContext context)
    {
        var id = Payload.Required(context.Request.Payload, "integrationId");
        if (context.Execute("DELETE FROM integration WHERE integration_id = :id;", (":id", id)) == 0)
            throw new RequestException($"No integration {id}.");
    }
}

/// <summary>integrations.test-result: { "integrationId", "state": "ok|partial|failed", "detail" }.</summary>
public sealed class TestResultHandler : IRequestHandler
{
    public string Kind => "integrations.test-result";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        context.Execute("INSERT INTO integration_test (integration_id, at, state, detail) VALUES (:id, :at, :state, :detail);",
            (":id", Payload.Required(payload, "integrationId")), (":at", context.NowText),
            (":state", Payload.OneOf(payload, "state", "ok", "partial", "failed")), (":detail", Payload.Text(payload, "detail")));
    }
}

public static class IntegrationHandlers
{
    public static IReadOnlyList<IRequestHandler> All() =>
        [new UpsertHandler(), new SetSecretHandler(), new RemoveHandler(), new TestResultHandler(), new Keeper.Vault.CreateKeyHandler()];
}
