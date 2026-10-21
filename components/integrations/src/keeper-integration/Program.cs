using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Queue;
using Keeper.Store;
using Keeper.Vault;
using Microsoft.Data.Sqlite;

// keeper-integration: how Keeper reaches each system. Every change is a queued, audited request; secrets
// are typed at a hidden prompt and sealed before they are queued - they never reach a file in plain text.
try
{
    var cli = new CliArgs(args, flags: ["enable", "disable", "disabled"]);
    if (cli.Help)
        return Usage(asked: true);
    var command = cli.At(0) ?? "list";
    if (command == "types")
        return Types();

    var (_, paths) = KeeperContext.Load(cli);
    var db = new Database(paths.Database);
    var writer = new RequestWriter(paths.Spool);
    MigrationSet[] schemas = [Vault.Schema, IntegrationStore.Schema];

    return command switch
    {
        "list" => List(db, schemas),
        "show" => Show(db, schemas, cli.At(1) ?? throw new ArgumentException("show needs an integration id.")),
        "add" => Add(writer, cli),
        "set" => Set(db, schemas, writer, cli),
        "set-secret" => SetSecret(db, schemas, writer, cli),
        "remove" => Remove(writer, cli),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is ArgumentException or SettingsException or IntegrationException or VaultException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static int Types()
{
    foreach (var type in IntegrationTypes.All)
    {
        Console.WriteLine($"{type.Id,-12} {type.Description}");
        Console.WriteLine($"{"",-12} protocols: {string.Join(", ", type.Protocols)}; auth: {string.Join(", ", type.AuthKinds)}" +
                          (type.AllowedHosts.Count > 0 ? $"; hosts: {string.Join(", ", type.AllowedHosts)}" : ""));
    }
    return ExitCodes.Ok;
}

static IReadOnlyList<IntegrationRecord> Read(Database db, MigrationSet[] schemas)
{
    using var connection = db.OpenReadOnly();
    SchemaManager.EnsureCurrent(connection, schemas);
    return IntegrationStore.All(connection);
}

static int List(Database db, MigrationSet[] schemas)
{
    var all = Read(db, schemas);
    if (all.Count == 0)
        Console.WriteLine("No integrations yet. 'keeper integration types' lists what Keeper can read; then: keeper integration add <id> --type <type> ...");
    foreach (var i in all)
    {
        var secrets = i.Secrets.Count == 0 ? "" : " secrets: " + string.Join(", ", i.Secrets.Values.Select(s => s.ExpiresOn is null ? s.Name : $"{s.Name} (expires {s.ExpiresOn})"));
        Console.WriteLine($"{i.Id,-20} {i.Type,-11} {(i.Enabled ? "on " : "off")} {i.AuthKind,-24} {i.Endpoint}{secrets}");
    }
    return ExitCodes.Ok;
}

static int Show(Database db, MigrationSet[] schemas, string id)
{
    var record = Read(db, schemas).FirstOrDefault(i => i.Id == id) ?? throw new ArgumentException($"No integration {id}.");
    Console.WriteLine(IntegrationStore.Describe(record));
    return ExitCodes.Ok;
}

static string Reason(CliArgs cli) =>
    cli.Get("reason") ?? throw new ArgumentException("--reason is required: every change is audited with why it was made.");

static JsonObject Options(JsonObject start, CliArgs cli)
{
    var options = (JsonObject)JsonNode.Parse(start.ToJsonString())!;
    foreach (var pair in cli.All("option"))
    {
        var equals = pair.IndexOf('=');
        if (equals < 1)
            throw new ArgumentException($"--option {pair}: use name=value.");
        var (name, value) = (pair[..equals].Trim(), pair[(equals + 1)..].Trim());
        if (name.StartsWith("headers.", StringComparison.Ordinal))
        {
            var headers = options["headers"] as JsonObject ?? [];
            headers[name["headers.".Length..]] = value;
            options["headers"] = headers;
        }
        else if (name is "targets" or "scopes")
        {
            options[name] = new JsonArray(value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(v => (JsonNode)JsonValue.Create(v)).ToArray());
        }
        else if (value.Length == 0)
        {
            options.Remove(name);
        }
        else
        {
            options[name] = value;
        }
    }
    return options;
}

static int Add(RequestWriter writer, CliArgs cli)
{
    var id = cli.At(1) ?? throw new ArgumentException("add needs an integration id.");
    writer.Submit("integrations.upsert", Reason(cli), new
    {
        integrationId = id,
        type = cli.Require("type"),
        endpoint = cli.Get("endpoint"),
        authKind = cli.Require("auth"),
        identity = cli.Get("identity"),
        options = Options([], cli),
        enabled = !cli.Has("disabled"),
    });
    Console.WriteLine($"Queued integration {id}. 'keeper qm run' applies it; then set its secrets if its auth needs any.");
    return ExitCodes.Ok;
}

static int Set(Database db, MigrationSet[] schemas, RequestWriter writer, CliArgs cli)
{
    var id = cli.At(1) ?? throw new ArgumentException("set needs an integration id.");
    var current = Read(db, schemas).FirstOrDefault(i => i.Id == id) ?? throw new ArgumentException($"No integration {id}.");
    var endpoint = cli.Get("endpoint") ?? current.Endpoint;
    if (IntegrationStore.EndpointFingerprint(endpoint) != IntegrationStore.EndpointFingerprint(current.Endpoint) && current.Secrets.Count > 0)
        Console.Error.WriteLine("The endpoint changes: the stored secrets were bound to the old one and will be dropped - set them again.");

    writer.Submit("integrations.upsert", Reason(cli), new
    {
        integrationId = id,
        type = current.Type,
        endpoint,
        authKind = cli.Get("auth") ?? current.AuthKind,
        identity = cli.Get("identity") ?? current.Identity,
        options = Options(current.Options, cli),
        enabled = cli.Has("disable") ? false : cli.Has("enable") || current.Enabled,
    });
    Console.WriteLine($"Queued the change to {id}. 'keeper qm run' applies it.");
    return ExitCodes.Ok;
}

static int SetSecret(Database db, MigrationSet[] schemas, RequestWriter writer, CliArgs cli)
{
    var id = cli.At(1) ?? throw new ArgumentException("set-secret needs an integration id.");
    var name = cli.At(2) ?? throw new ArgumentException("set-secret needs a secret name (password, token or clientSecret).");
    var reason = Reason(cli);

    IntegrationRecord record;
    Vault vault;
    var protector = KeyProtectors.Default();
    using (var connection = db.OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, schemas);
        record = IntegrationStore.Find(connection, id) ?? throw new ArgumentException($"No integration {id}. Add it first.");
        vault = Vault.Load(connection, protector);
    }
    if (!IntegrationTypes.SecretsFor.TryGetValue(record.AuthKind, out var allowed) || !allowed.Contains(name))
        throw new ArgumentException($"Auth {record.AuthKind} takes secrets: {string.Join(", ", allowed ?? [])}.");

    var expires = cli.Get("expires");
    if (expires is not null && !DateOnly.TryParseExact(expires, "yyyy-MM-dd", out _))
        throw new ArgumentException("--expires must be yyyy-MM-dd (when this credential expires, so Keeper warns before).");

    var binding = IntegrationStore.Binding(record.Id, name, record.Endpoint);
    var plaintext = SecretPrompt.Read($"{name} for {record.Id} (not shown): ");
    SealedSecret sealedSecret;
    if (vault.ActiveKeyId is null)
    {
        var (keyId, wrapped) = Vault.NewKey(protector);
        writer.Submit("vault.create-key", "First secret: create the vault key", new { keyId, protector = protector.Kind, wrapped = Convert.ToBase64String(wrapped) });
        sealedSecret = Vault.Seal(protector, keyId, wrapped, plaintext, binding);
    }
    else
    {
        sealedSecret = vault.Seal(plaintext, binding);
    }

    writer.Submit("integrations.set-secret", reason, new
    {
        integrationId = record.Id,
        name,
        keyId = sealedSecret.KeyId,
        nonce = Convert.ToBase64String(sealedSecret.Nonce),
        ciphertext = Convert.ToBase64String(sealedSecret.Ciphertext),
        tag = Convert.ToBase64String(sealedSecret.Tag),
        boundTo = binding,
        expiresOn = expires,
    });
    Console.WriteLine($"Queued the sealed {name} for {record.Id} (ciphertext only). 'keeper qm run' applies it.");
    return ExitCodes.Ok;
}

static int Remove(RequestWriter writer, CliArgs cli)
{
    var id = cli.At(1) ?? throw new ArgumentException("remove needs an integration id.");
    writer.Submit("integrations.remove", Reason(cli), new { integrationId = id });
    Console.WriteLine($"Queued the removal of {id} and its secrets. 'keeper qm run' applies it.");
    return ExitCodes.Ok;
}

static int Usage(bool asked = false) =>
    CliUsage.Print("""
        keeper-integration - how Keeper reaches each system

          keeper-integration types
          keeper-integration list
          keeper-integration show <id>
          keeper-integration add <id> --type <type> --auth <kind> [--endpoint <url|host>] [--identity <account>]
                                      [--option name=value ...] [--disabled] --reason "<why>"
          keeper-integration set <id> [--endpoint ..] [--auth ..] [--identity ..] [--option name=value ...]
                                      [--enable | --disable] --reason "<why>"
          keeper-integration set-secret <id> <password|token|clientSecret> [--expires yyyy-MM-dd] --reason "<why>"
          keeper-integration remove <id> --reason "<why>"

          Options: targets=a,b,c  scopes=x,y  clientId=..  tenantId=..  tokenUrl=https://..  header=..  prefix=..
                   param=..  headers.<name>=..  tls=trust (sql)  allowHttp=true (only if you accept cleartext)
                   cimProtocol=auto|wsman|dcom (cim: WinRM, then DCOM for hosts WinRM cannot reach)
        """, asked);
