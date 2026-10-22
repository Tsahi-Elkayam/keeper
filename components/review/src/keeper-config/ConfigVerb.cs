using System.Text;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Review.Cli;
using Keeper.Review.Config;
using Keeper.Review.Handlers;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper config: moves the client's configuration between the files that are its source of truth
// (clients\<client>\config\, or home\config\) and the store (keeper.db), which keeps it as data plus a
// cache. This increment covers systems, settings, overrides, registers and integrations. Writes to the store
// go through the one-writer queue + qm, exactly as 'keeper system' does. Integration secrets are the one thing
// that never travels this path: the file records a secret's NAME only, and no queued payload carries a value.
public static class ConfigVerb
{
    public static int Run(string[] args)
    {
        return RequestCli.Run("keeper config", args, [], Command, Usage);

        static int Command(RequestCli r)
        {
            var cli = r.Cli;
            var noun = cli.At(1);
            switch (cli.At(0))
            {
                case "export":
                    return noun switch
                    {
                        "systems" => ExportSystems(r),
                        "settings" => ExportSettings(r),
                        "overrides" => ExportOverrides(r),
                        "registers" => ExportRegisters(r),
                        "integration" or "integrations" => ExportIntegrations(r),
                        _ => Unsupported(noun),
                    };
                case "import":
                    return noun switch
                    {
                        "systems" => ImportSystems(r),
                        "settings" => ImportSettings(r),
                        "overrides" => ImportOverrides(r),
                        "registers" => ImportRegisters(r),
                        "integration" or "integrations" => ImportIntegrations(r),
                        _ => Unsupported(noun),
                    };
                default:
                    return Usage();
            }
        }

        static int Unsupported(string? noun)
        {
            Console.Error.WriteLine($"Config part must be systems, settings, overrides, registers or integrations{(noun is null ? "" : $", not '{noun}'")}.");
            return ExitCodes.Usage;
        }

        // Systems -----------------------------------------------------------------------

        static int ExportSystems(RequestCli r)
        {
            List<SystemRecord> systems;
            using (var connection = r.Read())
                systems = Sql.Rows(connection, SelectSystems()).Select(FromRow).ToList();

            var path = ConfigPath(r, "out", "systems.yaml");
            WriteConfig(path, SystemsConfig.Write(Client(r), systems));
            Console.WriteLine($"Wrote {systems.Count} systems to {path}");
            return ExitCodes.Ok;
        }

        static int ImportSystems(RequestCli r)
        {
            var reason = r.Reason;   // --reason is required; it is kept with every change.
            if (!TryRead(r, "systems.yaml", (text, path) => SystemsConfig.Read(text, path, out _), out var fromFile, out var path))
                return ExitCodes.Usage;

            Dictionary<string, SystemRecord> inStore;
            using (var connection = r.Read())
                inStore = Sql.Rows(connection, SelectSystems()).Select(FromRow).ToDictionary(s => s.Id, StringComparer.Ordinal);

            var writer = new RequestWriter(r.Paths.Spool);
            int added = 0, changed = 0, unchanged = 0;
            foreach (var system in fromFile)
            {
                if (inStore.TryGetValue(system.Id, out var current))
                {
                    if (current == system)
                    {
                        unchanged++;   // Already exactly this in the store: queue nothing, so re-import is idempotent.
                        continue;
                    }
                    changed++;
                }
                else
                {
                    added++;
                }
                writer.Submit("review.system", reason, Upsert(system));
            }

            var fileIds = fromFile.Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
            var onlyInStore = inStore.Keys.Where(id => !fileIds.Contains(id)).Order(StringComparer.Ordinal).ToList();

            Console.WriteLine($"{path}: {fromFile.Count} systems in the file - {added} new, {changed} changed, {unchanged} unchanged.");
            ReportOnlyInStore("systems", onlyInStore);
            return ApplyOrQueue(r, added + changed, "review.system");
        }

        // Settings ----------------------------------------------------------------------

        static int ExportSettings(RequestCli r)
        {
            List<SettingRecord> settings;
            using (var connection = r.Read())
                settings = Sql.Rows(connection, "SELECT key, value FROM setting ORDER BY key;")
                    .Select(row => new SettingRecord((string)row["key"]!, (string)row["value"]!)).ToList();

            var path = ConfigPath(r, "out", "settings.yaml");
            WriteConfig(path, SettingsConfig.Write(Client(r), settings));
            Console.WriteLine($"Wrote {settings.Count} settings to {path}");
            return ExitCodes.Ok;
        }

        static int ImportSettings(RequestCli r)
        {
            var reason = r.Reason;
            if (!TryRead(r, "settings.yaml", (text, path) => SettingsConfig.Read(text, path, out _), out var fromFile, out var path))
                return ExitCodes.Usage;

            Dictionary<string, string> inStore;
            using (var connection = r.Read())
                inStore = Sql.Rows(connection, "SELECT key, value FROM setting;")
                    .ToDictionary(row => (string)row["key"]!, row => (string)row["value"]!, StringComparer.Ordinal);

            var writer = new RequestWriter(r.Paths.Spool);
            int added = 0, changed = 0, unchanged = 0;
            foreach (var setting in fromFile)
            {
                if (inStore.TryGetValue(setting.Key, out var current))
                {
                    if (string.Equals(current, setting.Value, StringComparison.Ordinal))
                    {
                        unchanged++;
                        continue;
                    }
                    changed++;
                }
                else
                {
                    added++;
                }
                writer.Submit("review.setting", reason, new { key = setting.Key, value = setting.Value });
            }

            var fileKeys = fromFile.Select(s => s.Key).ToHashSet(StringComparer.Ordinal);
            var onlyInStore = inStore.Keys.Where(k => !fileKeys.Contains(k)).Order(StringComparer.Ordinal).ToList();

            Console.WriteLine($"{path}: {fromFile.Count} settings in the file - {added} new, {changed} changed, {unchanged} unchanged.");
            ReportOnlyInStore("settings", onlyInStore);
            return ApplyOrQueue(r, added + changed, "review.setting");
        }

        // Overrides ---------------------------------------------------------------------

        static int ExportOverrides(RequestCli r)
        {
            List<OverrideRecord> overrides;
            using (var connection = r.Read())
                overrides = Sql.Rows(connection,
                    "SELECT check_id, decision, entity, value, until, why FROM override WHERE active = 1;")
                    .Select(row => new OverrideRecord(
                        (string)row["check_id"]!, (string)row["decision"]!, (string)row["entity"]!, (string)row["value"]!,
                        row["until"] as string, (string)row["why"]!)).ToList();

            var path = ConfigPath(r, "out", "overrides.yaml");
            WriteConfig(path, OverridesConfig.Write(Client(r), overrides));
            Console.WriteLine($"Wrote {overrides.Count} active overrides to {path}");
            return ExitCodes.Ok;
        }

        static int ImportOverrides(RequestCli r)
        {
            _ = r.Reason;   // --reason is required; each override is then queued with its own reason (its 'why').
            if (!TryRead(r, "overrides.yaml", (text, path) => OverridesConfig.Read(text, path, out _), out var fromFile, out var path))
                return ExitCodes.Usage;

            // The store's active overrides, by identity, with their ids for the report.
            List<(string Id, (string, string, string, string, string?) Identity)> inStore;
            using (var connection = r.Read())
                inStore = Sql.Rows(connection, "SELECT override_id, check_id, decision, entity, value, until FROM override WHERE active = 1;")
                    .Select(row => ((string)row["override_id"]!,
                        ((string)row["check_id"]!, (string)row["decision"]!, (string)row["entity"]!, (string)row["value"]!, row["until"] as string)))
                    .ToList();
            var active = inStore.Select(o => o.Identity).ToHashSet();

            var writer = new RequestWriter(r.Paths.Spool);
            int added = 0, unchanged = 0;
            foreach (var o in fromFile)
            {
                if (active.Contains(o.Identity))
                {
                    unchanged++;   // An identical active override is already in the store: add nothing (idempotent).
                    continue;
                }
                added++;
                // review.override only adds or removes; the file is desired active state, so each new row is an 'add',
                // queued with its own reason so the stored 'why' matches the file.
                writer.Submit("review.override", o.Reason,
                    new { op = "add", checkId = o.CheckId, decision = o.Decision, entity = o.Entity, value = o.Value, until = o.Until });
            }

            var fileIdentities = fromFile.Select(o => o.Identity).ToHashSet();
            var onlyInStore = inStore.Where(o => !fileIdentities.Contains(o.Identity)).Select(o => o.Id).Order(StringComparer.Ordinal).ToList();

            Console.WriteLine($"{path}: {fromFile.Count} active overrides in the file - {added} new, {unchanged} unchanged.");
            ReportOnlyInStore("overrides", onlyInStore);
            return ApplyOrQueue(r, added, "review.override");
        }

        // Registers ---------------------------------------------------------------------

        static int ExportRegisters(RequestCli r)
        {
            var tables = new Dictionary<string, IReadOnlyList<RegisterRecord>>(StringComparer.Ordinal);
            List<AttestationRecord> attestations;
            using (var connection = r.Read())
            {
                foreach (var (spec, _) in RegistersConfig.Sections)
                    tables[spec.Table] = StoreRegister(connection, spec);
                attestations = Sql.Rows(connection,
                    "SELECT obligation, target, state, done_on, evidence, expires_on FROM latest_attestation ORDER BY obligation, target;")
                    .Select(row => new AttestationRecord(
                        (string)row["obligation"]!, (string)row["target"]!, (string)row["state"]!,
                        row["done_on"] as string, (string)row["evidence"]!, row["expires_on"] as string)).ToList();
            }

            var data = new RegisterData(tables, attestations);
            var path = ConfigPath(r, "out", "registers.yaml");
            WriteConfig(path, RegistersConfig.Write(Client(r), data));
            var total = tables.Values.Sum(t => t.Count) + attestations.Count;
            Console.WriteLine($"Wrote {total} register records to {path}");
            return ExitCodes.Ok;
        }

        static int ImportRegisters(RequestCli r)
        {
            var reason = r.Reason;
            if (!TryRead(r, "registers.yaml", (text, path) => RegistersConfig.Read(text, path, out _), out var data, out var path))
                return ExitCodes.Usage;

            var writer = new RequestWriter(r.Paths.Spool);
            int added = 0, changed = 0, unchanged = 0;
            var onlyInStore = new List<string>();

            using (var connection = r.Read())
            {
                foreach (var (spec, section) in RegistersConfig.Sections)
                {
                    var inStore = StoreRegister(connection, spec).ToDictionary(x => x.Id, StringComparer.Ordinal);
                    var fromFile = data.Tables.TryGetValue(spec.Table, out var list) ? list : [];
                    foreach (var record in fromFile)
                    {
                        if (inStore.TryGetValue(record.Id, out var current))
                        {
                            if (RegistersConfig.Same(spec, current, record))
                            {
                                unchanged++;
                                continue;
                            }
                            changed++;
                        }
                        else
                        {
                            added++;
                        }
                        writer.Submit(spec.Kind, reason, RegisterPayload(spec, record));
                    }
                    var fileIds = fromFile.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
                    onlyInStore.AddRange(inStore.Keys.Where(id => !fileIds.Contains(id)).Select(id => $"{section}:{id}"));
                }

                // Attestations are append-only: add one only when no identical row (full content) already exists.
                var existing = Sql.Rows(connection, "SELECT obligation, target, state, done_on, evidence, expires_on FROM attestation;")
                    .Select(row => ((string)row["obligation"]!, (string)row["target"]!, (string)row["state"]!,
                        row["done_on"] as string, (string)row["evidence"]!, row["expires_on"] as string)).ToHashSet();
                foreach (var a in data.Attestations)
                {
                    if (existing.Contains(a.Identity))
                    {
                        unchanged++;
                        continue;
                    }
                    added++;
                    writer.Submit("review.attestation", reason,
                        new { obligation = a.Obligation, target = a.Target, state = a.State, evidence = a.Evidence, doneOn = a.DoneOn, expiresOn = a.ExpiresOn });
                }
                var fileObligations = data.Attestations.Select(a => (a.Obligation, a.Target)).ToHashSet();
                onlyInStore.AddRange(Sql.Rows(connection, "SELECT obligation, target FROM latest_attestation;")
                    .Select(row => ((string)row["obligation"]!, (string)row["target"]!))
                    .Where(p => !fileObligations.Contains(p))
                    .Select(p => $"attestations:{p.Item1}/{p.Item2}"));
            }

            var total = data.Tables.Values.Sum(t => t.Count) + data.Attestations.Count;
            Console.WriteLine($"{path}: {total} register records in the file - {added} new, {changed} changed, {unchanged} unchanged.");
            onlyInStore.Sort(StringComparer.Ordinal);
            ReportOnlyInStore("register records", onlyInStore);
            return ApplyOrQueue(r, added + changed, "register");
        }

        static List<RegisterRecord> StoreRegister(SqliteConnection connection, RegisterSpec spec)
        {
            // Table and column names come from the register's spec in code, never from input.
            var rows = Sql.Rows(connection, $"SELECT * FROM {spec.Table} ORDER BY {spec.IdColumn};");
            return rows.Select(row =>
            {
                var columns = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var field in spec.Fields)
                    columns[field.Column] = row.GetValueOrDefault(field.Column);
                return new RegisterRecord((string)row[spec.IdColumn]!, columns);
            }).ToList();
        }

        static JsonObject RegisterPayload(RegisterSpec spec, RegisterRecord record)
        {
            var payload = new JsonObject { ["op"] = "upsert", [spec.IdField] = record.Id };
            foreach (var field in spec.Fields)
            {
                var value = record.Columns.GetValueOrDefault(field.Column);
                if (value is null)
                    continue;   // Absent: the handler writes the field's declared default.
                payload[field.Name] = field.Type switch
                {
                    FieldType.Bool => JsonValue.Create((long)value == 1L),
                    FieldType.Int => JsonValue.Create((long)value),
                    FieldType.Real => JsonValue.Create((double)value),
                    _ => JsonValue.Create((string)value),
                };
            }
            return payload;
        }

        // Integrations ------------------------------------------------------------------
        // The one secret-sensitive family. Export writes the NON-SECRET config only - and the NAMES of the secrets an
        // integration has, never a value or ciphertext. Import upserts the config through the same one-writer request
        // keeper integration uses (integrations.upsert); it never reads, writes or requires a secret. Secrets are set
        // out of band with 'keeper integration set-secret', and a file secret the store lacks is reported, not failed.

        static int ExportIntegrations(RequestCli r)
        {
            List<IntegrationRecord> entries;
            using (var connection = IntegrationRead(r))
                entries = Keeper.Integrations.IntegrationStore.All(connection).Select(ToEntry).ToList();

            var path = ConfigPath(r, "out", "integrations.yaml");
            WriteConfig(path, IntegrationsConfig.Write(Client(r), entries));
            Console.WriteLine($"Wrote {entries.Count} integrations to {path} (non-secret config and secret names only).");
            return ExitCodes.Ok;
        }

        static int ImportIntegrations(RequestCli r)
        {
            var reason = r.Reason;
            if (!TryRead(r, "integrations.yaml", (text, path) => IntegrationsConfig.Read(text, path, out _), out var fromFile, out var path))
                return ExitCodes.Usage;

            Dictionary<string, IntegrationRecord> inStore;
            using (var connection = IntegrationRead(r))
                inStore = Keeper.Integrations.IntegrationStore.All(connection).Select(ToEntry).ToDictionary(e => e.Id, StringComparer.Ordinal);

            var writer = new RequestWriter(r.Paths.Spool);
            int added = 0, changed = 0, unchanged = 0;
            var needSecret = new List<string>();
            foreach (var e in fromFile)
            {
                if (inStore.TryGetValue(e.Id, out var current))
                {
                    if (IntegrationsConfig.SameConfig(current, e))
                        unchanged++;   // Already exactly this config in the store: queue nothing, so re-import is idempotent.
                    else
                    {
                        changed++;
                        writer.Submit("integrations.upsert", reason, UpsertPayload(e));
                    }
                }
                else
                {
                    added++;
                    writer.Submit("integrations.upsert", reason, UpsertPayload(e));
                }

                // The file lists the secrets an integration expects, by name. Whatever is not already in the store must
                // be set out of band - the secret value is never in the file and never in the queued payload.
                var have = current?.Secrets.ToHashSet(StringComparer.Ordinal) ?? [];
                needSecret.AddRange(e.Secrets.Where(name => !have.Contains(name)).Select(name => $"{e.Id}:{name}"));
            }

            var fileIds = fromFile.Select(e => e.Id).ToHashSet(StringComparer.Ordinal);
            var onlyInStore = inStore.Keys.Where(id => !fileIds.Contains(id)).Order(StringComparer.Ordinal).ToList();

            Console.WriteLine($"{path}: {fromFile.Count} integrations in the file - {added} new, {changed} changed, {unchanged} unchanged.");
            ReportOnlyInStore("integrations", onlyInStore);
            if (needSecret.Count > 0)
            {
                needSecret.Sort(StringComparer.Ordinal);
                Console.WriteLine($"Secrets to set out of band ('keeper integration set-secret <id> <name>'), {needSecret.Count}: {string.Join(", ", needSecret)}");
            }
            return ApplyOrQueue(r, added + changed, "integrations.upsert");
        }

        // Read-only on the integration and vault tables, which another component (keeper integration) owns; a store
        // that has never had integrations initialised says so, the same way 'keeper integration list' would.
        static SqliteConnection IntegrationRead(RequestCli r)
        {
            var connection = new Database(r.Paths.Database).OpenReadOnly();
            SchemaManager.EnsureCurrent(connection, [Keeper.Vault.Vault.Schema, Keeper.Integrations.IntegrationStore.Schema]);
            return connection;
        }

        static IntegrationRecord ToEntry(Keeper.Integrations.IntegrationRecord i) => new(
            i.Id, i.Type, i.Endpoint, i.AuthKind, i.Identity, i.Enabled,
            IntegrationsConfig.Normalize(i.Options),
            i.Secrets.Keys.Order(StringComparer.Ordinal).ToList());

        static object UpsertPayload(IntegrationRecord e) => new
        {
            integrationId = e.Id,
            type = e.Type,
            endpoint = e.Endpoint,
            authKind = e.AuthKind,
            identity = e.Identity,
            options = e.Options,   // non-secret only; the config reader admits no secret value here
            enabled = e.Enabled,
        };

        // Shared ------------------------------------------------------------------------

        // The config file is a sibling of the data folder by default (<home>\config\<name>); --out/--in give an
        // explicit file, and --config a folder it sits in. The path is tenant data, so it is never guarded against the
        // source tree the way settings\ and data\ are - it is meant to live in git-ignored clients\ or home\.
        static string ConfigPath(RequestCli r, string option, string fileName)
        {
            if (r.Cli.Get(option) is { Length: > 0 } file)
                return Path.GetFullPath(file);
            var dir = r.Cli.Get("config") is { Length: > 0 } folder ? Path.GetFullPath(folder) : r.Paths.Config;
            return Path.Combine(dir, fileName);
        }

        static string? Client(RequestCli r) =>
            r.Cli.Get("client") is { Length: > 0 } given ? given : SettingsLoader.Load(r.Paths.SettingsFile).TenantName;

        static void WriteConfig(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            // UTF-8 without a BOM, and the \n line endings the writer produces, so the file is byte-stable.
            File.WriteAllText(path, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        static bool TryRead<T>(RequestCli r, string fileName, Func<string, string, T> read, out T value, out string path)
        {
            path = ConfigPath(r, "in", fileName);
            value = default!;
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"No config file at {path}. 'keeper config export {Path.GetFileNameWithoutExtension(fileName)}' writes one.");
                return false;
            }
            try
            {
                value = read(File.ReadAllText(path), path);
                return true;
            }
            catch (ConfigException ex)
            {
                Console.Error.WriteLine($"{path} is not a valid config file:");
                foreach (var error in ex.Errors)
                    Console.Error.WriteLine($"  {error}");
                return false;
            }
        }

        static void ReportOnlyInStore(string what, IReadOnlyList<string> ids)
        {
            if (ids.Count > 0)
                Console.WriteLine($"In the store but not in the file ({ids.Count} {what}, left as they are): {string.Join(", ", ids)}");
        }

        static int ApplyOrQueue(RequestCli r, int queued, string kind)
        {
            if (queued == 0)
            {
                Console.WriteLine("Nothing to apply.");
                return ExitCodes.Ok;
            }
            Console.WriteLine($"Queued {queued} {kind} request{(queued == 1 ? "" : "s")}.");
            if (!r.Cli.Has("now"))
            {
                Console.WriteLine("'keeper qm run' applies them (or add --now).");
                return ExitCodes.Ok;
            }
            string[] qmArgs = r.Cli.Get("settings") is { } settings ? ["run", "--settings", Path.GetFullPath(settings)] : ["run"];
            return Commands.Run("qm", qmArgs);
        }

        // The synthetic systems are built in and cannot be changed through review.system, so they stay out of the file.
        static string SelectSystems() =>
            """
            SELECT system_id, name, team, purpose, owner, owner_person, route, criticality, active, notes
            FROM system WHERE system_id NOT IN ('KEEPER', 'ORG', 'UNMAPPED') ORDER BY system_id;
            """;

        static SystemRecord FromRow(Dictionary<string, object?> row) => new(
            (string)row["system_id"]!,
            (string)row["name"]!,
            row["owner"] as string,
            row["owner_person"] as string,
            row["purpose"] as string,
            row["team"] as string,
            row["route"] as string,
            row["criticality"] is long crit ? (int)crit : null,
            row["active"] is not 0L,
            row["notes"] as string);

        static object Upsert(SystemRecord s) => new
        {
            op = "upsert",
            systemId = s.Id,
            name = s.Name,
            team = s.Team,
            purpose = s.Purpose,
            owner = s.Owner,
            ownerPerson = s.OwnerPerson,
            route = s.Route,
            criticality = s.Criticality,
            active = s.Active,
            notes = s.Notes,
        };

        static int Usage(bool asked = false) =>
            CliUsage.Print("""
                keeper config - move the client configuration between its files and the store; changes need --reason

                  keeper config export systems|settings|overrides|registers|integrations [--out <file>] [--config <dir>] [--client <name>]
                      Writes the config file from the store (schema keeper.config/1), records ordered deterministically.

                  keeper config import systems|settings|overrides|registers|integrations [--in <file>] [--config <dir>] --reason "<why>" [--now]
                      Upserts each record in the file into the store through the one-writer queue. Idempotent: a record
                      already matching the store queues nothing. A record in the store but absent from the file is left
                      alone and reported (this increment does not delete). Overrides are added when not already active.

                  integrations hold NON-SECRET config only: a secret's NAME is recorded, never its value. Export writes
                  the names; import never reads, writes or requires a secret value and reports which secrets must still
                  be set with 'keeper integration set-secret'.

                  Default folder: <home>\config\ (a sibling of data\). --now applies the change straight away.
                """, asked);
    }
}
