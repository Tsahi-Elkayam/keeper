using System.Globalization;
using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Rules;
using Keeper.Scan;
using Keeper.Store;
using Keeper.Vault;
using Microsoft.Data.Sqlite;

// keeper scan <system>: runs one system's rules through one integration and writes a run folder.
// Read-only towards the system; the only thing it writes is the run folder in the Keeper home.
public static class ScanVerb
{
    public static int Run(string[] args) => RunAsync(args).GetAwaiter().GetResult();

    private static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var cli = new CliArgs(args, flags: ["test", "list", "fresh-sign-in"]);
            if (cli.Help)
                return CliUsage.Print("""
                    keeper scan - run one system's rules through its integration and write a run folder (read-only towards the system)

                      keeper scan --list                    the systems there are rules for, and the integration each needs
                      keeper scan <system>                  scan it through its enabled integration
                      keeper scan <system> --test           connection test: the first rule only, no run kept; the result is
                                                            recorded on the integration ('keeper integrations' shows it)
                        --integration <id>   which one, when there are several of the type
                        --fresh-sign-in      take a new token (Entra): right after activating a PIM role, so the role is in it
                        --timeout 60         seconds per request     --parallel 8   requests at once
                    """, asked: true);
            var (_, paths) = KeeperContext.Load(cli);
            var rules = RuleSources.Load(paths.TenantRules);

            if (cli.Has("list") || cli.At(0) is null)
            {
                foreach (var system in rules.Systems)
                {
                    var files = rules.ForSystem(system);
                    Console.WriteLine($"{system,-22} {files.Sum(f => f.Rules.Count),4} rules  integration: {files[0].Integration}");
                }
                return cli.At(0) is null && !cli.Has("list") ? ExitCodes.Usage : ExitCodes.Ok;
            }

            var systemName = cli.At(0)!;
            var ruleFiles = rules.ForSystem(systemName);
            if (ruleFiles.Count == 0)
                throw new ArgumentException($"No rules for '{systemName}'. 'keeper scan --list' shows the systems.");
            var integrationType = ruleFiles[0].Integration;
            if (ruleFiles.Any(f => f.Integration != integrationType))
                throw new ArgumentException($"The rule files for {systemName} name different integration types.");

            IntegrationRecord record;
            Vault? vault = null;
            StoreInputs inputs;
            var db = new Database(paths.Database);
            var connection = db.OpenReadOnly();
            try
            {
                SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Vault.Schema, IntegrationStore.Schema]);
                record = IntegrationStore.Resolve(connection, integrationType, cli.Get("integration"));
                if (record.Secrets.Count > 0)
                    vault = Vault.Load(connection, KeyProtectors.Default(paths.SettingsDir));
                inputs = new StoreInputs(connection);
                var previous = inputs.PreviousRows(record.Id, systemName);

                var test = cli.Has("test");
                var runsDir = test ? Path.Combine(paths.DataDir, "tmp", "test-" + Iso.Stamp(DateTimeOffset.UtcNow)) : paths.Runs;
                using var link = new IntegrationConnection(record, vault) { FreshSignIn = cli.Has("fresh-sign-in") };
                var scanner = new Scanner(Keeper.Scan.Runners.Registry());
                var started = DateTimeOffset.UtcNow;
                var request = new ScanRequest
                {
                    Files = test ? [ruleFiles[0] with { Rules = [ruleFiles[0].Rules[0]] }] : ruleFiles,
                    Connection = link,
                    RunsDir = runsDir,
                    ImportsDir = paths.Imports,
                    StoreFile = paths.Database,
                    Threshold = inputs.Threshold,
                    OverrideThreshold = inputs.OverrideThreshold,
                    ResolveTargets = spec => inputs.Targets(spec, started),
                    ResolveTargetAttributes = spec => inputs.TargetAttributes(spec, started),
                    TargetsIncomplete = inputs.TargetsIncomplete,
                    // A connection test reads one rule once; comparing it with a full scan would only confuse the result.
                    PreviousRows = test ? _ => null : item => previous.GetValueOrDefault(item),
                    LastCleanRows = test ? _ => new Dictionary<string, CleanRead>() : query => inputs.LastCleanRows(record.Id, systemName, query),
                    Timeout = TimeSpan.FromSeconds(int.TryParse(cli.Get("timeout"), NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : 60),
                    Parallelism = int.TryParse(cli.Get("parallel"), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 8,
                    Log = message => Console.Error.WriteLine($"  {Redactor.Clean(message)}"),
                };
                Directory.CreateDirectory(runsDir);

                Console.WriteLine($"Scanning {systemName} through {record.Id} ({record.Type}){(test ? " - connection test" : "")}...");
                var report = await scanner.RunAsync(request, CancellationToken.None);

                Console.WriteLine($"{report.Manifest.Status}: {report.Rules} rules, {report.Queries} queries, {report.Rows} rows, " +
                                  $"{report.Findings} findings, {report.FailedQueries} failed queries." +
                                  (report.Manifest.Identity is { } readAs ? $" Read as {readAs}." : ""));
                foreach (var note in report.Manifest.Notes)
                    Console.WriteLine($"  {note}");

                if (test)
                {
                    Directory.Delete(runsDir, recursive: true);
                    new RequestWriter(paths.Spool).Submit("integrations.test-result", $"Connection test of {record.Id}", new
                    {
                        integrationId = record.Id,
                        state = report.Manifest.Status,
                        detail = string.Join("; ", report.Manifest.Notes),
                    });
                }
                else
                {
                    Console.WriteLine($"Run {report.Manifest.RunId} written. 'keeper load' then 'keeper qm run' takes it in.");
                }
                return report.Manifest.Status == "ok" ? ExitCodes.Ok : ExitCodes.NoData;
            }
            finally
            {
                connection.Dispose();
            }
        }
        catch (RuleException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return ExitCodes.Failed;
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
    }
}
