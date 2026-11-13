using System.Globalization;
using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Rules;
using Keeper.Runners;
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
            var cli = new CliArgs(args, flags: ["test", "list", "fresh-sign-in", "plan", "retry-sign-in"]);
            if (cli.Help)
                return CliUsage.Print("""
                    keeper scan - run one system's rules through its integration and write a run folder (read-only towards the system)

                      keeper scan --list                    the systems there are rules for, and the integration each needs
                      keeper scan <system>                  scan it through its enabled integration
                      keeper scan <system> --test           connection test: the first rule on the first host only, no run kept;
                                                            the result is recorded on the integration ('keeper integrations' shows it)
                      keeper scan <system> --plan           what the scan would cost each host (reads, sign-ins, time at the
                                                            pace) - nothing is sent anywhere
                        --integration <id>   which one, when there are several of the type
                        --fresh-sign-in      take a new token (Entra): right after activating a PIM role, so the role is in it
                        --timeout 60         seconds per request
                        --pace gentle        how hard to read: gentle (default: 4 hosts at once, 1 new session/s, 10 requests/s
                                             per host), normal or fast; the integration option 'pace' sets it per integration,
                                             and pace.hosts / pace.sessionsPerSecond / pace.requestsPerSecond / pace.stopAfter
                                             change one number of it
                        --parallel <n>       hosts at once (overrides the pace's)
                        --retry-sign-in      sign in again although this credential was refused before (after the
                                             account was unlocked); setting the secret again does the same
                    Keeper opens one session per host and reuses it, slows down for a host that pushes back (timeouts, 429/503,
                    busy) and stops reading it after a few times, and never presents a credential again after it was refused -
                    for the rest of the scan and of 'keeper run' - so an account is not locked out.
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
                    OverrideThresholds = inputs.OverrideThresholds,
                    ResolveTargets = spec => inputs.Targets(spec, started),
                    ResolveTargetAttributes = spec => inputs.TargetAttributes(spec, started),
                    TargetsIncomplete = inputs.TargetsIncomplete,
                    TargetsUnjudged = spec => inputs.TargetsUnjudged(spec, started),
                    // A connection test reads one rule once; comparing it with a full scan would only confuse the result.
                    PreviousRows = test ? _ => null : item => previous.GetValueOrDefault(item),
                    LastCleanRows = test ? _ => new Dictionary<string, CleanRead>() : query => inputs.LastCleanRows(record.Id, systemName, query),
                    Timeout = TimeSpan.FromSeconds(int.TryParse(cli.Get("timeout"), NumberStyles.None, CultureInfo.InvariantCulture, out var t) ? t : 60),
                    Pace = PaceProfile.From(record.Options, cli.Get("pace")),
                    Parallelism = int.TryParse(cli.Get("parallel"), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : null,
                    Guard = LogonGuard.Process,
                    TargetLimit = test ? 1 : null,
                    Log = message => Console.Error.WriteLine($"  {Redactor.Clean(message)}"),
                };
                if (cli.Has("plan"))
                {
                    PrintPlan(systemName, record.Id, scanner.Plan(request));
                    return ExitCodes.Ok;
                }
                Directory.CreateDirectory(runsDir);

                // A refusal outlives the process: separate scans must not each present a refused password once more -
                // nor separate integrations that sign in as one Windows account.
                var refusals = new SignInRefusals(Path.Combine(paths.DataDir, "state", "sign-in-refusals.json"));
                static string CredentialOf(IntegrationRecord r) =>
                    SignInRefusals.Fingerprint(r.Id, r.Identity, r.Endpoint, r.AuthKind, r.Secrets.Values.Select(v => $"{v.Name}={v.SetAt}"));
                var credentials = IntegrationStore.All(connection).ToDictionary(r => r.Id, CredentialOf, StringComparer.OrdinalIgnoreCase);
                var credential = CredentialOf(record);
                DateTimeOffset? secretSetAt = record.Secrets.Values
                    .Select(v => DateTimeOffset.TryParse(v.SetAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at) ? at : (DateTimeOffset?)null)
                    .Max();
                if (!LogonGuard.PresentsSecret(link))
                {
                    // Nothing Keeper presents can lock this account: no refusal is kept or restored.
                }
                else if (cli.Has("retry-sign-in"))
                    TryKeep(() => refusals.ClearAccount(link));
                else if (refusals.Find(link, id => id.Equals(record.Id, StringComparison.OrdinalIgnoreCase) ? credential : credentials.GetValueOrDefault(id), secretSetAt) is { } recorded)
                    request.Guard.Restore(link, recorded);
                // Kept the moment it happens: a scan stopped half-way (Ctrl-C, a crash) must not forget it.
                request.Guard.OnRefused = (refusedConnection, text) =>
                {
                    if (refusedConnection.Instance == link.Instance)
                        TryKeep(() => refusals.Record(link, credential, text, DateTimeOffset.UtcNow));
                };

                Console.WriteLine($"Scanning {systemName} through {record.Id} ({record.Type}){(test ? " - connection test" : "")}...");
                ScanReport report;
                try
                {
                    report = await scanner.RunAsync(request, CancellationToken.None);
                }
                finally
                {
                    request.Guard.OnRefused = null;
                    // vCenter and session-login products cap open sessions: the scan's is ended, not left to time out.
                    // Best effort: the run is written by now, and a sign-out that fails must not replace its result.
                    try
                    {
                        await link.SignOutAsync(CancellationToken.None);
                    }
#pragma warning disable CA1031 // Ending the session is a courtesy; its failure is said and the scan's own result stands.
                    catch (Exception ex)
#pragma warning restore CA1031
                    {
                        Console.Error.WriteLine($"  warning: the session was not ended ({Redactor.Clean(ex.Message)}); it ends at its idle timeout");
                    }
                }
                // A credential that read data in this scan and was not refused works: an old record of it is gone.
                if (LogonGuard.PresentsSecret(link) && request.Guard.Refusal(link) is null && request.Guard.Proven(link))
                    TryKeep(() => refusals.Clear(link));

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

    /// <summary>
    /// Keeping a refusal is a safeguard, not the scan: a home that cannot be written (read-only, a lock held too long)
    /// is said on stderr and the scan goes on - the in-process guard still stops the credential.
    /// </summary>
    private static void TryKeep(Action keep)
    {
        try
        {
            keep();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"  warning: could not keep the sign-in refusal in the Keeper home: {ex.Message}");
        }
    }

    private static void PrintPlan(string system, string integration, ScanPlan plan)
    {
        Console.WriteLine($"Plan for {system} through {integration} - nothing was sent.");
        Console.WriteLine($"  pace: {plan.Pace}");
        Console.WriteLine($"  {plan.Queries} queries -> {plan.UnmergedReads} reads on {plan.Hosts.Count} host(s); {plan.Reads} after merging; " +
                          $"{plan.Sessions} sign-in(s) in all; at least {Duration(plan.Time)}");
        foreach (var host in plan.Hosts.Take(50))
            Console.WriteLine($"  {host.Host,-40} {host.Queries,5} queries {host.Reads,5} reads {host.Sessions,2} sign-in(s)  {Duration(host.Time)}");
        if (plan.Hosts.Count > 50)
            Console.WriteLine($"  ... and {plan.Hosts.Count - 50} more hosts");
        foreach (var problem in plan.Problems.Take(10))
            Console.WriteLine($"  will fail: {problem}");
    }

    private static string Duration(TimeSpan time) =>
        time.TotalHours >= 1 ? $"{time.TotalHours:0.#} h" : time.TotalMinutes >= 1 ? $"{time.TotalMinutes:0.#} min" : $"{time.TotalSeconds:0} s";
}
