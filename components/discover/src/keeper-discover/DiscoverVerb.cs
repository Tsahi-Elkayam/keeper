using Keeper.Common;
using Keeper.Discover;
using Keeper.Discover.Probes;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Store;
using Keeper.Vault;
using Microsoft.Data.Sqlite;

// keeper discover: reads settings/discovery.yaml, probes targets in-process (read-only),
// and writes data/imports/discovery/inventory.json. Never writes the store directly.
public static class DiscoverVerb
{
    public static int Run(string[] args) => RunAsync(args).GetAwaiter().GetResult();

    public static async Task<int> RunAsync(string[] args, IDialer? dialer = null, Keeper.Discover.Sources.IResolver? resolver = null)
    {
        try
        {
            var cli = new CliArgs(args, flags: ["fresh", "dry-run", "ignore-window"]);
            if (cli.Help)
                return Usage(asked: true);
            cli.RejectUnknown(["fresh", "dry-run", "ignore-window", "targets", "settings"]);

            var (_, paths) = KeeperContext.Load(cli);
            var targetsPath = cli.Get("targets") is { } customTargets
                ? Path.GetFullPath(customTargets)
                : Path.Combine(paths.SettingsDir, "discovery.yaml");

            var targets = TargetsLoader.Load(targetsPath);
            if (targets.Snmp.AllowCleartext && targets.Snmp.V2c.Count > 0)
            {
                Console.Error.WriteLine("WARNING: SNMP v2c is enabled (allow-cleartext: true); community strings cross the network in clear text.");
            }

            SqliteConnection? storeConnection = null;
            var snmpCreds = new List<SnmpCredential>();
            TimeZoneInfo? orgTimeZone = null;

            try
            {
                if (File.Exists(paths.Database))
                {
                    storeConnection = new Database(paths.Database).OpenReadOnly();
                    orgTimeZone = LoadOrgTimeZone(storeConnection);
                    if (!cli.Has("dry-run"))
                        snmpCreds = LoadSnmpCredentials(storeConnection, targets.Snmp, paths.SettingsDir);
                }

                var discoverer = new Discoverer();
                var report = await discoverer.RunAsync(new DiscoverRequest
                {
                    Targets = targets,
                    ImportsDir = paths.Imports,
                    Dialer = dialer,
                    Resolver = resolver,
                    StoreConnection = storeConnection,
                    SnmpCredentials = snmpCreds,
                    TimeZone = orgTimeZone,
                    Fresh = cli.Has("fresh"),
                    IgnoreWindow = cli.Has("ignore-window"),
                    DryRun = cli.Has("dry-run"),
                    Log = Console.WriteLine,
                }).ConfigureAwait(false);

                if (cli.Has("dry-run"))
                {
                    Console.WriteLine($"Discovery plan (mode: {report.Plan.Mode}):");
                    Console.WriteLine($"  Candidate assets : {report.Plan.CandidateAssets}");
                    Console.WriteLine($"  Target addresses : {report.Plan.TotalAddresses}");
                    Console.WriteLine($"  Estimated time   : {report.Plan.EstimatedDuration.TotalSeconds:0} s (at {targets.Rate.ConnectionsPerSecond} conn/s)");
                    foreach (var src in report.Plan.SourceCoverage)
                        Console.WriteLine($"  Source {src.Item,-18}: {src.State} ({src.Count} items){(src.Reason is not null ? $" - {src.Reason}" : "")}");
                    Console.WriteLine("Dry run: no probes sent and nothing written (DNS lookups for named targets are still made).");
                    return ExitCodes.Ok;
                }

                var sum = report.Document.Coverage.Summary;
                Console.WriteLine($"Wrote {report.InventoryPath} (health: {report.Document.ScanHealth})");
                Console.WriteLine($"  Assets: {sum.TotalCandidates} total, {sum.Answering} answering ({sum.WithManagementProtocol} with management protocol), " +
                                  $"{sum.NotAnswering} not-answering, {sum.LikelyGone} likely-gone, {sum.Unresolved} unresolved, {sum.Excluded} excluded");
                foreach (var note in report.Document.Notes)
                    Console.WriteLine($"  Note: {note}");

                return report.Document.ScanHealth == ScanHealthStates.Ok ? ExitCodes.Ok : ExitCodes.NoData;
            }
            finally
            {
                storeConnection?.Dispose();
            }
        }
        catch (ScanWindowClosedException ex)
        {
            Console.Error.WriteLine($"{ex.Message} Use --ignore-window to run outside the window.");
            return ExitCodes.Usage;
        }
        catch (Exception ex) when (ex is ArgumentException or SettingsException)
        {
            Console.Error.WriteLine(ex.Message);
            return ExitCodes.Usage;
        }
        catch (Exception ex) when (ex is StoreException or SqliteException or IOException or UnauthorizedAccessException or VaultException)
        {
            Console.Error.WriteLine(Redactor.Clean(ex.Message));
            return ExitCodes.Failed;
        }
    }

    private static TimeZoneInfo? LoadOrgTimeZone(SqliteConnection connection)
    {
        try
        {
            var tz = Sql.Scalar(connection, "SELECT value FROM setting WHERE key = 'threshold.org.timezone';") as string;
            if (!string.IsNullOrWhiteSpace(tz) && TimeZoneInfo.TryFindSystemTimeZoneById(tz.Trim(), out var zone))
                return zone;
        }
        catch (SqliteException)
        {
            // Store may not be initialized yet.
        }
        return null;
    }

    private static List<SnmpCredential> LoadSnmpCredentials(SqliteConnection connection, SnmpSettings snmp, string settingsDir)
    {
        var requestedIds = snmp.V3.Concat(snmp.V2c).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (requestedIds.Count == 0)
            return [];

        IReadOnlyList<IntegrationRecord> all;
        try
        {
            all = IntegrationStore.All(connection);
        }
        catch (SqliteException)
        {
            return [];
        }

        var result = new List<SnmpCredential>();
        Vault? vault = null;

        foreach (var id in requestedIds)
        {
            var record = all.FirstOrDefault(i => i.Enabled && i.Id.Equals(id, StringComparison.OrdinalIgnoreCase) && i.Type == "snmp");
            if (record is null || !Addresses.TryParseNetwork(record.Endpoint, out var scope, out _))
                continue;

            vault ??= Vault.Load(connection, KeyProtectors.Default(settingsDir));
            string? ReadSecret(string name) =>
                record.Secrets.TryGetValue(name, out var s)
                    ? vault.Open(s.Sealed, IntegrationStore.Binding(record.Id, name, record.Endpoint))
                    : null;

            if (record.AuthKind == "snmp-v3")
            {
                result.Add(new SnmpCredential(
                    record.Id,
                    "snmp-v3",
                    scope,
                    Username: record.Identity,
                    AuthPassword: ReadSecret("authPassword"),
                    PrivPassword: ReadSecret("privPassword")));
            }
            else if (record.AuthKind == "snmp-v2c")
            {
                result.Add(new SnmpCredential(
                    record.Id,
                    "snmp-v2c",
                    scope,
                    Community: ReadSecret("community")));
            }
        }
        return result;
    }

    private static int Usage(bool asked = false) =>
        CliUsage.Print("""
            keeper discover - discover hosts on the network and write imports\discovery\inventory.json (read-only)

              keeper discover                         run using settings\discovery.yaml
              keeper discover --targets <file>        use another discovery.yaml file
              keeper discover --dry-run               show candidate counts, sources and time estimate; send nothing
              keeper discover --fresh                 ignore previous inventory (kept as inventory.previous.json)
              keeper discover --ignore-window         run even if outside the configured scan windows

            What is sent: TCP connect on the profile ports; credential-free SSH banner read, HTTP GET /,
            WinRM GET /wsman, TLS handshake, SMB2 NEGOTIATE, LDAP anonymous rootDSE, and SNMP v3 engine discovery
            (plus configured read-only SNMP GET/GETNEXT). Raw print ports (515, 9100-9107) and gentle ranges
            never receive payload bytes.
            """, asked);
}
