using System.Globalization;
using System.Text;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Scan;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-certs <host>... : the certificates a server presents on its TLS ports - valid or not, and until
// when. Runs only when a person starts it, never from keeper run or a schedule. Inspect-only handshakes:
// nothing is sent beyond TLS hello, and no credential is used.
try
{
    var cli = new CliArgs(args, flags: ["from-ad", "save"]);
    var hosts = cli.Positional.ToList();
    if (hosts.Count == 0 && !cli.Has("from-ad"))
        return Usage();

    var needsHome = cli.Has("from-ad") || cli.Has("save");
    KeeperPaths? paths = null;
    if (needsHome || File.Exists(KeeperPaths.DefaultSettingsFile) || cli.Get("settings") is not null)
        (_, paths) = KeeperContext.Load(cli);

    if (cli.Has("from-ad"))
    {
        using var connection = new Database(paths!.Database).OpenReadOnly();
        var servers = new StoreInputs(connection).Targets(new TargetSpec("computer",
            new AllCondition(
            [
                new LeafCondition("operatingSystem", "match", "Server", null),
                new LeafCondition("lastLogonTimestamp", "age-lt", 30, null),
            ]), "dNSHostName", []), DateTimeOffset.UtcNow);
        if (servers.Count == 0)
            throw new ArgumentException("The store has no servers from an Active Directory scan yet: run 'keeper scan active-directory' first, or name hosts.");
        Console.WriteLine($"{servers.Count} servers from the newest Active Directory scan.");
        hosts.AddRange(servers);
    }

    var ports = (cli.Get("ports") ?? "443,636,3269,5986,8443")
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(p => int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is > 0 and < 65536
            ? n : throw new ArgumentException($"--ports: '{p}' is not a port."))
        .ToList();
    // host:port names one endpoint; a bare host is tried on every port.
    var targets = hosts.SelectMany(h => h.Contains(':', StringComparison.Ordinal) ? [h] : ports.Select(p => $"{h}:{p}"))
        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    var noticeDays = int.TryParse(cli.Get("days"), NumberStyles.None, CultureInfo.InvariantCulture, out var nd) ? nd : 30;
    var timeout = TimeSpan.FromSeconds(int.TryParse(cli.Get("timeout"), NumberStyles.None, CultureInfo.InvariantCulture, out var t) && t > 0 ? t : 5);
    var parallel = int.TryParse(cli.Get("parallel"), NumberStyles.None, CultureInfo.InvariantCulture, out var par) && par > 0 ? par : 16;

    var rules = RuleSources.Load(paths?.TenantRules).ForSystem("certificates");
    if (rules.Count == 0)
        throw new ArgumentException($"No certificate rules in {RuleSources.BuiltIn}: use a full build.");

    Console.WriteLine($"Checking {targets.Count} endpoint(s) on {hosts.Count} host(s)...");
    // A plain TCP connect finds the open ports first, so each certificate is read with one handshake and a
    // closed port never becomes a blind spot in a saved run.
    var open = await OpenPorts(targets, timeout, parallel);
    var closed = targets.Except(open, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
    var scratch = Path.Combine(paths?.DataDir ?? Path.GetTempPath(), "tmp", "certs-" + Guid.NewGuid().ToString("N")[..8]);
    try
    {
        if (open.Count == 0)
        {
            Console.WriteLine($"No port answered on {targets.Count} endpoint(s).");
            return ExitCodes.NoData;
        }
        var save = cli.Has("save");
        var probe = await Scan(rules, open, save ? paths!.Runs : scratch, paths, timeout, parallel);
        var folder = Path.Combine(save ? paths!.Runs : scratch, probe.Manifest.RunId);
        var rows = Read<RowRecord>(folder, RunFolder.Rows)
            .GroupBy(r => r.Attrs["endpoint"]?.ToString() ?? r.EntityKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First().Attrs)
            .OrderBy(a => a["daysLeft"]?.GetValue<double>() ?? double.MaxValue)
            .ToList();
        var silent = Read<CoverageRecord>(folder, RunFolder.Coverage)
            .Where(c => c.Scope == "target" && c.State == "failed")
            .Select(c => c.Item[(c.Item.IndexOf('@', StringComparison.Ordinal) + 1)..])
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
        var findings = Read<FindingRecord>(folder, RunFolder.Findings).ToList();

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine();
        foreach (var row in rows)
        {
            var days = row["daysLeft"]?.GetValue<double>() ?? 0;
            var until = row["notAfter"]?.ToString() is { Length: >= 10 } a ? a[..10] : "?";
            var state = days < 0 ? $"EXPIRED {-(int)Math.Floor(days)} days ago"
                : days <= noticeDays ? $"expires in {(int)Math.Floor(days)} days"
                : $"valid, {(int)Math.Floor(days)} days left";
            var flags = new List<string>();
            if (row["selfSigned"]?.GetValue<bool>() == true) flags.Add("self-signed");
            else if (row["chainValid"]?.GetValue<bool>() == false) flags.Add("chain not trusted here");
            if (row["nameMatches"]?.GetValue<bool>() == false) flags.Add("name does not match");
            Console.WriteLine($"{row["endpoint"],-40} until {until}  {state}{(flags.Count > 0 ? " - " + string.Join(", ", flags) : "")}");
            Console.WriteLine($"{"",-40} {Cn(row["subject"]?.ToString())}, issued by {Cn(row["issuer"]?.ToString())}, {row["protocol"]}, {row["keyAlgorithm"]} {row["keySize"]}");
        }
        if (rows.Count == 0)
            Console.WriteLine("No endpoint answered with TLS.");
        if (silent.Count > 0)
            Console.WriteLine($"\nOpen but no TLS on {silent.Count} endpoint(s){(silent.Count <= 20 ? ": " + string.Join(", ", silent) : "")}.");
        if (closed.Count > 0)
            Console.WriteLine($"Closed or filtered: {closed.Count} endpoint(s){(closed.Count <= 20 ? ": " + string.Join(", ", closed) : " (--ports narrows the list)")}.");
        if (findings.Count > 0)
        {
            Console.WriteLine($"\nWhat the certificate rules found:");
            foreach (var group in findings.GroupBy(f => (f.Severity, f.Title)).OrderBy(g => Rank(g.Key.Severity)))
                Console.WriteLine($"  [{group.Key.Severity}] {group.Key.Title}: {string.Join(", ", group.Select(f => f.Target).Take(10))}{(group.Count() > 10 ? $" (+{group.Count() - 10})" : "")}");
        }

        if (save)
        {
            Console.WriteLine($"\nSaved as run {probe.Manifest.RunId}: 'keeper load' then 'keeper qm run' (or 'keeper run --no-scan') takes it in;");
            Console.WriteLine("expiry dates then become findings with deadlines, ranked in today's list.");
        }
        return rows.Count == 0 ? ExitCodes.NoData : ExitCodes.Ok;
    }
    finally
    {
        if (Directory.Exists(scratch))
            Directory.Delete(scratch, recursive: true);
    }
}
catch (Exception ex) when (ex is ArgumentException or SettingsException or RuleException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static async Task<ScanReport> Scan(IReadOnlyList<RuleFile> rules, IReadOnlyList<string> targets, string runsDir, KeeperPaths? paths,
    TimeSpan timeout, int parallel)
{
    Directory.CreateDirectory(runsDir);
    var record = new IntegrationRecord("tls-on-demand", "tls", "", "none", null, [], true, new Dictionary<string, StoredSecret>());
    using var link = new IntegrationConnection(record, null);
    return await new Scanner(Keeper.Scan.Runners.Registry()).RunAsync(new ScanRequest
    {
        Files = rules.Select(f => f with { Targets = new TargetSpec(null, null, null, targets) }).ToList(),
        Connection = link,
        RunsDir = runsDir,
        ImportsDir = paths?.Imports ?? runsDir,
        StoreFile = paths?.Database,
        Timeout = timeout,
        Parallelism = parallel,
    }, CancellationToken.None);
}

static async Task<List<string>> OpenPorts(IReadOnlyList<string> targets, TimeSpan timeout, int parallel)
{
    using var gate = new SemaphoreSlim(parallel);
    var probes = targets.Select(async target =>
    {
        await gate.WaitAsync();
        try
        {
            var (host, port) = Keeper.Runners.Tls.TlsRunner.Split(target, 443);
            using var tcp = new System.Net.Sockets.TcpClient();
            using var limit = new CancellationTokenSource(timeout);
            await tcp.ConnectAsync(host, port, limit.Token);
            return target;
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException)
        {
            return null;
        }
        finally
        {
            gate.Release();
        }
    }).ToList();
    return (await Task.WhenAll(probes)).OfType<string>().ToList();
}

static IEnumerable<T> Read<T>(string folder, string file) =>
    File.Exists(Path.Combine(folder, file)) ? JsonLines.Read<T>(Path.Combine(folder, file)) : [];

static string Cn(string? distinguishedName) =>
    distinguishedName?.Split(',').Select(p => p.Trim()).FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) is { } cn
        ? cn[3..] : distinguishedName ?? "?";

static int Rank(string severity) => severity switch { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };

static int Usage()
{
    Console.Error.WriteLine("""
        keeper-certs - which certificates a server presents, and until when (you start it; nothing runs on its own)

          keeper certs <host> [<host:port> ...]   each host on --ports (default 443,636,3269,5986,8443)
          keeper certs --from-ad                  every server the newest Active Directory scan saw
            --ports 443,8443   --days 30 (counts as "expires soon")   --timeout 5   --parallel 16
            --save             keep the result, so expiries become findings with deadlines
        """);
    return ExitCodes.Usage;
}
