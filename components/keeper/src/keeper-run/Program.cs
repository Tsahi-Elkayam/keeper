using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Scan;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-run: the daily pipeline, each stage its own process so each holds only what it needs:
// rules load -> scan every system (read-only towards it) -> load -> qm run
//            -> scan the store's own systems (they read what was just loaded) -> load -> qm run
//            -> track -> qm run -> rank -> qm run -> today.
try
{
    var cli = new CliArgs(args, flags: ["scan-all", "no-scan", "dry-run", "fresh-sign-in"]);
    if (cli.Help)
        return CliUsage.Print("""
            keeper-run - the daily pipeline: load rules, scan, load, track, rank, then today's list

              keeper run                      scan every system that has an enabled integration (and Keeper's own registers)
              keeper run --scan entra,intune  only these systems; each needs an enabled integration
              keeper run --no-scan            no scans: load, track and rank what is already there
              keeper run --dry-run            show which scans would run, and run nothing
              keeper run --fresh-sign-in      new Entra tokens for every scan: right after activating a PIM role
            """, asked: true);
    var (_, paths) = KeeperContext.Load(cli);
    var passSettings = cli.Get("settings") is { } s ? new[] { "--settings", Path.GetFullPath(s) } : [];
    string[] scanFlags = cli.Has("fresh-sign-in") ? ["--fresh-sign-in"] : [];
    var build = Iso.Stamp(DateTimeOffset.UtcNow);

    var scans = cli.Has("no-scan") ? [] : Plan(paths, cli);
    var external = scans.Where(p => !p.Type.Equals("keeper", StringComparison.OrdinalIgnoreCase)).ToList();
    var fromStore = scans.Except(external).ToList();
    Console.WriteLine(scans.Count == 0
        ? "No scans this run."
        : $"Scans: {string.Join(", ", scans.Select(p => p.Integration is null ? p.System : $"{p.System} via {p.Integration}"))}");
    if (cli.Has("dry-run"))
    {
        Console.WriteLine("Dry run: then load, track, rank and today. Nothing ran.");
        return ExitCodes.Ok;
    }

    // The rule catalogue first, so findings and blind spots can name every rule that ran or did not.
    var problems = new List<string>();
    if (!Stage("keeper-rules", ["load", .. passSettings], problems))
    {
        Report(problems);
        return ExitCodes.Failed;
    }

    // Rules over the store (Keeper's own health, cross-system checks) read what the other scans
    // found, so those scans are loaded first. A failed scan does not stop the run - the rest still count;
    // a stage the next one depends on does.
    Scan(external, [.. passSettings, .. scanFlags], problems);
    Console.WriteLine();
    if (!Stage("keeper-load", [.. passSettings], problems, tolerateNoData: true)
        || !Stage("keeper-qm", ["run", .. passSettings], problems))
    {
        Report(problems);
        return ExitCodes.Failed;
    }
    if (fromStore.Count > 0)
    {
        Scan(fromStore, passSettings, problems);
        Console.WriteLine();
        if (!Stage("keeper-load", [.. passSettings], problems, tolerateNoData: true)
            || !Stage("keeper-qm", ["run", .. passSettings], problems))
        {
            Report(problems);
            return ExitCodes.Failed;
        }
    }

    if (!Stage("keeper-track", ["--build", build, .. passSettings], problems)
        || !Stage("keeper-qm", ["run", .. passSettings], problems)
        || !Stage("keeper-rank", ["--build", build, .. passSettings], problems)
        || !Stage("keeper-qm", ["run", .. passSettings], problems))
    {
        Report(problems);
        return ExitCodes.Failed;
    }

    Console.WriteLine();
    string[] todayArgs = [.. passSettings, .. Passed(cli, "format", "out")];
    var todayCode = Siblings.Run("keeper-today", todayArgs);
    Report(problems);
    return todayCode != ExitCodes.Ok ? todayCode : problems.Count > 0 ? ExitCodes.NoData : ExitCodes.Ok;
}
catch (Exception ex) when (ex is SettingsException or ArgumentException or IntegrationException or RuleException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static void Scan(List<(string System, string? Integration, string Type)> scans, string[] passOn, List<string> problems)
{
    foreach (var (system, integration, _) in scans)
    {
        Console.WriteLine();
        string[] scanArgs = integration is null ? [system, .. passOn] : [system, "--integration", integration, .. passOn];
        var code = Siblings.Run("keeper-scan", scanArgs);
        if (code == ExitCodes.NoData)
            problems.Add($"{system}: partial scan (see its blind spots)");
        else if (code != ExitCodes.Ok)
            problems.Add($"{system}: scan failed (exit {code})");
    }
}

static List<(string System, string? Integration, string Type)> Plan(KeeperPaths paths, CliArgs cli)
{
    var rules = RuleSources.Load(paths.TenantRules);
    var asked = cli.Get("scan")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    foreach (var name in asked ?? [])
    {
        if (rules.ForSystem(name).Count == 0)
            throw new ArgumentException($"No rules for '{name}'. 'keeper scan --list' shows the systems.");
    }

    IReadOnlyList<IntegrationRecord> integrations;
    using (var connection = new Database(paths.Database).OpenReadOnly())
        integrations = IntegrationStore.All(connection);

    var plan = new List<(string, string?, string)>();
    foreach (var system in asked ?? rules.Systems.ToArray())
    {
        var type = rules.ForSystem(system)[0].Integration;
        var matching = integrations.Where(i => i.Enabled && i.Type.Equals(type, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matching.Count > 0)
            plan.AddRange(matching.Select(i => (system, (string?)i.Id, type)));
        else if (IntegrationTypes.IsImplicit(type))
            plan.Add((system, null, type));
        else if (asked is not null)
            throw new ArgumentException($"{system} needs a {type} integration and none is enabled. 'keeper integration add' sets one up.");
        // Unasked systems without an integration are skipped: nobody has said how to reach them.
    }
    return plan;
}

static bool Stage(string binary, string[] stageArgs, List<string> problems, bool tolerateNoData = false)
{
    var code = Siblings.Run(binary, stageArgs);
    if (code == ExitCodes.Ok || (tolerateNoData && code == ExitCodes.NoData))
    {
        if (code == ExitCodes.NoData)
            problems.Add($"{binary}: some scans were refused (see above)");
        return true;
    }
    problems.Add($"{binary} {string.Join(' ', stageArgs.TakeWhile(a => a != "--settings"))}: exit {code}; the run stopped here");
    return false;
}

static string[] Passed(CliArgs cli, params string[] names) =>
    names.Where(n => cli.Get(n) is not null).SelectMany(n => new[] { "--" + n, cli.Get(n)! }).ToArray();

static void Report(List<string> problems)
{
    if (problems.Count == 0)
        return;
    Console.WriteLine();
    Console.WriteLine("This run did not see everything:");
    foreach (var problem in problems)
        Console.WriteLine($"  - {problem}");
}
