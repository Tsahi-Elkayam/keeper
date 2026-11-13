using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Rules;
using Keeper.Scan;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper run: the daily pipeline, each stage a verb of this binary, run in turn in this process:
// rules load -> scan every system (read-only towards it) -> load -> qm run
//            -> scan the store's own systems (they read what was just loaded) -> load -> qm run
//            -> track -> qm run -> rank -> qm run -> today.
public static class RunVerb
{
    public static int Run(string[] args)
    {
        try
        {
            var cli = new CliArgs(args, flags: ["scan-all", "no-scan", "dry-run", "fresh-sign-in", "discover", "retry-sign-in", "ignore-window"]);
            if (cli.Help)
                return CliUsage.Print("""
                    keeper run - the daily pipeline: load rules, scan, load, track, rank, then today's list

                      keeper run                      scan every system that has an enabled integration (and Keeper's own registers)
                      keeper run --discover           run 'keeper discover' first (when settings\discovery.yaml exists), then scan
                      keeper run --scan entra,intune  only these systems; each needs an enabled integration
                      keeper run --no-scan            no scans: load, track and rank what is already there
                      keeper run --dry-run            show which scans would run and what each would cost every host, and run nothing
                      keeper run --fresh-sign-in      new Entra tokens for every scan: right after activating a PIM role
                      keeper run --pace gentle        how hard every scan reads (gentle, normal, fast; see 'keeper scan --help')
                      keeper run --retry-sign-in      sign in again with credentials refused before (after an account was unlocked)
                      keeper run --ignore-window      scan integrations whose scan window (option window) is closed now
                    """, asked: true);
            var (_, paths) = KeeperContext.Load(cli);
            var passSettings = cli.Get("settings") is { } s ? new[] { "--settings", Path.GetFullPath(s) } : [];
            string[] scanFlags = [.. cli.Has("fresh-sign-in") ? ["--fresh-sign-in"] : Array.Empty<string>(),
                .. cli.Has("retry-sign-in") ? ["--retry-sign-in"] : Array.Empty<string>(),
                .. cli.Has("ignore-window") ? ["--ignore-window"] : Array.Empty<string>(),
                .. cli.Get("pace") is { } pace ? ["--pace", pace] : Array.Empty<string>()];
            var build = Iso.Stamp(DateTimeOffset.UtcNow);

            var (scans, waiting) = cli.Has("no-scan") ? ([], []) : Plan(paths, cli);
            var external = scans.Where(p => !p.Type.Equals("keeper", StringComparison.OrdinalIgnoreCase)).ToList();
            // Keeper's own health checks read how every other scan went, the store's other systems included: last.
            var fromStore = scans.Except(external)
                .OrderBy(p => p.System.Equals("keeper", StringComparison.OrdinalIgnoreCase) ? 1 : 0).ToList();
            Console.WriteLine(scans.Count == 0
                ? "No scans this run."
                : $"Scans: {string.Join(", ", scans.Select(p => p.Integration is null ? p.System : $"{p.System} via {p.Integration}"))}");
            foreach (var line in waiting)
                Console.WriteLine(line);
            if (cli.Has("dry-run"))
            {
                // What each scan would cost the estate, read from the rules and the store only: nothing is sent.
                foreach (var (system, integration, _) in external)
                {
                    Console.WriteLine();
                    Commands.Run("scan", integration is null
                        ? [system, "--plan", .. passSettings, .. scanFlags]
                        : [system, "--integration", integration, "--plan", .. passSettings, .. scanFlags]);
                }
                Console.WriteLine();
                Console.WriteLine("Dry run: then load, track, rank and today. Nothing ran.");
                return ExitCodes.Ok;
            }

            // The rule catalogue first, so findings and blind spots can name every rule that ran or did not.
            var problems = new List<string>();
            if (!Stage("rules", ["load", .. passSettings], problems))
            {
                Report(problems);
                return ExitCodes.Failed;
            }

            if (cli.Has("discover") && !File.Exists(Path.Combine(paths.SettingsDir, "discovery.yaml")))
                Console.WriteLine("discover: skipped, there is no settings\\discovery.yaml");
            else if (cli.Has("discover"))
            {
                var code = Commands.Run("discover", passSettings);
                if (code == ExitCodes.NoData)
                    problems.Add("discover: partial or degraded discovery run");
                else if (code != ExitCodes.Ok)
                    problems.Add($"discover: failed (exit {code})");
            }

            // Rules over the store (Keeper's own health, cross-system checks) read what the other scans
            // found, so those scans are loaded first. A failed scan does not stop the run - the rest still count;
            // a stage the next one depends on does.
            // The systems scanned through one integration share its sign-in and its hosts' sessions: a Windows host the
            // baseline, services and event-log systems all read is signed in to once in the run, not once per system.
            // They are ended here, before loading - nothing is left signed in through load, track and rank.
            var shared = new RunSessions();
            RunSessions.Current = shared;
            try
            {
                Scan(external, [.. passSettings, .. scanFlags], problems);
            }
            finally
            {
                RunSessions.Current = null;
                shared.DisposeAsync().AsTask().GetAwaiter().GetResult();
                if (shared.Reused > 0)
                    Console.WriteLine($"Sessions reused across systems: {shared.Reused} sign-in(s) not repeated.");
            }
            Console.WriteLine();
            if (!Stage("load", [.. passSettings], problems, tolerateNoData: true)
                || !Stage("qm", ["run", .. passSettings], problems))
            {
                Report(problems);
                return ExitCodes.Failed;
            }
            if (fromStore.Count > 0)
            {
                Scan(fromStore, passSettings, problems);
                Console.WriteLine();
                if (!Stage("load", [.. passSettings], problems, tolerateNoData: true)
                    || !Stage("qm", ["run", .. passSettings], problems))
                {
                    Report(problems);
                    return ExitCodes.Failed;
                }
            }

            if (!Stage("track", ["--build", build, .. passSettings], problems)
                || !Stage("qm", ["run", .. passSettings], problems)
                || !Stage("rank", ["--build", build, .. passSettings], problems)
                || !Stage("qm", ["run", .. passSettings], problems))
            {
                Report(problems);
                return ExitCodes.Failed;
            }

            Console.WriteLine();
            string[] todayArgs = [.. passSettings, .. Passed(cli, "format", "out")];
            var todayCode = Commands.Run("today", todayArgs);
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
                var code = Commands.Run("scan", scanArgs);
                if (code == ExitCodes.NotNow)
                    problems.Add($"{system}: not scanned, outside its integration's scan window");
                else if (code == ExitCodes.NoData)
                    problems.Add($"{system}: partial scan (see its blind spots)");
                else if (code != ExitCodes.Ok)
                    problems.Add($"{system}: scan failed (exit {code})");
            }
        }

        static (List<(string System, string? Integration, string Type)> Plan, List<string> Waiting) Plan(KeeperPaths paths, CliArgs cli)
        {
            var rules = RuleSources.Load(paths.TenantRules);
            var asked = cli.Get("scan")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var name in asked ?? [])
            {
                if (rules.ForSystem(name).Count == 0)
                    throw new ArgumentException($"No rules for '{name}'. 'keeper scan --list' shows the systems.");
            }

            if (rules.Files.Count == 0)
                throw new ArgumentException($"No rule files found (built-in: {RuleSources.BuiltIn}; tenant: {paths.TenantRules}). " +
                                            "A build from build.ps1 puts the rules beside the binary.");

            var plan = new List<(string, string?, string)>();
            var waiting = new List<(PackReadiness.Waiting Kind, string Detail)>();
            using var connection = new Database(paths.Database).OpenReadOnly();
            var integrations = IntegrationStore.All(connection);
            var inputs = new StoreInputs(connection);
            var settings = Sql.Rows(connection, "SELECT key, value FROM setting;")
                .ToDictionary(r => (string)r["key"]!, r => (string)r["value"]!, StringComparer.Ordinal);
            var now = DateTimeOffset.UtcNow;
            foreach (var system in asked ?? rules.Systems.ToArray())
            {
                var files = rules.ForSystem(system);
                var type = files[0].Integration;
                var matching = integrations.Where(i => i.Enabled && IntegrationTypes.Satisfies(type, i.Type)).ToList();
                var candidates = matching.Select(i => (Id: (string?)i.Id, i.Options)).ToList();
                // A type that needs no configuration has its implicit instance; for host rules that is the local
                // machine, which is read beside any ssh fleet.
                if (IntegrationTypes.IsImplicit(type) && (matching.Count == 0 || type == "host"))
                    candidates.Add((null, new System.Text.Json.Nodes.JsonObject()));
                else if (matching.Count == 0 && asked is not null)
                    throw new ArgumentException($"{system} needs a {type} integration and none is enabled. 'keeper integration add' sets one up.");
                // Unasked systems without an integration are skipped: nobody has said how to reach them.

                foreach (var (id, options) in candidates)
                {
                    // A system named with --scan runs whatever it lacks, and says so; the daily run leaves a pack
                    // nobody set up out, in one line, instead of reporting it as a failed scan.
                    var notReady = asked is null
                        ? PackReadiness.Check(files, id is null, options, paths.Imports, settings.GetValueOrDefault,
                            inputs.Threshold, spec => inputs.Targets(spec, now))
                        : null;
                    if (notReady is { } why)
                        waiting.Add(why);
                    else
                        plan.Add((system, id, type));
                }
            }
            var lines = waiting.GroupBy(w => w.Kind).OrderBy(g => g.Key)
                .Select(g => PackReadiness.Line(g.Key, g.Select(w => w.Detail).Distinct(StringComparer.Ordinal))).ToList();
            return (plan, lines);
        }

        static bool Stage(string verb, string[] stageArgs, List<string> problems, bool tolerateNoData = false)
        {
            var code = Commands.Run(verb, stageArgs);
            if (code == ExitCodes.Ok || (tolerateNoData && code == ExitCodes.NoData))
            {
                if (code == ExitCodes.NoData)
                    problems.Add($"keeper {verb}: some scans were refused (see above)");
                return true;
            }
            problems.Add($"keeper {verb} {string.Join(' ', stageArgs.TakeWhile(a => a != "--settings"))}: exit {code}; the run stopped here");
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
    }
}
