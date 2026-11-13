using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keeper.Common;
using Keeper.Home;

// keeper <verb> ...: the one binary. Every verb runs in this process; a word that is not a verb is
// taken as a question (keeper broken == keeper query broken). setup and help live here.
// Each verb belongs to one part of Keeper; 'keeper help' shows the parts in this order, the engine's own verbs only
// with --all (the daily run calls them; a person rarely needs to).
var verbs = new (string Part, string Name, string What, Func<string[], int> Run)[]
{
    ("scan", "run", "scan everything that is set up, take the results in, then today's list", RunVerb.Run),
    ("scan", "scan", "scan one system now (keeper scan --list shows them)", ScanVerb.Run),
    ("scan", "discover", "find the machines on the networks you allow", DiscoverVerb.Run),
    ("scan", "certs", "which certificates a server presents, and until when", CertsVerb.Run),
    ("sign-in", "connect", "connect a Microsoft 365 tenant in one step and check its permissions", ConnectVerb.Run),
    ("sign-in", "integration", "how Keeper reaches each system, and its encrypted secrets", IntegrationVerb.Run),
    ("sign-in", "config", "export or import the whole configuration as files", ConfigVerb.Run),
    ("rules", "rules", "list, explain and validate the rules", RulesVerb.Run),
    ("rules", "query", "the questions Keeper answers (keeper query list)", QueryVerb.Run),
    ("reports", "today", "what to do today", TodayVerb.Run),
    ("reports", "report", "posture, security, expiring, changes, trends, finance, evidence and more", ReportVerb.Run),
    ("reports", "ui", "everything Keeper knows, as one page you open in a browser", args => ReportVerb.Run(["ui", .. args])),
    ("reports", "push", "open tickets for delegated findings (ServiceNow, monday.com)", PushVerb.Run),
    ("decide", "decide", "snooze, delegate, accept or disable a finding; set a threshold", DecideVerb.Run),
    ("decide", "system", "the systems findings are grouped and routed by", SystemVerb.Run),
    ("decide", "register", "vendors, contracts, licences, key dates, initiatives", RegisterVerb.Run),
    ("engine", "load", "queue the scans the store has not taken in", LoadVerb.Run),
    ("engine", "track", "turn the newest scans into the findings register", TrackVerb.Run),
    ("engine", "rank", "order the open findings into today's list", RankVerb.Run),
    ("engine", "qm", "the queue manager, the only writer of the store", QmVerb.Run),
    ("engine", "db", "the store: status, init, migrate, backup", DbVerb.Run),
};
foreach (var (_, name, _, run) in verbs)
    Commands.Add(name, run);
// Integration types a tenant adds (settings/integration-types/*.yaml) are known to every verb once it loads the home.
KeeperContext.Loaded += paths => Keeper.Integrations.IntegrationTypes.UseTenantFolder(Path.Combine(paths.SettingsDir, "integration-types"));

try
{
    var verb = args.Length > 0 ? args[0] : "help";
    var rest = args.Skip(1).ToArray();
    switch (verb)
    {
        case "help" or "--help" or "-h" or "/?":
            return Help(verbs, all: rest.Contains("--all"));
        case "version" or "--version":
            Console.WriteLine($"keeper {Assembly.GetExecutingAssembly().GetName().Version}");
            return ExitCodes.Ok;
        case "setup":
            return Setup(new CliArgs(rest, flags: ["apply"]));
    }

    if (!Regex.IsMatch(verb, "^[a-z][a-z0-9-]{0,32}$", RegexOptions.CultureInvariant))
    {
        Console.Error.WriteLine($"'{verb}' is not a keeper verb. 'keeper help' lists them.");
        return ExitCodes.Usage;
    }
    return Commands.Exists(verb)
        ? Commands.Run(verb, rest)
        : Commands.Run("query", args);   // a question: keeper broken == keeper query broken
}
catch (Exception ex) when (ex is SettingsException or ArgumentException or Keeper.Integrations.IntegrationException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static int Help((string Part, string Name, string What, Func<string[], int> Run)[] verbs, bool all)
{
    var version = Assembly.GetExecutingAssembly().GetName().Version;
    Console.WriteLine($"""
        Keeper {version?.ToString(3)} - a linter for systems. It reads them, never changes them, and says what is
        broken, misconfigured, missing or expiring, and what to do about it today.

        Start
          keeper setup --tenant <name> --apply    the Keeper home and its store
          keeper connect microsoft ...            sign in to a Microsoft 365 tenant (keeper connect --help)
          keeper run                              scan, then today's list

        """);
    (string Part, string Title, string What)[] parts =
    [
        ("scan", "Scan", "reads systems, read-only"),
        ("sign-in", "Sign-in", "how Keeper reaches what it reads"),
        ("rules", "Rules", "what is checked, and the questions you can ask"),
        ("reports", "Reports", "what was found, for you and for management"),
        ("decide", "Decisions", "what you decided about findings, and the records rules read"),
        ("engine", "Engine", "the steps 'keeper run' takes; rarely run by hand"),
    ];
    foreach (var (part, title, what) in parts)
    {
        if (part == "engine" && !all)
            continue;
        Console.WriteLine($"{title} - {what}");
        foreach (var (_, verb, text, _) in verbs.Where(v => v.Part == part))
            Console.WriteLine(Line($"keeper {verb}", text));
        if (part == "reports")
        {
            Console.WriteLine();
            Console.WriteLine("Trends - what changed, and whether it is getting better");
            Console.WriteLine(Line("keeper report trends", "each system now against 30 and 90 days ago: fixed, new, open"));
            Console.WriteLine(Line("keeper trend", "the daily rows behind it (--system <id>)"));
            Console.WriteLine(Line("keeper changed", "what appeared and what went away (--since <date>)"));
        }
        Console.WriteLine();
    }
    Console.WriteLine("Ask");
    Console.WriteLine(Line("keeper <question>", "broken, misconfigured, missing, expiring, blind-spots, ... (keeper query list)"));
    Console.WriteLine(Line("keeper <verb> --help", "a verb's own options"));
    if (!all)
        Console.WriteLine(Line("keeper help --all", "also the engine's own steps (load, track, rank, qm, db)"));
    Console.WriteLine();
    Console.WriteLine($"Keeper home: {KeeperHome.Resolve()}  (KEEPER_HOME moves it; one home per tenant)");
    return ExitCodes.Ok;

    static string Line(string command, string text) => $"  {command,-22} {text}";
}

static int Setup(CliArgs cli)
{
    if (cli.Help)
        return CliUsage.Print("""
            keeper setup - create the Keeper home: settings, tenant rules and queries, data; private to you

              keeper setup --tenant <name>           show what it would create; nothing changes
              keeper setup --tenant <name> --apply   create it; a second run only fills in what is missing
              then keeper db init --apply            create the store
              The home is KEEPER_HOME, else the keeper folder's home\ (git ignores home\ and demo\).
            """, asked: true);
    var apply = cli.Has("apply");
    var home = KeeperHome.Resolve();
    KeeperHome.EnsureOutsideCode(home, "The Keeper home");
    var settingsFile = Path.Combine(home, "settings", "settings.json");
    var exists = File.Exists(settingsFile);

    string tenant;
    if (exists)
    {
        tenant = SettingsLoader.Load(settingsFile).TenantName;
        if (cli.Get("tenant") is { } asked && !asked.Equals(tenant, StringComparison.Ordinal))
            throw new ArgumentException($"{settingsFile} belongs to tenant '{tenant}', not '{asked}'. Set KEEPER_HOME to a new folder for another tenant.");
    }
    else
    {
        tenant = cli.Require("tenant");
        if (!Regex.IsMatch(tenant, "^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$", RegexOptions.CultureInvariant))
            throw new ArgumentException("--tenant: letters, digits, space, dot, dash or underscore, at most 64.");
    }

    var folders = new[] { home, Path.Combine(home, "settings"), Path.Combine(home, "settings", "queries"),
                          Path.Combine(home, "settings", "rules"), Path.Combine(home, "data"), Path.Combine(home, "data", "imports") };
    // The three folders whose access matters; the rest are created inside them and inherit.
    var notPrivate = new[] { home, Path.Combine(home, "settings"), Path.Combine(home, "data") }
        .Where(f => Directory.Exists(f) && HomeSecurity.Problem(f) is not null).ToList();

    Console.WriteLine($"Keeper home: {home}");
    Console.WriteLine(exists ? $"  settings.json exists (tenant '{tenant}'); left as it is." : $"  writes {Path.Combine("settings", "settings.json")} for tenant '{tenant}'");
    foreach (var folder in folders.Where(f => !Directory.Exists(f)))
        Console.WriteLine(folder == home ? "  creates the home folder" : $"  creates {Path.GetRelativePath(home, folder)}{Path.DirectorySeparatorChar}");
    foreach (var folder in notPrivate)
        Console.WriteLine($"  makes {folder} private: {HomeSecurity.Problem(folder)}");
    if (!Directory.Exists(home) || notPrivate.Count > 0)
        Console.WriteLine(OperatingSystem.IsWindows()
            ? "  access: you, SYSTEM and Administrators only; inheritance off"
            : "  access: you only (mode 700)");
    var denyList = Path.Combine(home, "settings", "denylist.txt");
    if (!File.Exists(denyList))
        Console.WriteLine($"  writes {Path.Combine("settings", "denylist.txt")}: a template for build.ps1's leak check");
    Console.WriteLine("  then: keeper db init --apply (or migrate --apply when the store exists)");

    if (!apply)
    {
        Console.WriteLine("Dry run: nothing changed. Re-run with --apply.");
        return ExitCodes.Ok;
    }

    if (!Directory.Exists(home))
        HomeSecurity.MakePrivate(home);
    foreach (var folder in notPrivate)
        HomeSecurity.MakePrivate(folder);
    foreach (var folder in folders)
        Directory.CreateDirectory(folder);
    // Windows folders inherit the home's access list; Unix folders do not inherit a mode, so the two that
    // hold settings and data are made private after they exist.
    foreach (var folder in new[] { home, Path.Combine(home, "settings"), Path.Combine(home, "data") })
        if (HomeSecurity.Problem(folder) is not null)
            HomeSecurity.MakePrivate(folder);

    if (!exists)
    {
        var json = JsonSerializer.Serialize(new { tenantName = tenant, dataPath = "../data" }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(settingsFile + ".tmp", json + Environment.NewLine);
        File.Move(settingsFile + ".tmp", settingsFile);
        Console.WriteLine($"Wrote {settingsFile}");
    }
    if (!File.Exists(denyList))
    {
        File.WriteAllLines(denyList,
        [
            "# Leak check: one tenant identifier per line. build.ps1 stops if any appear in the repo.",
            "# Add your domains, tenant ID, hostname prefixes, IP prefixes and people's names.",
        ]);
        Console.WriteLine($"Wrote {denyList} - add your identifiers.");
    }

    var settingsArgs = new[] { "--settings", settingsFile };
    return Commands.Run("db", [File.Exists(Path.Combine(home, "data", "keeper.db")) ? "migrate" : "init", "--apply", .. settingsArgs]);
}
