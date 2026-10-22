using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keeper.Common;
using Keeper.Home;

// keeper <verb> ...: the one binary. Every verb runs in this process; a word that is not a verb is
// taken as a question (keeper broken == keeper query broken). setup and help live here.
var verbs = new (string Name, string What, Func<string[], int> Run)[]
{
    ("run", "the daily pipeline: scan, load, track, rank, then today's list", RunVerb.Run),
    ("today", "what to do today", TodayVerb.Run),
    ("scan", "scan one system through its integration (read-only towards it)", ScanVerb.Run),
    ("certs", "which certificates a server presents, valid or not, until when (you start it)", CertsVerb.Run),
    ("load", "queue the scans the store has not taken in", LoadVerb.Run),
    ("track", "turn the newest scans into the findings register", TrackVerb.Run),
    ("rank", "order the open findings into today's list", RankVerb.Run),
    ("qm", "the queue manager, the only writer of the store", QmVerb.Run),
    ("query", "answer a named question (keeper query list)", QueryVerb.Run),
    ("report", "posture, summary, security, expiring, changes, trends, finance and evidence reports", ReportVerb.Run),
    ("ui", "the interactive page: everything Keeper knows, in one file you open in a browser", args => ReportVerb.Run(["ui", .. args])),
    ("decide", "snooze, delegate, accept or disable a finding; set a threshold", DecideVerb.Run),
    ("system", "the systems Keeper knows and what maps to them", SystemVerb.Run),
    ("register", "vendors, contracts, licences, key dates, initiatives", RegisterVerb.Run),
    ("integration", "how Keeper reaches each system, and its encrypted secrets", IntegrationVerb.Run),
    ("config", "export and import the client configuration as files (systems, settings, overrides, registers, integrations)", ConfigVerb.Run),
    ("rules", "validate, list and explain rule files", RulesVerb.Run),
    ("push", "open tickets for delegated findings (plan, apply, sync)", PushVerb.Run),
    ("db", "the store: status, init, migrate, backup", DbVerb.Run),
};
foreach (var (name, _, run) in verbs)
    Commands.Add(name, run);

try
{
    var verb = args.Length > 0 ? args[0] : "help";
    var rest = args.Skip(1).ToArray();
    switch (verb)
    {
        case "help" or "--help" or "-h" or "/?":
            return Help(verbs);
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
catch (Exception ex) when (ex is SettingsException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}

static int Help((string Name, string What, Func<string[], int> Run)[] verbs)
{
    Console.WriteLine("""
        keeper - tells you what to do today

          keeper setup --tenant <name> [--apply]   create the Keeper home and the store (dry run without --apply)
        """);
    foreach (var (verb, what, _) in verbs)
        Console.WriteLine($"  keeper {verb,-12} {what}");
    Console.WriteLine("""

          keeper <question>      any question from 'keeper query list', e.g. keeper broken, keeper expiring
          keeper <verb> --help   the verb's own flags

        Every verb reads the Keeper home: KEEPER_HOME, else the keeper folder's home\ (git ignores it).
        --settings <file> points one command at another home's settings.json.
        """);
    return ExitCodes.Ok;
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
    Console.WriteLine(exists ? $"  settings.json exists (tenant '{tenant}'); left as it is." : $"  writes settings\\settings.json for tenant '{tenant}'");
    foreach (var folder in folders.Where(f => !Directory.Exists(f)))
        Console.WriteLine(folder == home ? "  creates the home folder" : $"  creates {Path.GetRelativePath(home, folder)}\\");
    foreach (var folder in notPrivate)
        Console.WriteLine($"  makes {folder} private: {HomeSecurity.Problem(folder)}");
    if (!Directory.Exists(home) || notPrivate.Count > 0)
        Console.WriteLine("  access: you, SYSTEM and Administrators only; inheritance off");
    var denyList = Path.Combine(home, "settings", "denylist.txt");
    if (!File.Exists(denyList))
        Console.WriteLine("  writes settings\\denylist.txt: a template for build.ps1's leak check");
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
