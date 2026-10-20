using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keeper.Common;
using Keeper.Home;

// keeper <verb> ...: the front door. Each verb is its own binary beside this one (keeper-<verb>);
// a word that is not a verb is taken as a question for keeper-query. setup and help live here.
var verbs = new Dictionary<string, string>(StringComparer.Ordinal)
{
    ["run"] = "the daily pipeline: scan, load, track, rank, then today's list",
    ["today"] = "what to do today",
    ["scan"] = "scan one system through its integration (read-only towards it)",
    ["certs"] = "which certificates a server presents, valid or not, until when (you start it)",
    ["load"] = "queue the scans the store has not taken in",
    ["track"] = "turn the newest scans into the findings register",
    ["rank"] = "order the open findings into today's list",
    ["qm"] = "the queue manager, the only writer of the store",
    ["query"] = "answer a named question (keeper query list)",
    ["report"] = "summary, security, expiring, changes, trends, finance and evidence reports",
    ["decide"] = "snooze, delegate, accept or disable a finding; set a threshold",
    ["system"] = "the systems Keeper knows and what maps to them",
    ["register"] = "vendors, contracts, licences, key dates, initiatives",
    ["integration"] = "how Keeper reaches each system, and its encrypted secrets",
    ["rules"] = "validate, list and explain rule files",
    ["push"] = "open tickets for delegated findings (plan, apply, sync)",
    ["db"] = "the store: status, init, migrate, backup",
};

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
    if (Siblings.Exists("keeper-" + verb))
        return Siblings.Run("keeper-" + verb, rest);
    if (Siblings.Exists("keeper-query"))
        return Siblings.Run("keeper-query", args);   // a question: keeper broken == keeper query broken

    Console.Error.WriteLine($"No keeper-{verb} beside keeper in {Siblings.Folder}. 'keeper help' lists the verbs.");
    return ExitCodes.Usage;
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

static int Help(Dictionary<string, string> verbs)
{
    Console.WriteLine("""
        keeper - tells you what to do today

          keeper setup --tenant <name> [--apply]   create the Keeper home and the store (dry run without --apply)
        """);
    foreach (var (verb, what) in verbs)
    {
        var present = Siblings.Exists("keeper-" + verb) ? "" : "  (not in this build)";
        Console.WriteLine($"  keeper {verb,-12} {what}{present}");
    }
    Console.WriteLine("""

          keeper <question>      any question from 'keeper query list', e.g. keeper broken, keeper expiring

        Every binary reads the Keeper home: KEEPER_HOME, else the per-user application data folder.
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
              The home is KEEPER_HOME, else the per-user application data folder, and never inside the code folder.
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

    if (!Siblings.Exists("keeper-db"))
    {
        Console.WriteLine("keeper-db is not in this build: run 'keeper-db init --apply' from a full build.");
        return ExitCodes.NoData;
    }
    var settingsArgs = new[] { "--settings", settingsFile };
    return Siblings.Run("keeper-db", [File.Exists(Path.Combine(home, "data", "keeper.db")) ? "migrate" : "init", "--apply", .. settingsArgs]);
}
