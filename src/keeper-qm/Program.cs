using System.Text.Json;
using Keeper.Core;
using Keeper.Queue;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-qm: the queue manager, the only writer of the store. Everything else submits requests.
try
{
    var cli = new CliArgs(args);
    var command = cli.Positional.Count > 0 ? cli.Positional[0] : "status";
    var (_, paths) = KeeperContext.Load(cli);

    return command switch
    {
        "status" => Status(paths),
        "run" => Run(paths),
        "submit" => Submit(paths, cli),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is SettingsException or ArgumentException or JsonException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or QueueBusyException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Failed;
}

static int Status(KeeperPaths paths)
{
    Console.WriteLine($"Spool: {paths.Spool}");
    foreach (var (folder, count) in Spool.Counts(paths.Spool))
        Console.WriteLine($"  {folder,-7}{count}");
    return ExitCodes.Ok;
}

static int Run(KeeperPaths paths)
{
    var manager = new QueueManager(new KeeperDb(paths.Database), paths.Spool, QueueManager.BuiltInHandlers());
    var report = manager.DrainOnce();
    Console.WriteLine($"Applied {report.Done}, failed {report.Failed}, already applied {report.Skipped}.");
    if (report.Failed > 0)
        Console.WriteLine($"Failed requests are in {Path.Combine(paths.Spool, Spool.Failed)}, each with its reason.");
    return report.Failed > 0 ? ExitCodes.Failed : ExitCodes.Ok;
}

static int Submit(KeeperPaths paths, CliArgs cli)
{
    if (cli.Positional.Count < 2)
        return Usage();

    var kind = cli.Positional[1];
    if (!QueueManager.BuiltInHandlers().Any(h => h.Kind == kind))
        throw new ArgumentException($"Unknown request kind '{kind}'. Known: {string.Join(", ", QueueManager.BuiltInHandlers().Select(h => h.Kind))}.");
    var reason = cli.Get("reason") ?? throw new ArgumentException("--reason is required: say why, in 1 to 500 characters.");
    var payloadFile = cli.Get("payload") ?? throw new ArgumentException("--payload <file.json> is required.");

    using var payload = JsonDocument.Parse(File.ReadAllText(payloadFile));
    var id = new RequestWriter(paths.Spool).Submit(kind, reason, payload.RootElement.Clone());
    Console.WriteLine($"Queued {kind} request {id}. 'keeper-qm run' applies it.");
    return ExitCodes.Ok;
}

static int Usage()
{
    Console.Error.WriteLine("""
        keeper-qm - the queue manager, the only writer of the store

          keeper-qm status                                         files waiting in each spool folder
          keeper-qm run                                            apply every queued request once
          keeper-qm submit <kind> --reason "<why>" --payload <f>   queue a request (kinds: override, attestation, triage)

          --settings <file>                                        default: settings\settings.json in the Keeper home (KEEPER_HOME)
        """);
    return ExitCodes.Usage;
}
