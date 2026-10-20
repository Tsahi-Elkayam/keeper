using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Review.Load;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-load: submits every complete, verified scan folder the store has not loaded yet.
try
{
    var cli = new CliArgs(args, flags: ["dry-run"]);
    var (_, paths) = KeeperContext.Load(cli);
    using var connection = new Database(paths.Database).OpenReadOnly();
    SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema]);

    var writer = new RequestWriter(paths.Spool);
    int queued = 0, refused = 0;
    foreach (var candidate in RunLoader.Pending(connection, paths.Runs, paths.DataDir))
    {
        if (candidate.Problem is not null)
        {
            Console.Error.WriteLine($"Refused {candidate.RunId}: {Redactor.Clean(candidate.Problem)}");
            refused++;
        }
        else if (cli.Has("dry-run"))
        {
            Console.WriteLine($"Would load {candidate.RunId}");
        }
        else
        {
            RunLoader.Submit(writer, candidate);
            Console.WriteLine($"Queued {candidate.RunId}");
            queued++;
        }
    }
    Console.WriteLine($"{queued} scan(s) queued, {refused} refused. 'keeper qm run' applies them.");
    return refused > 0 ? ExitCodes.NoData : ExitCodes.Ok;
}
catch (Exception ex) when (ex is SettingsException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}
