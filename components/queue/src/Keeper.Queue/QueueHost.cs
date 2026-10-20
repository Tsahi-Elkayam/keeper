using System.Text.Json;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Queue;

/// <summary>Where a queue manager works: its store, spool and data folder.</summary>
public sealed record QueueLocation(Database Db, string Spool, string DataDir);

/// <summary>
/// The command line of a queue manager binary. Whoever composes the binary supplies the handlers
/// and schemas - nothing is discovered or loaded at runtime.
/// </summary>
public static class QueueHost
{
    public static int Run(string name, string[] args, Func<CliArgs, QueueLocation> locate,
        IReadOnlyList<MigrationSet> schemas, IReadOnlyList<IRequestHandler> handlers)
    {
        try
        {
            var cli = new CliArgs(args);
            var location = locate(cli);
            return (cli.At(0) ?? "status") switch
            {
                "status" => Status(location),
                "run" => Drain(location, schemas, handlers),
                "submit" => Submit(location, cli, handlers),
                "kinds" => Kinds(handlers),
                _ => Usage(name),
            };
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException or RequestException)
        {
            Console.Error.WriteLine(Redactor.Clean(ex.Message));
            return ExitCodes.Usage;
        }
        catch (Exception ex) when (ex is StoreException or SqliteException or QueueBusyException or IOException)
        {
            Console.Error.WriteLine(Redactor.Clean(ex.Message));
            return ExitCodes.Failed;
        }
    }

    private static int Status(QueueLocation location)
    {
        Console.WriteLine($"Spool: {location.Spool}");
        foreach (var (folder, count) in Spool.Counts(location.Spool))
            Console.WriteLine($"  {folder,-7}{count}");
        return ExitCodes.Ok;
    }

    private static int Drain(QueueLocation location, IReadOnlyList<MigrationSet> schemas, IReadOnlyList<IRequestHandler> handlers)
    {
        var manager = new QueueManager(location.Db, location.Spool, location.DataDir, schemas, handlers);
        var report = manager.DrainOnce();
        Console.WriteLine($"Applied {report.Done}, failed {report.Failed}, already applied {report.Skipped}.");
        if (report.Failed > 0)
            Console.WriteLine($"Failed requests are in {Path.Combine(location.Spool, Spool.Failed)}, each with its reason.");
        return report.Failed > 0 ? ExitCodes.Failed : ExitCodes.Ok;
    }

    private static int Submit(QueueLocation location, CliArgs cli, IReadOnlyList<IRequestHandler> handlers)
    {
        var kind = cli.At(1) ?? throw new ArgumentException("submit needs a kind.");
        if (!handlers.Any(h => h.Kind == kind))
            throw new ArgumentException($"Unknown request kind '{kind}'. 'kinds' lists them.");
        var reason = cli.Get("reason") ?? throw new ArgumentException("--reason is required: say why, in 1 to 500 characters.");
        var payloadFile = cli.Require("payload");

        using var payload = JsonDocument.Parse(File.ReadAllText(payloadFile));
        var id = new RequestWriter(location.Spool).Submit(kind, reason, payload.RootElement.Clone());
        Console.WriteLine($"Queued {kind} request {id}. 'run' applies it.");
        return ExitCodes.Ok;
    }

    private static int Kinds(IReadOnlyList<IRequestHandler> handlers)
    {
        foreach (var kind in handlers.Select(h => h.Kind).Order(StringComparer.Ordinal))
            Console.WriteLine(kind);
        return ExitCodes.Ok;
    }

    private static int Usage(string name)
    {
        Console.Error.WriteLine($"""
            {name} - the queue manager, the only writer of the store

              {name} status                                         files waiting in each spool folder
              {name} run                                            apply every queued request once
              {name} submit <kind> --reason "<why>" --payload <f>   queue a request
              {name} kinds                                          the request kinds this build handles
            """);
        return ExitCodes.Usage;
    }
}
