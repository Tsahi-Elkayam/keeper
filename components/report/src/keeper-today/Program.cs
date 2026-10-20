using System.Text;
using Keeper.Common;
using Keeper.Home;
using Keeper.Rank;
using Keeper.Report;
using Keeper.Review;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-today: what to do today. Read-only.
try
{
    var cli = new CliArgs(args);
    var (_, paths) = KeeperContext.Load(cli);
    TodayReport report;
    using (var connection = new Database(paths.Database).OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
        report = TodayBuilder.Build(connection, DateTimeOffset.UtcNow);
    }

    var format = cli.Get("format") ?? (cli.Get("out") is { } o && o.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ? "html" : "text");
    var text = Render.As(TodayDocument.From(report), format);
    if (cli.Get("out") is { } file)
    {
        File.WriteAllText(file, text, new UTF8Encoding(false));
        Console.WriteLine($"Written to {file}");
    }
    else
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Write(text);
    }
    return ExitCodes.Ok;
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
