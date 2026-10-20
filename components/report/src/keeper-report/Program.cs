using System.Text;
using Keeper.Common;
using Keeper.Home;
using Keeper.Rank;
using Keeper.Report;
using Keeper.Review;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-report <summary|security|expiring|changes>: reports for people who read rather than act. Read-only.
try
{
    var cli = new CliArgs(args);
    var name = cli.At(0) ?? throw new ArgumentException($"Which report? {string.Join(", ", Reports.Names)}.");
    var (_, paths) = KeeperContext.Load(cli);
    var now = DateTimeOffset.UtcNow;

    Document document;
    using (var connection = new Database(paths.Database).OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
        document = Reports.Build(name, connection, now, cli.Get("since"));
    }

    var format = cli.Get("format") ?? "markdown";
    var extension = format switch { "html" => "html", "text" => "txt", _ => "md" };
    var file = cli.Get("out") ?? Path.Combine(paths.Reports, $"{Iso.Date(now)}-{name}.{extension}");
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
    File.WriteAllText(file, Render.As(document, format), new UTF8Encoding(false));
    Console.WriteLine($"Written to {file}");
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
