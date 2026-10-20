using System.Text;
using Keeper.Common;
using Keeper.Home;
using Keeper.Rank;
using Keeper.Report;
using Keeper.Review;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-report <summary|security|expiring|changes|evidence>: reports for people who read rather than act.
// Read-only towards the store; it writes only the report (or the evidence pack) under data\reports\.
try
{
    var cli = new CliArgs(args, flags: ["pack"]);
    var name = cli.At(0) ?? throw new ArgumentException($"Which report? {string.Join(", ", Reports.Names)}, evidence.");
    var (_, paths) = KeeperContext.Load(cli);
    var now = DateTimeOffset.UtcNow;
    var format = cli.Get("format") ?? (name is "evidence" or "trends" ? "html" : "markdown");
    var extension = format switch { "html" => "html", "text" => "txt", _ => "md" };

    Document document;
    EvidenceSet? evidence = null;
    using (var connection = new Database(paths.Database).OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
        if (name == "evidence")
        {
            evidence = EvidenceBuilder.Build(connection, cli.Get("framework"), now);
            document = EvidenceBuilder.Document(evidence);
        }
        else
        {
            var days = int.TryParse(cli.Get("days"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var d) && d > 0 ? d : 90;
            document = Reports.Build(name, connection, now, cli.Get("since"), days);
        }
    }

    var text = Render.As(document, format);
    if (evidence is not null && cli.Has("pack"))
    {
        var label = string.Concat(evidence.Framework.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' ? c : '_'));
        var folder = cli.Get("out") ?? Path.Combine(paths.Reports, $"evidence-{label}-{Iso.Stamp(now)}");
        EvidencePack.Write(folder, evidence, text, extension, paths.DataDir);
        Console.WriteLine($"Evidence pack: {folder} ({evidence.Rows.Count} rows; SHA256SUMS.txt covers every file)");
        return ExitCodes.Ok;
    }

    var file = cli.Get("out") ?? Path.Combine(paths.Reports, $"{Iso.Date(now)}-{name}.{extension}");
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
    File.WriteAllText(file, text, new UTF8Encoding(false));
    Console.WriteLine($"Written to {file}");
    return ExitCodes.Ok;
}
catch (Exception ex) when (ex is SettingsException or ArgumentException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(Redactor.Clean(ex.Message));
    return ExitCodes.Failed;
}
