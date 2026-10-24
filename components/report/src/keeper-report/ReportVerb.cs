using System.Text;
using Keeper.Common;
using Keeper.Home;
using Keeper.Rank;
using Keeper.Report;
using Keeper.Review;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper report <summary|security|expiring|changes|evidence>: reports for people who read rather than act.
// Read-only towards the store; it writes only the report (or the evidence pack) under data\reports\.
public static class ReportVerb
{
    public static int Run(string[] args)
    {
        try
        {
            var cli = new CliArgs(args, flags: ["pack"]);
            if (cli.Help)
                return CliUsage.Print($"""
                    keeper report - reports for people who read rather than act (read-only; writes under data\reports\)

                      keeper report <{string.Join("|", Reports.Names)}> [--format markdown|html|text] [--out <file>]
                        assets also takes --format csv: one row per machine and device, for a spreadsheet
                        --days <n>        how far back trends and finance look (default 90)
                        --since <date>    changes since this date
                      keeper report target <name> [--format markdown|html|text] [--out <file>]
                                          point-in-time dossier for one server, computer, account, or entity
                      keeper report evidence [--framework <id>] [--pack [--out <folder>]]
                                          controls the rules cite and how each stands; --pack adds the scan evidence and SHA256SUMS.txt
                      keeper ui [--out <file>]  the interactive page: overview, findings with every object, correct, could not check
                    """, asked: true);
            var name = cli.At(0) ?? throw new ArgumentException($"Which report? {string.Join(", ", Reports.Names)}, target <name>, evidence, ui.");
            var (settings, paths) = KeeperContext.Load(cli);
            var now = DateTimeOffset.UtcNow;

            if (name == "ui")
            {
                string page;
                using (var connection = new Database(paths.Database).OpenReadOnly())
                {
                    SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
                    page = Ui.Build(connection, now, settings.TenantName);
                }
                var uiFile = cli.Get("out") ?? Path.Combine(paths.Reports, $"{Iso.Date(now)}-keeper.html");
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(uiFile))!);
                File.WriteAllText(uiFile, page, new UTF8Encoding(false));
                Console.WriteLine($"Written to {uiFile}");
                return ExitCodes.Ok;
            }
            var format = cli.Get("format") ?? (name is "evidence" or "trends" ? "html" : "markdown");
            var extension = format switch { "html" => "html", "text" => "txt", "csv" => "csv", _ => "md" };
            if (format == "csv" && name is not ("assets" or "inventory"))
                throw new ArgumentException("--format csv is for 'keeper report assets'. Other reports: markdown, html or text.");
            var targetArg = name is "target" or "object" ? (cli.At(1) ?? cli.Get("target")) : cli.Get("target");

            Document document;
            string? csv = null;
            EvidenceSet? evidence = null;
            using (var connection = new Database(paths.Database).OpenReadOnly())
            {
                SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
                if (name == "evidence")
                {
                    evidence = EvidenceBuilder.Build(connection, cli.Get("framework"), now);
                    document = EvidenceBuilder.Document(evidence);
                }
                else if (format == "csv")
                {
                    csv = Assets.Csv(connection, now);
                    document = new Document("", "", []);
                }
                else
                {
                    var days = int.TryParse(cli.Get("days"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var d) && d > 0 ? d : 90;
                    document = Reports.Build(name, connection, now, cli.Get("since"), days, targetArg);
                }
            }

            var text = csv ?? Render.As(document, format);
            if (evidence is not null && cli.Has("pack"))
            {
                var label = string.Concat(evidence.Framework.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' ? c : '_'));
                var folder = cli.Get("out") ?? Path.Combine(paths.Reports, $"evidence-{label}-{Iso.Stamp(now)}");
                EvidencePack.Write(folder, evidence, text, extension, paths.DataDir);
                Console.WriteLine($"Evidence pack: {folder} ({evidence.Rows.Count} rows; SHA256SUMS.txt covers every file)");
                return ExitCodes.Ok;
            }

            var reportSlug = name is "target" or "object" && !string.IsNullOrWhiteSpace(targetArg)
                ? $"target-{string.Concat(targetArg.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' ? c : '_'))}"
                : name;
            var file = cli.Get("out") ?? Path.Combine(paths.Reports, $"{Iso.Date(now)}-{reportSlug}.{extension}");
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
    }
}
