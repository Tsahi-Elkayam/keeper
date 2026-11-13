using System.Text.Json;
using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper rank: orders the open findings into today's list and submits it as one rank.register request.
public static class RankVerb
{
    public static int Run(string[] args)
    {
        try
        {
            var cli = new CliArgs(args, flags: ["dry-run"]);
            if (cli.Help)
                return CliUsage.Print("""
                    keeper rank - order the open findings into today's list, within the daily minutes (rank.daily-minutes)

                      keeper rank              rank and queue the result; 'keeper qm run' applies it
                      keeper rank --dry-run    show the counts and queue nothing
                      --build <id>             the build id to record (default: now)
                    """, asked: true);
            var (_, paths) = KeeperContext.Load(cli);
            var buildId = cli.Get("build") ?? Iso.Stamp(DateTimeOffset.UtcNow);

            RankingFile ranking;
            using (var connection = new Database(paths.Database).OpenReadOnly())
            {
                SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema, Ranker.Schema]);
                ranking = new Ranker(connection).Rank(buildId);
            }

            var today = ranking.Items.Where(i => i.List == "today").ToList();
            Console.WriteLine($"Today: {today.Count} items, about {today.Sum(i => i.Minutes)} of {ranking.BudgetMinutes} minutes. " +
                              $"Waiting: {ranking.Items.Count(i => i.List == "waiting")}. Later: {ranking.Items.Count(i => i.List == "later")}. " +
                              $"Snoozed: {ranking.Items.Count(i => i.List == "snoozed")}.");
            if (cli.Has("dry-run"))
                return ExitCodes.Ok;

            var file = Path.Combine(paths.Builds, buildId, "ranking.json");
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file + ".tmp", JsonSerializer.Serialize(ranking, JsonLines.Options));
            File.Move(file + ".tmp", file, overwrite: true);
            new RequestWriter(paths.Spool).Submit("rank.register", $"Ranking for build {buildId}", new
            {
                file = Path.GetRelativePath(paths.DataDir, file).Replace('\\', '/'),
                sha256 = Hashing.Sha256File(file),
            });
            Console.WriteLine("Queued. 'keeper qm run' applies it; 'keeper today' shows it.");
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
    }
}
