using System.Text.Json;
using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Review.Track;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-track: computes the register from the newest scans and submits it as one review.register request.
try
{
    var cli = new CliArgs(args, flags: ["dry-run"]);
    if (cli.Help)
        return CliUsage.Print("""
            keeper-track - turn the newest scans into the findings register: new, open, resolved, stale

              keeper track             compute and queue the register; 'keeper qm run' applies it
              keeper track --dry-run   show the counts and queue nothing
              --build <id>             the build id to record (default: now)
            """, asked: true);
    var (_, paths) = KeeperContext.Load(cli);
    var buildId = cli.Get("build") ?? Iso.Stamp(DateTimeOffset.UtcNow);

    RegisterFile register;
    using (var connection = new Database(paths.Database).OpenReadOnly())
    {
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema]);
        register = new Tracker(connection).Build(buildId);
    }

    Console.WriteLine(string.Join(", ", register.Counts.Select(c => $"{c.Key} {c.Value}")));
    if (cli.Has("dry-run"))
    {
        Console.WriteLine("Dry run: nothing submitted.");
        return ExitCodes.Ok;
    }

    var file = Path.Combine(paths.Builds, buildId, "register.json");
    Directory.CreateDirectory(Path.GetDirectoryName(file)!);
    File.WriteAllText(file + ".tmp", JsonSerializer.Serialize(register, JsonLines.Options));
    File.Move(file + ".tmp", file, overwrite: true);

    new RequestWriter(paths.Spool).Submit("review.register", $"Register for build {buildId}", new
    {
        file = Path.GetRelativePath(paths.DataDir, file).Replace('\\', '/'),
        sha256 = Hashing.Sha256File(file),
    });
    Console.WriteLine($"Queued the register for build {buildId}. 'keeper qm run' applies it.");
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
