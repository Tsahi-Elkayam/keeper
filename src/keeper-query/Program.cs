using Keeper.Core;
using Keeper.Query;
using Keeper.Store;
using Microsoft.Data.Sqlite;

// keeper-query: answers questions from the store. Opens it read-only, so it cannot change anything.
try
{
    var cli = new CliArgs(args);
    var (_, paths) = KeeperContext.Load(cli);
    var catalog = QueryCatalog.Load(paths.TenantQueries);

    if (cli.Positional.Count == 0 || cli.Positional[0] == "list")
        return List(catalog);

    if (!catalog.TryGetValue(cli.Positional[0], out var query))
    {
        Console.Error.WriteLine($"No question named '{cli.Positional[0]}'. 'keeper-query list' shows them.");
        return ExitCodes.Usage;
    }

    string[] reserved = ["settings", "format", "out"];
    var arguments = cli.Options
        .Where(o => !reserved.Contains(o.Key, StringComparer.OrdinalIgnoreCase))
        .ToDictionary(o => o.Key, o => o.Value, StringComparer.OrdinalIgnoreCase);

    using var connection = new KeeperDb(paths.Database).OpenReadOnly();
    KeeperDb.EnsureCurrentVersion(connection);
    Answer(connection, query, arguments, cli.Get("format") ?? "jsonl", cli.Get("out"));
    return ExitCodes.Ok;
}
catch (Exception ex) when (ex is SettingsException or ArgumentException or QueryException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}
catch (Exception ex) when (ex is StoreException or SqliteException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Failed;
}

static int List(IReadOnlyDictionary<string, NamedQuery> catalog)
{
    foreach (var query in catalog.Values.OrderBy(q => q.Name, StringComparer.Ordinal))
        Console.WriteLine($"{query.Name,-15}{query.Description}  [{QueryRunner.Describe(query)}]");
    return ExitCodes.Ok;
}

static void Answer(SqliteConnection connection, NamedQuery query, IReadOnlyDictionary<string, string?> arguments, string format, string? outFile)
{
    if (format == "table")
    {
        if (outFile is not null)
            throw new ArgumentException("--out writes JSON Lines; drop --format table.");
        QueryRunner.Run(connection, query, arguments, new TableWriter(Console.Out));
        return;
    }
    if (format != "jsonl")
        throw new ArgumentException("--format must be jsonl or table.");

    if (outFile is null)
    {
        // Raw UTF-8 to stdout: the console code page would mangle non-Latin text.
        using var stdout = Console.OpenStandardOutput();
        using var stdoutWriter = new JsonLinesWriter(stdout);
        QueryRunner.Run(connection, query, arguments, stdoutWriter);
        return;
    }

    // Written to .tmp and renamed, so the next stage never reads half a file.
    var tmp = outFile + ".tmp";
    using (var file = File.Create(tmp))
    using (var fileWriter = new JsonLinesWriter(file))
        QueryRunner.Run(connection, query, arguments, fileWriter);
    File.Move(tmp, outFile, overwrite: true);
}
