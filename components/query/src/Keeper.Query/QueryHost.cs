using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Query;

/// <summary>Where a query binary reads: the store, the schemas it must match, and the tenant's own questions.</summary>
public sealed record QueryLocation(Database Db, IReadOnlyList<MigrationSet> Schemas, string? TenantQueries);

/// <summary>
/// The command line of a question-answering binary. Opens the store read-only, so it cannot change
/// anything; every argument is bound as a parameter.
/// </summary>
public static class QueryHost
{
    private static readonly string[] Reserved = ["settings", "format", "out"];

    public static int Run(string name, string[] args, Func<CliArgs, QueryLocation> locate, IReadOnlyList<QueryPack> packs)
    {
        try
        {
            var cli = new CliArgs(args);
            var location = locate(cli);
            var catalog = QueryCatalog.Load(packs, location.TenantQueries);

            var question = cli.At(0);
            if (question is null or "list")
                return List(catalog);

            if (!catalog.TryGetValue(question, out var query))
            {
                Console.Error.WriteLine($"No question named '{question}'. '{name} list' shows them.");
                return ExitCodes.Usage;
            }
            if (cli.Help)
            {
                Console.WriteLine($"{query.Name}: {query.Description}\n  parameters: {QueryRunner.Describe(query)}\n  --format table|jsonl   --out <file> (jsonl)");
                return ExitCodes.Ok;
            }

            var arguments = cli.Options
                .Where(o => !Reserved.Contains(o.Key, StringComparer.OrdinalIgnoreCase))
                .ToDictionary(o => o.Key, o => o.Value, StringComparer.OrdinalIgnoreCase);

            using var connection = location.Db.OpenReadOnly();
            SchemaManager.EnsureCurrent(connection, location.Schemas);
            Answer(connection, query, arguments, cli.Get("format") ?? "table", cli.Get("out"));
            return ExitCodes.Ok;
        }
        catch (Exception ex) when (ex is ArgumentException or QueryException)
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

    private static int List(IReadOnlyDictionary<string, NamedQuery> catalog)
    {
        foreach (var query in catalog.Values.OrderBy(q => q.Name, StringComparer.Ordinal))
            Console.WriteLine($"{query.Name,-18}{query.Description}  [{QueryRunner.Describe(query)}]");
        return ExitCodes.Ok;
    }

    private static void Answer(SqliteConnection connection, NamedQuery query, IReadOnlyDictionary<string, string?> arguments,
        string format, string? outFile)
    {
        if (format == "table")
        {
            if (outFile is not null)
                throw new ArgumentException("--out writes JSON Lines; use --format jsonl.");
            QueryRunner.Run(connection, query, arguments, new TableWriter(Console.Out));
            return;
        }
        if (format != "jsonl")
            throw new ArgumentException("--format must be table or jsonl.");

        if (outFile is null)
        {
            // Raw UTF-8 to stdout: the console code page would mangle non-Latin text.
            using var stdout = Console.OpenStandardOutput();
            using var stdoutWriter = new JsonLinesRowWriter(stdout);
            QueryRunner.Run(connection, query, arguments, stdoutWriter);
            return;
        }

        // Written to .tmp and renamed, so the next stage never reads half a file.
        var tmp = outFile + ".tmp";
        using (var file = File.Create(tmp))
        using (var fileWriter = new JsonLinesRowWriter(file))
            QueryRunner.Run(connection, query, arguments, fileWriter);
        File.Move(tmp, outFile, overwrite: true);
    }
}
