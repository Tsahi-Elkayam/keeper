using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Review.Cli;

/// <summary>
/// What the review CLIs share: they read the store to check what they are told, then queue one request
/// for the queue manager - they never write the store themselves.
/// </summary>
public sealed class RequestCli
{
    private RequestCli(CliArgs cli, KeeperPaths paths)
    {
        Cli = cli;
        Paths = paths;
    }

    public CliArgs Cli { get; }

    public KeeperPaths Paths { get; }

    /// <param name="usage">Prints the binary's usage; true when it was asked for, false when the arguments were wrong.</param>
    public static int Run(string name, string[] args, string[] flags, Func<RequestCli, int> body, Func<bool, int> usage)
    {
        try
        {
            var cli = new CliArgs(args, flags: [.. flags, "now"]);
            if (cli.Help || cli.At(0) is "help")
                return usage(true);
            if (cli.At(0) is null)
                return usage(false);
            var (_, paths) = KeeperContext.Load(cli);
            return body(new RequestCli(cli, paths));
        }
        catch (Exception ex) when (ex is SettingsException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return ExitCodes.Usage;
        }
        catch (Exception ex) when (ex is StoreException or SqliteException or IOException)
        {
            Console.Error.WriteLine($"{name}: {Redactor.Clean(ex.Message)}");
            return ExitCodes.Failed;
        }
    }

    /// <summary>Opens the store read-only, checked against the review schema.</summary>
    public SqliteConnection Read()
    {
        var connection = new Database(Paths.Database).OpenReadOnly();
        SchemaManager.EnsureCurrent(connection, [ReviewComponent.Schema]);
        return connection;
    }

    public string Reason =>
        Cli.Get("reason") is { Length: > 0 and <= 500 } reason
            ? reason
            : throw new ArgumentException("--reason is required: say why, in 1 to 500 characters. It is kept with the change.");

    public string Positional(int index, string what) =>
        Cli.At(index) ?? throw new ArgumentException($"Missing {what}.");

    /// <summary>Queues the request; with --now also runs the queue manager.</summary>
    public int Submit<T>(string kind, T payload, string done) where T : notnull
    {
        var reason = Reason;
        var id = new RequestWriter(Paths.Spool).Submit(kind, reason, payload);
        Console.WriteLine($"Queued {kind} {id[..8]}: {done}");
        if (!Cli.Has("now"))
        {
            Console.WriteLine("'keeper qm run' applies it (or add --now).");
            return ExitCodes.Ok;
        }
        string[] qmArgs = Cli.Get("settings") is { } settings ? ["run", "--settings", Path.GetFullPath(settings)] : ["run"];
        return Commands.Run("qm", qmArgs);
    }

    /// <summary>A finding by its key or a unique prefix of at least 6 characters.</summary>
    public static FindingRef Finding(SqliteConnection connection, string prefix)
    {
        var key = prefix.ToLowerInvariant();
        if (key.Length < 6 || key.Any(c => !char.IsAsciiHexDigitLower(c)))
            throw new ArgumentException($"'{prefix}' is not a finding key: give at least 6 of its hex characters ('keeper broken' shows them).");

        var rows = Sql.Rows(connection,
            "SELECT finding_key, check_id, target, title, status FROM finding WHERE substr(finding_key, 1, :n) = :p LIMIT 3;",
            null, (":n", key.Length), (":p", key));
        return rows.Count switch
        {
            1 => new FindingRef((string)rows[0]["finding_key"]!, (string)rows[0]["check_id"]!, (string)rows[0]["target"]!,
                (string)rows[0]["title"]!, (string)rows[0]["status"]!),
            0 => throw new ArgumentException($"No finding starts with {key}."),
            _ => throw new ArgumentException($"More than one finding starts with {key}; give more characters."),
        };
    }

    /// <summary>A date as yyyy-MM-dd, or a duration from today (3d, 2w).</summary>
    public static string Date(string value, string what)
    {
        if (DateOnly.TryParseExact(value, "yyyy-MM-dd", out var date))
            return date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        if (Durations.TryParse(value, out var span) && span > TimeSpan.Zero)
            return Iso.Date(DateTimeOffset.UtcNow + span);
        throw new ArgumentException($"{what}: give a date (yyyy-MM-dd) or a duration (3d, 2w).");
    }
}

public sealed record FindingRef(string Key, string CheckId, string Target, string Title, string Status);
