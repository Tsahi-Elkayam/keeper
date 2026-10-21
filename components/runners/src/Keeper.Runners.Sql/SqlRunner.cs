using System.Data;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Microsoft.Data.SqlClient;

namespace Keeper.Runners.Sql;

/// <summary>
/// sql: one SELECT against SQL Server, per target instance. Read-only three ways: the text guard, a
/// read-only application intent, and a transaction that is always rolled back. TLS is mandatory and the
/// server certificate is checked, unless the integration sets the option tls: trust (and owns that).
/// Windows authentication by default; a SQL login when the integration's auth is basic. databases: all (or
/// user: without master, model, msdb and tempdb) runs the same SELECT in every online database, each row
/// with its database; one the login cannot open makes the read partial.
/// </summary>
public sealed class SqlRunner : IRunner
{
    private const int MaxRows = 500_000;

    public string Protocol => "sql";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (SqlGuard.Problem(query.Text("text")) is { } problem)
            yield return problem;
        if (query.Text("database") is { } database && database.Any(c => !(char.IsLetterOrDigit(c) || c is '_' or '-' or ' ')))
            yield return "database must be a plain name";
        if (query.Text("databases") is { } every && every is not ("all" or "user"))
            yield return "databases must be all or user";
        else if (query.Text("databases") is not null && query.Text("database") is not null)
            yield return "database names one database; databases reads them all - not both";
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (SqlGuard.Problem(query.Text("text")) is { } problem)
            return RunnerResult.Failed(problem);
        var server = context.Target ?? context.Connection.Endpoint;
        if (string.IsNullOrWhiteSpace(server))
            return RunnerResult.Failed("sql needs a target instance");
        if (query.Text("databases") is { } every)
            return await Every(server, every == "user", query, context, cancellationToken).ConfigureAwait(false);
        return await ReadOne(server, query.Text("database") ?? "master", query, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The same SELECT in each online database, each row with its database; one the login cannot open is a blind spot.</summary>
    private static async Task<RunnerResult> Every(string server, bool userOnly, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        List<(string Name, string State, bool Access)> databases = [];
        bool seesAll;
        try
        {
            await using var connection = new SqlConnection(ConnectionString(server, "master", context));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            // Without VIEW ANY DATABASE, sys.databases lists only what the login owns: the rest would be missing unseen.
            await using (var sees = new SqlCommand("SELECT CAST(ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE'), 0) AS int);", connection) { CommandTimeout = 15 })
                seesAll = Convert.ToInt32(await sees.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) == 1;
            await using var list = new SqlCommand(
                "SELECT name, state_desc, CAST(ISNULL(HAS_DBACCESS(name), 0) AS int) FROM sys.databases" +
                (userOnly ? " WHERE database_id > 4" : "") + " ORDER BY name;", connection) { CommandTimeout = 30 };
            await using var reader = await list.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                databases.Add((reader.GetString(0), reader.GetString(1), reader.GetInt32(2) == 1));
        }
        catch (Exception ex) when (ex is SqlException or InvalidOperationException or TimeoutException)
        {
            return RunnerResult.Failed($"{server}: the databases could not be listed: {Keeper.Common.Redactor.Clean(ex.Message)}");
        }

        var rows = new List<JsonObject>();
        // Every database the rule should have read and did not is a blind spot: one not online (offline,
        // restoring, suspect), one the login cannot open, and - when the login cannot see them all - the rest.
        var problems = databases.Where(d => d.State != "ONLINE").Select(d => d.State == "RESTORING"
                ? $"{d.Name}: restoring (a standby or secondary copy is never read; scan the primary)"
                : $"{d.Name}: {d.State.ToLowerInvariant()}")
            .Concat(databases.Where(d => d.State == "ONLINE" && !d.Access).Select(d => $"{d.Name}: the login cannot open it"))
            .ToList();
        if (!seesAll)
            problems.Insert(0, "the login lacks VIEW ANY DATABASE, so databases it does not own are not even listed");
        if (databases.Count == 0)
            return RunnerResult.Partial([], problems.Count > 0 ? problems[0] : $"{server} listed no databases");
        var read = 0;
        foreach (var (name, _, _) in databases.Where(d => d.State == "ONLINE" && d.Access))
        {
            var one = await ReadOne(server, name, query, context, cancellationToken).ConfigureAwait(false);
            foreach (var row in one.Rows)
                row["database"] = name;
            rows.AddRange(one.Rows);
            if (one.State == "failed")
                problems.Add($"{name}: {one.Reason}");
            else
                read++;
            if (one.State == "partial")
                problems.Add($"{name}: {one.Reason}");
            if (rows.Count >= MaxRows)
                return RunnerResult.Partial(rows, $"stopped at {MaxRows} rows");
        }
        if (read == 0)
            return RunnerResult.Failed($"{server}: no database could be read: {string.Join("; ", problems.Take(3))}");
        return problems.Count == 0 ? RunnerResult.Ok(rows)
            : RunnerResult.Partial(rows, $"{read} of {databases.Count} databases read, not all of them whole: {string.Join("; ", problems.Take(3))}");
    }

    private static async Task<RunnerResult> ReadOne(string server, string database, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = new SqlConnection(ConnectionString(server, database, context));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
            try
            {
                string? missing;
                await using (var probe = new SqlCommand(SqlPermissions.Probe, connection, transaction) { CommandTimeout = 15 })
                await using (var answer = await probe.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    await answer.ReadAsync(cancellationToken).ConfigureAwait(false);
                    missing = SqlPermissions.Missing(query.Text("text")!, answer.IsDBNull(0) ? "the login" : answer.GetString(0),
                        !answer.IsDBNull(1) && answer.GetInt32(1) == 1, !answer.IsDBNull(2) && answer.GetInt32(2) == 1);
                }

                await using var command = new SqlCommand(query.Text("text"), connection, transaction)
                {
                    CommandTimeout = (int)Math.Max(5, context.Timeout.TotalSeconds),
                };
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                var rows = new List<JsonObject>();
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var row = new JsonObject { ["instance"] = server };
                    for (var i = 0; i < reader.FieldCount; i++)
                        row[reader.GetName(i)] = RowValues.From(reader.IsDBNull(i) ? null : reader.GetValue(i));
                    rows.Add(row);
                    if (rows.Count >= MaxRows)
                        return RunnerResult.Partial(rows, missing is null ? $"stopped at {MaxRows} rows" : $"stopped at {MaxRows} rows; {missing}");
                }
                // Missing a view permission is not an error to SQL Server: the views just show less.
                return missing is null ? RunnerResult.Ok(rows) : RunnerResult.Partial(rows, missing);
            }
            finally
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SqlException or InvalidOperationException or TimeoutException)
        {
            return RunnerResult.Failed($"{server}: {Keeper.Common.Redactor.Clean(ex.Message)}");
        }
    }

    public static string ConnectionString(string server, string database, RunnerContext context)
    {
        var builder = new SqlConnectionStringBuilder
        {
            DataSource = server,
            InitialCatalog = database,
            ApplicationIntent = ApplicationIntent.ReadOnly,
            ApplicationName = "Keeper",
            Encrypt = SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = context.Connection.Options["tls"]?.ToString() == "trust",
            ConnectTimeout = (int)Math.Clamp(context.Timeout.TotalSeconds, 5, 60),
            Pooling = false,
        };
        if (context.Connection.AuthKind == "basic")
        {
            builder.UserID = context.Connection.Identity ?? throw new InvalidOperationException("A SQL login needs the integration's identity (the login name).");
            builder.Password = context.Connection.Secret("password") ?? throw new InvalidOperationException("The SQL login's password is not set.");
        }
        else
        {
            builder.IntegratedSecurity = true;
        }
        return builder.ConnectionString;
    }
}
