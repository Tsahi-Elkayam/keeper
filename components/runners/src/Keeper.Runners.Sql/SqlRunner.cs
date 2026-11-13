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
/// A scan signs in once per instance: the session holds one open connection to master and moves between
/// databases on it with ChangeDatabase, so a <c>databases:</c> read is one logon, not one per database.
/// </summary>
public sealed class SqlRunner : ISessionRunner
{
    private const int MaxRows = 500_000;

    public string Protocol => "sql";

    public bool PerTarget => true;

    public string SessionFamily => "sql";

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

    /// <summary>One connection to the instance, signed in once. Pooling stays off (credential isolation): this session is the reuse.</summary>
    public sealed class SqlSession(string server, SqlConnection connection) : IRunnerSession
    {
        internal string Server { get; } = server;

        internal SqlConnection Connection { get; } = connection;

        /// <summary>Connections to databases that cannot be switched to on one connection (Azure SQL Database), by name.</summary>
        internal Dictionary<string, SqlConnection> Separate { get; } = new(StringComparer.OrdinalIgnoreCase);

        public async ValueTask DisposeAsync()
        {
            foreach (var other in Separate.Values)
                await other.DisposeAsync().ConfigureAwait(false);
            await Connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Runs one query on its own connection: opens a session, runs, closes. A scan uses the session overload instead.</summary>
    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (SqlGuard.Problem(query.Text("text")) is { } problem)
            return RunnerResult.Failed(problem);
        if (string.IsNullOrWhiteSpace(context.Target ?? context.Connection.Endpoint))
            return RunnerResult.Failed("sql needs a target instance");
        IRunnerSession session;
        try
        {
            session = await OpenAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (RunnerFailureException ex)
        {
            return RunnerResult.Failed(ex.Message, ex.Kind);
        }
        await using (session.ConfigureAwait(false))
            return await RunAsync(session, query, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs in to the instance once, to master. A refused login throws with kind Refused and is not tried again.</summary>
    public async Task<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken cancellationToken)
    {
        var server = context.Target ?? context.Connection.Endpoint;
        if (string.IsNullOrWhiteSpace(server))
            throw new RunnerFailureException("sql needs a target instance", FailureKind.Error);
        SqlConnection? connection = null;
        try
        {
            connection = new SqlConnection(ConnectionString(server, "master", context));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            return new SqlSession(server, connection);
        }
        catch (Exception ex) when (ex is SqlException or InvalidOperationException or TimeoutException)
        {
            if (connection is not null)
                await connection.DisposeAsync().ConfigureAwait(false);
            throw new RunnerFailureException($"{server}: {Keeper.Common.Redactor.Clean(ex.Message)}", ClassifyException(ex), ex);
        }
    }

    public async Task<RunnerResult> RunAsync(IRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (SqlGuard.Problem(query.Text("text")) is { } problem)
            return RunnerResult.Failed(problem);
        var open = (SqlSession)session;
        var steps = new Steps(context, cancellationToken);
        if (query.Text("databases") is { } every)
            return await Every(open, every == "user", query, context, steps, cancellationToken).ConfigureAwait(false);
        return await ReadOne(open, query.Text("database") ?? "master", query, context, steps, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Paces the requests of one query: the first is covered by the scanner's wait before the query, each further one
    /// (the database list, a switch of database, the permission probe, the SELECT) waits its turn.
    /// </summary>
    private sealed class Steps(RunnerContext context, CancellationToken cancellationToken)
    {
        private bool _first = true;

        public async Task NextAsync()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_first)
                await context.Pace.WaitAsync(cancellationToken).ConfigureAwait(false);
            _first = false;
        }
    }

    /// <summary>The same SELECT in each online database, each row with its database; one the login cannot open is a blind spot.</summary>
    private static async Task<RunnerResult> Every(SqlSession session, bool userOnly, QuerySpec query, RunnerContext context, Steps steps, CancellationToken cancellationToken)
    {
        var server = session.Server;
        List<(string Name, string State, bool Access)> databases = [];
        bool seesAll;
        try
        {
            var connection = await Ready(session, "master", context, steps, cancellationToken).ConfigureAwait(false);
            // Without VIEW ANY DATABASE, sys.databases lists only what the login owns: the rest would be missing unseen.
            await steps.NextAsync().ConfigureAwait(false);
            await using (var sees = new SqlCommand("SELECT CAST(ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE'), 0) AS int);", connection) { CommandTimeout = 15 })
                seesAll = Convert.ToInt32(await sees.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) == 1;
            await steps.NextAsync().ConfigureAwait(false);
            await using var list = new SqlCommand(
                "SELECT name, state_desc, CAST(ISNULL(HAS_DBACCESS(name), 0) AS int) FROM sys.databases" +
                (userOnly ? " WHERE database_id > 4" : "") + " ORDER BY name;", connection) { CommandTimeout = 30 };
            await using var reader = await list.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                databases.Add((reader.GetString(0), reader.GetString(1), reader.GetInt32(2) == 1));
        }
        catch (Exception ex) when (ex is SqlException or InvalidOperationException or TimeoutException)
        {
            return RunnerResult.Failed($"{server}: the databases could not be listed: {Keeper.Common.Redactor.Clean(ex.Message)}", ClassifyException(ex));
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
        FailureKind? pushedBack = null;
        foreach (var (name, _, _) in databases.Where(d => d.State == "ONLINE" && d.Access))
        {
            var one = await ReadOne(session, name, query, context, steps, cancellationToken).ConfigureAwait(false);
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
            // A server that pushes back, or that stopped answering, is not asked for the rest: the scan slows or stops it.
            if (one.State == "failed" && one.Failure is FailureKind.Throttled or FailureKind.Timeout or FailureKind.Unreachable or FailureKind.Refused)
            {
                pushedBack = one.Failure;
                context.Pace.Signal(one.Failure);
                problems.Add("the remaining databases were not read");
                break;
            }
        }
        if (read == 0)
            return RunnerResult.Failed($"{server}: no database could be read: {string.Join("; ", problems.Take(3))}", pushedBack ?? FailureKind.Error);
        return problems.Count == 0 ? RunnerResult.Ok(rows)
            : RunnerResult.Partial(rows, $"{read} of {databases.Count} databases read, not all of them whole: {string.Join("; ", problems.Take(3))}")
                with { Failure = pushedBack is FailureKind.Refused ? FailureKind.Refused : FailureKind.None };
    }

    /// <summary>
    /// The session's connection, moved to <paramref name="database"/>. A connection that broke is signed in again once.
    /// Azure SQL Database cannot switch databases on one connection (error 40508 and kin): a database that refuses the
    /// switch that way gets its own connection, kept for the rest of the scan.
    /// </summary>
    private static async Task<SqlConnection> Ready(SqlSession session, string database, RunnerContext context, Steps steps, CancellationToken cancellationToken)
    {
        if (session.Separate.TryGetValue(database, out var separate) && separate.State == ConnectionState.Open)
            return separate;
        var connection = session.Connection;
        if (connection.State != ConnectionState.Open)
        {
            connection.Close();
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        if (string.Equals(connection.Database, database, StringComparison.OrdinalIgnoreCase))
            return connection;
        await steps.NextAsync().ConfigureAwait(false);
        try
        {
            await connection.ChangeDatabaseAsync(database, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch (SqlException ex) when (ex.Number is 40508 or 40515)
        {
            var other = new SqlConnection(ConnectionString(session.Server, database, context));
            try
            {
                await other.OpenAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await other.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            session.Separate[database] = other;
            return other;
        }
    }

    private static async Task<RunnerResult> ReadOne(SqlSession session, string database, QuerySpec query, RunnerContext context, Steps steps, CancellationToken cancellationToken)
    {
        var server = session.Server;
        try
        {
            var connection = await Ready(session, database, context, steps, cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
            try
            {
                string? missing;
                await steps.NextAsync().ConfigureAwait(false);
                await using (var probe = new SqlCommand(SqlPermissions.Probe, connection, transaction) { CommandTimeout = 15 })
                await using (var answer = await probe.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    await answer.ReadAsync(cancellationToken).ConfigureAwait(false);
                    missing = SqlPermissions.Missing(query.Text("text")!, answer.IsDBNull(0) ? "the login" : answer.GetString(0),
                        !answer.IsDBNull(1) && answer.GetInt32(1) == 1, !answer.IsDBNull(2) && answer.GetInt32(2) == 1);
                }

                await steps.NextAsync().ConfigureAwait(false);
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
            // The switch to this database failed (it cannot be opened, or was dropped): reported for this database, the connection stays usable.
            return RunnerResult.Failed($"{server}: {Keeper.Common.Redactor.Clean(ex.Message)}", ClassifyException(ex));
        }
    }

    /// <summary>The kind of a failed SQL call, from its exception.</summary>
    public static FailureKind ClassifyException(Exception ex) => ex switch
    {
        SqlException sql => Classify(sql.Number),
        _ => Failures.Classify(ex),
    };

    /// <summary>
    /// The kind of a SQL Server error number. Login failed (18456), locked out (18486), password expired or must change
    /// (18487, 18488) and disabled (18470) are the credential itself. 916, 4060, 229 and 297 are a login that is in but
    /// may not use this database or object. 10928, 10929, 40501 and 40613 are limits and busy servers; -2 and 258 are timeouts;
    /// 53, 40, -1, 2 and 11001 are no server there.
    /// </summary>
    public static FailureKind Classify(int number) => number switch
    {
        18456 or 18486 or 18487 or 18488 or 18470 => FailureKind.Refused,
        916 or 4060 or 229 or 297 => FailureKind.Denied,
        -2 or 258 => FailureKind.Timeout,
        10928 or 10929 or 40501 or 40613 => FailureKind.Throttled,
        53 or 40 or -1 or 2 or 11001 => FailureKind.Unreachable,
        _ => FailureKind.Error,
    };

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
