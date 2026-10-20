using System.Data;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Microsoft.Data.SqlClient;

namespace Keeper.Runners.Sql;

/// <summary>
/// sql: one SELECT against SQL Server, per target instance. Read-only three ways: the text guard, a
/// read-only application intent, and a transaction that is always rolled back. TLS is mandatory and the
/// server certificate is checked, unless the integration sets the option tls: trust (and owns that).
/// Windows authentication by default; a SQL login when the integration's auth is basic.
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
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (SqlGuard.Problem(query.Text("text")) is { } problem)
            return RunnerResult.Failed(problem);
        var server = context.Target ?? context.Connection.Endpoint;
        if (string.IsNullOrWhiteSpace(server))
            return RunnerResult.Failed("sql needs a target instance");

        try
        {
            await using var connection = new SqlConnection(ConnectionString(server, query.Text("database") ?? "master", context));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
            try
            {
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
                        return RunnerResult.Partial(rows, $"stopped at {MaxRows} rows");
                }
                return RunnerResult.Ok(rows);
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
