using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Runners.Files;

/// <summary>
/// store: rules over Keeper's own registers - licences, contracts, key dates, attestations - so the dates
/// no scan can see become findings too. Read-only connection, one SELECT, and never the tables that hold
/// secrets or the write audit. :now and :today are bound for date arithmetic.
/// </summary>
public sealed class StoreRunner : IRunner
{
    public static readonly IReadOnlyCollection<string> ForbiddenTables =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "integration_secret", "vault_key", "request", "schema_version", "sqlite_master", "sqlite_schema" };

    public string Protocol => "store";

    public bool PerTarget => false;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (SqlGuard.Problem(query.Text("text"), ForbiddenTables) is { } problem)
            yield return problem;
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (SqlGuard.Problem(query.Text("text"), ForbiddenTables) is { } problem)
            return Task.FromResult(RunnerResult.Failed(problem));
        if (context.StoreFile is null || !File.Exists(context.StoreFile))
            return Task.FromResult(RunnerResult.Failed("the store does not exist yet"));

        try
        {
            using var connection = new Database(context.StoreFile).OpenReadOnly();
            using var command = Sql.Command(connection, query.Text("text")!, null,
                (":now", RowValues.Iso(context.Now)), (":today", context.Now.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)));
            using var reader = command.ExecuteReader();
            var rows = new List<JsonObject>();
            while (reader.Read())
            {
                var row = new JsonObject();
                for (var i = 0; i < reader.FieldCount; i++)
                    row[reader.GetName(i)] = RowValues.From(reader.IsDBNull(i) ? null : reader.GetValue(i));
                rows.Add(row);
            }
            return Task.FromResult(RunnerResult.Ok(rows));
        }
        catch (SqliteException ex)
        {
            return Task.FromResult(RunnerResult.Failed(ex.Message));
        }
    }
}
