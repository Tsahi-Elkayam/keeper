using System.Text.Json;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Queue;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.load-run: { "folder": "runs/&lt;runId&gt;", "manifestSha256" }. Verifies the run folder - the
/// manifest hash given at submit time, every file's hash and every record - then loads it. A run
/// already loaded is a no-op. Old runs beyond the retention setting are dropped.
/// </summary>
public sealed class LoadRunHandler : IRequestHandler
{
    public const int DefaultRetention = 10;

    public string Kind => "review.load-run";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var relative = Payload.Required(payload, "folder");
        string folder;
        try
        {
            folder = PathGuard.Resolve(context.DataDir, relative);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new RequestException(ex.Message);
        }

        if (!RunFolder.IsComplete(folder))
            throw new RequestException($"{relative} is not a complete run folder.");
        if (!string.Equals(Hashing.Sha256File(Path.Combine(folder, RunFolder.Manifest)), Payload.Required(payload, "manifestSha256"), StringComparison.OrdinalIgnoreCase))
            throw new RequestException($"{relative}: run.json changed after it was submitted.");

        RunManifest manifest;
        try
        {
            manifest = RunFolder.Verify(folder);
        }
        catch (ContractException ex)
        {
            throw new RequestException(ex.Message);
        }

        if (context.Scalar("SELECT 1 FROM run WHERE run_id = :id;", (":id", manifest.RunId)) is not null)
            return;

        context.Execute(
            """
            INSERT INTO run (run_id, instance, system, identity, host, started_at, finished_at, status, folder, manifest, manifest_sha256, loaded_at)
            VALUES (:id, :instance, :system, :identity, :host, :started, :finished, :status, :folder, :manifest, :sha, :at);
            """,
            (":id", manifest.RunId), (":instance", manifest.Instance), (":system", manifest.System),
            (":identity", manifest.Identity), (":host", manifest.Host), (":started", manifest.StartedAt),
            (":finished", manifest.FinishedAt), (":status", manifest.Status), (":folder", relative),
            (":manifest", JsonSerializer.Serialize(manifest, JsonLines.Options)),
            (":sha", Payload.Required(payload, "manifestSha256").ToLowerInvariant()), (":at", context.NowText));

        LoadRows(context, folder, manifest.RunId);
        LoadCoverage(context, folder, manifest.RunId);
        LoadResults(context, folder, manifest.RunId);
        LoadFindings(context, folder, manifest.RunId);
        Prune(context, manifest);
    }

    private static void LoadRows(RequestContext context, string folder, string runId)
    {
        using var insert = context.Command(
            """
            INSERT OR REPLACE INTO row_seen (run_id, query, entity_type, entity_key, entity_name, target, attrs, observed_at)
            VALUES (:run, :query, :type, :key, :name, :target, :attrs, :at);
            """);
        var p = Parameters(insert, ":run", ":query", ":type", ":key", ":name", ":target", ":attrs", ":at");
        p[":run"].Value = runId;
        foreach (var row in Read<RowRecord>(folder, RunFolder.Rows))
        {
            p[":query"].Value = row.Query;
            p[":type"].Value = row.EntityType;
            p[":key"].Value = row.EntityKey;
            p[":name"].Value = (object?)row.EntityName ?? DBNull.Value;
            p[":target"].Value = (object?)row.Target ?? DBNull.Value;
            p[":attrs"].Value = row.Attrs.ToJsonString(JsonLines.Options);
            p[":at"].Value = row.ObservedAt;
            insert.ExecuteNonQuery();
        }
    }

    private static void LoadCoverage(RequestContext context, string folder, string runId)
    {
        using var insert = context.Command(
            """
            INSERT OR REPLACE INTO coverage (run_id, scope, item, state, reason, count, observed_at)
            VALUES (:run, :scope, :item, :state, :reason, :count, :at);
            """);
        var p = Parameters(insert, ":run", ":scope", ":item", ":state", ":reason", ":count", ":at");
        p[":run"].Value = runId;
        foreach (var coverage in Read<CoverageRecord>(folder, RunFolder.Coverage))
        {
            p[":scope"].Value = coverage.Scope;
            p[":item"].Value = coverage.Item;
            p[":state"].Value = coverage.State;
            p[":reason"].Value = (object?)coverage.Reason ?? DBNull.Value;
            p[":count"].Value = (object?)coverage.Count ?? DBNull.Value;
            p[":at"].Value = coverage.ObservedAt;
            insert.ExecuteNonQuery();
        }
    }

    private static void LoadResults(RequestContext context, string folder, string runId)
    {
        // A result replaces the stored one only if it is at least as new.
        using var upsert = context.Command(
            """
            INSERT INTO result (instance, rule_id, entity_type, entity_key, state, value, operand, why, ttl_minutes, at, run_id)
            VALUES (:instance, :rule, :type, :key, :state, :value, :operand, :why, :ttl, :at, :run)
            ON CONFLICT (instance, rule_id, entity_type, entity_key) DO UPDATE SET
                state = excluded.state, value = excluded.value, operand = excluded.operand, why = excluded.why,
                ttl_minutes = excluded.ttl_minutes, at = excluded.at, run_id = excluded.run_id
            WHERE excluded.at >= result.at;
            """);
        var p = Parameters(upsert, ":instance", ":rule", ":type", ":key", ":state", ":value", ":operand", ":why", ":ttl", ":at", ":run");
        p[":run"].Value = runId;
        foreach (var result in Read<ResultRecord>(folder, RunFolder.Results))
        {
            p[":instance"].Value = result.Instance;
            p[":rule"].Value = result.RuleId;
            p[":type"].Value = result.EntityType;
            p[":key"].Value = result.EntityKey;
            p[":state"].Value = result.State;
            p[":value"].Value = (object?)result.Value ?? DBNull.Value;
            p[":operand"].Value = (object?)result.Operand ?? DBNull.Value;
            p[":why"].Value = (object?)result.Why ?? DBNull.Value;
            p[":ttl"].Value = result.TtlMinutes;
            p[":at"].Value = result.At;
            upsert.ExecuteNonQuery();
        }
    }

    private static void LoadFindings(RequestContext context, string folder, string runId)
    {
        using var insert = context.Command("INSERT OR REPLACE INTO reported (run_id, finding_key, record) VALUES (:run, :key, :record);");
        var p = Parameters(insert, ":run", ":key", ":record");
        p[":run"].Value = runId;
        foreach (var record in RunFolder.ReadRaw(folder, RunFolder.Findings))
        {
            p[":key"].Value = record["findingKey"]!.GetValue<string>();
            p[":record"].Value = record.ToJsonString(JsonLines.Options);
            insert.ExecuteNonQuery();
        }
    }

    private static void Prune(RequestContext context, RunManifest manifest)
    {
        var keep = int.TryParse(context.Scalar("SELECT value FROM setting WHERE key = 'retention.runs';") as string, out var n) && n > 0
            ? n
            : DefaultRetention;
        // Old runs lose their bulk - rows, coverage, reported findings. The run row itself (with its manifest
        // hash) stays while a result still cites it, so evidence can always name the scan that proved it.
        const string old = """
            SELECT run_id FROM run WHERE instance = :instance AND system = :system AND run_id NOT IN (
                SELECT run_id FROM run WHERE instance = :instance AND system = :system ORDER BY started_at DESC LIMIT :keep)
            """;
        (string, object?)[] parameters = [(":instance", manifest.Instance), (":system", manifest.System), (":keep", keep)];
        context.Execute($"DELETE FROM row_seen WHERE run_id IN ({old});", parameters);
        context.Execute($"DELETE FROM coverage WHERE run_id IN ({old});", parameters);
        context.Execute($"DELETE FROM reported WHERE run_id IN ({old});", parameters);
        context.Execute($"DELETE FROM run WHERE run_id IN ({old}) AND NOT EXISTS (SELECT 1 FROM result WHERE result.run_id = run.run_id);", parameters);
    }

    private static IEnumerable<T> Read<T>(string folder, string file)
    {
        var path = Path.Combine(folder, file);
        return File.Exists(path) ? JsonLines.Read<T>(path) : [];
    }

    private static Dictionary<string, Microsoft.Data.Sqlite.SqliteParameter> Parameters(Microsoft.Data.Sqlite.SqliteCommand command, params string[] names)
    {
        var map = new Dictionary<string, Microsoft.Data.Sqlite.SqliteParameter>(StringComparer.Ordinal);
        foreach (var name in names)
            map[name] = command.Parameters.Add(name, Microsoft.Data.Sqlite.SqliteType.Text);
        return map;
    }
}
