using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Queue;

public sealed record QueueReport(int Done, int Failed, int Skipped);

/// <summary>
/// The only writer of the store. Holds the spool lock, then moves each queued request through work\
/// to done\ or failed\, applying it in one transaction together with its audit row.
/// A file left in work\ by a crash is retried first; a request id already done is never applied twice.
/// </summary>
public sealed class QueueManager
{
    private readonly Database _db;
    private readonly string _spool;
    private readonly string _dataDir;
    private readonly IReadOnlyList<MigrationSet> _schemas;
    private readonly Dictionary<string, IRequestHandler> _handlers;
    private readonly TimeProvider _clock;

    /// <param name="schemas">Every schema the handlers write to; the store must be current for all of them.</param>
    public QueueManager(Database db, string spoolDir, string dataDir, IEnumerable<MigrationSet> schemas,
        IEnumerable<IRequestHandler> handlers, TimeProvider? clock = null)
    {
        _db = db;
        _spool = spoolDir;
        _dataDir = dataDir;
        _schemas = schemas.ToList();
        _clock = clock ?? TimeProvider.System;
        _handlers = new Dictionary<string, IRequestHandler>(StringComparer.Ordinal);
        foreach (var handler in handlers)
        {
            if (!_handlers.TryAdd(handler.Kind, handler))
                throw new ArgumentException($"Two handlers for '{handler.Kind}'.");
        }
    }

    public IReadOnlyCollection<string> Kinds => _handlers.Keys;

    public QueueReport DrainOnce()
    {
        Spool.EnsureFolders(_spool);
        using var writerLock = AcquireLock();
        using var connection = _db.OpenReadWrite();
        SchemaManager.EnsureCurrent(connection, _schemas);

        int done = 0, failed = 0, skipped = 0;
        void Count(Outcome outcome)
        {
            if (outcome == Outcome.Done) done++;
            else if (outcome == Outcome.Failed) failed++;
            else skipped++;
        }

        foreach (var file in Sorted(Spool.Work))
            Count(Process(connection, file));

        foreach (var file in Sorted(Spool.Queue))
        {
            var work = Path.Combine(_spool, Spool.Work, Path.GetFileName(file));
            File.Move(file, work);
            Count(Process(connection, work));
        }

        return new QueueReport(done, failed, skipped);
    }

    private enum Outcome { Done, Failed, Skipped }

    private Outcome Process(SqliteConnection connection, string workFile)
    {
        var text = File.ReadAllText(workFile);
        var sha = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        RequestEnvelope? request = null;

        try
        {
            request = RequestEnvelope.Parse(text);
            if (StateOf(connection, request.Id) == "done")
            {
                Finish(workFile, text, "done", "already applied");
                return Outcome.Skipped;
            }
            if (!_handlers.TryGetValue(request.Kind, out var handler))
                throw new RequestException($"Unknown request kind '{request.Kind}'.");

            using (var transaction = connection.BeginTransaction())
            {
                handler.Apply(new RequestContext(connection, transaction, request, _clock.GetUtcNow(), _dataDir));
                Audit(connection, transaction, request, sha, text, "done", null);
                transaction.Commit();
            }
            Finish(workFile, text, "done", null);
            return Outcome.Done;
        }
        catch (Exception ex) when (ex is RequestException or SqliteException or FormatException or JsonException)
        {
            var reason = Redactor.Clean(ex.Message);
            if (request is not null)
                Audit(connection, null, request, sha, text, "failed", reason);
            Finish(workFile, text, "failed", reason);
            return Outcome.Failed;
        }
    }

    private void Audit(SqliteConnection connection, SqliteTransaction? transaction, RequestEnvelope request,
        string sha, string text, string state, string? error)
    {
        Sql.Execute(connection,
            """
            INSERT INTO request (request_id, kind, submitted_by, submitted_at, reason, envelope_sha256, envelope,
                                 state, error, applied_at, applied_by)
            VALUES (:id, :kind, :submittedBy, :submittedAt, :reason, :sha, :envelope, :state, :error, :at, :by)
            ON CONFLICT (request_id) DO UPDATE SET
                state = excluded.state, error = excluded.error, applied_at = excluded.applied_at, applied_by = excluded.applied_by;
            """,
            transaction,
            (":id", request.Id), (":kind", request.Kind), (":submittedBy", request.SubmittedBy),
            (":submittedAt", Iso.Utc(request.SubmittedAt)), (":reason", request.Reason), (":sha", sha),
            (":envelope", text), (":state", state), (":error", error),
            (":at", Iso.Utc(_clock.GetUtcNow())), (":by", RequestWriter.CurrentUser()));
    }

    private static string? StateOf(SqliteConnection connection, string requestId) =>
        Sql.Scalar(connection, "SELECT state FROM request WHERE request_id = :id;", null, (":id", requestId)) as string;

    /// <summary>Writes the request with its result into done\ or failed\, then removes it from work\.</summary>
    private void Finish(string workFile, string text, string state, string? reason)
    {
        JsonNode? original;
        try
        {
            original = JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            original = JsonValue.Create(text);
        }

        var wrapped = new JsonObject
        {
            ["request"] = original,
            ["result"] = new JsonObject
            {
                ["state"] = state,
                ["reason"] = reason,
                ["at"] = Iso.Utc(_clock.GetUtcNow()),
                ["by"] = RequestWriter.CurrentUser(),
            },
        };

        var folder = state == "done" ? Spool.Done : Spool.Failed;
        File.WriteAllText(Path.Combine(_spool, folder, Path.GetFileName(workFile)), wrapped.ToJsonString());
        File.Delete(workFile);
    }

    private IEnumerable<string> Sorted(string folder) =>
        Directory.GetFiles(Path.Combine(_spool, folder), "*.json").Order(StringComparer.Ordinal);

    private FileStream AcquireLock()
    {
        try
        {
            return new FileStream(Path.Combine(_spool, "writer.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            throw new QueueBusyException(@"Another queue manager holds the spool lock (spool\writer.lock).");
        }
    }
}
