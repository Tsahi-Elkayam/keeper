using System.Text.Json;
using Keeper.Queue;
using Keeper.Store;

namespace Keeper.Review.Tests;

public sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>A migrated store with the queue and review schemas in a fresh temp folder, deleted on dispose.</summary>
public sealed class TempStore : IDisposable
{
    public static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema];

    public TempStore()
    {
        Dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;
        Db = new Database(Path.Combine(DataDir, "keeper.db"));
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public string Dir { get; }
    public string DataDir => Path.Combine(Dir, "data");
    public string Spool => Path.Combine(DataDir, "spool");
    public string Runs => Path.Combine(DataDir, "runs");
    public string Builds => Path.Combine(DataDir, "builds");
    public Database Db { get; }

    public QueueManager Manager(TimeProvider? clock = null) =>
        new(Db, Spool, DataDir, Schemas, ReviewComponent.Handlers(), clock);

    public string Submit(string kind, string payloadJson, string reason = "test")
    {
        using var payload = JsonDocument.Parse(payloadJson);
        return new RequestWriter(Spool).Submit(kind, reason, payload.RootElement.Clone(), @"TEST\user");
    }

    /// <summary>Writes directly, for test setup only. Real writes go through the queue manager.</summary>
    public void Seed(string sql)
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection, sql);
    }

    public object? Scalar(string sql)
    {
        using var connection = Db.OpenReadOnly();
        return Sql.Scalar(connection, sql);
    }

    public List<Dictionary<string, object?>> Rows(string sql)
    {
        using var connection = Db.OpenReadOnly();
        return Sql.Rows(connection, sql);
    }

    /// <summary>Open (or other status) findings on one example system, all synthetic.</summary>
    public void SeedFindings(params (string Key, string Kind, string Severity, string Status, string Title)[] findings)
    {
        Seed("INSERT OR IGNORE INTO system (system_id, name, updated_by, updated_at) VALUES ('SYS1', 'Example system', 'test', '2026-10-01T00:00:00Z');");
        using var connection = Db.OpenReadWrite();
        foreach (var f in findings)
        {
            Sql.Execute(connection,
                """
                INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, kind, lens,
                                     category, severity, title, status, lifecycle, first_seen, last_seen)
                VALUES (:key, 'ex-main', 'example', 'SYS1', 'CHK-' || :key, 'CHK-' || :key, 'host', 'host1.example.org', :kind, 'both',
                        'HLT', :severity, :title, :status, CASE :status WHEN 'resolved' THEN 'resolved' ELSE 'open' END,
                        '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                """,
                null,
                (":key", f.Key), (":kind", f.Kind), (":severity", f.Severity), (":status", f.Status), (":title", f.Title));
        }
    }

    public void Dispose() => Directory.Delete(Dir, recursive: true);
}
