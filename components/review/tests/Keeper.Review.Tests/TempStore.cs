using Keeper.Store;

namespace Keeper.Testing;

/// <summary>A migrated store in a fresh temp folder, deleted on dispose.</summary>
public sealed class TempStore : IDisposable
{
    public TempStore()
    {
        Dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;
        Db = new KeeperDb(Path.Combine(Dir, "keeper.db"));
        using var connection = Db.OpenReadWrite(create: true);
        Migrations.Apply(connection, Migrations.All);
    }

    public string Dir { get; }

    public KeeperDb Db { get; }

    public string Spool => Path.Combine(Dir, "spool");

    /// <summary>Writes directly, for test setup only. Real writes go through keeper-qm.</summary>
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

    /// <summary>One system and the findings a test needs, all synthetic.</summary>
    public void SeedFindings(params (string Key, string Kind, string Severity, string Status, string Problem)[] findings)
    {
        Seed("INSERT OR IGNORE INTO system (system_id, name, source) VALUES ('SYS1', 'Example system', 'manual');");
        using var connection = Db.OpenReadWrite();
        foreach (var f in findings)
        {
            using var insert = Sql.Command(connection,
                """
                INSERT INTO finding (finding_key, system_id, check_id, target, kind, category, severity, problem,
                                     status, lifecycle, origin, source, first_seen, last_seen)
                VALUES (:key, 'SYS1', 'CHK-' || :key, 'host1.example.org', :kind, 'HLT', :severity, :problem,
                        :status, CASE :status WHEN 'resolved' THEN 'resolved' ELSE 'open' END, 'evaluate', 'test',
                        '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                """,
                null,
                (":key", f.Key), (":kind", f.Kind), (":severity", f.Severity), (":status", f.Status), (":problem", f.Problem));
            insert.ExecuteNonQuery();
        }
    }

    public void Dispose() => Directory.Delete(Dir, recursive: true);
}
