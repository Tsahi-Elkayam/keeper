using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class PostureTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public PostureTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    private string Text()
    {
        using var connection = Db.OpenReadOnly();
        return Render.As(Reports.Build("posture", connection, DateTimeOffset.UtcNow, null), "text");
    }

    [Fact]
    public void An_empty_store_claims_nothing_is_correct()
    {
        var text = Text();

        Assert.Contains("No scan has results yet: nothing is known to be correct, wrong or broken.", text, StringComparison.Ordinal);
        Assert.Contains("Nothing yet: a check counts as correct only when it passed everywhere", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_three_answers_and_what_was_not_checked()
    {
        using (var connection = Db.OpenReadWrite())
        {
            Sql.Execute(connection,
                """
                INSERT INTO system (system_id, name, updated_by, updated_at) VALUES ('SYS1', 'Example system', 'test', '2026-10-01T00:00:00Z');
                INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, source_file, loaded_at)
                VALUES ('EX-GOOD', 'example', 'Remote desktop without network level authentication', 'misconfigured', 'security', 'AUT', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                       ('EX-DOWN', 'example', 'Backup service stopped', 'broken', 'maintenance', 'BCK', 'critical', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                       ('EX-UNREAD', 'example', 'Audit policy incomplete', 'missing', 'security', 'MON', 'medium', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z');
                INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
                VALUES ('R1', 'ex-main', 'example', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'ok', 'r1', '{}', '2026-10-01T00:00:00Z');
                INSERT INTO coverage (run_id, scope, item, state, reason, count, observed_at)
                VALUES ('R1', 'rule', 'EX-GOOD', 'ok', NULL, 3, '2026-10-01T00:00:00Z'),
                       ('R1', 'rule', 'EX-DOWN', 'ok', NULL, 3, '2026-10-01T00:00:00Z'),
                       ('R1', 'rule', 'EX-UNREAD', 'failed', 'access denied', 0, '2026-10-01T00:00:00Z');
                INSERT INTO result (instance, rule_id, entity_type, entity_key, state, ttl_minutes, at, run_id)
                VALUES ('ex-main', 'EX-GOOD', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R1'),
                       ('ex-main', 'EX-GOOD', 'host', 'h2', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R1'),
                       ('ex-main', 'EX-DOWN', 'host', 'h1', 'fail', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R1'),
                       ('ex-main', 'EX-UNREAD', 'host', '-', 'unknown', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R1');
                INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, entity_name, kind, lens,
                                     category, severity, title, evidence, why, fix, status, lifecycle, first_seen, last_seen)
                VALUES ('k1', 'ex-main', 'example', 'SYS1', 'EX-DOWN', 'EX-DOWN', 'host', 'h1', 'h1.example.org', 'broken', 'maintenance',
                        'BCK', 'critical', 'Backup service stopped', 'service state Stopped since 3 days', 'No backups run while it is stopped.',
                        'Start the service and find why it stopped.', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z'),
                       ('k2', 'ex-main', 'example', 'SYS1', 'EX-GPO', 'EX-GPO', 'gpo-setting', '{11111111-2222-3333-4444-555555555555}|machine|x', NULL, 'misconfigured', 'security',
                        'CFG', 'high', 'GPO weakens something', '{11111111-2222-3333-4444-555555555555} (machine): x = 1', NULL, NULL,
                        'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                -- SYSVOL knows a GPO by its GUID; the directory read has its display name.
                INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at)
                VALUES ('R1', 'q-gpo', 'gpo', '{11111111-2222-3333-4444-555555555555}', 'Workstation hardening',
                        '{"cn":"{11111111-2222-3333-4444-555555555555}","displayName":"Workstation hardening"}', '2026-10-20T00:00:00Z');
                """);
        }

        var text = Text();

        Assert.Contains("Keeper ran 3 checks on 1 system(s). 1 found the configuration correct, 0 found something that should be configured, 1 found something broken, and 1 could not check", text, StringComparison.Ordinal);
        Assert.Contains("1 correct, 0 should be configured, 1 broken, 1 could not check, 0 no result", text, StringComparison.Ordinal);
        // The finding as a reader wants it: what, where, what was seen, why, what to do - and first in "Fix first".
        Assert.Contains("[critical] Found: Backup service stopped - h1.example.org: service state Stopped since 3 days [example]", text, StringComparison.Ordinal);
        Assert.Contains("Why: No backups run while it is stopped.", text, StringComparison.Ordinal);
        Assert.Contains("Fix: Start the service and find why it stopped.", text, StringComparison.Ordinal);
        Assert.Contains("      - h1.example.org: service state Stopped since 3 days", text, StringComparison.Ordinal);
        Assert.Contains("Fix first:", text, StringComparison.Ordinal);
        Assert.Contains("\"Workstation hardening\" {11111111-2222-3333-4444-555555555555} (machine): x = 1", text, StringComparison.Ordinal);
        Assert.Contains("example: checked 2, none found - Remote desktop without network level authentication", text, StringComparison.Ordinal);
        Assert.Contains("example: 1 check(s) - 1 result(s) unknown: the data could not be read", text, StringComparison.Ordinal);
    }
}
