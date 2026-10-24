using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class TargetMatrixCoverageTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public TargetMatrixCoverageTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    private void SeedSampleEstate()
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO system (system_id, name, updated_by, updated_at)
            VALUES ('SYS-AD', 'Directory', 'test', '2026-10-01T00:00:00Z'),
                   ('SYS-NET', 'Network', 'test', '2026-10-01T00:00:00Z'),
                   ('SYS-WIN', 'Windows Fleet', 'test', '2026-10-01T00:00:00Z');

            INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, source_file, loaded_at)
            VALUES ('NET-SMB-001', 'network', 'SMBv1 enabled on network host', 'misconfigured', 'security', 'CFG', 'critical', 'computer', 'files', 1440, 'builtin:network.yaml', '2026-10-01T00:00:00Z'),
                   ('NET-UNLISTED-001', 'network', 'Answering machine not in directory', 'missing', 'security', 'HYG', 'high', 'computer', 'files', 1440, 'builtin:network.yaml', '2026-10-01T00:00:00Z'),
                   ('WIN-BCK-001', 'windows-server', 'Backup agent stopped', 'broken', 'maintenance', 'BCK', 'critical', 'computer', 'cim', 1440, 'builtin:windows-server.yaml', '2026-10-01T00:00:00Z'),
                   ('WIN-NLA-001', 'windows-server', 'RDP NLA enabled', 'misconfigured', 'security', 'AUT', 'high', 'computer', 'cim', 1440, 'builtin:windows-server.yaml', '2026-10-01T00:00:00Z'),
                   ('SQL-UNUSED-001', 'sql-server', 'SQL Server backup age', 'broken', 'maintenance', 'BCK', 'high', 'database', 'sql', 1440, 'builtin:sql-server.yaml', '2026-10-01T00:00:00Z');

            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES ('R-NET', 'net-main', 'network', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'ok', 'r-net', '{}', '2026-10-20T00:00:00Z'),
                   ('R-WIN', 'win-main', 'windows-server', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'partial', 'r-win', '{}', '2026-10-20T00:00:00Z');

            INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at)
            VALUES ('R-NET', 'inventory', 'computer', 'srv01.example.com', 'srv01.example.com',
                    '{"key":"srv01.example.com","state":"answering","kind":"windows-server","kindWhy":"smb+winrm","addresses":["192.0.2.10"],"names":["srv01.example.com"],"sources":[{"kind":"ad"}],"answered":["smb","winrm"],"services":[{"port":445,"transport":"tcp","service":"smb"},{"port":5985,"transport":"tcp","service":"winrm"}]}',
                    '2026-10-20T00:00:00Z'),
                   ('R-NET', 'inventory', 'computer', 'ip:192.0.2.55', 'ip:192.0.2.55',
                    '{"key":"ip:192.0.2.55","state":"answering","kind":"network-device","kindWhy":"snmp sysObjectID","addresses":["192.0.2.55"],"names":[],"sources":[{"kind":"sweep"}],"answered":["ssh","snmp"],"snmp":{"version":"v3","sysName":"sw01.example.com","sysDescr":"Example Switch"}}',
                    '2026-10-20T00:00:00Z'),
                   ('R-NET', 'inventory', 'computer', 'old01.example.com', 'old01.example.com',
                    '{"key":"old01.example.com","state":"likely-gone","kind":"unknown","addresses":["192.0.2.99"],"names":["old01.example.com"],"sources":[{"kind":"ad"}],"answered":[]}',
                    '2026-10-20T00:00:00Z');

            INSERT INTO coverage (run_id, scope, item, state, reason, count, observed_at)
            VALUES ('R-NET', 'rule', 'NET-SMB-001', 'ok', NULL, 3, '2026-10-20T00:00:00Z'),
                   ('R-NET', 'rule', 'NET-UNLISTED-001', 'ok', NULL, 3, '2026-10-20T00:00:00Z'),
                   ('R-WIN', 'rule', 'WIN-BCK-001', 'ok', NULL, 1, '2026-10-20T00:00:00Z'),
                   ('R-WIN', 'rule', 'WIN-NLA-001', 'ok', NULL, 1, '2026-10-20T00:00:00Z'),
                   ('R-WIN', 'target', 'services@srv01.example.com', 'partial', 'WinRM event log channel timed out', 1, '2026-10-20T00:00:00Z');

            INSERT INTO result (instance, rule_id, entity_type, entity_key, state, why, ttl_minutes, at, run_id)
            VALUES ('net-main', 'NET-SMB-001', 'computer', 'srv01.example.com', 'fail', 'SMBv1 dialect negotiated', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-NET'),
                   ('net-main', 'NET-SMB-001', 'computer', 'ip:192.0.2.55', 'fail', 'SMBv1 dialect negotiated', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-NET'),
                   ('net-main', 'NET-UNLISTED-001', 'computer', 'ip:192.0.2.55', 'fail', 'not in directory', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-NET'),
                   ('win-main', 'WIN-BCK-001', 'computer', 'srv01.example.com', 'fail', 'service stopped', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-WIN'),
                   ('win-main', 'WIN-NLA-001', 'computer', 'srv01.example.com', 'pass', NULL, 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-WIN');

            INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, entity_name, kind, lens,
                                 category, severity, security, title, evidence, why, fix, status, lifecycle, first_seen, last_seen)
            VALUES ('f1', 'net-main', 'network', 'SYS-NET', 'NET-SMB-001', 'NET-SMB-001', 'computer', 'srv01.example.com', 'srv01.example.com', 'misconfigured', 'security',
                    'CFG', 'critical', 1, 'SMBv1 enabled on network host', 'srv01.example.com negotiated SMBv1', 'SMBv1 is vulnerable.', 'Disable SMBv1.', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z'),
                   ('f2', 'net-main', 'network', 'SYS-NET', 'NET-SMB-001', 'NET-SMB-001', 'computer', 'ip:192.0.2.55', 'ip:192.0.2.55', 'misconfigured', 'security',
                    'CFG', 'critical', 1, 'SMBv1 enabled on network host', '192.0.2.55 negotiated SMBv1', 'SMBv1 is vulnerable.', 'Disable SMBv1.', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z'),
                   ('f3', 'win-main', 'windows-server', 'SYS-WIN', 'WIN-BCK-001', 'WIN-BCK-001', 'computer', 'srv01.example.com', 'srv01.example.com', 'broken', 'maintenance',
                    'BCK', 'critical', 0, 'Backup agent stopped', 'BackupSvc is Stopped on srv01.example.com', 'Backups fail while stopped.', 'Start BackupSvc.', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
            """);
    }

    [Fact]
    public void Target_dossier_reports_identity_broken_config_passed_and_blind_spots_by_hostname_or_ip()
    {
        SeedSampleEstate();

        using var connection = Db.OpenReadOnly();
        // Query by IP address alias (192.0.2.10 belongs to srv01.example.com)
        var doc = Reports.Build("target", connection, DateTimeOffset.UtcNow, null, target: "192.0.2.10");
        var text = Render.As(doc, "text");

        Assert.Contains("Object dossier: 192.0.2.10", text, StringComparison.Ordinal);
        Assert.Contains("state=answering, kind=windows-server (smb+winrm), addresses=[192.0.2.10]", text, StringComparison.Ordinal);
        Assert.Contains("Open services: 445/tcp smb, 5985/tcp winrm", text, StringComparison.Ordinal);
        Assert.Contains("Total open on 192.0.2.10: 2 (2 critical, 0 high, 0 medium, 0 low/info; 1 broken, 1 misconfigured/missing; 1 maintenance, 1 security).", text, StringComparison.Ordinal);
        Assert.Contains("Backup agent stopped [windows-server / BCK / WIN-BCK-001]", text, StringComparison.Ordinal);
        Assert.Contains("SMBv1 enabled on network host [network / CFG / NET-SMB-001]", text, StringComparison.Ordinal);
        Assert.Contains("[windows-server] RDP NLA enabled (WIN-NLA-001) - passed", text, StringComparison.Ordinal);
        Assert.Contains("windows-server (win-main): target read services@srv01.example.com was partial - WinRM event log channel timed out", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Matrix_report_shows_categories_widespread_checks_and_object_hotspots()
    {
        SeedSampleEstate();

        using var connection = Db.OpenReadOnly();
        var doc = Reports.Build("matrix", connection, DateTimeOffset.UtcNow, null);
        var text = Render.As(doc, "text");

        Assert.Contains("Cross-cutting estate matrix", text, StringComparison.Ordinal);
        Assert.Contains("[CFG]", text, StringComparison.Ordinal);
        Assert.Contains("[BCK]", text, StringComparison.Ordinal);
        Assert.Contains("Found on 2 objects across 1 system(s): SMBv1 enabled on network host [CFG / NET-SMB-001]", text, StringComparison.Ordinal);
        Assert.Contains("srv01.example.com (computer, in network,windows-server): 2 open (2 critical, 0 high; 1 broken, 1 security)", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Coverage_report_surfaces_estate_reachability_rule_standing_blind_spots_and_unscanned_packs()
    {
        SeedSampleEstate();

        using var connection = Db.OpenReadOnly();
        var doc = Reports.Build("coverage", connection, DateTimeOffset.UtcNow, null);
        var text = Render.As(doc, "text");

        Assert.Contains("Operational and scan coverage", text, StringComparison.Ordinal);
        Assert.Contains("Known machines/devices: 3 (3 in network discovery, 2 in directory).", text, StringComparison.Ordinal);
        Assert.Contains("Network reachability: 2 answering, 0 not-answering, 1 likely-gone, 0 unresolved DNS, 0 excluded.", text, StringComparison.Ordinal);
        Assert.Contains("Management protocol reachability: 2 reachable via at least one management channel (SSH: 1, WinRM: 1, HTTPS: 0, SNMP: 1).", text, StringComparison.Ordinal);
        Assert.Contains("Unlisted / dark machines (answering on the network but absent from directory): 1.", text, StringComparison.Ordinal);
        Assert.Contains("Inspection depth: 1 with deep host-level checks (OS/services/SMB/TLS/events), 2 with surface or directory-only visibility.", text, StringComparison.Ordinal);
        Assert.Contains("windows-server (win-main, status=partial", text, StringComparison.Ordinal);
        Assert.Contains("windows-server (win-main): target services@srv01.example.com was partial: WinRM event log channel timed out", text, StringComparison.Ordinal);
        Assert.Contains("sql-server: 1 rule(s) in catalogue, 0 scans recorded", text, StringComparison.Ordinal);
    }
}
