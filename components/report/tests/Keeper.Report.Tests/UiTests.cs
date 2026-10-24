using System.Text.RegularExpressions;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class UiTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public UiTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    private string Page()
    {
        using var connection = Db.OpenReadOnly();
        return Ui.Build(connection, DateTimeOffset.UtcNow, "example");
    }

    [Fact]
    public void An_empty_store_still_builds_a_page()
    {
        var page = Page();

        Assert.StartsWith("<!doctype html>", page, StringComparison.Ordinal);
        Assert.DoesNotContain("/*KEEPER-DATA*/", page, StringComparison.Ordinal);
        Assert.Contains("\"checks\":[]", page, StringComparison.Ordinal);
        Assert.Contains("\"entities\":[]", page, StringComparison.Ordinal);
        Assert.Contains("\"categories\":[]", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Results_without_a_loaded_rule_catalogue_are_not_reported_as_no_scan_at_all()
    {
        using (var connection = Db.OpenReadWrite())
        {
            Sql.Execute(connection,
                """
                INSERT INTO result (instance, rule_id, entity_type, entity_key, state, ttl_minutes, at)
                VALUES ('ex-main', 'EX-X', 'host', 'h1', 'pass', 4320, '2026-10-20T00:00:00Z');
                """);
        }

        var page = Page();

        Assert.Contains("\"catalogueMissing\":true", page, StringComparison.Ordinal);
        Assert.Contains("rule catalogue is not loaded", page, StringComparison.Ordinal);
        Assert.Contains("keeper rules load", page, StringComparison.Ordinal);
    }

    [Fact]
    public void A_view_that_has_nothing_to_show_in_a_section_leaves_it_out_instead_of_printing_null()
    {
        // The coverage view returns null for a section with no rows; appending that raw prints the word "null" on the page.
        // (Seen in a real render. The page's script cannot run here, so the guard is checked in its source.)
        Assert.Contains("views[state.tab]().flat().filter(n => n != null && n !== false)", Page(), StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_store_is_not_blamed_on_the_catalogue()
    {
        Assert.Contains("\"catalogueMissing\":false", Page(), StringComparison.Ordinal);
    }

    [Fact]
    public void Text_from_a_scanned_system_cannot_become_markup()
    {
        using (var connection = Db.OpenReadWrite())
        {
            Sql.Execute(connection,
                """
                INSERT INTO system (system_id, name, updated_by, updated_at) VALUES ('SYS1', 'Example system', 'test', '2026-10-01T00:00:00Z');
                INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, entity_name, kind, lens,
                                     category, severity, title, evidence, status, lifecycle, first_seen, last_seen)
                VALUES ('k1', 'ex-main', 'example', 'SYS1', 'EX-X', 'EX-X', 'host', 'h1', '</script><img src=x onerror=alert(1)>', 'broken', 'maintenance',
                        'HLT', 'high', 'Hostile name', 'value "</script><script>alert(2)</script>"', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                """);
        }

        var page = Page();

        // Only the page's own two script elements close; the hostile text is escaped inside the JSON.
        Assert.Equal(2, Regex.Matches(page, "</script", RegexOptions.IgnoreCase).Count);
        Assert.DoesNotContain("<img", page, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Hostile name", page, StringComparison.Ordinal);
        // The page draws values as text: no data goes through innerHTML.
        Assert.DoesNotContain("innerHTML", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Embeds_object_dossiers_cross_cutting_matrix_and_estate_coverage_data()
    {
        using (var connection = Db.OpenReadWrite())
        {
            Sql.Execute(connection,
                """
                INSERT INTO system (system_id, name, updated_by, updated_at)
                VALUES ('SYS-NET', 'Network', 'test', '2026-10-01T00:00:00Z');

                INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, source_file, loaded_at)
                VALUES ('NET-SMB-001', 'network', 'SMBv1 enabled', 'misconfigured', 'security', 'CFG', 'critical', 'computer', 'files', 1440, 'builtin:network.yaml', '2026-10-01T00:00:00Z'),
                       ('WIN-SVC-001', 'windows-server', 'Backup service running', 'broken', 'maintenance', 'BCK', 'high', 'computer', 'cim', 1440, 'builtin:windows-server.yaml', '2026-10-01T00:00:00Z');

                INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
                VALUES ('R-NET', 'net-main', 'network', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'ok', 'r-net', '{}', '2026-10-20T00:00:00Z'),
                       ('R-WIN', 'win-main', 'windows-server', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'ok', 'r-win', '{}', '2026-10-20T00:00:00Z');

                INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at)
                VALUES ('R-NET', 'inventory', 'computer', 'srv01.example.com', 'srv01.example.com',
                        '{"key":"srv01.example.com","state":"answering","kind":"windows-server","kindWhy":"smb+winrm","addresses":["192.0.2.10"],"names":["srv01.example.com"],"sources":[{"kind":"ad"}],"answered":["smb","winrm"],"services":[{"port":445,"transport":"tcp","service":"smb"}]}',
                        '2026-10-20T00:00:00Z'),
                       ('R-NET', 'inventory', 'computer', 'ip:192.0.2.77', 'ip:192.0.2.77',
                        '{"key":"ip:192.0.2.77","state":"answering","kind":"printer","kindWhy":"ipp","addresses":["192.0.2.77"],"names":[],"sources":[{"kind":"sweep"}],"answered":["http"]}',
                        '2026-10-20T00:00:00Z');

                INSERT INTO result (instance, rule_id, entity_type, entity_key, state, ttl_minutes, at, run_id)
                VALUES ('net-main', 'NET-SMB-001', 'computer', 'srv01.example.com', 'fail', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-NET'),
                       ('win-main', 'WIN-SVC-001', 'computer', 'srv01.example.com', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hours'), 'R-WIN');

                INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, entity_name, kind, lens,
                                     category, severity, security, title, evidence, status, lifecycle, first_seen, last_seen)
                VALUES ('f1', 'net-main', 'network', 'SYS-NET', 'NET-SMB-001', 'NET-SMB-001', 'computer', 'srv01.example.com', 'srv01.example.com', 'misconfigured', 'security',
                        'CFG', 'critical', 1, 'SMBv1 enabled', 'srv01.example.com negotiated SMBv1', 'open', 'open', '2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z');
                """);
        }

        var page = Page();

        // Verify embedded JSON contains entities, categories, and estate coverage metrics
        Assert.Contains("\"key\":\"srv01.example.com\"", page, StringComparison.Ordinal);
        Assert.Contains("\"kind\":\"windows-server\"", page, StringComparison.Ordinal);
        Assert.Contains("\"unlisted\":true", page, StringComparison.Ordinal);
        Assert.Contains("\"deep\":true", page, StringComparison.Ordinal);
        Assert.Contains("\"code\":\"CFG\"", page, StringComparison.Ordinal);
        Assert.Contains("\"answering\":2", page, StringComparison.Ordinal);
        Assert.Contains("Object dossier", page, StringComparison.Ordinal);
        Assert.Contains("Cross-cutting estate matrix", page, StringComparison.Ordinal);
        Assert.Contains("Operational and scan coverage", page, StringComparison.Ordinal);
    }
}
