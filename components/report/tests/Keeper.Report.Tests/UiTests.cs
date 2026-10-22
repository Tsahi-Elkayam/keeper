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
}
