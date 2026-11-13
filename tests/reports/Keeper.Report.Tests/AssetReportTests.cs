using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class AssetReportTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];
    private static readonly DateTimeOffset Now = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-assets-").FullName;

    public AssetReportTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    private void Seed()
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO system (system_id, name, updated_by, updated_at) VALUES ('SYS-A', 'Estate', 'test', '2026-10-01T00:00:00Z');
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES ('R1', 'ad-1', 'active-directory', '2026-10-24T11:00:00Z', '2026-10-24T11:00:00Z', 'ok', 'r1', '{}', '2026-10-24T11:00:00Z');
            INSERT INTO entity (instance, entity_type, entity_key, entity_name, system_id, mapped_by, first_seen, last_seen, gone_since) VALUES
              ('ad-1', 'computer', 'srv01.example.org', 'srv01', 'SYS-A', 'unmapped', '2026-09-01T00:00:00Z', '2026-10-24T11:00:00Z', NULL),
              ('ad-1', 'computer', 'pc07.example.org',  'pc07',  'SYS-A', 'unmapped', '2026-09-01T00:00:00Z', '2026-09-10T00:00:00Z', NULL),
              ('ad-1', 'computer', 'old01.example.org', 'old01', 'SYS-A', 'unmapped', '2026-01-01T00:00:00Z', '2026-06-01T00:00:00Z', '2026-06-02T00:00:00Z'),
              ('ad-1', 'printer',  '192.0.2.20',        'front-desk', 'SYS-A', 'unmapped', '2026-09-01T00:00:00Z', '2026-10-24T11:00:00Z', NULL),
              ('ad-1', 'computer', '=cmd|calc',         '=cmd|calc, "x"', 'SYS-A', 'unmapped', '2026-09-01T00:00:00Z', '2026-10-24T11:00:00Z', NULL),
              ('ad-1', 'user',     'u1',                'Example User', 'SYS-A', 'unmapped', '2026-09-01T00:00:00Z', '2026-10-24T11:00:00Z', NULL);
            INSERT INTO row_seen (run_id, query, entity_type, entity_key, entity_name, attrs, observed_at) VALUES
              ('R1', 'q', 'computer', 'srv01.example.org', 'srv01', '{"operatingSystem":"Windows Server 2022 Standard","addresses":["192.0.2.10"],"kind":"windows-server"}', '2026-10-24T11:00:00Z'),
              ('R1', 'q', 'computer', 'pc07.example.org', 'pc07', '{"operatingSystem":"Windows 11 Pro"}', '2026-09-10T00:00:00Z'),
              ('R1', 'q', 'printer', '192.0.2.20', 'front-desk', '{"model":"Example LaserJet 100","serialNumber":"SN-0001"}', '2026-10-24T11:00:00Z');
            INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, kind, lens, category, severity, title,
                                 status, lifecycle, first_seen, last_seen)
            VALUES ('k1', 'ad-1', 'active-directory', 'SYS-A', 'R1', 'R1', 'computer', 'srv01.example.org', 'misconfigured', 'security', 'CFG', 'high', 'Example',
                    'open', 'open', '2026-10-01T00:00:00Z', '2026-10-24T11:00:00Z');
            """);
    }

    private (Document Document, string Csv) Build()
    {
        using var connection = Db.OpenReadOnly();
        return (Assets.Build(connection, Now), Assets.Csv(connection, Now));
    }

    private static string Text(Document document) => Render.Text(document);

    [Fact]
    public void An_empty_store_gives_a_report_that_says_there_are_no_assets()
    {
        var (document, csv) = Build();

        Assert.Contains("No assets", Text(document), StringComparison.Ordinal);
        Assert.Single(csv.Split('\n', StringSplitOptions.RemoveEmptyEntries));   // the header only
    }

    [Fact]
    public void Machines_and_devices_are_assets_and_accounts_are_not()
    {
        Seed();

        var (_, csv) = Build();

        Assert.Contains("srv01.example.org", csv, StringComparison.Ordinal);
        Assert.Contains("192.0.2.20", csv, StringComparison.Ordinal);
        Assert.DoesNotContain("Example User", csv, StringComparison.Ordinal);
    }

    [Fact]
    public void The_csv_carries_what_was_learned_about_each_asset()
    {
        Seed();

        var line = Build().Csv.Split('\n').Single(l => l.StartsWith("computer,srv01.example.org", StringComparison.Ordinal));

        Assert.Contains("Windows Server 2022 Standard", line, StringComparison.Ordinal);
        Assert.Contains("192.0.2.10", line, StringComparison.Ordinal);
        Assert.Contains(",1", line.TrimEnd('\r'), StringComparison.Ordinal);       // one open finding
    }

    [Fact]
    public void A_printer_shows_its_model_and_serial_number()
    {
        Seed();

        var line = Build().Csv.Split('\n').Single(l => l.StartsWith("printer,192.0.2.20", StringComparison.Ordinal));

        Assert.Contains("Example LaserJet 100", line, StringComparison.Ordinal);
        Assert.Contains("SN-0001", line, StringComparison.Ordinal);
    }

    [Fact]
    public void An_asset_the_scans_no_longer_return_is_marked_gone_and_one_unseen_for_a_month_is_stale()
    {
        Seed();

        var csv = Build().Csv;

        Assert.Contains("gone", csv.Split('\n').Single(l => l.Contains("old01", StringComparison.Ordinal)), StringComparison.Ordinal);
        Assert.Contains("stale", csv.Split('\n').Single(l => l.Contains("pc07", StringComparison.Ordinal)), StringComparison.Ordinal);
        Assert.Contains("current", csv.Split('\n').Single(l => l.StartsWith("computer,srv01", StringComparison.Ordinal)), StringComparison.Ordinal);
    }

    [Fact]
    public void A_name_that_a_spreadsheet_would_run_as_a_formula_is_defused_and_commas_and_quotes_are_escaped()
    {
        Seed();

        var line = Build().Csv.Split('\n').Single(l => l.Contains("cmd|calc", StringComparison.Ordinal));

        Assert.StartsWith("computer,'=cmd|calc,", line, StringComparison.Ordinal);
        Assert.Contains("\"'=cmd|calc, \"\"x\"\"\"", line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_summary_counts_assets_by_type_and_by_how_recently_they_were_seen()
    {
        Seed();

        var text = Text(Build().Document);

        Assert.Contains("5 assets", text, StringComparison.Ordinal);
        Assert.Contains("computer: 4", text, StringComparison.Ordinal);
        Assert.Contains("printer: 1", text, StringComparison.Ordinal);
        Assert.Contains("1 not seen for 30 days", text, StringComparison.Ordinal);
        Assert.Contains("1 gone", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Operating_systems_are_counted_and_machines_whose_os_is_unknown_are_not_hidden()
    {
        Seed();

        var text = Text(Build().Document);

        Assert.Contains("Windows Server 2022 Standard: 1", text, StringComparison.Ordinal);
        Assert.Contains("Windows 11 Pro: 1", text, StringComparison.Ordinal);
        Assert.Contains("unknown: ", text, StringComparison.Ordinal);
    }
}
