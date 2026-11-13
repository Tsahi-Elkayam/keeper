using Keeper.Common;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class FinanceTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public FinanceTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
        string In(int days) => Iso.Date(DateTimeOffset.UtcNow.AddDays(days));
        Sql.Execute(connection,
            $$"""
            INSERT INTO licence (licence_id, product, seats, seats_used, expires_on, auto_renews, cost, currency, owner, updated_by, updated_at) VALUES
                ('backup', 'Backup suite', 100, 40, '{{In(20)}}', 1, 50000, 'ILS', 'ops', 'test', '2026-10-01T00:00:00Z'),
                ('chat', 'Chat tool', 50, 61, '{{In(400)}}', 0, NULL, NULL, NULL, 'test', '2026-10-01T00:00:00Z');
            INSERT INTO contract (contract_id, title, end_on, notice_days, value, currency, decision, updated_by, updated_at) VALUES
                ('crm', 'CRM support', '{{In(30)}}', 90, 120000, 'ILS', NULL, 'test', '2026-10-01T00:00:00Z');
            INSERT INTO initiative (initiative_id, title, status, saving_monthly, currency, measured, updated_by, updated_at) VALUES
                ('rightsize', 'Right-size servers', 'done', 8000, 'USD', 'bill', 'test', '2026-10-01T00:00:00Z'),
                ('reserve', 'Reserved capacity', 'proposed', 3000, 'USD', 'estimate', 'test', '2026-10-01T00:00:00Z');
            """);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    [Fact]
    public void Finance_shows_what_falls_due_what_is_idle_what_is_over_and_what_was_saved()
    {
        string text;
        using (var connection = Db.OpenReadOnly())
            text = Render.As(Finance.Build(connection, DateTimeOffset.UtcNow, 90), "text");

        Assert.Contains("Licence Backup suite: expires", text, StringComparison.Ordinal);
        Assert.Contains("renews by itself (owner ops)", text, StringComparison.Ordinal);
        Assert.Contains("Contract CRM support: ends", text, StringComparison.Ordinal);
        Assert.Contains("CRM support: ends", text[text.IndexOf("Decisions overdue", StringComparison.Ordinal)..], StringComparison.Ordinal);
        Assert.Contains("Backup suite: 40 of 100 seats used - about 30,000 ILS of its cost is idle", text, StringComparison.Ordinal);
        Assert.Contains("Chat tool: 61 used of 50", text, StringComparison.Ordinal);
        Assert.Contains("done: 1 initiative(s), 8,000 USD a month (8,000 USD seen on the bill)", text, StringComparison.Ordinal);
        Assert.Contains("proposed: 1 initiative(s), 3,000 USD a month (estimated)", text, StringComparison.Ordinal);
    }
}
