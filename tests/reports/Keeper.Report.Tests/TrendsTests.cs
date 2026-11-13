using Keeper.Common;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class TrendsTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public TrendsTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
        Sql.Execute(connection, "INSERT INTO system (system_id, name, updated_by, updated_at) VALUES ('ERP', 'Finance ERP', 'test', '2026-01-01T00:00:00Z');");
        // Sixty days of ERP getting better: 40 open, 10 serious, falling to 12 open, 2 serious.
        for (var day = 60; day >= 0; day--)
        {
            var open = 12 + (28 * day / 60);
            var serious = 2 + (8 * day / 60);
            Sql.Execute(connection,
                """
                INSERT INTO system_trend (day, system_id, open, critical, high, medium, low, info, security, overdue, accepted,
                                          opened, resolved, checks_passing, checks_judged, at)
                VALUES (:day, 'ERP', :open, 0, :serious, :rest, 0, 0, 0, 0, 0, 0, 1, 80, 100, :day),
                       (:day, '*', :open, 0, :serious, :rest, 0, 0, 0, 0, 0, 0, 1, 80, 100, :day);
                """,
                null, (":day", Iso.Date(DateTimeOffset.UtcNow.AddDays(-day))), (":open", open), (":serious", serious), (":rest", open - serious));
        }
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private Database Db => new(Path.Combine(_dir, "keeper.db"));

    [Fact]
    public void A_system_getting_better_shows_its_fall_and_lands_in_most_improved()
    {
        Document document;
        using (var connection = Db.OpenReadOnly())
            document = Trends.Build(connection, DateTimeOffset.UtcNow, 90);

        var text = Render.As(document, "text");
        Assert.Contains("Open findings: 12 now, 26 30 days ago (-14)", text, StringComparison.Ordinal);
        Assert.Contains("ERP - Finance ERP: open 12, 26 30 d (-14)", text, StringComparison.Ordinal);
        Assert.Contains("Most improved", text, StringComparison.Ordinal);
        Assert.Contains("ERP - Finance ERP: 26 -> 12 open (-14)", text, StringComparison.Ordinal);
        Assert.Contains("No system has more open findings than 30 days ago.", text, StringComparison.Ordinal);
        Assert.Contains("█", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(new long[] { 5, 4, 3, 2, 1 }, "█▆▅▃▁")]
    [InlineData(new long[] { 3, 3, 3 }, "▄▄▄")]
    [InlineData(new long[] { 7 }, "")]
    public void Sparklines_run_from_lowest_to_highest(long[] values, string expected)
    {
        Assert.Equal(expected, Trends.Spark(values));
    }

    [Fact]
    public void Nothing_recorded_yet_says_so_instead_of_showing_zeros()
    {
        using (var connection = Db.OpenReadWrite())
            Sql.Execute(connection, "DELETE FROM system_trend;");
        using var read = Db.OpenReadOnly();

        Assert.Contains("first trend appears after the first 'keeper run'", Render.As(Trends.Build(read, DateTimeOffset.UtcNow, 90), "text"), StringComparison.Ordinal);
    }
}
