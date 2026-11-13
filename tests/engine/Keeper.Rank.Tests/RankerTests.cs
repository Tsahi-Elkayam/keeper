using System.Text.Json;
using Keeper.Common;
using Keeper.Queue;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Rank.Tests;

public sealed class RankerTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public RankerTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
        Sql.Execute(connection, "INSERT INTO system (system_id, name, criticality, updated_by, updated_at) VALUES ('SYS1', 'Example', NULL, 'test', '2026-10-01T00:00:00Z');");
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string DataDir => Path.Combine(_dir, "data");

    private Database Db => new(Path.Combine(DataDir, "keeper.db"));

    private void Finding(string key, string severity, string lifecycle = "open", int? dueInDays = null, string? check = null)
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection,
            """
            INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, kind, lens,
                                 category, severity, title, deadline, status, lifecycle, first_seen, last_seen)
            VALUES (:k, 'ex', 'example', 'SYS1', :check, :check, 'host', :k || '.example.org', 'broken', 'both',
                    'HLT', :s, 'Finding ' || :k, :due, 'open', :l, :now, :now);
            """,
            null, (":k", key), (":check", check ?? "R-" + key), (":s", severity), (":l", lifecycle),
            (":due", dueInDays is { } d ? Iso.Date(DateTimeOffset.UtcNow.AddDays(d)) : null), (":now", Iso.Utc(DateTimeOffset.UtcNow)));
    }

    private void Triage(string key, string decision, string? owner = null, int? untilDays = null)
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection,
            "INSERT INTO triage (finding_key, decision, owner, until, actor, at, why) VALUES (:k, :d, :o, :u, 'test', :now, 'test');",
            null, (":k", key), (":d", decision), (":o", owner), (":u", untilDays is { } u ? Iso.Date(DateTimeOffset.UtcNow.AddDays(u)) : null),
            (":now", Iso.Utc(DateTimeOffset.UtcNow)));
    }

    private void Setting(string key, string value)
    {
        using var connection = Db.OpenReadWrite();
        Sql.Execute(connection, "INSERT INTO setting (key, value, actor, at, why) VALUES (:k, :v, 'test', '2026-10-01T00:00:00Z', 'test');",
            null, (":k", key), (":v", value));
    }

    private RankingFile Rank(string build = "b1")
    {
        using var connection = Db.OpenReadOnly();
        return new Ranker(connection).Rank(build);
    }

    [Fact]
    public void Overdue_comes_first_and_the_budget_decides_what_fits_today()
    {
        Finding("a", "critical", dueInDays: -2);   // 60 min
        Finding("b", "high", lifecycle: "new");    // 45 min
        Finding("c", "medium");                    // 30 min
        Finding("d", "low");                       // 15 min
        Setting("rank.daily-minutes", "100");

        var ranking = Rank();

        Assert.Equal(new[] { "a", "b", "c", "d" }, ranking.Items.Select(i => i.FindingKey));
        Assert.Contains("overdue by 2 days", ranking.Items[0].Reasons);
        // a (60) fits; b (45) would make 105; c (30) fits in the 40 left; d (15) would make 105.
        Assert.Equal(new[] { "today", "later", "today", "later" }, ranking.Items.Select(i => i.List));
        Assert.Equal(100, ranking.BudgetMinutes);
    }

    [Fact]
    public void Handed_off_findings_wait_and_snoozed_ones_stay_out()
    {
        Finding("a", "high");
        Finding("w", "critical");
        Finding("s", "critical");
        Triage("w", "delegate", owner: "network team");
        Triage("s", "snooze", untilDays: 5);

        var ranking = Rank();

        Assert.Equal("today", ranking.Items.Single(i => i.FindingKey == "a").List);
        Assert.Equal("waiting", ranking.Items.Single(i => i.FindingKey == "w").List);
        Assert.Contains("with network team", ranking.Items.Single(i => i.FindingKey == "w").Reasons);
        Assert.Equal("snoozed", ranking.Items.Single(i => i.FindingKey == "s").List);
    }

    [Fact]
    public void One_check_on_many_targets_is_one_task_that_outranks_the_same_problem_on_one()
    {
        for (var i = 0; i < 91; i++)
            Finding($"adm{i:D2}", "high", check: "WS-LOCAL-ADMINS");
        Finding("solo", "high", check: "WS-OTHER");
        Setting("rank.daily-minutes", "60");

        var ranking = Rank();

        var lead = ranking.Items[0];
        Assert.StartsWith("adm", lead.FindingKey, StringComparison.Ordinal);
        Assert.Contains("91 targets", lead.Reasons);
        Assert.Equal(60 + Ranker.Spread(91), lead.Score, 1);
        // Its 91 findings take the budget once (45 minutes), so the other high finding (45) is later.
        Assert.Equal(91, ranking.Items.Count(i => i.List == "today"));
        Assert.Equal(45, ranking.Items.Where(i => i.List == "today").Sum(i => i.Minutes));
        Assert.Equal("later", ranking.Items.Single(i => i.FindingKey == "solo").List);
    }

    [Fact]
    public void One_item_over_the_budget_still_makes_today_rather_than_an_empty_list()
    {
        Finding("a", "critical");
        Setting("rank.daily-minutes", "20");

        Assert.Equal("today", Assert.Single(Rank().Items).List);
    }

    [Fact]
    public void An_empty_ranking_replaces_yesterdays_list_instead_of_falling_back_to_it()
    {
        Finding("a", "high");
        Register(Rank("20261019-060000"));
        Assert.Equal(1L, Scalar("SELECT COUNT(*) FROM latest_ranking;"));

        using (var connection = Db.OpenReadWrite())
            Sql.Execute(connection, "UPDATE finding SET status = 'resolved', lifecycle = 'resolved';");
        Register(Rank("20261020-060000"));

        Assert.Empty(Rank("x").Items);
        Assert.Equal(0L, Scalar("SELECT COUNT(*) FROM latest_ranking;"));
        Assert.Equal(2L, Scalar("SELECT COUNT(*) FROM rank_build;"));
    }

    private void Register(RankingFile ranking)
    {
        var file = Path.Combine(DataDir, "builds", ranking.BuildId, "ranking.json");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(ranking, JsonLines.Options));
        new RequestWriter(Path.Combine(DataDir, "spool")).Submit("rank.register", "test", new
        {
            file = Path.GetRelativePath(DataDir, file).Replace('\\', '/'),
            sha256 = Hashing.Sha256File(file),
        });
        var report = new QueueManager(Db, Path.Combine(DataDir, "spool"), DataDir, Schemas, [new RankRegisterHandler()]).DrainOnce();
        Assert.Equal(1, report.Done);
    }

    private object? Scalar(string sql)
    {
        using var connection = Db.OpenReadOnly();
        return Sql.Scalar(connection, sql);
    }
}
