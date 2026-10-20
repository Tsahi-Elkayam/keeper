using Keeper.Query;

namespace Keeper.Review.Tests;

public sealed class QuestionTests : IDisposable
{
    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    private sealed class Rows : IRowWriter
    {
        public List<string> Names { get; private set; } = [];
        public List<IReadOnlyList<object?>> Values { get; } = [];
        public void Columns(IReadOnlyList<string> names) => Names = [.. names];
        public void Row(IReadOnlyList<object?> values) => Values.Add(values);
        public void Complete() { }
        public List<object?> Column(string name) => Values.Select(v => v[Names.IndexOf(name)]).ToList();
    }

    private Rows Ask(string name, params (string Key, string? Value)[] arguments)
    {
        var rows = new Rows();
        using var connection = _store.Db.OpenReadOnly();
        QueryRunner.Run(connection, QueryCatalog.Load([ReviewComponent.Questions], null)[name],
            arguments.ToDictionary(a => a.Key, a => a.Value), rows);
        return rows;
    }

    public static TheoryData<string> Questions()
    {
        var names = new TheoryData<string>();
        foreach (var query in ReviewComponent.Questions.Load())
            names.Add(query.Name);
        return names;
    }

    [Theory]
    [MemberData(nameof(Questions))]
    public void Every_question_runs_on_an_empty_store(string name)
    {
        var required = QueryCatalog.Load([ReviewComponent.Questions], null)[name].Parameters
            .Where(p => p.Required)
            .Select(p => (p.Name, (string?)"2026-01-01"))
            .ToArray();

        Assert.NotEmpty(Ask(name, required).Names);
    }

    [Fact]
    public void The_questions_cover_the_review()
    {
        var names = ReviewComponent.Questions.Load().Select(q => q.Name).ToList();

        foreach (var question in new[] { "broken", "misconfigured", "missing", "blind-spots", "changed", "inventory", "expiring", "licences", "rules", "history" })
            Assert.Contains(question, names);
    }

    [Fact]
    public void Broken_lists_only_open_broken_findings_most_severe_first()
    {
        _store.SeedFindings(
            ("k1", "broken", "medium", "open", "Disk 95% full"),
            ("k2", "broken", "critical", "open", "Service down"),
            ("k3", "broken", "high", "resolved", "Fixed last week"),
            ("k4", "misconfigured", "high", "open", "TLS 1.0 enabled"));

        Assert.Equal(new object?[] { "k2", "k1" }, Ask("broken").Column("finding_key"));
    }

    [Fact]
    public void Expiring_includes_a_licence_inside_the_window_and_licences_shows_when_to_start()
    {
        _store.Seed("""
            INSERT INTO licence (licence_id, product, expires_on, notice_days, updated_by, updated_at)
            VALUES ('soon', 'Expiring product', date('now', '+20 days'), 60, 'test', '2026-10-01T00:00:00Z'),
                   ('later', 'Later product', date('now', '+400 days'), 60, 'test', '2026-10-01T00:00:00Z');
            """);

        Assert.Equal(new object?[] { "soon" }, Ask("expiring").Column("id"));
        var licences = Ask("licences");
        Assert.Equal(20L, licences.Column("days_left")[0]);
        Assert.NotNull(licences.Column("start_renewal_by")[0]);
    }
}
