using Keeper.Testing;

namespace Keeper.Query.Tests;

public sealed class QueryTests : IDisposable
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

    private Rows Run(string name, params (string Key, string? Value)[] arguments)
    {
        var rows = new Rows();
        using var connection = _store.Db.OpenReadOnly();
        QueryRunner.Run(connection, QueryCatalog.Load(null)[name], arguments.ToDictionary(a => a.Key, a => a.Value), rows);
        return rows;
    }

    public static TheoryData<string> BuiltInNames()
    {
        var names = new TheoryData<string>();
        foreach (var query in QueryCatalog.LoadBuiltIns())
            names.Add(query.Name);
        return names;
    }

    [Theory]
    [MemberData(nameof(BuiltInNames))]
    public void Every_built_in_query_runs_on_an_empty_store(string name)
    {
        var required = QueryCatalog.Load(null)[name].Parameters
            .Where(p => p.Required)
            .Select(p => (p.Name, (string?)"2026-01-01"))
            .ToArray();

        var rows = Run(name, required);

        Assert.NotEmpty(rows.Names);
    }

    [Fact]
    public void Built_ins_answer_the_review_questions()
    {
        var names = QueryCatalog.LoadBuiltIns().Select(q => q.Name).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var question in new[] { "broken", "misconfigured", "missing", "blind-spots", "changed", "inventory", "expiring" })
            Assert.Contains(question, names);
    }

    [Fact]
    public void Broken_returns_only_active_broken_findings_most_severe_first()
    {
        _store.SeedFindings(
            ("k1", "broken", "medium", "open", "Disk 95% full"),
            ("k2", "broken", "critical", "open", "Service down"),
            ("k3", "broken", "high", "resolved", "Fixed last week"),
            ("k4", "misconfigured", "high", "open", "TLS 1.0 enabled"));

        var rows = Run("broken");

        Assert.Equal(new object?[] { "k2", "k1" }, rows.Column("finding_key"));
    }

    [Fact]
    public void Required_parameter_is_enforced()
    {
        var ex = Assert.Throws<QueryException>(() => Run("changed"));

        Assert.Contains("--since", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Undeclared_parameter_is_refused()
    {
        Assert.Throws<QueryException>(() => Run("broken", ("colour", "red")));
    }

    [Fact]
    public void Parameters_are_bound_not_spliced()
    {
        _store.SeedFindings(("k1", "broken", "high", "open", "Disk full"));

        var rows = Run("broken", ("system", "SYS1' OR '1'='1"));

        Assert.Empty(rows.Values);
    }

    [Fact]
    public void Tenant_query_adds_a_question()
    {
        var dir = Path.Combine(_store.Dir, "queries");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "my-systems.sql"), "-- name: my-systems\n-- description: Every system.\nSELECT system_id FROM system;");

        Assert.True(QueryCatalog.Load(dir).ContainsKey("my-systems"));
    }

    [Fact]
    public void Tenant_query_cannot_redefine_a_built_in()
    {
        var dir = Path.Combine(_store.Dir, "queries");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "mine.sql"), "-- name: broken\n-- description: shadow\nSELECT 1;");

        Assert.Throws<QueryException>(() => QueryCatalog.Load(dir));
    }

    [Fact]
    public void Query_without_a_description_is_refused()
    {
        Assert.Throws<QueryException>(() => NamedQuery.Parse("-- name: x\nSELECT 1;", "test"));
    }
}
