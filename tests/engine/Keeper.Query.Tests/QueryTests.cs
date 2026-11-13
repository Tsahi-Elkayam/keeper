using Keeper.Store;

namespace Keeper.Query.Tests;

public sealed class QueryTests : IDisposable
{
    private static readonly QueryPack Pack = new("test", typeof(QueryTests).Assembly, "questions/");
    private static readonly MigrationSet Items = MigrationSet.FromResources("items", typeof(QueryTests).Assembly, "items/");

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;
    private readonly Database _db;

    public QueryTests()
    {
        _db = new Database(Path.Combine(_dir, "store.db"));
        using var connection = _db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, [Items]);
        Sql.Execute(connection, "INSERT INTO item VALUES ('a', 'red', 1), ('b', 'blue', 5), ('c', 'red', 9);");
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

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
        using var connection = _db.OpenReadOnly();
        QueryRunner.Run(connection, QueryCatalog.Load([Pack], null)[name], arguments.ToDictionary(a => a.Key, a => a.Value), rows);
        return rows;
    }

    [Fact]
    public void Answers_with_bound_parameters()
    {
        Assert.Equal(new object?[] { "c", "b" }, Run("big", ("min", "5")).Column("item_id"));
        Assert.Equal(new object?[] { "c" }, Run("big", ("min", "5"), ("colour", "red")).Column("item_id"));
    }

    [Fact]
    public void A_required_parameter_is_enforced()
    {
        var ex = Assert.Throws<QueryException>(() => Run("big"));
        Assert.Contains("--min", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_undeclared_parameter_is_refused()
    {
        Assert.Throws<QueryException>(() => Run("big", ("min", "1"), ("shape", "round")));
    }

    [Fact]
    public void Parameters_are_bound_not_spliced()
    {
        Assert.Empty(Run("big", ("min", "0"), ("colour", "red' OR '1'='1")).Values);
    }

    [Fact]
    public void A_tenant_question_is_added()
    {
        var tenant = Path.Combine(_dir, "queries");
        Directory.CreateDirectory(tenant);
        File.WriteAllText(Path.Combine(tenant, "all.sql"), "-- name: all\n-- description: Every item.\nSELECT * FROM item;");

        Assert.True(QueryCatalog.Load([Pack], tenant).ContainsKey("all"));
    }

    [Fact]
    public void A_tenant_question_cannot_redefine_a_built_in()
    {
        var tenant = Path.Combine(_dir, "queries");
        Directory.CreateDirectory(tenant);
        File.WriteAllText(Path.Combine(tenant, "mine.sql"), "-- name: big\n-- description: shadow\nSELECT 1;");

        Assert.Throws<QueryException>(() => QueryCatalog.Load([Pack], tenant));
    }

    [Fact]
    public void A_question_without_a_description_is_refused()
    {
        Assert.Throws<QueryException>(() => NamedQuery.Parse("-- name: x\nSELECT 1;", "test"));
    }
}
