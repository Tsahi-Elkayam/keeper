using System.Text.Json;
using Keeper.Review.Config;

namespace Keeper.Review.Tests;

public sealed class SystemsConfigTests : IDisposable
{
    // The columns review.system upserts; a system in the store not from the file (the two synthetic seeds) is excluded.
    private const string SelectSystems =
        """
        SELECT system_id, name, team, purpose, owner, owner_person, route, criticality, active, notes
        FROM system WHERE system_id NOT IN ('KEEPER', 'ORG', 'UNMAPPED') ORDER BY system_id;
        """;

    private static readonly SystemRecord[] Sample =
    [
        new("AD", "Active Directory", "IT dept", "Alex", "Authentication and DNS", "03-Windows", "servicenow", 1, true, "4 live DCs."),
        new("MAIL-01", "Mail", null, null, null, null, "monday", 2, true, null),
        new("sql.db", "SQL estate", "IT dept", null, "Databases", "03-Windows", null, null, false, "Note with a ' quote and\na newline."),
        new("WEB", "Web tier", null, "Dana", null, "10-Reference", "triage", 3, true, ""),
    ];

    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    [Fact]
    public void Write_then_read_then_write_is_byte_stable()
    {
        var yaml1 = SystemsConfig.Write("acme", Sample);
        var records = SystemsConfig.Read(yaml1, "mem", out var client);
        var yaml2 = SystemsConfig.Write(client, records);

        Assert.Equal("acme", client);
        Assert.Equal(yaml1, yaml2);
    }

    [Fact]
    public void Read_recovers_every_field_including_nulls_and_defaults()
    {
        var yaml = SystemsConfig.Write(null, Sample);
        var byId = SystemsConfig.Read(yaml, "mem", out _).ToDictionary(s => s.Id, StringComparer.Ordinal);

        // Ordered by id, nulls preserved as nulls (not empty strings), active defaults are kept.
        Assert.Equal(["AD", "MAIL-01", "WEB", "sql.db"], byId.Keys.Order(StringComparer.Ordinal));
        Assert.Null(byId["MAIL-01"].Owner);
        Assert.Null(byId["MAIL-01"].Notes);
        Assert.Null(byId["sql.db"].Criticality);
        Assert.False(byId["sql.db"].Active);
        Assert.Equal("Note with a ' quote and\na newline.", byId["sql.db"].Notes);
    }

    [Fact]
    public void Export_import_export_through_the_store_is_stable_and_import_is_idempotent()
    {
        // Export shape 1 (from the sample, as if it had come from a store).
        var yaml1 = SystemsConfig.Write("acme", Sample);
        var fromFile = SystemsConfig.Read(yaml1, "file", out var client);

        // Import: one review.system upsert per system, through the real queue + handler (the one writer).
        foreach (var system in fromFile)
            _store.Submit("review.system", Upsert(system));
        var report = _store.Manager().DrainOnce();
        Assert.Equal(Sample.Length, report.Done);
        Assert.Equal(0, report.Failed);

        // Export shape 2, read back from the store the same way keeper-config export does.
        var inStore = _store.Rows(SelectSystems).Select(FromRow).ToList();
        var yaml2 = SystemsConfig.Write(client, inStore);
        Assert.Equal(yaml1, yaml2);

        // Idempotent: every file record now equals its store record, so a second import would queue nothing.
        var byId = inStore.ToDictionary(s => s.Id, StringComparer.Ordinal);
        foreach (var system in fromFile)
            Assert.Equal(system, byId[system.Id]);
    }

    [Fact]
    public void A_system_in_the_store_but_not_in_the_file_is_left_alone()
    {
        _store.Submit("review.system", Upsert(new SystemRecord("LEGACY", "Old box", null, null, null, null, null, null, true, null)));
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        // Importing a file that does not mention LEGACY must not touch it (this increment never deletes).
        foreach (var system in Sample)
            _store.Submit("review.system", Upsert(system));
        _store.Manager().DrainOnce();

        Assert.Equal(1L, _store.Scalar("SELECT COUNT(*) FROM system WHERE system_id = 'LEGACY'"));
    }

    [Theory]
    [InlineData("this: is: not: valid: yaml")]                                            // unparseable
    [InlineData("schema: wrong/9\nsystems: []")]                                          // wrong schema
    [InlineData("client: 'x'\nsystems: []")]                                              // missing schema
    [InlineData("schema: keeper.config/1")]                                               // missing systems
    [InlineData("schema: keeper.config/1\nsystems:\n  - name: 'No id'")]                  // system missing id
    [InlineData("schema: keeper.config/1\nsystems:\n  - id: 'A'")]                        // system missing name
    [InlineData("schema: keeper.config/1\nsystems:\n  - id: 'A'\n    name: 'A'\n    bogus: 1")] // unknown field
    [InlineData("schema: keeper.config/1\nsystems:\n  - id: 'A'\n    name: 'A'\n    criticality: 9")] // bad criticality
    [InlineData("schema: keeper.config/1\nsystems:\n  - id: 'bad id!'\n    name: 'A'")]   // bad id
    [InlineData("schema: keeper.config/1\nsystems:\n  - id: 'A'\n    name: 'A'\n  - id: 'A'\n    name: 'B'")] // duplicate id
    public void A_malformed_file_throws_config_exception(string yaml)
    {
        var ex = Assert.Throws<ConfigException>(() => SystemsConfig.Read(yaml, "bad.yaml", out _));
        Assert.NotEmpty(ex.Errors);
    }

    [Fact]
    public void A_well_formed_empty_file_reads_as_no_systems()
    {
        var records = SystemsConfig.Read("schema: keeper.config/1\nsystems: []\n", "mem", out _);
        Assert.Empty(records);
    }

    private static SystemRecord FromRow(Dictionary<string, object?> row) => new(
        (string)row["system_id"]!,
        (string)row["name"]!,
        row["owner"] as string,
        row["owner_person"] as string,
        row["purpose"] as string,
        row["team"] as string,
        row["route"] as string,
        row["criticality"] is long crit ? (int)crit : null,
        row["active"] is not 0L,
        row["notes"] as string);

    private static string Upsert(SystemRecord s) => JsonSerializer.Serialize(new
    {
        op = "upsert",
        systemId = s.Id,
        name = s.Name,
        team = s.Team,
        purpose = s.Purpose,
        owner = s.Owner,
        ownerPerson = s.OwnerPerson,
        route = s.Route,
        criticality = s.Criticality,
        active = s.Active,
        notes = s.Notes,
    });
}
