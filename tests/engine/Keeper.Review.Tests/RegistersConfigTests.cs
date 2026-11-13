using System.Text.Json.Nodes;
using Keeper.Review.Config;
using Keeper.Review.Handlers;

namespace Keeper.Review.Tests;

public sealed class RegistersConfigTests : IDisposable
{
    private readonly TempStore _store = new();

    public void Dispose() => _store.Dispose();

    private static RegisterData Sample()
    {
        var vendors = new List<RegisterRecord>
        {
            Rec(Registers.Vendor, "acme-av", ("name", "Acme AV"), ("sole_vendor", 1L), ("sensitive", 1L),
                ("security_review_on", "2026-01-15"), ("notes", "Dana reviewed it, with a ' quote.")),
            Rec(Registers.Vendor, "beta-mon", ("name", "Beta Monitor"), ("state", "candidate"), ("data_handled", "metrics")),
        };
        var contracts = new List<RegisterRecord>
        {
            Rec(Registers.Contract, "c-001", ("title", "Support contract"), ("vendor_id", "acme-av"),
                ("value", 1234.5), ("currency", "ILS"), ("decision", "renew"), ("end_on", "2027-06-30")),
        };
        var licences = new List<RegisterRecord>
        {
            Rec(Registers.Licence, "l-001", ("product", "Backup suite"), ("vendor_id", "acme-av"), ("seats", 50L),
                ("seats_used", 40L), ("expires_on", "2027-03-31"), ("auto_renews", 1L), ("cost", 999.0), ("currency", "ILS"), ("owner", "Alex")),
        };
        var keyDates = new List<RegisterRecord>
        {
            Rec(Registers.KeyDate, "k-001", ("kind", "report"), ("title", "Quarterly report"), ("due_on", "2026-12-25"), ("owner", "Dana")),
        };
        var initiatives = new List<RegisterRecord>
        {
            Rec(Registers.Initiative, "i-001", ("title", "Right-size instances"), ("status", "in-progress"),
                ("saving_monthly", 250.0), ("currency", "USD"), ("measured", "estimate")),
        };
        var tables = new Dictionary<string, IReadOnlyList<RegisterRecord>>(StringComparer.Ordinal)
        {
            [Registers.Vendor.Table] = vendors,
            [Registers.Contract.Table] = contracts,
            [Registers.Licence.Table] = licences,
            [Registers.KeyDate.Table] = keyDates,
            [Registers.Initiative.Table] = initiatives,
        };
        var attestations = new List<AttestationRecord>
        {
            new("backup.restore-test", "-", "yes", "2026-10-01", "Restore log reviewed.", "2027-10-01"),
            new("dr.drill", "site-a", "no", null, "Not yet scheduled.", null),
        };
        return new RegisterData(tables, attestations);
    }

    [Fact]
    public void Write_then_read_then_write_is_byte_stable()
    {
        var data = Sample();
        var yaml1 = RegistersConfig.Write("acme", data);
        var read = RegistersConfig.Read(yaml1, "mem", out var client);
        var yaml2 = RegistersConfig.Write(client, read);

        Assert.Equal("acme", client);
        Assert.Equal(yaml1, yaml2);
    }

    [Fact]
    public void Read_recovers_fields_of_every_type()
    {
        var read = RegistersConfig.Read(RegistersConfig.Write(null, Sample()), "mem", out _);
        var licence = read.Tables[Registers.Licence.Table].Single();

        Assert.Equal(50L, licence.Columns["seats"]);
        Assert.Equal(999.0, licence.Columns["cost"]);
        Assert.Equal(1L, licence.Columns["auto_renews"]);
        Assert.Equal("2027-03-31", licence.Columns["expires_on"]);
        Assert.Equal(60L, licence.Columns["notice_days"]);   // default kept when absent

        var candidate = read.Tables[Registers.Vendor.Table].Single(v => v.Id == "beta-mon");
        Assert.Equal("candidate", candidate.Columns["state"]);
        Assert.Equal("site-a", read.Attestations.Single(a => a.Obligation == "dr.drill").Target);
    }

    [Fact]
    public void Export_import_export_through_the_store_is_stable_and_import_is_idempotent()
    {
        var data = Sample();
        var yaml1 = RegistersConfig.Write("acme", data);
        var fromFile = RegistersConfig.Read(yaml1, "file", out var client);

        var expected = 0;
        foreach (var (spec, _) in RegistersConfig.Sections)
            foreach (var record in fromFile.Tables[spec.Table])
            {
                _store.Submit(spec.Kind, RegJson(spec, record));
                expected++;
            }
        foreach (var a in fromFile.Attestations)
        {
            _store.Submit("review.attestation", AttestJson(a));
            expected++;
        }
        var report = _store.Manager().DrainOnce();
        Assert.Equal(expected, report.Done);
        Assert.Equal(0, report.Failed);

        var inStore = FromStore();
        var yaml2 = RegistersConfig.Write(client, inStore);
        Assert.Equal(yaml1, yaml2);

        // Idempotent: every file record matches its store record, so a second import would queue nothing.
        foreach (var (spec, _) in RegistersConfig.Sections)
        {
            var byId = inStore.Tables[spec.Table].ToDictionary(r => r.Id, StringComparer.Ordinal);
            foreach (var record in fromFile.Tables[spec.Table])
                Assert.True(RegistersConfig.Same(spec, record, byId[record.Id]));
        }
    }

    [Fact]
    public void A_record_in_the_store_but_not_in_the_file_is_left_alone()
    {
        _store.Submit("review.vendor", RegJson(Registers.Vendor, Rec(Registers.Vendor, "only-in-store", ("name", "Kept"))));
        Assert.Equal(1, _store.Manager().DrainOnce().Done);

        foreach (var v in Sample().Tables[Registers.Vendor.Table])
            _store.Submit("review.vendor", RegJson(Registers.Vendor, v));
        _store.Manager().DrainOnce();

        Assert.Equal(1L, _store.Scalar("SELECT COUNT(*) FROM vendor WHERE vendor_id = 'only-in-store'"));
    }

    [Theory]
    [InlineData("this: is: not: valid: yaml")]                                              // unparseable
    [InlineData("schema: wrong/9")]                                                         // wrong schema
    [InlineData("schema: keeper.config/1\nvendors: 5")]                                     // section not a list
    [InlineData("schema: keeper.config/1\nvendors:\n  - name: 'V'")]                        // missing id
    [InlineData("schema: keeper.config/1\nvendors:\n  - id: 'v1'")]                         // missing required name
    [InlineData("schema: keeper.config/1\nvendors:\n  - id: 'bad id!'\n    name: 'V'")]     // bad id
    [InlineData("schema: keeper.config/1\nvendors:\n  - id: 'v1'\n    name: 'A'\n  - id: 'v1'\n    name: 'B'")] // duplicate id
    [InlineData("schema: keeper.config/1\nvendors:\n  - id: 'v1'\n    name: 'V'\n    bogus: 1")] // unknown field
    [InlineData("schema: keeper.config/1\nvendors:\n  - id: 'v1'\n    name: 'V'\n    state: maybe")] // bad choice
    [InlineData("schema: keeper.config/1\nlicences:\n  - id: 'l1'\n    product: 'P'\n    seats: lots")] // bad whole number
    [InlineData("schema: keeper.config/1\nlicences:\n  - id: 'l1'\n    product: 'P'\n    expiresOn: soon")] // bad date
    [InlineData("schema: keeper.config/1\nattestations:\n  - state: yes\n    evidence: 'e'")] // attestation missing obligation
    [InlineData("schema: keeper.config/1\nattestations:\n  - obligation: 'Bad Ob'\n    state: yes\n    evidence: 'e'")] // bad obligation
    [InlineData("schema: keeper.config/1\nattestations:\n  - obligation: a.b\n    state: perhaps\n    evidence: 'e'")] // bad state
    [InlineData("schema: keeper.config/1\nattestations:\n  - obligation: a.b\n    state: yes\n    evidence: 'e'\n  - obligation: a.b\n    state: yes\n    evidence: 'e'")] // duplicate
    public void A_malformed_file_throws_config_exception(string yaml)
    {
        var ex = Assert.Throws<ConfigException>(() => RegistersConfig.Read(yaml, "bad.yaml", out _));
        Assert.NotEmpty(ex.Errors);
    }

    [Fact]
    public void A_well_formed_empty_file_reads_as_no_records()
    {
        var read = RegistersConfig.Read("schema: keeper.config/1\n", "mem", out _);
        Assert.All(RegistersConfig.Sections, s => Assert.Empty(read.Tables[s.Spec.Table]));
        Assert.Empty(read.Attestations);
    }

    private RegisterData FromStore()
    {
        var tables = new Dictionary<string, IReadOnlyList<RegisterRecord>>(StringComparer.Ordinal);
        foreach (var (spec, _) in RegistersConfig.Sections)
            tables[spec.Table] = _store.Rows($"SELECT * FROM {spec.Table} ORDER BY {spec.IdColumn}")
                .Select(row =>
                {
                    var columns = new Dictionary<string, object?>(StringComparer.Ordinal);
                    foreach (var field in spec.Fields)
                        columns[field.Column] = row.GetValueOrDefault(field.Column);
                    return new RegisterRecord((string)row[spec.IdColumn]!, columns);
                }).ToList();
        var attestations = _store.Rows("SELECT obligation, target, state, done_on, evidence, expires_on FROM latest_attestation ORDER BY obligation, target")
            .Select(row => new AttestationRecord(
                (string)row["obligation"]!, (string)row["target"]!, (string)row["state"]!,
                row["done_on"] as string, (string)row["evidence"]!, row["expires_on"] as string)).ToList();
        return new RegisterData(tables, attestations);
    }

    private static RegisterRecord Rec(RegisterSpec spec, string id, params (string Column, object? Value)[] values)
    {
        var given = values.ToDictionary(v => v.Column, v => v.Value, StringComparer.Ordinal);
        var columns = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var field in spec.Fields)
            columns[field.Column] = given.TryGetValue(field.Column, out var v) ? v : RegistersConfig.DefaultValue(field);
        return new RegisterRecord(id, columns);
    }

    private static string RegJson(RegisterSpec spec, RegisterRecord record)
    {
        var payload = new JsonObject { ["op"] = "upsert", [spec.IdField] = record.Id };
        foreach (var field in spec.Fields)
        {
            var value = record.Columns.GetValueOrDefault(field.Column);
            if (value is null)
                continue;
            payload[field.Name] = field.Type switch
            {
                FieldType.Bool => JsonValue.Create((long)value == 1L),
                FieldType.Int => JsonValue.Create((long)value),
                FieldType.Real => JsonValue.Create((double)value),
                _ => JsonValue.Create((string)value),
            };
        }
        return payload.ToJsonString();
    }

    private static string AttestJson(AttestationRecord a)
    {
        var payload = new JsonObject
        {
            ["obligation"] = a.Obligation,
            ["target"] = a.Target,
            ["state"] = a.State,
            ["evidence"] = a.Evidence,
        };
        if (a.DoneOn is not null)
            payload["doneOn"] = a.DoneOn;
        if (a.ExpiresOn is not null)
            payload["expiresOn"] = a.ExpiresOn;
        return payload.ToJsonString();
    }
}
