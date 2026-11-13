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

        foreach (var question in new[] { "correct", "posture", "broken", "misconfigured", "missing", "blind-spots", "changed", "inventory", "expiring", "licences", "rules", "history", "printers" })
            Assert.Contains(question, names);
    }

    [Fact]
    public void Printers_shows_each_one_with_what_was_learned_from_all_its_reads_and_the_pages_printed()
    {
        _store.Seed("""
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES ('r-net', 'office', 'printers', '2026-10-24T10:00:00Z', '2026-10-24T10:01:00Z', 'ok', 'r-net', '{}', '2026-10-24T10:02:00Z'),
                   ('r-loc', 'host', 'printers-local', '2026-10-24T10:00:00Z', '2026-10-24T10:01:00Z', 'ok', 'r-loc', '{}', '2026-10-24T10:02:00Z'),
                   ('r-old', 'office', 'printers', '2026-10-01T10:00:00Z', '2026-10-01T10:01:00Z', 'ok', 'r-old', '{}', '2026-10-01T10:02:00Z');
            INSERT INTO row_seen (run_id, query, entity_type, entity_key, attrs, observed_at) VALUES
              ('r-net', 'q-ports', 'printer', '192.0.2.50', '{"host":"192.0.2.50","telnet":false,"openPorts":[80,631]}', '2026-10-24T10:00:30Z'),
              ('r-net', 'q-ipp', 'printer', '192.0.2.50', '{"host":"192.0.2.50","printer-make-and-model":"HP LaserJet Pro M404","printer-firmware-string-version":"20240612","printer-state":3}', '2026-10-24T10:00:31Z'),
              ('r-net', 'q-info', 'printer', '192.0.2.50', '{"host":"192.0.2.50","model":"HP LaserJet Pro M404dn","serialNumber":"PHBXY12345","status":"idle","pageCount":123456,"pageCountUnit":"sheets","sysLocation":"Reception"}', '2026-10-24T10:00:32Z'),
              ('r-old', 'q-info', 'printer', '192.0.2.99', '{"host":"192.0.2.99","model":"Retired printer","pageCount":1}', '2026-10-01T10:00:00Z'),
              ('r-loc', 'q-queues', 'queue', 'desk-pc|Reception_USB', '{"host":"desk-pc","name":"Reception_USB","scheme":"usb","usb":true,"network":false,"vendor":"HP","model":"LaserJet 1018","serial":"ABC123","state":"idle"}', '2026-10-24T10:00:33Z'),
              ('r-loc', 'q-queues', 'queue', 'desk-pc|Shared_Net', '{"host":"desk-pc","name":"Shared_Net","scheme":"ipps","usb":false,"network":true,"deviceUri":"ipps://print.example.org/ipp/print","state":"printing"}', '2026-10-24T10:00:33Z'),
              ('r-loc', 'q-pages', 'printer-usage', 'desk-pc|Reception_USB', '{"host":"desk-pc","name":"Reception_USB","pages":2210,"jobs":300,"users":4,"lastPrinted":"2026-10-23T16:00:00Z"}', '2026-10-24T10:00:34Z');
            """);

        var all = Ask("printers");

        Assert.Equal(["network", "usb", "queue"], all.Column("kind").Select(k => k!.ToString()!).ToArray());
        var network = all.Values[0];
        Assert.Equal("HP LaserJet Pro M404dn", network[all.Names.IndexOf("model")]);          // the SNMP model wins over the IPP make-and-model
        Assert.Equal("PHBXY12345", network[all.Names.IndexOf("serial")]);
        Assert.Equal("20240612", network[all.Names.IndexOf("firmware")]);
        Assert.Equal("idle", network[all.Names.IndexOf("state")]);
        Assert.Equal(123456L, network[all.Names.IndexOf("pages_printed")]);
        Assert.Equal("sheets", network[all.Names.IndexOf("pages_unit")]);
        var usb = all.Values[1];
        Assert.Equal("HP LaserJet 1018", usb[all.Names.IndexOf("model")]);
        Assert.Equal("ABC123", usb[all.Names.IndexOf("serial")]);
        Assert.Equal(2210L, usb[all.Names.IndexOf("pages_printed")]);
        Assert.Equal("pages sent from this computer", usb[all.Names.IndexOf("pages_unit")]);
        Assert.Null(all.Values[2][all.Names.IndexOf("pages_printed")]);                       // no page log for that queue: unknown, not zero
        Assert.DoesNotContain("Retired printer", all.Column("model").Select(m => m?.ToString() ?? ""));   // only the newest scan of each system
    }

    [Fact]
    public void Printers_can_be_narrowed_to_usb_ones()
    {
        _store.Seed("""
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES ('r1', 'host', 'printers-local', '2026-10-24T10:00:00Z', '2026-10-24T10:01:00Z', 'ok', 'r1', '{}', '2026-10-24T10:02:00Z');
            INSERT INTO row_seen (run_id, query, entity_type, entity_key, attrs, observed_at) VALUES
              ('r1', 'q', 'queue', 'a|U', '{"host":"a","name":"U","usb":true,"vendor":"HP","model":"X","state":"idle"}', '2026-10-24T10:00:00Z'),
              ('r1', 'q', 'queue', 'a|N', '{"host":"a","name":"N","usb":false,"network":true,"deviceUri":"ipp://x","state":"idle"}', '2026-10-24T10:00:00Z');
            """);

        Assert.Equal(["usb"], Ask("printers", ("kind", "usb")).Column("kind").Select(k => k!.ToString()!).ToArray());
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
