using Keeper.Query;

namespace Keeper.Review.Tests;

/// <summary>
/// The three questions - correct, should be configured, broken - and the honesty bound on the first: a check is
/// correct only when it passed everywhere in a clean, fresh read of the newest scan.
/// </summary>
public sealed class StandingTests : IDisposable
{
    private readonly TempStore _store = new();

    public StandingTests()
    {
        _store.Seed(
            """
            INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, source_file, loaded_at)
            VALUES ('OK-1', 'example', 'Weak setting', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('FAIL-1', 'example', 'Setting missing', 'missing', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('BRK-1', 'example', 'Service down', 'broken', 'maintenance', 'HLT', 'critical', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('PART-1', 'example', 'Read partly', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('UNK-1', 'example', 'One host unread', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('STALE-1', 'example', 'Old result', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 60, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('GONE-1', 'example', 'Failed on a host since gone', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('NA-1', 'example', 'Needs a setting', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('NONE-1', 'example', 'Nothing to judge', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('THR-1', 'example', 'Admin count high', 'misconfigured', 'security', 'IAM', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z'),
                   ('NEVER-1', 'example', 'Never ran', 'misconfigured', 'maintenance', 'CFG', 'high', 'host', 'cim', 1440, 'builtin:example.yaml', '2026-10-01T00:00:00Z');

            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, loaded_at)
            VALUES ('R0', 'ex-main', 'example', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-2 days'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-2 days'), 'ok', 'r0', '{}', '2026-10-01T00:00:00Z'),
                   ('R1', 'ex-main', 'example', strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'partial', 'r1', '{}', '2026-10-01T00:00:00Z');

            INSERT INTO coverage (run_id, scope, item, state, reason, count, observed_at)
            SELECT 'R1', 'rule', rule_id, CASE rule_id WHEN 'PART-1' THEN 'partial' WHEN 'NA-1' THEN 'not-applicable' ELSE 'ok' END,
                   CASE rule_id WHEN 'PART-1' THEN 'returned 2 row(s); this query always returns at least 10' END, 2, '2026-10-01T00:00:00Z'
            FROM rule WHERE rule_id <> 'NEVER-1';

            INSERT INTO result (instance, rule_id, entity_type, entity_key, state, ttl_minutes, at, run_id)
            VALUES ('ex-main', 'OK-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'OK-1', 'host', 'h2', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'FAIL-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'FAIL-1', 'host', 'h2', 'fail', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'BRK-1', 'host', 'h1', 'fail', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'PART-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'UNK-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'UNK-1', 'host', 'h2', 'unknown', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'STALE-1', 'host', 'h1', 'pass', 60, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'GONE-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'GONE-1', 'host', 'old', 'fail', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-2 days'), 'R0'),
                   ('ex-main', 'NA-1', 'host', '-', 'n-a', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'NONE-1', 'host', 'h1', 'n-a', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1'),
                   ('ex-main', 'THR-1', 'host', 'h1', 'pass', 1440, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-3 hours'), 'R1');

            INSERT INTO override (override_id, check_id, decision, value, actor, at, why)
            VALUES ('OVR-0001', 'THR-*', 'threshold', '5', 'test', '2026-10-01T00:00:00Z', 'five admins is the agreed number');
            """);
    }

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

    [Fact]
    public void Each_check_gets_one_standing_and_only_clean_fresh_complete_passes_are_correct()
    {
        var standing = _store.Rows("SELECT rule_id, standing FROM rule_standing ORDER BY rule_id;")
            .ToDictionary(r => (string)r["rule_id"]!, r => (string)r["standing"]!);

        Assert.Equal("correct", standing["OK-1"]);
        Assert.Equal("should-configure", standing["FAIL-1"]);
        Assert.Equal("broken", standing["BRK-1"]);
        Assert.Equal("not-checked", standing["PART-1"]);    // a partial read is never a pass
        Assert.Equal("not-checked", standing["UNK-1"]);     // one host unread
        Assert.Equal("not-checked", standing["STALE-1"]);   // older than its refresh interval
        Assert.Equal("correct", standing["GONE-1"]);        // the old run's failure on a gone host does not count
        Assert.Equal("not-checked", standing["NA-1"]);      // its setting is not configured
        Assert.Equal("not-applicable", standing["NONE-1"]); // nothing to judge is not correct
        Assert.Equal("correct", standing["THR-1"]);
        Assert.False(standing.ContainsKey("NEVER-1"));
    }

    [Fact]
    public void Correct_lists_the_passing_checks_and_names_a_changed_threshold()
    {
        var correct = Ask("correct");

        Assert.Equal(new object?[] { "GONE-1", "OK-1", "THR-1" }, correct.Column("rule_id"));
        Assert.Equal(new object?[] { null, null, "OVR-0001" }, correct.Column("threshold_override"));
        Assert.Equal(2L, correct.Column("judged")[1]);
        Assert.Equal(new object?[] { "THR-1" }, Ask("correct", ("security", "1")).Column("rule_id"));
    }

    [Fact]
    public void Posture_counts_every_bucket_including_what_did_not_run()
    {
        var posture = Ask("posture");

        Assert.Single(posture.Values);
        Assert.Equal(3L, posture.Column("correct")[0]);
        Assert.Equal(1L, posture.Column("should_configure")[0]);
        Assert.Equal(1L, posture.Column("broken")[0]);
        Assert.Equal(4L, posture.Column("not_checked")[0]);
        Assert.Equal(1L, posture.Column("not_applicable")[0]);
        Assert.Equal(1L, posture.Column("not_run")[0]);
    }

    [Fact]
    public void Why_not_correct_says_what_kept_a_check_out()
    {
        var why = _store.Rows("SELECT rule_id, why_not_correct FROM rule_standing WHERE standing = 'not-checked' ORDER BY rule_id;")
            .ToDictionary(r => (string)r["rule_id"]!, r => (string?)r["why_not_correct"]);

        Assert.StartsWith("read partial: returned 2 row(s)", why["PART-1"], StringComparison.Ordinal);
        Assert.StartsWith("1 result(s) unknown", why["UNK-1"], StringComparison.Ordinal);
        Assert.StartsWith("the newest result is older", why["STALE-1"], StringComparison.Ordinal);
        Assert.StartsWith("read not-applicable", why["NA-1"], StringComparison.Ordinal);
    }
}
