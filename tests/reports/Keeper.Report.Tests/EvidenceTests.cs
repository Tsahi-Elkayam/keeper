using Keeper.Common;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Report.Tests;

public sealed class EvidenceTests : IDisposable
{
    private static readonly MigrationSet[] Schemas = [QueueSchema.Migrations, ReviewComponent.Schema, Ranker.Schema];
    private const string ManifestHash = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-test-").FullName;

    public EvidenceTests()
    {
        using var connection = Db.OpenReadWrite(create: true);
        SchemaManager.Apply(connection, Schemas);
        Sql.Execute(connection,
            $$"""
            INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, refs, source_file, loaded_at) VALUES
                ('R1', 'active-directory', 'Stale accounts', 'misconfigured', 'security', 'IAM', 'medium', 'user', 'ldap', 1440, '["NIST-800-53:AC-2","CIS-Controls-v8:5.3"]', 'builtin:a.yaml', '2026-10-20T00:00:00Z'),
                ('R2', 'active-directory', 'Account reviews', 'missing', 'security', 'IAM', 'low', 'user', 'ldap', 1440, '["NIST-800-53:AC-2"]', 'builtin:a.yaml', '2026-10-20T00:00:00Z'),
                ('R3', 'active-directory', 'Password policy', 'misconfigured', 'security', 'AUT', 'high', 'domain', 'ldap', 1440, '["NIST-800-53:IA-5"]', 'builtin:a.yaml', '2026-10-20T00:00:00Z');
            INSERT INTO run (run_id, instance, system, started_at, finished_at, status, folder, manifest, manifest_sha256, loaded_at)
                VALUES ('20261020-060000-ad', 'ad-1', 'active-directory', '{{Now}}', '{{Now}}', 'ok', 'runs/20261020-060000-ad', '{}', '{{ManifestHash}}', '{{Now}}');
            INSERT INTO result (instance, rule_id, entity_type, entity_key, state, ttl_minutes, at, run_id) VALUES
                ('ad-1', 'R1', 'user', 'u1', 'pass', 1440, '{{Now}}', '20261020-060000-ad'),
                ('ad-1', 'R1', 'user', 'u2', 'fail', 1440, '{{Now}}', '20261020-060000-ad'),
                ('ad-1', 'R2', 'user', 'u1', 'pass', 1440, '{{Now}}', '20261020-060000-ad');
            INSERT INTO system (system_id, name, updated_by, updated_at) VALUES ('SYS1', 'Example', 'test', '{{Now}}');
            INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, kind, lens, category, severity, title,
                                 status, lifecycle, first_seen, last_seen)
                VALUES ('k1', 'ad-1', 'active-directory', 'SYS1', 'R1', 'R1', 'user', 'u2', 'misconfigured', 'security', 'IAM', 'medium', 'Stale accounts',
                        'exception', 'disabled', '{{Now}}', '{{Now}}');
            INSERT INTO override (override_id, check_id, decision, entity, value, actor, at, why)
                VALUES ('OVR-0001', 'R1', 'exception', 'u2', '', 'EXAMPLE\auditor', '{{Now}}', 'Break-glass account, reviewed quarterly');
            INSERT INTO attestation (obligation, target, state, done_on, evidence, expires_on, actor, recorded_at)
                VALUES ('backup.restore-test', '-', 'yes', '2026-10-01', 'Restore of a sample mailbox, ticket 123', '2027-01-01', 'EXAMPLE\ops', '{{Now}}');
            """);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Now => Iso.Utc(DateTimeOffset.UtcNow);

    private string DataDir => Path.Combine(_dir, "data");

    private Database Db => new(Path.Combine(DataDir, "keeper.db"));

    private EvidenceSet Build(string? framework)
    {
        using var connection = Db.OpenReadOnly();
        return EvidenceBuilder.Build(connection, framework, DateTimeOffset.UtcNow);
    }

    [Fact]
    public void A_control_passes_only_when_every_rule_citing_it_ran_and_passed()
    {
        var set = Build("NIST-800-53");

        Assert.All(set.Rows, r => Assert.Equal("NIST-800-53", r.Framework));
        Assert.Equal("failing, risk accepted", set.Rows.Single(r => r.RuleId == "R1").Status);
        Assert.Equal("passing", set.Rows.Single(r => r.RuleId == "R2").Status);
        Assert.Equal("not tested", set.Rows.Single(r => r.RuleId == "R3").Status);
        Assert.Equal(ManifestHash, set.Rows.Single(r => r.RuleId == "R1").ManifestSha256);

        var text = Render.As(EvidenceBuilder.Document(set), "text");
        Assert.Contains("NIST-800-53 AC-2 - failing, risk accepted", text, StringComparison.Ordinal);
        Assert.Contains("NIST-800-53 IA-5 - not tested", text, StringComparison.Ordinal);
        Assert.Contains("OVR-0001: exception R1 for u2", text, StringComparison.Ordinal);
        Assert.Contains("backup.restore-test", text, StringComparison.Ordinal);
    }

    [Fact]
    public void An_evidence_pack_copies_the_cited_scans_and_hashes_every_file()
    {
        var run = Path.Combine(DataDir, "runs", "20261020-060000-ad");
        Directory.CreateDirectory(run);
        File.WriteAllText(Path.Combine(run, "run.json"), "{}");
        File.WriteAllText(Path.Combine(run, "results.jsonl"), "");
        var set = Build(null);
        var pack = Path.Combine(_dir, "pack");

        EvidencePack.Write(pack, set, Render.As(EvidenceBuilder.Document(set), "html"), "html", DataDir);

        Assert.True(File.Exists(Path.Combine(pack, "runs", "20261020-060000-ad", "run.json")));
        var sums = File.ReadAllLines(Path.Combine(pack, "SHA256SUMS.txt"));
        Assert.Contains(sums, l => l.EndsWith("  evidence.jsonl", StringComparison.Ordinal));
        Assert.Contains(sums, l => l.EndsWith("  runs/20261020-060000-ad/run.json", StringComparison.Ordinal));
        foreach (var line in sums)
        {
            var (hash, file) = (line[..64], line[66..]);
            Assert.Equal(hash, Hashing.Sha256File(Path.Combine(pack, file)));
        }
    }

    [Fact]
    public void The_controls_question_rolls_rules_up_to_their_controls()
    {
        var query = ReviewComponent.Questions.Load().Single(q => q.Name == "controls");
        var output = new StringWriter();

        using (var connection = Db.OpenReadOnly())
            Query.QueryRunner.Run(connection, query, new Dictionary<string, string?> { ["framework"] = "NIST-800-53" }, new Query.TableWriter(output));

        var text = output.ToString();
        Assert.Matches(@"NIST-800-53\s+AC-2\s+2\s+2\s+1\s+1\s+0\s+0\s+\S+\s+failing, risk accepted", text);
        Assert.Matches(@"NIST-800-53\s+IA-5\s+1\s+0\s+0\s+0\s+0\s+1\s+.*not tested", text);
    }

    [Fact]
    public void A_control_whose_only_rule_is_not_configured_is_not_tested_never_passing()
    {
        using (var connection = Db.OpenReadWrite())
            Sql.Execute(connection,
                $$"""
                INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, refs, source_file, loaded_at)
                    VALUES ('R4', 'workstations', 'Watched agents', 'misconfigured', 'both', 'MON', 'info', 'service', 'cim', 1440, '["NIST-800-53:SI-4"]', 'builtin:w.yaml', '{{Now}}');
                INSERT INTO result (instance, rule_id, entity_type, entity_key, state, why, ttl_minutes, at, run_id)
                    VALUES ('ad-1', 'R4', 'service', '-', 'n-a', 'not configured: set threshold.workstations.watch-agent-pattern', 1440, '{{Now}}', '20261020-060000-ad');
                """);
        var query = ReviewComponent.Questions.Load().Single(q => q.Name == "controls");
        var output = new StringWriter();

        using (var connection = Db.OpenReadOnly())
            Query.QueryRunner.Run(connection, query, new Dictionary<string, string?> { ["framework"] = "NIST-800-53" }, new Query.TableWriter(output));

        Assert.Matches(@"NIST-800-53\s+SI-4\s+1\s+0\s+0\s+0\s+0\s+1\s+.*not tested", output.ToString());
    }
}
