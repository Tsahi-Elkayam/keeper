using System.Text;
using System.Text.Json;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// One control, one rule, one instance: what was checked, when, with what result, and which scan proves it.
/// The manifest hash names the exact run.json, and run.json carries the hash of every file the scan wrote.
/// </summary>
public sealed record EvidenceRow
{
    public string Schema { get; init; } = "keeper.evidence/1";
    public required string Framework { get; init; }
    public required string Control { get; init; }
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required string System { get; init; }
    public string? Instance { get; init; }
    public required string Status { get; init; }
    public long Pass { get; init; }
    public long Fail { get; init; }
    public long Accepted { get; init; }
    public long Unknown { get; init; }
    public long NotApplicable { get; init; }
    public string? LastTested { get; init; }
    public string? RunId { get; init; }
    public string? RunStartedAt { get; init; }
    public string? ReadAs { get; init; }
    public string? ManifestSha256 { get; init; }
    public string? RunFolder { get; init; }
}

public sealed record AcceptedRisk(string OverrideId, string CheckId, string Decision, string Entity, string Actor, string At, string Why)
{
    /// <summary>The last day the acceptance holds, or null for no end date.</summary>
    public string? Until { get; init; }
}

public sealed record Attested(string Obligation, string Target, string State, string? DoneOn, string Evidence, string? ExpiresOn, string Actor, string RecordedAt);

public sealed record EvidenceSet(string Framework, string GeneratedAt, IReadOnlyList<EvidenceRow> Rows,
    IReadOnlyList<AcceptedRisk> AcceptedRisks, IReadOnlyList<Attested> Attestations);

public static class EvidenceBuilder
{
    public static EvidenceSet Build(SqliteConnection connection, string? framework, DateTimeOffset now)
    {
        var rows = Sql.Rows(connection,
            """
            WITH refs AS (
                SELECT r.rule_id, j.value AS ref,
                       CASE WHEN instr(j.value, ':') > 0 THEN substr(j.value, 1, instr(j.value, ':') - 1) ELSE j.value END AS framework,
                       CASE WHEN instr(j.value, ':') > 0 THEN substr(j.value, instr(j.value, ':') + 1) ELSE '-' END AS control
                FROM rule r, json_each(r.refs) j
            ),
            res AS (
                SELECT rule_id, instance,
                       SUM(state = 'pass') AS pass, SUM(state = 'fail') AS fail, SUM(state = 'unknown') AS unknown, SUM(state = 'n-a') AS na,
                       MAX(at) AS last_tested, MAX(run_id) AS run_id
                FROM result GROUP BY rule_id, instance
            ),
            accepted AS (
                SELECT rule_id, instance, COUNT(*) AS n FROM finding WHERE status IN ('exception', 'disabled') GROUP BY rule_id, instance
            )
            SELECT f.framework, f.control, f.rule_id, ru.title, ru.system, res.instance,
                   res.pass, res.fail, res.unknown, res.na, COALESCE(a.n, 0) AS accepted, res.last_tested,
                   res.run_id, run.started_at, run.identity, run.manifest_sha256, run.folder
            FROM refs f
            JOIN rule ru ON ru.rule_id = f.rule_id
            LEFT JOIN res ON res.rule_id = f.rule_id
            LEFT JOIN accepted a ON a.rule_id = f.rule_id AND a.instance = res.instance
            LEFT JOIN run ON run.run_id = res.run_id
            WHERE (:framework IS NULL OR f.framework = :framework)
            ORDER BY f.framework, f.control, f.rule_id, res.instance;
            """,
            null, (":framework", framework))
            .Select(r =>
            {
                long N(string column) => r[column] as long? ?? 0;
                var ran = r["instance"] is not null;
                var status = !ran ? "not tested"
                    : N("fail") > N("accepted") ? "failing"
                    : N("fail") > 0 ? "failing, risk accepted"
                    : N("unknown") > 0 ? "partly tested"
                    : N("pass") == 0 ? "not applicable"
                    : "passing";
                return new EvidenceRow
                {
                    Framework = (string)r["framework"]!, Control = (string)r["control"]!, RuleId = (string)r["rule_id"]!,
                    Title = (string)r["title"]!, System = (string)r["system"]!, Instance = r["instance"] as string, Status = status,
                    Pass = N("pass"), Fail = N("fail"), Accepted = N("accepted"), Unknown = N("unknown"), NotApplicable = N("na"),
                    LastTested = r["last_tested"] as string, RunId = r["run_id"] as string, RunStartedAt = r["started_at"] as string,
                    ReadAs = r["identity"] as string, ManifestSha256 = r["manifest_sha256"] as string, RunFolder = r["folder"] as string,
                };
            })
            .ToList();

        var risks = Sql.Rows(connection,
            """
            SELECT override_id, check_id, decision, entity, actor, at, why, until FROM override
            WHERE active = 1 AND decision IN ('exception', 'disable') AND (until IS NULL OR until >= :today) ORDER BY at;
            """,
            null, (":today", now.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)))
            .Select(r => new AcceptedRisk((string)r["override_id"]!, (string)r["check_id"]!, (string)r["decision"]!, (string)r["entity"]!,
                (string)r["actor"]!, (string)r["at"]!, (string)r["why"]!) { Until = r["until"] as string })
            .ToList();

        var attested = Sql.Rows(connection,
            "SELECT obligation, target, state, done_on, evidence, expires_on, actor, recorded_at FROM latest_attestation ORDER BY obligation, target;")
            .Select(r => new Attested((string)r["obligation"]!, (string)r["target"]!, (string)r["state"]!, r["done_on"] as string,
                (string)r["evidence"]!, r["expires_on"] as string, (string)r["actor"]!, (string)r["recorded_at"]!))
            .ToList();

        return new EvidenceSet(framework ?? "all", Iso.Utc(now), rows, risks, attested);
    }

    public static Document Document(EvidenceSet set)
    {
        var controls = set.Rows.GroupBy(r => (r.Framework, r.Control)).ToList();
        string StatusOf(IEnumerable<EvidenceRow> rows)
        {
            var list = rows.ToList();
            if (list.Any(r => r.Status == "failing")) return "failing";
            if (list.Any(r => r.Status == "failing, risk accepted")) return "failing, risk accepted";
            if (list.All(r => r.Status == "not tested")) return "not tested";
            if (list.Any(r => r.Status is "partly tested" or "not tested")) return "partly tested";
            return "passing";
        }

        var summary = controls.GroupBy(c => c.Key.Framework)
            .Select(f =>
            {
                var states = f.Select(c => StatusOf(c)).ToList();
                return $"{f.Key}: {states.Count} controls - {states.Count(s => s == "passing")} passing, {states.Count(s => s == "failing")} failing, " +
                       $"{states.Count(s => s == "failing, risk accepted")} failing with risk accepted, {states.Count(s => s == "partly tested")} partly tested, " +
                       $"{states.Count(s => s == "not tested")} not tested";
            })
            .ToList();

        var sections = new List<Section>
        {
            new("Summary", summary, "No rule cites this framework."),
            new("How to read this",
            [
                "Each line is one rule on one source: its results in the newest scan, and the scan that produced them.",
                "The manifest SHA-256 identifies that scan's run.json, which lists the SHA-256 of every file the scan wrote.",
                "Passing means every result passed. Failing with risk accepted means each failure has a recorded exception (see Accepted risks).",
                "Not tested means the rule has never run here; it is not a pass.",
            ]),
        };
        foreach (var control in controls)
        {
            sections.Add(new Section($"{control.Key.Framework} {control.Key.Control} - {StatusOf(control)}",
                control.Select(r => r.Instance is null
                    ? $"[not tested] {r.RuleId} {r.Title}"
                    : $"[{r.Status}] {r.RuleId} {r.Title} - {r.Instance}: {r.Pass} pass, {r.Fail} fail" +
                      $"{(r.Accepted > 0 ? $" ({r.Accepted} accepted)" : "")}, {r.Unknown} unknown, {r.NotApplicable} n/a; " +
                      $"tested {r.LastTested} in run {r.RunId ?? "(not kept)"}{(r.ReadAs is null ? "" : $" as {r.ReadAs}")}" +
                      $"{(r.ManifestSha256 is null ? "" : $", manifest SHA-256 {r.ManifestSha256}")}")
                    .ToList()));
        }
        sections.Add(new Section("Accepted risks",
            set.AcceptedRisks.Select(a => $"{a.OverrideId}: {a.Decision} {a.CheckId}{(a.Entity.Length > 0 ? $" for {a.Entity}" : "")} - by {a.Actor} on {a.At}" +
                $"{(a.Until is null ? ", no end date" : $", until {a.Until}")}: {a.Why}").ToList(),
            "No exceptions or disabled rules."));
        sections.Add(new Section("Attestations (evidence people recorded)",
            set.Attestations.Select(a => $"{a.Obligation} / {a.Target}: {a.State}{(a.DoneOn is null ? "" : $", done {a.DoneOn}")}" +
                $"{(a.ExpiresOn is null ? "" : $", valid until {a.ExpiresOn}")} - {a.Evidence} (recorded by {a.Actor} on {a.RecordedAt})").ToList(),
            "No attestations recorded."));

        return new Document($"Control evidence - {set.Framework}", $"Generated {set.GeneratedAt} from the Keeper store.", sections);
    }
}

/// <summary>
/// An evidence pack: a folder an auditor can check without Keeper. The report, the evidence as JSON Lines,
/// a copy of every cited scan's run.json and results (when the run folder still exists), and SHA256SUMS.txt
/// over all of it.
/// </summary>
public static class EvidencePack
{
    public static string Write(string folder, EvidenceSet set, string report, string reportExtension, string dataDir)
    {
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, $"evidence.{reportExtension}"), report, new UTF8Encoding(false));
        using (var writer = new JsonLinesWriter(Path.Combine(folder, "evidence.jsonl")))
        {
            foreach (var row in set.Rows)
                writer.Write(row);
        }
        File.WriteAllText(Path.Combine(folder, "accepted-risks.json"), JsonSerializer.Serialize(set.AcceptedRisks, JsonLines.Options));
        File.WriteAllText(Path.Combine(folder, "attestations.json"), JsonSerializer.Serialize(set.Attestations, JsonLines.Options));

        var missing = new List<string>();
        foreach (var run in set.Rows.Where(r => r.RunId is not null && r.RunFolder is not null).DistinctBy(r => r.RunId))
        {
            var source = PathGuard.Resolve(dataDir, run.RunFolder!);
            if (!Directory.Exists(source))
            {
                missing.Add($"{run.RunId}: run folder pruned; manifest SHA-256 recorded at load {run.ManifestSha256}");
                continue;
            }
            var target = Path.Combine(folder, "runs", run.RunId!);
            Directory.CreateDirectory(target);
            foreach (var file in new[] { RunFolder.Manifest, RunFolder.Results, RunFolder.Coverage, RunFolder.Findings })
            {
                if (File.Exists(Path.Combine(source, file)))
                    File.Copy(Path.Combine(source, file), Path.Combine(target, file));
            }
        }

        File.WriteAllLines(Path.Combine(folder, "README.txt"),
        [
            $"Keeper evidence pack - {set.Framework} - generated {set.GeneratedAt}",
            "",
            "evidence.*            the report: per control, each rule's results and the scan that produced them",
            "evidence.jsonl        the same, one keeper.evidence/1 record per control, rule and source",
            "accepted-risks.json   exceptions and disabled rules in force, with who, when and why",
            "attestations.json     evidence people recorded (restore tests, reviews), with expiry",
            "runs\\<run>\\          each cited scan's run.json and results, copied as they were",
            "SHA256SUMS.txt        SHA-256 of every file above",
            "",
            "To verify: Get-FileHash -Algorithm SHA256 <file> for each line of SHA256SUMS.txt; then check that each",
            "runs\\<run>\\run.json has the manifest SHA-256 named in evidence.jsonl, and that the files it lists match.",
            .. missing.Count == 0 ? Array.Empty<string>() : ["", "Runs no longer on disk (their manifest hash is still in evidence.jsonl):", .. missing],
        ]);

        var sums = Directory.GetFiles(folder, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.Ordinal)
            .Select(f => $"{Hashing.Sha256File(f)}  {Path.GetRelativePath(folder, f).Replace('\\', '/')}");
        File.WriteAllLines(Path.Combine(folder, "SHA256SUMS.txt"), sums);
        return folder;
    }
}
