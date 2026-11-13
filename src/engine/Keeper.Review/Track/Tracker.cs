using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Review.Track;

/// <summary>
/// Turns the newest scans into the register: maps entities to systems, and gives every finding its
/// lifecycle. A finding resolves only when its rule passed on that entity, or the entity is gone and
/// the rule ran cleanly - never because a scan simply did not report it.
/// </summary>
public sealed class Tracker(SqliteConnection connection, TimeProvider? clock = null)
{
    private const int DefaultTtlMinutes = 7 * 24 * 60;
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public RegisterFile Build(string buildId)
    {
        var now = Iso.Utc(_clock.GetUtcNow());
        var runs = Sql.Rows(connection, "SELECT run_id, instance, system, status, started_at FROM latest_run;");
        var usable = runs.Where(r => (string)r["status"]! != "failed").ToList();
        var systemRules = LoadSystemRules();

        var entities = MapEntities(usable, systemRules, now);
        var entityIndex = entities.ToDictionary(e => (e.Instance, e.EntityType, e.EntityKey), e => e);

        var events = new List<EventRow>();
        var findings = TrackFindings(usable, entityIndex, systemRules, events, now);

        return new RegisterFile
        {
            BuildId = buildId,
            At = now,
            Findings = findings,
            Events = events,
            Entities = entities,
            Counts = new Dictionary<string, int>
            {
                ["runs"] = runs.Count,
                ["entities"] = entities.Count,
                ["findings"] = findings.Count,
                ["new"] = events.Count(e => e.Event == "new"),
                ["reopened"] = events.Count(e => e.Event == "reopened"),
                ["resolved"] = events.Count(e => e.Event == "resolved"),
                ["stale"] = events.Count(e => e.Event == "stale"),
            },
        };
    }

    // ---- entities -------------------------------------------------------------

    private sealed record SystemRule(string RuleId, string Instance, string EntityType, string Field, Regex Pattern, string SystemId);

    private List<SystemRule> LoadSystemRules() =>
        Sql.Rows(connection, "SELECT rule_id, instance, entity_type, field, pattern, system_id FROM system_rule ORDER BY ord, rule_id;")
            .Select(r => new SystemRule((string)r["rule_id"]!, (string)r["instance"]!, (string)r["entity_type"]!, (string)r["field"]!,
                new Regex((string)r["pattern"]!, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)),
                (string)r["system_id"]!))
            .ToList();

    /// <summary>
    /// Keeper's own rules (system 'keeper') are about Keeper. Other rules over Keeper's registers (instance
    /// 'keeper') belong to the system the register row names, or else to the organisation. Anything else no
    /// rule claims is unmapped.
    /// </summary>
    private (string SystemId, string MappedBy) Unclaimed(string instance, string ruleSystem, JsonObject? attrs)
    {
        if (ruleSystem.Equals("keeper", StringComparison.OrdinalIgnoreCase))
            return ("KEEPER", "builtin");
        if (!instance.Equals("keeper", StringComparison.OrdinalIgnoreCase))
            return ("UNMAPPED", "unmapped");
        var named = attrs is null ? null : Lookup(attrs, "system_id");
        _systems ??= Sql.Rows(connection, "SELECT system_id FROM system;").Select(r => (string)r["system_id"]!).ToHashSet(StringComparer.Ordinal);
        return named is not null && _systems.Contains(named) && named != "UNMAPPED" ? (named, "register") : ("ORG", "builtin");
    }

    private HashSet<string>? _systems;

    private (string SystemId, string MappedBy) MapSystem(IEnumerable<SystemRule> rules, string instance, string entityType,
        string key, string? name, JsonObject? attrs, string ruleSystem)
    {
        foreach (var rule in rules)
        {
            if (rule.Instance != "*" && !rule.Instance.Equals(instance, StringComparison.OrdinalIgnoreCase))
                continue;
            if (rule.EntityType != "*" && !rule.EntityType.Equals(entityType, StringComparison.OrdinalIgnoreCase))
                continue;

            var value = rule.Field switch
            {
                "key" => key,
                "name" => name,
                "instance" => instance,
                _ => attrs is null ? null : Lookup(attrs, rule.Field),
            };
            try
            {
                if (value is not null && rule.Pattern.IsMatch(value))
                    return (rule.SystemId, "rule:" + rule.RuleId);
            }
            catch (RegexMatchTimeoutException)
            {
                // A pathological pattern never maps anything; the entity stays unmapped.
            }
        }
        return Unclaimed(instance, ruleSystem, attrs);
    }

    private static string? Lookup(JsonObject attrs, string path)
    {
        JsonNode? node = attrs;
        foreach (var part in path.Split('.'))
        {
            node = node is JsonObject o && o.TryGetPropertyValue(part, out var next) ? next : null;
            if (node is null)
                return null;
        }
        return node is JsonValue v ? v.ToString() : node.ToJsonString();
    }

    private List<EntityRow> MapEntities(List<Dictionary<string, object?>> runs, List<SystemRule> systemRules, string now)
    {
        var existing = Sql.Rows(connection, "SELECT * FROM entity;")
            .ToDictionary(r => ((string)r["instance"]!, (string)r["entity_type"]!, (string)r["entity_key"]!), r => r);
        var result = new Dictionary<(string, string, string), EntityRow>();

        // Every run's rows first: an entity any of these scans returned is not gone, whatever the run order.
        foreach (var run in runs)
        {
            var runId = (string)run["run_id"]!;
            var instance = (string)run["instance"]!;
            var system = (string)run["system"]!;

            foreach (var row in Sql.Rows(connection,
                         "SELECT entity_type, entity_key, MAX(entity_name) AS entity_name, MAX(attrs) AS attrs FROM row_seen WHERE run_id = :r GROUP BY entity_type, entity_key;",
                         null, (":r", runId)))
            {
                var key = (instance, (string)row["entity_type"]!, (string)row["entity_key"]!);
                var attrs = JsonNode.Parse((string)row["attrs"]!) as JsonObject;
                var name = row["entity_name"] as string;
                var (systemId, mappedBy) = MapSystem(systemRules, instance, key.Item2, key.Item3, name, attrs, system);
                existing.TryGetValue(key, out var before);
                result[key] = new EntityRow
                {
                    Instance = instance,
                    EntityType = key.Item2,
                    EntityKey = key.Item3,
                    EntityName = name,
                    SystemId = systemId,
                    MappedBy = mappedBy,
                    FirstSeen = before?["first_seen"] as string ?? now,
                    LastSeen = now,
                    GoneSince = null,
                    SeenBy = system,
                };
            }
        }

        // Entities none of the newest scans returned. One is gone only when every read that ever returned it - each
        // rule system, query and host - read cleanly without it in that system's newest scan. A failed or
        // partial read says nothing about its entities, and no longer hides every other read's.
        // Two runs of one system started in the same second: the later id (…-2) is the later run.
        var newest = runs.GroupBy(r => ((string)r["instance"]!, (string)r["system"]!))
            .ToDictionary(g => g.Key, g => g.MaxBy(r => (string)r["run_id"]!, StringComparer.Ordinal)!);
        var instances = runs.Select(r => (string)r["instance"]!).ToHashSet(StringComparer.Ordinal);
        foreach (var (key, before) in existing.Where(e => instances.Contains(e.Key.Item1) && !result.ContainsKey(e.Key)))
        {
            if (before["gone_since"] is null && !ReadCleanlyWithout(key, before["seen_by"] as string, newest))
                continue;
            result[key] = new EntityRow
            {
                Instance = key.Item1,
                EntityType = key.Item2,
                EntityKey = key.Item3,
                EntityName = before["entity_name"] as string,
                SystemId = (string)before["system_id"]!,
                MappedBy = (string)before["mapped_by"]!,
                FirstSeen = (string)before["first_seen"]!,
                LastSeen = (string)before["last_seen"]!,
                GoneSince = before["gone_since"] as string ?? now,
                SeenBy = before["seen_by"] as string,
            };
        }
        return result.Values.ToList();
    }

    /// <summary>
    /// What one run read: the reads that came back clean, every read it made (query-wide records included), and
    /// the per-host queries that read at least one host cleanly.
    /// </summary>
    private sealed record RunReads(HashSet<string> Clean, HashSet<string> Attempted, HashSet<string> CleanPerHostQueries, bool WholeRunClean);

    private readonly Dictionary<string, RunReads> _reads = new(StringComparer.Ordinal);

    private RunReads ReadsOf(Dictionary<string, object?> run)
    {
        var runId = (string)run["run_id"]!;
        if (_reads.TryGetValue(runId, out var known))
            return known;
        var rows = Sql.Rows(connection, "SELECT scope, item, state FROM coverage WHERE run_id = :r AND scope IN ('query', 'target');", null, (":r", runId));
        var reads = new RunReads(
            rows.Where(r => (string)r["state"]! == "ok").Select(r => (string)r["item"]!).ToHashSet(StringComparer.OrdinalIgnoreCase),
            rows.Select(r => (string)r["item"]!).ToHashSet(StringComparer.OrdinalIgnoreCase),
            rows.Where(r => (string)r["scope"]! == "target" && (string)r["state"]! == "ok" && ((string)r["item"]!).Contains('@', StringComparison.Ordinal))
                .Select(r => ((string)r["item"]!).Split('@', 2)[0]).ToHashSet(StringComparer.Ordinal),
            (string)run["status"]! == "ok");
        _reads[runId] = reads;
        return reads;
    }

    /// <summary>
    /// A host is retired from a per-host query when the newest scan read that query - at least one host cleanly,
    /// from a host list nothing casts doubt on (no query-wide record beside the hosts') - but no longer tried the
    /// host at all (a decommissioned PC, a server that left the workstation list).
    /// </summary>
    private static bool Retired(RunReads reads, string query, string host) =>
        reads.CleanPerHostQueries.Contains(query) && !reads.Attempted.Contains(query) && !reads.Attempted.Contains(RunFolder.CoverageItem(query, host));

    private readonly Dictionary<(string, string, string), HashSet<string>> _knownHosts = [];

    /// <summary>Every host this system's retained scans through this integration ever read with this query.</summary>
    private HashSet<string> KnownHosts(string instance, string system, string query)
    {
        if (_knownHosts.TryGetValue((instance, system, query), out var hosts))
            return hosts;
        hosts = Sql.Rows(connection,
                """
                SELECT DISTINCT substr(c.item, length(:q) + 2) AS host FROM coverage c JOIN run r ON r.run_id = c.run_id
                WHERE r.instance = :i AND r.system = :s AND c.scope = 'target' AND substr(c.item, 1, length(:q) + 1) = :q || '@';
                """,
                null, (":i", instance), (":s", system), (":q", query))
            .Select(r => (string)r["host"]!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _knownHosts[(instance, system, query)] = hosts;
        return hosts;
    }

    private Dictionary<string, string>? _ruleQueries;

    /// <summary>The query a rule reads, from the catalogue (null for a catalogue loaded before review 7).</summary>
    private string? QueryOf(string ruleId)
    {
        _ruleQueries ??= Sql.Rows(connection, "SELECT rule_id, query_id FROM rule WHERE query_id IS NOT NULL;")
            .ToDictionary(r => (string)r["rule_id"]!, r => (string)r["query_id"]!, StringComparer.Ordinal);
        return _ruleQueries.GetValueOrDefault(ruleId);
    }

    /// <summary>
    /// Every read that returned this entity (rule system, query, host) read cleanly without it in that system's
    /// newest scan. A host the scan no longer reads at all, while it read the query's other hosts, is retired
    /// (a decommissioned PC). A query the newest scan did not run at all (removed from the rules) counts only
    /// when that whole scan was clean. With no read on record (its runs were pruned), the entity's own system's
    /// newest scan must have been clean throughout.
    /// </summary>
    private bool ReadCleanlyWithout((string Instance, string Type, string Key) entity, string? seenBy,
        Dictionary<(string, string), Dictionary<string, object?>> newest)
    {
        var sources = Sql.Rows(connection,
            """
            SELECT DISTINCT r.system, rs.query, rs.target FROM row_seen rs JOIN run r ON r.run_id = rs.run_id
            WHERE r.instance = :i AND rs.entity_type = :t AND rs.entity_key = :k;
            """,
            null, (":i", entity.Instance), (":t", entity.Type), (":k", entity.Key));
        // The system that last returned it, even when its rows of the entity were pruned: its newest scan must
        // have been clean throughout.
        if (seenBy is not null && !sources.Any(s => (string)s["system"]! == seenBy)
            && !(newest.TryGetValue((entity.Instance, seenBy), out var own) && ReadsOf(own).WholeRunClean))
            return false;
        if (sources.Count == 0)
            return seenBy is not null;

        foreach (var source in sources)
        {
            if (!newest.TryGetValue((entity.Instance, (string)source["system"]!), out var run))
                return false;   // that system's newest scan failed: it says nothing
            var reads = ReadsOf(run);
            var query = (string)source["query"]!;
            var target = source["target"] as string;
            var item = RunFolder.CoverageItem(query, target);
            if (reads.Clean.Contains(item))
                continue;
            if (reads.Attempted.Contains(item))
                return false;   // read, but not cleanly
            if (!(target is not null && Retired(reads, query, target)) && !reads.WholeRunClean)
                return false;
        }
        return true;
    }

    // ---- findings ------------------------------------------------------------

    private sealed record Override(string CheckPattern, string Decision, string Entity, string? Until)
    {
        /// <summary>In force through its until day (yyyy-MM-dd), or for good.</summary>
        public bool InForce(string now) => Until is null || string.CompareOrdinal(Until, now[..10]) >= 0;

        public bool Covers(FindingRecord r) => Covers(r.CheckId, r.RuleId, r.Target);

        public bool Covers(string checkId, string ruleId, string target) => MatchesCheck(checkId, ruleId)
            && (Decision == "disable" || Entity.Equals(target, StringComparison.OrdinalIgnoreCase));

        /// <summary>The finding's status under the decisions in force: a disabled rule first, then an exception.</summary>
        public static string StatusUnder(List<Override> overrides, string now, string checkId, string ruleId, string target) =>
            overrides.Any(o => o.Decision == "disable" && o.InForce(now) && o.Covers(checkId, ruleId, target)) ? "disabled"
            : overrides.Any(o => o.Decision == "exception" && o.InForce(now) && o.Covers(checkId, ruleId, target)) ? "exception"
            : "open";

        public bool MatchesCheck(string checkId, string ruleId) => Matches(checkId) || Matches(ruleId);

        private bool Matches(string id) =>
            CheckPattern.EndsWith('*')
                ? id.StartsWith(CheckPattern[..^1], StringComparison.OrdinalIgnoreCase)
                : id.Equals(CheckPattern, StringComparison.OrdinalIgnoreCase);
    }

    private List<FindingRow> TrackFindings(List<Dictionary<string, object?>> runs,
        Dictionary<(string, string, string), EntityRow> entities, List<SystemRule> systemRules, List<EventRow> events, string now)
    {
        // Lapsed ones too: a finding an override no longer covers says when its exception ended.
        var overrides = Sql.Rows(connection, "SELECT check_id, decision, entity, until FROM override WHERE active = 1 AND decision IN ('disable', 'exception');")
            .Select(r => new Override((string)r["check_id"]!, (string)r["decision"]!, (string)r["entity"]!, r["until"] as string))
            .ToList();
        var existing = Sql.Rows(connection, "SELECT * FROM finding;").ToDictionary(r => (string)r["finding_key"]!, r => r);
        var touched = new Dictionary<string, FindingRow>();

        // Every run's reports first, so no other run's silence can overwrite them.
        var reportedKeys = new HashSet<string>();
        foreach (var run in runs)
        {
            var runId = (string)run["run_id"]!;
            foreach (var raw in Sql.Rows(connection, "SELECT record FROM reported WHERE run_id = :r;", null, (":r", runId)))
            {
                var record = JsonSerializer.Deserialize<FindingRecord>((string)raw["record"]!, JsonLines.Options)!;
                reportedKeys.Add(record.FindingKey);
                existing.TryGetValue(record.FindingKey, out var before);
                touched[record.FindingKey] = Present(record, before, entities, systemRules, overrides, runId, events, now);
            }
        }

        foreach (var run in runs)
        {
            var instance = (string)run["instance"]!;
            var system = (string)run["system"]!;
            var startedAt = (string)run["started_at"]!;

            // Open findings of this instance and rule system that the newest scan did not report. Another rule
            // system reading through the same integration says nothing about them.
            foreach (var (key, before) in existing.Where(e =>
                         (string)e.Value["instance"]! == instance && (string)e.Value["system"]! == system
                         && (string)e.Value["status"]! == "open" && !reportedKeys.Contains(e.Key)))
            {
                if (string.CompareOrdinal((string)before["last_seen"]!, startedAt) > 0)
                    continue;   // seen by something newer than this run
                var absent = Absent(before, entities, run, events, now);
                if (absent is not null)
                    touched[key] = absent;
            }
        }

        foreach (var (key, before) in existing.Where(e => !touched.ContainsKey(e.Key) && (string)e.Value["status"]! == "open"))
        {
            var claimed = ClaimedFixed(before, events, now);
            if (claimed is not null)
                touched[key] = claimed;
        }

        // A decision that ended - its until day passed, or it was undone - gives its findings back even when no
        // scan has reported them since: the last thing known about them is that they fail. Without this an
        // unscanned entity would stay "accepted" in the evidence long after the acceptance ran out.
        foreach (var (key, before) in existing.Where(e => !touched.ContainsKey(e.Key) && (string)e.Value["status"]! is "exception" or "disabled"))
        {
            var (checkId, ruleId, target) = ((string)before["check_id"]!, (string)before["rule_id"]!, (string)before["target"]!);
            var status = Override.StatusUnder(overrides, now, checkId, ruleId, target);
            if (status == (string)before["status"]!)
                continue;
            if (status != "open")
            {
                events.Add(new EventRow(key, now, status == "disabled" ? "disabled" : "exception", null, null, "by decision"));
                touched[key] = Copy(before) with { Status = status, Lifecycle = "disabled" };
                continue;
            }
            var lapsed = overrides.Where(o => !o.InForce(now) && o.Covers(checkId, ruleId, target)).MaxBy(o => o.Until);
            events.Add(new EventRow(key, now, "reopened", null, null,
                (lapsed is null ? "the decision was removed" : $"the {(lapsed.Decision == "disable" ? "disabled rule" : "exception")} ended on {lapsed.Until}")
                + $"; not scanned since {before["last_seen"]}"));
            touched[key] = Copy(before) with { Status = "open", Lifecycle = "reopened" };
        }
        return touched.Values.ToList();
    }

    private FindingRow Present(FindingRecord r, Dictionary<string, object?>? before,
        Dictionary<(string, string, string), EntityRow> entities, List<SystemRule> systemRules, List<Override> overrides,
        string runId, List<EventRow> events, string now)
    {
        var status = Override.StatusUnder(overrides, now, r.CheckId, r.RuleId, r.Target);
        var previousStatus = before?["status"] as string;
        var previousLifecycle = before?["lifecycle"] as string;

        string lifecycle;
        if (status != "open")
        {
            lifecycle = "disabled";
            if (previousStatus != status)
                events.Add(new EventRow(r.FindingKey, now, status == "disabled" ? "disabled" : "exception", runId, null, "by decision"));
        }
        else if (before is null)
        {
            lifecycle = "new";
            events.Add(new EventRow(r.FindingKey, now, "new", runId, null, null));
        }
        else if (previousStatus is "resolved" or "disabled" or "exception")
        {
            lifecycle = "reopened";
            var lapsed = previousStatus is "disabled" or "exception"
                ? overrides.Where(o => !o.InForce(now) && o.Covers(r)).MaxBy(o => o.Until) : null;
            events.Add(new EventRow(r.FindingKey, now, "reopened", runId, null,
                lapsed is null ? null : $"the {(lapsed.Decision == "disable" ? "disabled rule" : "exception")} ended on {lapsed.Until}"));
        }
        else if (previousLifecycle == "claimed-fixed")
        {
            lifecycle = "open";
            events.Add(new EventRow(r.FindingKey, now, "claim-rejected", runId, null, "the ticket was closed but the check still fails"));
        }
        else
        {
            lifecycle = "open";
        }

        if (before is not null && before["severity"] is string oldSeverity && oldSeverity != r.Severity && status == "open")
            events.Add(new EventRow(r.FindingKey, now, "severity-changed", runId, null, $"{oldSeverity} -> {r.Severity}"));

        var systemId = r.Target == "-"
            ? MapSystem(systemRules, r.Instance, "instance", r.Instance, null, null, r.System).SystemId
            : entities.TryGetValue((r.Instance, r.EntityType, r.Target), out var entity) ? entity.SystemId : Unclaimed(r.Instance, r.System, null).SystemId;

        return new FindingRow
        {
            FindingKey = r.FindingKey,
            Instance = r.Instance,
            System = r.System,
            SystemId = systemId,
            RuleId = r.RuleId,
            CheckId = r.CheckId,
            EntityType = r.EntityType,
            Target = r.Target,
            EntityName = r.EntityName,
            Kind = r.Kind,
            Lens = r.Lens,
            Category = r.Category,
            Severity = r.Severity,
            Security = r.Security,
            Title = r.Title,
            Evidence = r.Evidence,
            Why = r.Why,
            Fix = r.Fix,
            Refs = r.Refs,
            Deadline = r.Deadline,
            Status = status,
            Lifecycle = lifecycle,
            FirstSeen = before?["first_seen"] as string ?? r.ObservedAt,
            LastSeen = r.ObservedAt,
            ResolvedAt = null,
            RunId = runId,
        };
    }

    private FindingRow? Absent(Dictionary<string, object?> before, Dictionary<(string, string, string), EntityRow> entities,
        Dictionary<string, object?> run, List<EventRow> events, string now)
    {
        var key = (string)before["finding_key"]!;
        var instance = (string)before["instance"]!;
        var ruleId = (string)before["rule_id"]!;
        var entityType = (string)before["entity_type"]!;
        var target = (string)before["target"]!;
        var runId = (string)run["run_id"]!;

        // 1. The rule passed on this entity in a result at least as new as the finding.
        var passed = Sql.Scalar(connection,
            "SELECT 1 FROM result WHERE instance = :i AND rule_id = :r AND entity_type = :t AND entity_key = :k AND state = 'pass' AND at >= :seen;",
            null, (":i", instance), (":r", ruleId), (":t", entityType), (":k", target), (":seen", (string)before["last_seen"]!)) is not null;

        // 2. The entity is gone: every read that returned it read cleanly without it (MapEntities).
        // 3. The rule ran cleanly and an imported tool no longer reports the row, or an instance-wide result is gone.
        var ruleRanCleanly = Sql.Scalar(connection,
            "SELECT 1 FROM coverage WHERE run_id = :run AND scope = 'rule' AND item = :r AND state = 'ok';",
            null, (":run", runId), (":r", ruleId)) is not null;
        var entityGone = entities.TryGetValue((instance, entityType, target), out var entity) && entity.GoneSince is not null;
        var imported = (string)before["check_id"]! != ruleId;
        // 4. A finding about one host (a per-host count) of a rule whose own query read that host before, and no
        //    longer tries it at all: retired. Never an imported tool's row: only the tool can say it is gone.
        var query = QueryOf(ruleId);
        var hostRetired = !imported && target != "-" && query is not null && Retired(ReadsOf(run), query, target)
                          && KnownHosts(instance, (string)run["system"]!, query).Contains(target);

        if (passed || entityGone || hostRetired || (ruleRanCleanly && (imported || target == "-")))
        {
            var note = passed ? "the check passed" : entityGone ? "the entity no longer exists"
                : hostRetired ? "the host is no longer scanned (no longer in the host list)" : "no longer reported";
            events.Add(new EventRow(key, now, "resolved", runId, null, note));
            return Copy(before) with { Status = "resolved", Lifecycle = "resolved", ResolvedAt = now, RunId = runId };
        }

        // 3. Still unconfirmed: stale once its evidence is older than the rule's TTL.
        var ttl = TtlMinutes(instance, ruleId, entityType, target);
        var lastSeen = DateTimeOffset.Parse((string)before["last_seen"]!, System.Globalization.CultureInfo.InvariantCulture);
        if ((string)before["lifecycle"]! != "stale" && lastSeen.AddMinutes(ttl) < _clock.GetUtcNow())
        {
            events.Add(new EventRow(key, now, "stale", runId, null, $"no result newer than {ttl / 60} h"));
            return Copy(before) with { Lifecycle = "stale" };
        }
        return null;
    }

    private FindingRow? ClaimedFixed(Dictionary<string, object?> before, List<EventRow> events, string now)
    {
        var key = (string)before["finding_key"]!;
        if ((string)before["lifecycle"]! == "claimed-fixed")
            return null;
        var closed = Sql.Scalar(connection,
            "SELECT 1 FROM finding_ref WHERE finding_key = :k AND closed_at IS NOT NULL AND closed_at >= :seen;",
            null, (":k", key), (":seen", (string)before["last_seen"]!)) is not null;
        if (!closed)
            return null;
        events.Add(new EventRow(key, now, "claimed-fixed", null, null, "the ticket was closed; the next passing check resolves it"));
        return Copy(before) with { Lifecycle = "claimed-fixed" };
    }

    private int TtlMinutes(string instance, string ruleId, string entityType, string target)
    {
        var fromResult = Sql.Scalar(connection,
            "SELECT ttl_minutes FROM result WHERE instance = :i AND rule_id = :r AND entity_type = :t AND entity_key = :k;",
            null, (":i", instance), (":r", ruleId), (":t", entityType), (":k", target));
        if (fromResult is long ttl)
            return (int)ttl;
        var fromRule = Sql.Scalar(connection, "SELECT refresh_min * 3 FROM rule WHERE rule_id = :r;", null, (":r", ruleId));
        return fromRule is long refresh ? (int)refresh : DefaultTtlMinutes;
    }

    private static FindingRow Copy(Dictionary<string, object?> r) => new()
    {
        FindingKey = (string)r["finding_key"]!,
        Instance = (string)r["instance"]!,
        System = (string)r["system"]!,
        SystemId = (string)r["system_id"]!,
        RuleId = (string)r["rule_id"]!,
        CheckId = (string)r["check_id"]!,
        EntityType = (string)r["entity_type"]!,
        Target = (string)r["target"]!,
        EntityName = r["entity_name"] as string,
        Kind = (string)r["kind"]!,
        Lens = (string)r["lens"]!,
        Category = (string)r["category"]!,
        Severity = (string)r["severity"]!,
        Security = r["security"] is long s && s == 1,
        Title = (string)r["title"]!,
        Evidence = r["evidence"] as string,
        Why = r["why"] as string,
        Fix = r["fix"] as string,
        Refs = JsonSerializer.Deserialize<List<string>>((string)r["refs"]!) ?? [],
        Deadline = r["deadline"] as string,
        Status = (string)r["status"]!,
        Lifecycle = (string)r["lifecycle"]!,
        FirstSeen = (string)r["first_seen"]!,
        LastSeen = (string)r["last_seen"]!,
        ResolvedAt = r["resolved_at"] as string,
        RunId = r["run_id"] as string,
    };
}
