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

        foreach (var run in runs)
        {
            // Only a complete scan can say an entity is gone, and only of entities its own rule system returned.
            if ((string)run["status"]! != "ok")
                continue;
            var instance = (string)run["instance"]!;
            var system = (string)run["system"]!;
            foreach (var (key, before) in existing.Where(e => e.Key.Item1 == instance && !result.ContainsKey(e.Key)
                         && (e.Value["seen_by"] as string ?? system) == system))
            {
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
                    SeenBy = system,
                };
            }
        }
        return result.Values.ToList();
    }

    // ---- findings ------------------------------------------------------------

    private sealed record Override(string CheckPattern, string Decision, string Entity)
    {
        public bool MatchesCheck(string checkId, string ruleId) => Matches(checkId) || Matches(ruleId);

        private bool Matches(string id) =>
            CheckPattern.EndsWith('*')
                ? id.StartsWith(CheckPattern[..^1], StringComparison.OrdinalIgnoreCase)
                : id.Equals(CheckPattern, StringComparison.OrdinalIgnoreCase);
    }

    private List<FindingRow> TrackFindings(List<Dictionary<string, object?>> runs,
        Dictionary<(string, string, string), EntityRow> entities, List<SystemRule> systemRules, List<EventRow> events, string now)
    {
        var overrides = Sql.Rows(connection, "SELECT check_id, decision, entity FROM override WHERE active = 1 AND decision IN ('disable', 'exception');")
            .Select(r => new Override((string)r["check_id"]!, (string)r["decision"]!, (string)r["entity"]!))
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
        return touched.Values.ToList();
    }

    private FindingRow Present(FindingRecord r, Dictionary<string, object?>? before,
        Dictionary<(string, string, string), EntityRow> entities, List<SystemRule> systemRules, List<Override> overrides,
        string runId, List<EventRow> events, string now)
    {
        var decision = overrides.FirstOrDefault(o => o.Decision == "disable" && o.MatchesCheck(r.CheckId, r.RuleId))?.Decision
            ?? overrides.FirstOrDefault(o => o.Decision == "exception" && o.MatchesCheck(r.CheckId, r.RuleId)
                                             && o.Entity.Equals(r.Target, StringComparison.OrdinalIgnoreCase))?.Decision;
        var status = decision switch { "disable" => "disabled", "exception" => "exception", _ => "open" };
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
            events.Add(new EventRow(r.FindingKey, now, "reopened", runId, null, null));
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

        // 2. The rule ran cleanly and the entity is gone (or, for an imported tool's row, the tool no longer reports it).
        var ruleRanCleanly = Sql.Scalar(connection,
            "SELECT 1 FROM coverage WHERE run_id = :run AND scope = 'rule' AND item = :r AND state = 'ok';",
            null, (":run", runId), (":r", ruleId)) is not null;
        var entityGone = entities.TryGetValue((instance, entityType, target), out var entity) && entity.GoneSince is not null;
        var imported = (string)before["check_id"]! != ruleId;

        if (passed || (ruleRanCleanly && (entityGone || imported || target == "-")))
        {
            var note = passed ? "the check passed" : entityGone ? "the entity no longer exists" : "no longer reported";
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
