using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Scan;

/// <summary>A read's history: the rows of its newest clean read, and the partial reads since (newest first).</summary>
public sealed record PreviousRead(int Clean, IReadOnlyList<PartialRead> PartialSince);

/// <summary>A partial read: its rows, when, and whether the drop guard made it partial (a low read).</summary>
public sealed record PartialRead(int Count, DateTimeOffset At, bool Low);

/// <summary>
/// What a scan reads from the store before it starts: tenant thresholds, threshold overrides, and the
/// hosts earlier scans saw (targets for per-host rules). Read-only.
/// </summary>
public sealed class StoreInputs
{
    private readonly Dictionary<string, string> _thresholds;
    private readonly List<(string Check, string Entity, string Value)> _overrides;
    private readonly SqliteConnection _connection;

    public StoreInputs(SqliteConnection readOnly)
    {
        _connection = readOnly;
        _thresholds = Sql.Rows(readOnly, "SELECT key, value FROM setting WHERE key LIKE 'threshold.%';")
            .ToDictionary(r => ((string)r["key"]!)["threshold.".Length..], r => (string)r["value"]!, StringComparer.Ordinal);
        _overrides = Sql.Rows(readOnly, "SELECT check_id, entity, value FROM override WHERE active = 1 AND decision = 'threshold';")
            .Select(r => ((string)r["check_id"]!, (string)r["entity"]!, (string)r["value"]!))
            .ToList();
    }

    public string? Threshold(string name) => _thresholds.GetValueOrDefault(name);

    /// <summary>An override for this rule and entity wins over one for the whole rule.</summary>
    public string? OverrideThreshold(string ruleId, string entity)
    {
        bool Matches(string pattern) => pattern.EndsWith('*')
            ? ruleId.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
            : ruleId.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        return _overrides.Where(o => Matches(o.Check) && o.Entity.Equals(entity, StringComparison.OrdinalIgnoreCase)).Select(o => o.Value).FirstOrDefault()
            ?? _overrides.Where(o => Matches(o.Check) && o.Entity.Length == 0).Select(o => o.Value).FirstOrDefault();
    }

    /// <summary>
    /// For every read this system's loaded scans through this integration made - a query (its id) or one host
    /// of a per-host query (query@host): the rows of its newest clean (ok) read, and the row counts of the
    /// partial reads since, newest first. Read once per scan.
    /// </summary>
    public IReadOnlyDictionary<string, PreviousRead> PreviousRows(string instance, string system)
    {
        var history = new Dictionary<string, List<(string State, PartialRead Read)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Sql.Rows(_connection,
                     """
                     SELECT c.item, c.state, c.count, c.reason, r.started_at FROM coverage c JOIN run r ON r.run_id = c.run_id
                     WHERE r.instance = :i AND r.system = :s AND c.scope IN ('query', 'target')
                       AND c.state IN ('ok', 'partial') AND c.count IS NOT NULL
                     ORDER BY r.started_at DESC;
                     """,
                     null, (":i", instance), (":s", system)))
        {
            var item = (string)r["item"]!;
            if (!history.TryGetValue(item, out var reads))
                history[item] = reads = [];
            var low = r["reason"] is string reason && reason.StartsWith(Scanner.LowReadMarker, StringComparison.Ordinal);
            reads.Add(((string)r["state"]!, new PartialRead((int)(long)r["count"]!,
                DateTimeOffset.Parse((string)r["started_at"]!, System.Globalization.CultureInfo.InvariantCulture), low)));
        }

        var previous = new Dictionary<string, PreviousRead>(StringComparer.OrdinalIgnoreCase);
        foreach (var (item, reads) in history)
        {
            var clean = reads.FindIndex(r => r.State == "ok");
            if (clean >= 0)
                previous[item] = new PreviousRead(reads[clean].Read.Count, [.. reads.Take(clean).Select(r => r.Read)]);
        }
        return previous;
    }

    /// <summary>Hosts from the newest scans: rows of the target entity type that match 'where', value of 'field'.</summary>
    public IReadOnlyList<string> Targets(TargetSpec spec, DateTimeOffset now)
    {
        if (spec.Entity is null || spec.Field is null)
            return spec.List;
        var evaluator = new Evaluator(_ => null, now);
        var hosts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in Sql.Rows(_connection,
                     "SELECT rs.attrs FROM row_seen rs JOIN latest_run lr ON lr.run_id = rs.run_id WHERE rs.entity_type = :t;",
                     null, (":t", spec.Entity)))
        {
            if (JsonNode.Parse((string)row["attrs"]!) is not JsonObject attrs)
                continue;
            if (spec.Where is not null && evaluator.Each(spec.Where, attrs).Fails != true)
                continue;
            if (Values.Text(FieldPath.First(attrs, spec.Field)) is { Length: > 0 } host)
                hosts.Add(host);
        }
        return [.. hosts];
    }

    /// <summary>
    /// Why the host list from <see cref="Targets"/> may be missing hosts, or null when every read that supplied
    /// it was clean. A host missing from an incomplete list is not a retired host, and must not be judged as one.
    /// </summary>
    public string? TargetsIncomplete(TargetSpec spec)
    {
        if (spec.Entity is null || spec.Field is null)
            return null;
        // Every inventory read (read once, not per host) that has ever supplied this entity type must have read
        // cleanly in its system's newest scan. A failed one wrote no rows, so its hosts would silently drop out of
        // the list; a per-host read that came back partial still proves its own host exists, so it is not asked.
        var unclean = Sql.Rows(_connection,
            """
            WITH supplier AS (
                SELECT DISTINCT r.instance, r.system, rs.query FROM row_seen rs JOIN run r ON r.run_id = rs.run_id
                WHERE rs.entity_type = :t AND rs.target IS NULL)
            SELECT s.system, COALESCE(c.state, 'failed') AS state
            FROM supplier s
            JOIN latest_run lr ON lr.instance = s.instance AND lr.system = s.system
            LEFT JOIN coverage c ON c.run_id = lr.run_id AND c.scope = 'query' AND c.item = s.query
            -- A query the newest scan no longer runs supplied none of today's list: it cannot have dropped hosts from it.
            WHERE (c.state IS NOT NULL AND c.state <> 'ok') OR (c.state IS NULL AND lr.status = 'failed');
            """,
            null, (":t", spec.Entity));
        return unclean.Count == 0 ? null
            : $"the list of hosts comes from {spec.Entity} reads that were not all clean ({unclean[0]["system"]}: {unclean[0]["state"]}), so it may miss hosts";
    }
}
