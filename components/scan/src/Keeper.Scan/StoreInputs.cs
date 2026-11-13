using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Scan;

/// <summary>A read's history: the rows of its newest clean read, and the partial reads since (newest first).</summary>
public sealed record PreviousRead(int Clean, IReadOnlyList<PartialRead> PartialSince);

/// <summary>A partial read: its rows, when, and whether the drop guard made it partial (a low read).</summary>
public sealed record PartialRead(int Count, DateTimeOffset At, bool Low);

/// <summary>The newest clean read of one query (or one host of a per-host query): when it started, and its rows by entity key.</summary>
public sealed record CleanRead(string At, IReadOnlyDictionary<string, JsonObject> Rows);

/// <summary>
/// A lockout policy an Active Directory scan read: the domain's own (<c>lockoutThreshold</c> on the domain object) or a
/// fine-grained one (<c>msDS-LockoutThreshold</c> on a password settings object). Threshold 0 never locks.
/// </summary>
public sealed record LockoutPolicy(string Key, string? Name, bool FineGrained, int Threshold, string At)
{
    /// <summary>The domain the policy belongs to, as the DC= part of its DN (dc=example,dc=org).</summary>
    public string Domain => string.Join(',', Key.Split(',', StringSplitOptions.TrimEntries)
        .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))).ToLowerInvariant();
}

/// <summary>What Keeper knows about how many bad passwords lock an account, and from where.</summary>
public sealed record LockoutKnown(int Threshold, string Domain, string At, bool FineGrained)
{
    /// <summary>How many sign-ins answered "access denied" may be risked: never as many as lock the account.</summary>
    public int DeniedSignInsAllowed => Threshold == 0 ? int.MaxValue : Math.Max(1, Threshold - 1);
}

/// <summary>
/// What a scan reads from the store before it starts: tenant thresholds, threshold overrides, and the
/// hosts earlier scans saw (targets for per-host rules). Read-only.
/// </summary>
public sealed class StoreInputs
{
    private readonly Dictionary<string, string> _thresholds;
    private readonly List<(string Check, string Entity, string Value)> _overrides;
    private readonly SqliteConnection _connection;

    /// <param name="today">The scan's day (yyyy-MM-dd): a threshold override whose until day has passed no longer applies.</param>
    public StoreInputs(SqliteConnection readOnly, string? today = null)
    {
        _connection = readOnly;
        _thresholds = Sql.Rows(readOnly, "SELECT key, value FROM setting WHERE key LIKE 'threshold.%';")
            .ToDictionary(r => ((string)r["key"]!)["threshold.".Length..], r => (string)r["value"]!, StringComparer.Ordinal);
        _overrides = Sql.Rows(readOnly,
                // Most specific first: an exact rule id before a prefix*, a longer prefix before a shorter, the newest first.
                """
                SELECT check_id, entity, value FROM override
                WHERE active = 1 AND decision = 'threshold' AND (until IS NULL OR until >= COALESCE(:today, date('now')))
                ORDER BY (substr(check_id, -1) = '*'), length(check_id) DESC, at DESC, override_id DESC;
                """,
                null, (":today", today))
            .Select(r => ((string)r["check_id"]!, (string)r["entity"]!, (string)r["value"]!))
            .ToList();
    }

    public string? Threshold(string name) => _thresholds.GetValueOrDefault(name);

    /// <summary>
    /// The lockout policies the newest Active Directory reads found: for each query that read one, the rows of its
    /// newest run (a policy deleted since is gone from it). Nothing is sent anywhere: it is what earlier scans stored.
    /// </summary>
    public IReadOnlyList<LockoutPolicy> LockoutPolicies()
    {
        var policies = new List<LockoutPolicy>();
        foreach (var r in Sql.Rows(_connection,
                     """
                     WITH policy AS (
                         SELECT rs.run_id, rs.query, rs.entity_key, rs.entity_name, rs.attrs, r.instance, r.started_at
                         FROM row_seen rs JOIN run r ON r.run_id = rs.run_id
                         WHERE json_valid(rs.attrs)
                           AND (json_extract(rs.attrs, '$.lockoutThreshold') IS NOT NULL
                                OR json_extract(rs.attrs, '$."msDS-LockoutThreshold"') IS NOT NULL)),
                     -- The newest clean read of each query that ever read a policy: one with no rows means the
                     -- policies are gone, and a failed read says nothing.
                     newest AS (
                         SELECT q.instance, q.query, MAX(r.started_at) AS started_at
                         FROM (SELECT DISTINCT instance, query FROM policy) q
                         JOIN run r ON r.instance = q.instance
                         JOIN coverage c ON c.run_id = r.run_id AND c.scope = 'query' AND c.item = q.query AND c.state = 'ok'
                         GROUP BY q.instance, q.query)
                     SELECT DISTINCT p.entity_key, p.entity_name, p.attrs, p.started_at
                     FROM policy p JOIN newest n ON n.instance = p.instance AND n.query = p.query AND n.started_at = p.started_at
                     ORDER BY p.started_at DESC, p.entity_key;
                     """))
        {
            if (JsonNode.Parse((string)r["attrs"]!) is not JsonObject attrs)
                continue;
            var fineGrained = attrs["lockoutThreshold"] is null;
            if (Integer(attrs[fineGrained ? "msDS-LockoutThreshold" : "lockoutThreshold"]) is not { } threshold)
                continue;
            var key = (string)r["entity_key"]!;
            // A key read from another field (cn of a policy) has no DN: the row's own DN says the domain.
            if (!key.Contains("DC=", StringComparison.OrdinalIgnoreCase) && Values.Text(attrs["distinguishedName"]) is { } dn)
                key = dn;
            var name = r["entity_name"] as string ?? Values.Text(attrs[fineGrained ? "cn" : "name"]);
            policies.Add(new LockoutPolicy(key, name, fineGrained, threshold, (string)r["started_at"]!));
        }
        return policies;

        static int? Integer(JsonNode? node)
        {
            if (node is JsonArray { Count: > 0 } list)
                node = list[0];
            return int.TryParse(Values.Text(node), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var n) && n >= 0
                ? n
                : null;
        }
    }

    /// <summary>
    /// How many bad passwords lock <paramref name="identity"/> (EXAMPLE\reader or reader@example.org), from the
    /// stored policies of its domain: the strictest of the domain's own and every fine-grained policy of that domain
    /// (which one applies to the account needs its groups; the strictest is the safe guess). Null when no Active
    /// Directory scan stored the domain's policy, or the account's domain cannot be told.
    /// </summary>
    public static LockoutKnown? LockoutFor(string? identity, IReadOnlyList<LockoutPolicy> policies)
    {
        var domains = policies.Where(p => !p.FineGrained).ToList();
        if (identity is null || domains.Count == 0)
            return null;
        LockoutPolicy? domain = null;
        if (identity.Contains('@', StringComparison.Ordinal))
        {
            var dn = string.Join(',', identity[(identity.IndexOf('@') + 1)..].Split('.').Select(label => "dc=" + label.ToLowerInvariant()));
            domain = domains.FirstOrDefault(d => d.Domain == dn);
        }
        else if (identity.Contains('\\', StringComparison.Ordinal))
        {
            var netbios = identity[..identity.IndexOf('\\')];
            domain = domains.FirstOrDefault(d => string.Equals(d.Name, netbios, StringComparison.OrdinalIgnoreCase)
                                                 || d.Domain.Split(',')[0].Equals("dc=" + netbios, StringComparison.OrdinalIgnoreCase));
        }
        // One domain known and an identity that names no domain at all: that domain. One that names another domain is
        // not given this one's policy.
        if (domain is null && !identity.Contains('@', StringComparison.Ordinal) && !identity.Contains('\\', StringComparison.Ordinal))
            domain = domains.Select(d => d.Domain).Distinct(StringComparer.Ordinal).Count() == 1 ? domains[0] : null;
        if (domain is null)
            return null;
        var applying = policies.Where(p => p.Domain == domain.Domain && (p == domain || p.FineGrained)).ToList();
        var locking = applying.Where(p => p.Threshold > 0).ToList();
        var strictest = locking.Count > 0 ? locking.MinBy(p => p.Threshold)! : domain;
        return new LockoutKnown(strictest.Threshold, domain.Name ?? domain.Domain, domain.At, strictest.FineGrained);
    }

    /// <summary>
    /// The threshold overrides of this rule, most specific first: those for this entity, then those for the whole
    /// rule; within each, an exact rule id before a prefix and the newest first.
    /// </summary>
    public IReadOnlyList<string> OverrideThresholds(string ruleId, string entity)
    {
        bool Matches(string pattern) => pattern.EndsWith('*')
            ? ruleId.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase)
            : ruleId.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        return [.. _overrides.Where(o => Matches(o.Check) && o.Entity.Equals(entity, StringComparison.OrdinalIgnoreCase)).Select(o => o.Value)
            .Concat(_overrides.Where(o => Matches(o.Check) && o.Entity.Length == 0).Select(o => o.Value))];
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

    /// <summary>
    /// The rows of a query's newest clean read in this system's scans through this integration, by coverage item
    /// (the query id, or query@host: each host's own newest clean read). For rules that compare with the last read.
    /// </summary>
    public IReadOnlyDictionary<string, CleanRead> LastCleanRows(string instance, string system, string queryId)
    {
        var reads = new Dictionary<string, (string At, Dictionary<string, JsonObject> Rows)>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Sql.Rows(_connection,
                     """
                     WITH clean AS (
                         SELECT c.item, c.run_id, r.started_at,
                                ROW_NUMBER() OVER (PARTITION BY c.item ORDER BY r.started_at DESC, r.run_id DESC) AS n
                         FROM coverage c JOIN run r ON r.run_id = c.run_id
                         WHERE r.instance = :i AND r.system = :s AND c.scope IN ('query', 'target') AND c.state = 'ok'
                           AND (c.item = :q OR substr(c.item, 1, length(:q) + 1) = :q || '@'))
                     SELECT clean.item, clean.started_at, rs.entity_key, rs.attrs
                     FROM clean JOIN row_seen rs ON rs.run_id = clean.run_id AND rs.query = :q
                     WHERE clean.n = 1
                       AND ((clean.item = :q AND rs.target IS NULL) OR clean.item = :q || '@' || rs.target);
                     """,
                     null, (":i", instance), (":s", system), (":q", queryId)))
        {
            var item = (string)r["item"]!;
            if (!reads.TryGetValue(item, out var read))
                reads[item] = read = ((string)r["started_at"]!, new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase));
            if (JsonNode.Parse((string)r["attrs"]!) is JsonObject attrs)
                read.Rows[(string)r["entity_key"]!] = attrs;
        }
        // A clean read with no rows wrote none to join: it is still a read to compare with.
        foreach (var r in Sql.Rows(_connection,
                     """
                     SELECT c.item, MAX(r.started_at) AS started_at FROM coverage c JOIN run r ON r.run_id = c.run_id
                     WHERE r.instance = :i AND r.system = :s AND c.scope IN ('query', 'target') AND c.state = 'ok' AND c.count = 0
                       AND (c.item = :q OR substr(c.item, 1, length(:q) + 1) = :q || '@')
                     GROUP BY c.item;
                     """,
                     null, (":i", instance), (":s", system), (":q", queryId)))
        {
            var item = (string)r["item"]!;
            var at = (string)r["started_at"]!;
            if (!reads.TryGetValue(item, out var read) || string.CompareOrdinal(at, read.At) > 0)
                reads[item] = (at, new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase));
        }
        return reads.ToDictionary(p => p.Key, p => new CleanRead(p.Value.At, p.Value.Rows), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Hosts from the newest scans: rows of the target entity type that match 'where', value of 'field'.</summary>
    public IReadOnlyList<string> Targets(TargetSpec spec, DateTimeOffset now)
    {
        if (spec.Entity is null || spec.Field is null)
            return spec.List;
        return [.. new SortedSet<string>(MatchingHosts(spec, now).Select(h => h.Host), StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The same hosts as <see cref="Targets"/>, each with the attributes it was found with (the newest read wins).</summary>
    public IReadOnlyDictionary<string, JsonObject> TargetAttributes(TargetSpec spec, DateTimeOffset now)
    {
        var byHost = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
        if (spec.Entity is null || spec.Field is null)
            return byHost;
        foreach (var (host, attrs) in MatchingHosts(spec, now))
            byHost[host] = attrs;
        return byHost;
    }

    private IEnumerable<(string Host, JsonObject Attrs)> MatchingHosts(TargetSpec spec, DateTimeOffset now) =>
        Judged(spec, now).Where(h => h.Matches == true).Select(h => (h.Host, h.Attrs));

    /// <summary>Every known host of the entity type with what 'where' says of it: true, false, or null when it cannot tell.</summary>
    private IEnumerable<(string Host, JsonObject Attrs, bool? Matches)> Judged(TargetSpec spec, DateTimeOffset now)
    {
        if (spec.Entity is null || spec.Field is null)
            yield break;
        var evaluator = new Evaluator(_ => null, now);
        foreach (var row in Sql.Rows(_connection,
                     // Oldest first: a host two systems list keeps the attributes of the newest read (TargetAttributes: the last one wins).
                     "SELECT rs.attrs FROM row_seen rs JOIN latest_run lr ON lr.run_id = rs.run_id WHERE rs.entity_type = :t ORDER BY lr.started_at, lr.run_id, rs.observed_at;",
                     null, (":t", spec.Entity)))
        {
            if (JsonNode.Parse((string)row["attrs"]!) is not JsonObject attrs)
                continue;
            if (Values.Text(FieldPath.First(attrs, spec.Field)) is not { Length: > 0 } host)
                continue;
            yield return (host, attrs, spec.Where is null ? true : evaluator.Each(spec.Where, attrs).Fails);
        }
    }

    /// <summary>
    /// Why the host list from <see cref="Targets"/> may be missing hosts, or null when every read that supplied
    /// it was clean. A host missing from an incomplete list is not a retired host, and must not be judged as one.
    /// </summary>
    /// <summary>
    /// Hosts the targets' 'where' could not judge (the field it asks about is missing: a computer that never signed
    /// in has no lastLogonTimestamp), said rather than dropped silently - or null. A note, not an incomplete list:
    /// such objects are common and mostly rightly out, and an incomplete list would keep every finding open.
    /// </summary>
    public string? TargetsUnjudged(TargetSpec spec, DateTimeOffset now)
    {
        if (spec.Where is null)
            return null;
        var unjudged = Judged(spec, now).Where(h => h.Matches is null).Select(h => h.Host)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return unjudged.Count == 0 ? null
            : $"{unjudged.Count} {spec.Entity} host(s) are not read: the targets' where could not judge them, a field it asks about is missing " +
              $"({string.Join(", ", unjudged.Take(3))}{(unjudged.Count > 3 ? ", ..." : "")})";
    }

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
            WHERE (c.state IS NOT NULL AND c.state <> 'ok') OR (c.state IS NULL AND lr.status = 'failed')
            ORDER BY s.system, s.query;
            """,
            null, (":t", spec.Entity));
        return unclean.Count == 0 ? null
            : $"the list of hosts comes from {spec.Entity} reads that were not all clean ({unclean[0]["system"]}: {unclean[0]["state"]}), so it may miss hosts";
    }
}
