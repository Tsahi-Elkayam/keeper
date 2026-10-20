using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Scan;

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
}
