using System.Text;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;

namespace Keeper.Scan;

public sealed record ScanRequest
{
    public required IReadOnlyList<RuleFile> Files { get; init; }
    public required IConnection Connection { get; init; }
    public required string RunsDir { get; init; }
    public required string ImportsDir { get; init; }
    public string? StoreFile { get; init; }

    /// <summary>A tenant threshold by name (setting threshold.&lt;name&gt;), or null.</summary>
    public Func<string, string?> Threshold { get; init; } = _ => null;

    /// <summary>A threshold override for one rule (and entity), or null.</summary>
    public Func<string, string, string?> OverrideThreshold { get; init; } = (_, _) => null;

    /// <summary>Hosts for per-target rules, from what earlier scans saw.</summary>
    public Func<TargetSpec, IReadOnlyList<string>> ResolveTargets { get; init; } = _ => [];

    /// <summary>Why the resolved host list may be missing hosts (its source read was not clean), or null.</summary>
    public Func<TargetSpec, string?> TargetsIncomplete { get; init; } = _ => null;

    /// <summary>
    /// A read's history in this system's earlier scans, by coverage item (the query id, or query@host for a
    /// per-host query), or null when it never read cleanly.
    /// </summary>
    public Func<string, PreviousRead?> PreviousRows { get; init; } = _ => null;

    /// <summary>
    /// A query's newest clean read in this system's earlier scans, by coverage item - for rules that compare a row
    /// with the same entity's last read (changed, _new, _previous). Asked only for queries such rules read.
    /// </summary>
    public Func<string, IReadOnlyDictionary<string, CleanRead>> LastCleanRows { get; init; } = _ => new Dictionary<string, CleanRead>();

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);
    public int Parallelism { get; init; } = 8;
    public Action<string> Log { get; init; } = _ => { };
}

public sealed record ScanReport(RunManifest Manifest, int Rules, int Queries, int Rows, int Findings, int FailedQueries);

/// <summary>
/// Runs one system's rules through one integration: every distinct query once (per target for per-host
/// protocols), every rule against the rows, and one run folder with rows, results, findings and coverage.
/// A query that fails makes its rules unknown, never passed.
/// </summary>
public sealed class Scanner(RunnerRegistry registry, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<ScanReport> RunAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        if (request.Files.Count == 0)
            throw new ArgumentException("No rule files to scan.");
        // Every scan, whoever starts it: a type's guards (read paths, commands, hosts) are written for its own
        // runners, and for its endpoint as the type allows it.
        if (request.Connection.Protocols is { } offered
            && request.Files.SelectMany(f => f.Rules).FirstOrDefault(r => !offered.Contains(r.Query.Protocol)) is { } stray)
            throw new ArgumentException($"Rule {stray.Id} reads with {stray.Query.Protocol}, which the {request.Connection.Type} integration type does not offer ({string.Join(", ", offered)}).");
        if (request.Connection.EndpointProblem is { } endpointProblem)
            throw new ArgumentException($"Integration {request.Connection.Instance}: {endpointProblem}.");
        var system = request.Files[0].System;
        var instance = request.Connection.Instance;
        var started = _clock.GetUtcNow();
        var observedAt = Iso.Utc(started);
        var notes = new List<string>();

        using var run = new RunWriter(request.RunsDir, instance, system, started);
        var rules = request.Files.SelectMany(f => f.Rules.Select(r => (Rule: r, File: f))).ToList();
        var queries = rules.GroupBy(r => r.Rule.Query.Id).ToList();
        var outcomes = new Dictionary<string, QueryOutcome>(StringComparer.Ordinal);

        var dropRatio = double.TryParse(request.Threshold("scan.row-drop-ratio"), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var r) && r is > 0 and <= 1 ? r : DefaultDropRatio;
        var confirmScans = int.TryParse(request.Threshold("scan.drop-confirm-scans"), System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var confirm) && confirm >= 1 ? confirm : DefaultDropConfirmScans;
        var confirmAge = TimeSpan.FromDays(double.TryParse(request.Threshold("scan.drop-confirm-days"), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var days) && days >= 0 ? days : DefaultDropConfirmDays);
        foreach (var group in queries)
        {
            var (rule, file) = group.First();
            var outcome = await RunQuery(rule.Query, file, request, cancellationToken).ConfigureAwait(false);
            // Keeper's own store and other tools' files cannot lose sight of rows, so only their min_rows applies.
            var dropCheck = rule.Query.Protocol is not ("store" or "file");
            Distrust(outcome, group.Key, group.Max(g => g.Rule.Query.MinRows), dropCheck ? request.PreviousRows : _ => null, dropRatio,
                confirmScans, confirmAge, started);
            outcomes[group.Key] = outcome;
            // A field any rule of the query masks is masked in every row the scan keeps; conditions read the real value.
            outcome.Mask = [.. group.SelectMany(g => g.Rule.Mask).Distinct(StringComparer.OrdinalIgnoreCase)];

            foreach (var (row, target) in outcome.Rows)
                run.Row(new RowRecord
                {
                    Instance = instance,
                    System = system,
                    Query = group.Key,
                    EntityType = rule.EntityType,
                    EntityKey = KeyOf(rule.Query, row, target),
                    EntityName = rule.Query.Name is { } nameField ? Values.Text(FieldPath.First(row, nameField)) : null,
                    Target = target,
                    Attrs = outcome.Masked(row),
                    ObservedAt = observedAt,
                });
            // Rows are written as read; a rule that compares with the last read sees that read beside each row.
            if (group.Any(g => g.Rule.ComparesWithPrevious))
                AddLastRead(outcome, group.Key, rule.Query, request.LastCleanRows(group.Key));
            foreach (var target in outcome.Targets)
                run.Coverage(new CoverageRecord
                {
                    Instance = instance,
                    System = system,
                    Scope = target.Target is null ? "query" : "target",
                    Item = RunFolder.CoverageItem(group.Key, target.Target),
                    State = target.State,
                    Reason = target.Reason is null ? null : Redactor.Clean(target.Reason),
                    Count = target.Count,
                    ObservedAt = observedAt,
                });
            if (outcome.State != "ok")
                notes.Add($"{group.Key} ({rule.Query.Protocol}): {outcome.State} - {Redactor.Clean(outcome.Reason)}");
        }

        var findings = 0;
        foreach (var (rule, _) in rules)
            findings += Evaluate(rule, outcomes[rule.Query.Id], request, run, instance, system, observedAt);

        var states = outcomes.Values.Select(o => o.State).ToList();
        var status = states.All(s => s == "ok") ? "ok" : states.Any(s => s is "ok" or "partial") ? "partial" : "failed";
        var manifest = run.Complete(status, _clock.GetUtcNow(), request.Connection.SignedInAs ?? request.Connection.Identity, notes);
        return new ScanReport(manifest, rules.Count, queries.Count, outcomes.Values.Sum(o => o.Rows.Count), findings,
            states.Count(s => s == "failed"));
    }

    /// <summary>A read that returns less than this share of its last clean read's rows is not trusted yet.</summary>
    public const double DefaultDropRatio = 0.5;

    /// <summary>How many scans in a row must read that low before the lower count is accepted.</summary>
    public const int DefaultDropConfirmScans = 3;

    /// <summary>...and over how many days at least: frequent scans must not accept a lost permission within hours.</summary>
    public const double DefaultDropConfirmDays = 2;

    /// <summary>How a read the drop guard made partial begins its reason: the next scan counts it as a low read.</summary>
    public const string LowReadMarker = "low read: ";

    /// <summary>
    /// A read that succeeded but returned too little is partial, so it can neither mark its entities gone nor
    /// resolve their findings: fewer rows than the query's min_rows, or less than half of what its last clean
    /// read returned - judged per host for a per-host query. A lost permission, an admin role not activated
    /// yet, a wrong base or a broken WMI repository looks exactly like that, and stays a blind spot until
    /// several scans in a row read as low: then the lower count is accepted as the truth (a real clean-up).
    /// </summary>
    private static void Distrust(QueryOutcome outcome, string queryId, int? minRows, Func<string, PreviousRead?> previousRows, double ratio,
        int confirmScans, TimeSpan confirmAge, DateTimeOffset now)
    {
        for (var i = 0; i < outcome.Targets.Count; i++)
        {
            var target = outcome.Targets[i];
            if (target.State != "ok")
                continue;
            if (minRows is { } min && target.Count < min)
            {
                outcome.Targets[i] = target with { State = "partial", Reason = $"returned {target.Count} row(s); this query always returns at least {min}" };
                continue;
            }
            if (previousRows(RunFolder.CoverageItem(queryId, target.Target)) is not { Clean: > 0 } previous || target.Count >= previous.Clean * ratio)
                continue;
            // Only reads the guard itself held back count: a partial for another reason (a row cap) breaks the streak.
            var streak = previous.PartialSince.TakeWhile(p => p.Low).ToList();
            var lowInARow = streak.Count + 1;
            var since = streak.Count > 0 ? streak[^1].At : now;
            outcome.Targets[i] = lowInARow >= confirmScans && now - since >= confirmAge
                ? target with { Reason = $"returned {target.Count} row(s), down from {previous.Clean}: accepted after {lowInARow} scans in a row read as low since {Iso.Utc(since)}" }
                : target with
                {
                    State = "partial",
                    Reason = $"{LowReadMarker}returned {target.Count} row(s), the last clean scan {previous.Clean}: not trusted until {confirmScans} scans " +
                             $"over {confirmAge.TotalDays:0.#} days read as low ({lowInARow} so far) - a lost permission or a wrong base looks the same",
                };
        }
    }

    /// <summary>
    /// Beside each row, the same entity in the query's last clean read (of its host, per host): _new (true when
    /// that read did not have it), _previous (its row then) and _previous_at. No clean read yet: none of them,
    /// so changed is unknown rather than "everything is new".
    /// </summary>
    private static void AddLastRead(QueryOutcome outcome, string queryId, QuerySpec query, IReadOnlyDictionary<string, CleanRead> reads)
    {
        foreach (var (row, target) in outcome.Rows)
        {
            if (!reads.TryGetValue(RunFolder.CoverageItem(queryId, target), out var read))
                continue;
            row["_previous_at"] = read.At;
            if (read.Rows.TryGetValue(KeyOf(query, row, target), out var before))
            {
                // Masked as the rows are now, whatever the mask was then: a row kept before a field was masked
                // holds its value, and evidence can name _previous.
                row["_new"] = false;
                row["_previous"] = outcome.Masked(before) is var masked && ReferenceEquals(masked, before) ? before.DeepClone() : masked;
            }
            else
            {
                row["_new"] = true;
            }
        }
    }

    private sealed record TargetOutcome(string? Target, string State, string? Reason, int Count);

    private sealed record QueryOutcome(List<(JsonObject Row, string? Target)> Rows, List<TargetOutcome> Targets)
    {
        /// <summary>Fields masked in what the scan keeps.</summary>
        public IReadOnlyList<string> Mask { get; set; } = [];

        /// <summary>The row as the scan may keep it: a copy with the masked fields replaced, or the row itself.</summary>
        public JsonObject Masked(JsonObject row)
        {
            if (Mask.Count == 0)
                return row;
            var copy = (JsonObject)row.DeepClone();
            foreach (var path in Mask)
                FieldPath.Mask(copy, path);
            return copy;
        }

        public string State =>
            Targets.All(t => t.State == "ok") ? "ok"
            : Targets.Any(t => t.State is "ok" or "partial") ? "partial"
            : "failed";

        public string? Reason => string.Join("; ", Targets.Where(t => t.Reason is not null).Select(t => t.Target is null ? t.Reason : $"{t.Target}: {t.Reason}").Take(5));
    }

    private async Task<QueryOutcome> RunQuery(QuerySpec query, RuleFile file, ScanRequest request, CancellationToken cancellationToken)
    {
        var runner = registry.Get(query.Protocol);
        var outcome = new QueryOutcome([], []);

        if (!runner.PerTarget)
        {
            var result = await Safe(runner, query, Context(request, null), cancellationToken).ConfigureAwait(false);
            outcome.Rows.AddRange(result.Rows.Select(r => (r, (string?)null)));
            outcome.Targets.Add(new TargetOutcome(null, result.State, result.Reason, result.Rows.Count));
            return outcome;
        }

        var targets = Targets(file, request);
        if (targets.Count == 0)
        {
            outcome.Targets.Add(new TargetOutcome(null, "failed", "no targets: set the file's targets or the integration's targets option", 0));
            return outcome;
        }
        // A query-wide record beside the hosts' own: it tells the tracker that a host missing from this read may
        // simply be missing from the list, not retired.
        if (file.Targets is { List.Count: 0 } spec && request.TargetsIncomplete(spec) is { } incomplete)
            outcome.Targets.Add(new TargetOutcome(null, "partial", incomplete, 0));

        using var gate = new SemaphoreSlim(Math.Max(1, request.Parallelism));
        var tasks = targets.Select(async target =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return (Target: target, Result: await Safe(runner, query, Context(request, target), cancellationToken).ConfigureAwait(false));
            }
            finally
            {
                gate.Release();
            }
        }).ToList();

        foreach (var (target, result) in await Task.WhenAll(tasks).ConfigureAwait(false))
        {
            outcome.Rows.AddRange(result.Rows.Select(r => (r, (string?)target)));
            outcome.Targets.Add(new TargetOutcome(target, result.State, result.Reason, result.Rows.Count));
        }
        return outcome;
    }

    private static IReadOnlyList<string> Targets(RuleFile file, ScanRequest request)
    {
        if (file.Targets is { } spec)
            return spec.List.Count > 0 ? spec.List : request.ResolveTargets(spec);
        if (request.Connection.Options["targets"] is JsonArray fromOptions)
            return fromOptions.Select(t => Values.Text(t)).OfType<string>().Where(t => t.Length > 0).ToList();
        return string.IsNullOrWhiteSpace(request.Connection.Endpoint) ? [] : [request.Connection.Endpoint];
    }

    private RunnerContext Context(ScanRequest request, string? target) =>
        new(request.Connection, target, request.ImportsDir, request.StoreFile, _clock.GetUtcNow(), request.Timeout,
            message => request.Log(target is null ? message : $"{target}: {message}"))
        {
            Threshold = request.Threshold,
        };

    /// <summary>A runner that throws is a failed query, never a crashed scan.</summary>
    private static async Task<RunnerResult> Safe(IRunner runner, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            return await runner.RunAsync(query, context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A runner's failure is data: it becomes a failed coverage record.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return RunnerResult.Failed($"{runner.Protocol} runner error: {ex.Message}");
        }
    }

    /// <summary>
    /// The row's entity key: a field, or a template of fields ("{host}|{PartComponent}") when one field is not
    /// unique - several members of one host's Administrators group are several findings, not one.
    /// </summary>
    private static string KeyOf(QuerySpec query, JsonObject row, string? target)
    {
        var key = query.Key.Contains('{', StringComparison.Ordinal)
            ? Templates.Render(query.Key, row)
            : Values.Text(FieldPath.First(row, query.Key));
        if (string.IsNullOrEmpty(key))
            return target ?? "-";
        // Per host, a key must name its host: the same service, event id or package on two machines are two
        // entities, and one machine's failed read must never speak for the other's. The host must be a whole
        // part of the key ("db" is not in "dbo.users").
        return target is null || NamesHost(key, target) ? key : $"{target}|{key}";
    }

    private static bool NamesHost(string key, string target) =>
        key.Split('|').Any(part => part.Equals(target, StringComparison.OrdinalIgnoreCase));

    private int Evaluate(Rule rule, QueryOutcome outcome, ScanRequest request, RunWriter run, string instance, string system, string observedAt)
    {
        var now = _clock.GetUtcNow();
        void Coverage(string state, string? reason, int count) => run.Coverage(new CoverageRecord
        {
            Instance = instance, System = system, Scope = "rule", Item = rule.Id, State = state,
            Reason = reason is null ? null : Redactor.Clean(reason), Count = count, ObservedAt = observedAt,
        });
        // A rule whose conditions read a masked field (its own mask or another rule's on the same query) keeps no
        // row value in its results: the value may be the masked one. A count is only a number.
        var hide = rule.Count is null && rule.Reads(outcome.Mask);
        void Result(string entityType, string key, Verdict verdict, string? why = null) => run.Result(new ResultRecord
        {
            Instance = instance, System = system, RuleId = rule.Id, EntityType = entityType, EntityKey = key,
            State = verdict.State, Value = hide ? Hidden(verdict.Value) : Truncate(verdict.Value), Operand = hide ? Hidden(verdict.Operand) : verdict.Operand,
            Why = why ?? verdict.Why, TtlMinutes = rule.TtlMinutes, At = observedAt,
        });

        // A rule that compares with the tenant's own list (names of its agents, its admin groups) says nothing
        // until the list is set: not configured, never a pass.
        var unset = rule.RequiredSettings.Where(name => (request.OverrideThreshold(rule.Id, "-") ?? request.Threshold(name)) is not { Length: > 0 }).ToList();
        if (unset.Count > 0)
        {
            var reason = $"not configured: set {string.Join(", ", unset.Select(n => "threshold." + n))} ('keeper decide setting threshold.{unset[0]} <value>')";
            run.Result(new ResultRecord
            {
                Instance = instance, System = system, RuleId = rule.Id, EntityType = rule.EntityType, EntityKey = "-",
                State = "n-a", Why = reason, TtlMinutes = rule.TtlMinutes, At = observedAt,
            });
            Coverage("not-applicable", reason, 0);
            return 0;
        }

        if (outcome.State == "failed")
        {
            run.Result(new ResultRecord
            {
                Instance = instance, System = system, RuleId = rule.Id, EntityType = rule.EntityType, EntityKey = "-",
                State = "unknown", Why = Redactor.Clean($"the query failed: {outcome.Reason}"), TtlMinutes = rule.TtlMinutes, At = observedAt,
            });
            Coverage("failed", outcome.Reason, 0);
            return 0;
        }

        var findings = 0;
        if (rule.Count is { } count)
        {
            // A per-host query counts per host: "no update installed in 45 days" and "more than 3 local
            // administrators" are about each machine. A host whose query failed is unknown, never a pass.
            if (outcome.Targets.Any(t => t.Target is not null))
            {
                var byTarget = outcome.Rows.ToLookup(r => r.Target, StringComparer.OrdinalIgnoreCase);
                foreach (var target in outcome.Targets.Where(t => t.Target is not null))
                {
                    if (target.State == "failed")
                    {
                        run.Result(new ResultRecord
                        {
                            Instance = instance, System = system, RuleId = rule.Id, EntityType = rule.EntityType, EntityKey = target.Target!,
                            State = "unknown", Why = Redactor.Clean($"the query failed on this host: {target.Reason}"), TtlMinutes = rule.TtlMinutes, At = observedAt,
                        });
                        continue;
                    }
                    findings += CountRows(byTarget[target.Target].ToList(), rule.EntityType, target.Target!, target.State == "partial" ? target.Reason : null);
                }
            }
            else
            {
                findings += CountRows(outcome.Rows, "instance", "-", outcome.State == "partial" ? outcome.Reason : null);
            }
        }
        else
        {
            foreach (var (row, target) in outcome.Rows)
            {
                var key = KeyOf(rule.Query, row, target);
                var evaluator = new Evaluator(name => request.OverrideThreshold(rule.Id, key) ?? request.Threshold(name), now) { Mask = outcome.Mask };
                var verdict = evaluator.Each(rule.Each!, row);
                Result(rule.EntityType, key, verdict);
                if (verdict.Fails != true)
                    continue;

                // Evidence, titles and check ids are written from the row as the scan keeps it, masked fields masked.
                var kept = outcome.Masked(row);
                var name = rule.Query.Name is { } nameField ? Values.Text(FieldPath.First(row, nameField)) : null;
                var evidence = rule.Evidence is not null ? Templates.Render(rule.Evidence, kept)
                    : verdict.Value is null ? null
                    : hide ? "the value is masked"
                    : $"value {verdict.Value}{(verdict.Operand is null ? "" : $" (rule: {verdict.Operand})")}";
                run.Finding(BuildFinding(rule, instance, system, rule.EntityType, key, name, kept, evaluator, observedAt, evidence, severityRow: row));
                findings++;
            }
        }

        Coverage(outcome.State, outcome.State == "ok" ? null : outcome.Reason, outcome.Rows.Count);
        return findings;

        // by: one count per value of a field - "more than one admin per site" - each its own result and finding.
        int CountRows(List<(JsonObject Row, string? Target)> rows, string entityType, string target, string? partial)
        {
            if (rule.Count!.By is not { } by)
                return CountOne(rows, entityType, target, partial, null, 0, 0);
            if (rows.Count == 0)
            {
                Result(entityType, target, new Verdict(null, "0", null, $"no rows, so no {by} to count by"));
                return 0;
            }
            var groups = rows.GroupBy(r => Values.Text(FieldPath.First(r.Row, by)), StringComparer.OrdinalIgnoreCase).ToList();
            // Rows whose group cannot be read could belong to any group: not a group that could pass, and they could
            // add to every other group's count.
            var orphans = groups.FirstOrDefault(g => g.Key is null)?.ToList() ?? [];
            var evaluator = new Evaluator(name => request.OverrideThreshold(rule.Id, target) ?? request.Threshold(name), now);
            var mayCount = rule.Count.Where is null ? orphans.Count : orphans.Count(o => evaluator.Each(rule.Count.Where, o.Row).Fails != false);
            var total = 0;
            foreach (var group in groups)
            {
                if (group.Key is null)
                {
                    // Said only when those rows could change something: they could count, or dilute a share.
                    if (mayCount > 0 || rule.Count.Percent)
                    {
                        var none = target == "-" ? "(no " + by + ")" : $"{target}|(no {by})";
                        Result(entityType, none, new Verdict(null, group.Count().ToString(System.Globalization.CultureInfo.InvariantCulture), null, $"{group.Count()} rows have no {by}"));
                    }
                    continue;
                }
                total += CountOne([.. group], entityType, target == "-" ? group.Key : $"{target}|{group.Key}", partial, group.Key, orphans.Count, mayCount);
            }
            return total;
        }

        // partial: why the read is incomplete. Its count is a floor - enough to fail, never to pass; a share
        // of a partial read says nothing either way.
        // Rows outside this count that could still belong to it (rows with no group, for a count by group): all of
        // them (they could join a share and dilute it), and those that could also match (they could add to it).
        int CountOne(List<(JsonObject Row, string? Target)> rows, string entityType, string target, string? partial, string? group,
            double mayJoin, double extraUnknown)
        {
            var count = rule.Count!;
            var evaluator = new Evaluator(name => request.OverrideThreshold(rule.Id, target) ?? request.Threshold(name), now);
            var judged = count.Where is null
                ? rows.Select(r => (r.Row, r.Target, Fails: (bool?)true)).ToList()
                : rows.Select(r => (r.Row, r.Target, evaluator.Each(count.Where, r.Row).Fails)).ToList();
            var matching = judged.Where(j => j.Fails == true).ToList();
            var unjudged = judged.Count(j => j.Fails is null);
            if (count.Percent && judged.Count == 0)
            {
                Result(entityType, target, new Verdict(null, null, null, "no rows, so there is no share to compare"));
                return 0;
            }
            // Rows that could not be judged might all match or none might: judge both ends. A pass that the
            // unjudged rows could overturn is unknown, never a pass. A failure stands, as before: an unreadable
            // policy never satisfies a must-exist rule.
            double low, high, shown;
            if (count.Percent)
            {
                // Rows that may belong here may join and not match (all of them: the share falls), or join and match
                // (those that could: the share rises).
                var (m, t) = ((double)matching.Count, (double)judged.Count);
                shown = 100 * m / t;
                low = Math.Min(shown, 100 * m / (t + mayJoin));
                high = Math.Max(100 * (m + unjudged) / t, 100 * (m + unjudged + extraUnknown) / (t + extraUnknown));
            }
            else if (count.Distinct is { } field)
            {
                var values = matching.Select(m => Values.Text(FieldPath.First(m.Row, field))).ToList();
                low = shown = values.OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Count();
                high = low + unjudged + values.Count(v => v is null) + extraUnknown;
            }
            else
            {
                low = shown = matching.Count;
                high = matching.Count + unjudged + extraUnknown;
            }
            var verdict = evaluator.Count(count, shown);
            // The far end, and the limit itself when it lies between: "eq 3" passes at 2 and at 4, not at 3. For
            // eq and ne a failure is no floor either - "ne 2" fails at 1 and passes at 2 - so a limit within reach
            // of the unjudged rows makes either verdict unknown.
            // A share has no floor: rows that may join can tip it either way.
            var limitInRange = Values.TryNumber(verdict.Operand, out var limit) && limit >= low && limit <= high;
            bool Differs(double v) => evaluator.Count(count, v).Fails != verdict.Fails;
            var uncertain = high != low && (count.Op is "eq" or "ne" ? limitInRange
                : count.Percent ? Differs(low) || Differs(high)
                : verdict.Fails == false && (Differs(high) || Differs(low)));
            if (uncertain)
            {
                Result(entityType, target, new Verdict(null, verdict.Value, verdict.Operand,
                    $"{unjudged + (int)extraUnknown} rows could not be judged, and they could change the outcome"));
                return 0;
            }
            if (partial is not null && (verdict.Fails != true || count.Percent))
            {
                run.Result(new ResultRecord
                {
                    Instance = instance, System = system, RuleId = rule.Id, EntityType = entityType, EntityKey = target, State = "unknown",
                    Value = verdict.Value, Operand = verdict.Operand, TtlMinutes = rule.TtlMinutes, At = observedAt,
                    Why = Redactor.Clean($"the read was partial, so {verdict.Value} is only a floor: {partial}"),
                });
                return 0;
            }
            Result(entityType, target, verdict);
            if (verdict.Fails != true)
                return 0;

            var sample = string.Join(", ", matching.Take(10).Select(r => KeyOf(rule.Query, r.Row, r.Target)));
            var note = unjudged > 0 ? $" ({unjudged} of {judged.Count} rows could not be judged)" : "";
            var where = target == "-" ? "" : $"{target}: ";
            var counting = count.Percent ? $"{verdict.Value}% of {judged.Count} rows" : count.Distinct is not null ? $"{verdict.Value} distinct" : $"{verdict.Value}";
            run.Finding(BuildFinding(rule, instance, system, entityType, target, target == "-" ? null : target, null, evaluator, observedAt,
                rule.Evidence is null
                    ? $"{where}{counting} found (limit {verdict.Operand}){(sample.Length > 0 ? ": " + sample : "")}{note}"
                    : Templates.Render(rule.Evidence, new JsonObject
                    {
                        ["host"] = target, ["group"] = group, ["count"] = matching.Count, ["value"] = verdict.Value, ["rows"] = judged.Count,
                        ["unjudged"] = unjudged, ["sample"] = sample,
                    }) + note));
            return 1;
        }
    }

    /// <param name="row">The row as the scan keeps it (masked fields masked): what the finding shows.</param>
    /// <param name="severityRow">The row as read, when it differs: a severity can depend on a masked value without showing it.</param>
    private static FindingRecord BuildFinding(Rule rule, string instance, string system, string entityType, string target, string? name,
        JsonObject? row, Evaluator evaluator, string observedAt, string? evidence, JsonObject? severityRow = null)
    {
        var emit = rule.Emit;
        var checkId = emit?.Check is { } template && row is not null ? Sanitize(Templates.Render(template, row)) : rule.Id;
        if (checkId.Length == 0)
            checkId = rule.Id;
        severityRow ??= row;
        var severity = emit?.Severity is { } emitSeverity ? evaluator.Severity(emitSeverity, severityRow)
            : rule.SeverityBy is { } map ? evaluator.Severity(map, severityRow)
            : rule.Severity;
        var kind = emit?.Kind ?? rule.Kind;
        var category = emit?.Category ?? rule.Category;
        var title = emit?.Title is { } titleTemplate && row is not null ? Templates.Render(titleTemplate, row) : rule.Title;

        return new FindingRecord
        {
            FindingKey = FindingKey.For(instance, checkId, target),
            Instance = instance,
            System = system,
            RuleId = rule.Id,
            CheckId = checkId,
            EntityType = entityType,
            Target = target,
            EntityName = name,
            Kind = kind,
            Lens = rule.Lens,
            Category = category,
            Severity = severity,
            Security = Vocabulary.IsSecurity(category, rule.Lens),
            Title = Truncate(title, 300)!,
            Evidence = evidence is null ? null : Truncate(Redactor.Clean(evidence), 2000),
            Why = rule.Why,
            Fix = rule.Fix,
            Refs = rule.Refs,
            // deadline: a field of the row, or a date of its own (a product's end of support) for every finding of the rule.
            Deadline = rule.Deadline is not { } deadline ? null
                : Values.IsLiteralDate(deadline) ? deadline
                : row is not null ? Values.IsoDate(Values.Text(FieldPath.First(row, deadline))) : null,
            ObservedAt = observedAt,
        };
    }

    /// <summary>An imported tool's own check id, made safe to use as an id.</summary>
    private static string Sanitize(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text.Trim())
            builder.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '-');
        var id = builder.ToString().Trim('-');
        return id.Length > 100 ? id[..100] : id;
    }

    private static string? Truncate(string? text, int max = 500) => text is null || text.Length <= max ? text : text[..max] + "...";

    private static string? Hidden(string? text) => text is null ? null : "(masked)";
}
