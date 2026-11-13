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
    /// <summary>A rule's threshold overrides for an entity ("-" for the rule as a whole), most specific first.</summary>
    public Func<string, string, IReadOnlyList<string>> OverrideThresholds { get; init; } = (_, _) => [];

    /// <summary>Hosts for per-target rules, from what earlier scans saw.</summary>
    public Func<TargetSpec, IReadOnlyList<string>> ResolveTargets { get; init; } = _ => [];

    /// <summary>
    /// The attributes of each target host (by the target's name), for the rules that say which hosts they
    /// <c>applies</c> to. A host missing here is one the rule cannot be judged on.
    /// </summary>
    public Func<TargetSpec, IReadOnlyDictionary<string, JsonObject>> ResolveTargetAttributes { get; init; } = _ => new Dictionary<string, JsonObject>();

    /// <summary>Why the resolved host list may be missing hosts (its source read was not clean), or null.</summary>
    public Func<TargetSpec, string?> TargetsIncomplete { get; init; } = _ => null;

    /// <summary>Hosts a file's targets 'where' could not judge, as a note for the scan's manifest - or null.</summary>
    public Func<TargetSpec, string?> TargetsUnjudged { get; init; } = _ => null;

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

    /// <summary>
    /// How hard the estate is read: hosts at once, new sessions per second, requests per second per host, when to stop a
    /// host. Unlimited unless set - the verbs always set it (<c>keeper scan</c>: the integration's profile, gentle by default).
    /// </summary>
    public PaceProfile Pace { get; init; } = PaceProfile.Unlimited;

    /// <summary>Hosts read at once, when set: overrides the pace profile's (the old --parallel).</summary>
    public int? Parallelism { get; init; }

    /// <summary>Read at most this many hosts per query (a connection test reads one), or every host when null.</summary>
    public int? TargetLimit { get; init; }

    /// <summary>Credentials refused so far. <see cref="LogonGuard.Process"/> in the binary, so a refusal holds for every system of a run.</summary>
    public LogonGuard Guard { get; init; } = new();

    public Action<string> Log { get; init; } = _ => { };
}

/// <summary>What a scan would cost one host.</summary>
public sealed record HostPlan(string Host, int Queries, int Reads, int Sessions, TimeSpan Time);

/// <summary>What a scan would cost the estate, before it runs.</summary>
public sealed record ScanPlan(PaceProfile Pace, IReadOnlyList<HostPlan> Hosts, int Queries, int UnmergedReads, int Reads, int Sessions,
    TimeSpan Time, IReadOnlyList<string> Problems);

/// <summary>What the scan cost the estate: sessions (logons) opened, per host.</summary>
public sealed record ScanCost(int Sessions, int Hosts, int Reads, int MergedAway);

public sealed record ScanReport(RunManifest Manifest, int Rules, int Queries, int Rows, int Findings, int FailedQueries)
{
    public ScanCost Cost { get; init; } = new(0, 0, 0, 0);
}

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
        var (queries, readOf) = Group(rules);
        var outcomes = new Dictionary<string, QueryOutcome>(StringComparer.Ordinal);

        var dropRatio = double.TryParse(request.Threshold("scan.row-drop-ratio"), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var r) && r is > 0 and <= 1 ? r : DefaultDropRatio;
        var confirmScans = int.TryParse(request.Threshold("scan.drop-confirm-scans"), System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out var confirm) && confirm >= 1 ? confirm : DefaultDropConfirmScans;
        var confirmAge = TimeSpan.FromDays(double.TryParse(request.Threshold("scan.drop-confirm-days"), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var days) && days >= 0 ? days : DefaultDropConfirmDays);
        // Hosts left out because the targets' where could not judge them are said, once per target list.
        if (request.Connection.Options["targets"] is not JsonArray)
        {
            foreach (var spec in request.Files.Select(f => f.Targets).OfType<TargetSpec>().Where(t => t.List.Count == 0)
                         .DistinctBy(TargetsText, StringComparer.Ordinal))
            {
                if (request.TargetsUnjudged(spec) is { } unjudged)
                    notes.Add(unjudged);
            }
        }
        var (fetched, cost, paceNotes) = await FetchAll(queries, request, cancellationToken).ConfigureAwait(false);
        foreach (var group in queries)
        {
            // The rows' entity type and name come from a rule judged row by row when there is one: a count rule's
            // entity (the instance, a host) is what the count is about, not what the rows are.
            var rule = group.Select(g => g.Rule).FirstOrDefault(r => r.Count is null) ?? group.First().Rule;
            var nameField = group.Select(g => g.Rule.Query.Name).FirstOrDefault(n => n is not null);
            var outcome = fetched[group.Key];
            // Keeper's own store and other tools' files cannot lose sight of rows, so only their min_rows applies.
            var dropCheck = rule.Query.Protocol is not ("store" or "file");
            Distrust(outcome, group.Key, group.Max(g => g.Rule.Query.MinRows), dropCheck ? request.PreviousRows : _ => null, dropRatio,
                confirmScans, confirmAge, started);
            outcomes[group.Key] = outcome;
            AssignKeyless(outcome, rule.Query);
            // A field any rule of the query masks is masked in every row the scan keeps; conditions read the real value.
            outcome.Mask = [.. group.SelectMany(g => g.Rule.Mask).Distinct(StringComparer.OrdinalIgnoreCase)];

            foreach (var (row, target) in outcome.Rows)
            {
                // Another rule of the query may mask what this one names the entity by: the name is read from the row as kept.
                var kept = outcome.Masked(row);
                run.Row(new RowRecord
                {
                    Instance = instance,
                    System = system,
                    Query = group.Key,
                    EntityType = rule.EntityType,
                    EntityKey = KeyOf(rule.Query, row, target),
                    EntityName = nameField is not null ? Values.Text(FieldPath.First(kept, nameField)) : null,
                    Target = target,
                    Attrs = kept,
                    ObservedAt = observedAt,
                });
            }
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
        var attributesByFile = new Dictionary<RuleFile, IReadOnlyDictionary<string, JsonObject>>();
        foreach (var (rule, file) in rules)
        {
            Func<string?, bool?>? appliesTo = null;
            if (rule.Applies is { } applies && file.Targets is { } spec)
            {
                if (!attributesByFile.TryGetValue(file, out var attributes))
                    attributesByFile[file] = attributes = new Dictionary<string, JsonObject>(request.ResolveTargetAttributes(spec), StringComparer.OrdinalIgnoreCase);
                var evaluator = new Evaluator(name => request.Threshold(name), _clock.GetUtcNow());
                // true: judged here. false: this rule is not about this host. null: the host's kind is not known.
                appliesTo = target => target is null ? true
                    : attributes.TryGetValue(target, out var host) ? evaluator.Each(applies, host).Fails
                    : null;
            }
            findings += Evaluate(rule, outcomes[readOf[(rule, file)]], request, run, instance, system, observedAt, appliesTo);
        }

        var states = outcomes.Values.Select(o => o.State).ToList();
        var status = states.All(s => s == "ok") ? "ok" : states.Any(s => s is "ok" or "partial") ? "partial" : "failed";
        notes.AddRange(paceNotes);
        var manifest = run.Complete(status, _clock.GetUtcNow(), request.Connection.SignedInAs ?? request.Connection.Identity, notes);
        return new ScanReport(manifest, rules.Count, queries.Count, outcomes.Values.Sum(o => o.Rows.Count), findings,
            states.Count(s => s == "failed")) { Cost = cost };
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

    /// <summary>One read the scan makes: one query (or several merged into one) on one host - or on the integration's endpoint.</summary>
    private sealed record Read(IReadOnlyList<(string Id, QuerySpec Query, string? Target)> Members, QuerySpec Query, IRunner Runner, string? Target, string Lane);

    /// <summary>
    /// Reads every query of the scan, host by host: up to the pace's number of hosts at once; on one host one read at a
    /// time over one session per runner family; a host that pushes back is slowed and then stopped; a refused credential
    /// is never presented again. The outcomes are then assembled per query - groups in order, hosts in list order -
    /// exactly as reading query by query gave them.
    /// </summary>
    private async Task<(Dictionary<string, QueryOutcome> Outcomes, ScanCost Cost, List<string> Notes)> FetchAll(
        List<IGrouping<string, (Rule Rule, RuleFile File)>> queries, ScanRequest request, CancellationToken cancellationToken)
    {
        var connection = request.Connection;
        var profile = Profile(request);
        var pacer = new Pacer(profile, _clock);
        var endpointHost = EndpointHost(connection.Endpoint);
        var (outcomes, plans, reads) = BuildPlan(queries, request);

        var merged = Merge(reads);
        var results = new System.Collections.Concurrent.ConcurrentDictionary<(string Id, string? Target), RunnerResult>();
        var sessions = 0;
        var lanes = merged.GroupBy(r => r.Lane, StringComparer.OrdinalIgnoreCase).ToList();
        using var gate = new SemaphoreSlim(Math.Max(1, profile.Hosts));
        await Task.WhenAll(lanes.Select(async lane =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var opened = await ReadLane(lane.Key.Length == 0 ? endpointHost : lane.Key, [.. lane], request, pacer, results, cancellationToken).ConfigureAwait(false);
                Interlocked.Add(ref sessions, opened);
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        foreach (var (id, targets) in plans)
        {
            var outcome = outcomes[id];
            foreach (var target in targets)
            {
                var result = results[(id, target)];
                outcome.Rows.AddRange(result.Rows.Select(r => (r, target)));
                outcome.Targets.Add(new TargetOutcome(target, result.State, result.Reason, result.Rows.Count));
            }
        }

        var notes = new List<string>();
        var remote = reads.Any(r => r.Runner.IsRemote(connection));
        if (remote)
            notes.Add($"pace: {profile}; {sessions} session(s) opened on {lanes.Count} host(s) for {merged.Count} read(s)" +
                      (reads.Count > merged.Count ? $" ({reads.Count - merged.Count} merged into others)" : ""));
        foreach (var (host, signals, stopped) in pacer.PushedBack())
            notes.Add(stopped ? pacer.Stopped(host)! : $"{host} pushed back {signals} time(s); Keeper slowed down for it");
        if (request.Guard.Refusal(connection) is { } refusal)
            notes.Add(refusal);
        return (outcomes, new ScanCost(sessions, lanes.Count, merged.Count, reads.Count - merged.Count), notes);
    }

    private static PaceProfile Profile(ScanRequest request) =>
        request.Parallelism is { } hosts ? request.Pace with { Hosts = Math.Max(1, hosts) } : request.Pace;

    /// <summary>Every read the scan will make (before merging), and each query's outcome with its query-wide records already in.</summary>
    private (Dictionary<string, QueryOutcome> Outcomes, List<(string Id, IReadOnlyList<string?> Targets)> Plans, List<Read> Reads) BuildPlan(
        List<IGrouping<string, (Rule Rule, RuleFile File)>> queries, ScanRequest request)
    {
        var connection = request.Connection;

        var outcomes = new Dictionary<string, QueryOutcome>(StringComparer.Ordinal);
        var plans = new List<(string Id, IReadOnlyList<string?> Targets)>();
        var reads = new List<Read>();
        foreach (var group in queries)
        {
            var (rule, file) = group.First();
            var runner = registry.Get(rule.Query.Protocol);
            var outcome = new QueryOutcome([], []);
            outcomes[group.Key] = outcome;
            if (!runner.IsPerTarget(connection))
            {
                plans.Add((group.Key, [null]));
                reads.Add(new Read([(group.Key, rule.Query, null)], rule.Query, runner, null, ""));
                continue;
            }

            var (targets, targetsProblem) = ResolveTargets(file, request);
            if (targets.Count == 0)
            {
                outcome.Targets.Add(new TargetOutcome(null, "failed", targetsProblem ?? "no targets: set the file's targets or the integration's targets option (or targetsFrom=discovery)", 0));
                continue;
            }
            // Discovery supplied the list and it may be short: said, so the scan is partial and not quietly smaller.
            if (targetsProblem is not null)
                outcome.Targets.Add(new TargetOutcome(null, "partial", targetsProblem, 0));
            // A query-wide record beside the hosts' own: it tells the tracker that a host missing from this read may
            // simply be missing from the list, not retired.
            if (file.Targets is { List.Count: 0 } spec && connection.Options["targets"] is not JsonArray && request.TargetsIncomplete(spec) is { } incomplete)
                outcome.Targets.Add(new TargetOutcome(null, "partial", incomplete, 0));

            // A host listed twice is read once (its rows would count twice).
            var unique = targets.Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(request.TargetLimit ?? int.MaxValue).ToList();
            if (unique.Count == 0)
            {
                outcome.Targets.Add(new TargetOutcome(null, "failed", "no targets: every listed target was blank", 0));
                continue;
            }
            plans.Add((group.Key, unique));
            reads.AddRange(unique.Select(target => new Read([(group.Key, rule.Query, target)], rule.Query, runner, target, target)));
        }
        return (outcomes, plans, reads);
    }

    /// <summary>
    /// What a scan would cost each host, with no network traffic: its queries, the reads left after merging, the
    /// sessions (sign-ins) it opens, and the time at the pace - at least, since a read may make several requests.
    /// </summary>
    public ScanPlan Plan(ScanRequest request)
    {
        var (queries, _) = Group([.. request.Files.SelectMany(f => f.Rules.Select(r => (Rule: r, File: f)))]);
        var (outcomes, _, reads) = BuildPlan(queries, request);
        var profile = Profile(request);
        var endpointHost = EndpointHost(request.Connection.Endpoint);
        var merged = Merge(reads);
        var hosts = merged.GroupBy(r => r.Lane, StringComparer.OrdinalIgnoreCase).Select(lane =>
        {
            var remote = lane.Where(r => r.Runner.IsRemote(request.Connection)).ToList();
            var sessions = remote.Select(r => r.Runner).OfType<ISessionRunner>().Select(r => r.SessionFamily).Distinct(StringComparer.Ordinal).Count();
            var seconds = profile.RequestsPerSecond > 0 ? remote.Count / profile.RequestsPerSecond : 0;
            return new HostPlan(lane.Key.Length == 0 ? endpointHost : lane.Key, lane.Sum(r => r.Members.Count), lane.Count(), sessions, TimeSpan.FromSeconds(seconds));
        }).OrderBy(h => h.Host, StringComparer.OrdinalIgnoreCase).ToList();
        var totalSessions = hosts.Sum(h => h.Sessions);
        var sessionTime = profile.SessionsPerSecond > 0 ? totalSessions / profile.SessionsPerSecond : 0;
        var readTime = hosts.Count == 0 ? 0 : Math.Max(hosts.Max(h => h.Time.TotalSeconds), hosts.Sum(h => h.Time.TotalSeconds) / Math.Max(1, profile.Hosts));
        var problems = outcomes.Where(o => o.Value.Targets.Any(t => t.State == "failed")).Select(o => $"{o.Key}: {o.Value.Targets.First(t => t.State == "failed").Reason}").ToList();
        return new ScanPlan(profile, hosts, queries.Count, reads.Count, merged.Count, totalSessions, TimeSpan.FromSeconds(Math.Max(readTime, sessionTime)), problems);
    }

    /// <summary>
    /// Rules with the same query share one read - unless their files name different targets: each read then gets the
    /// hosts its own file names. The first target list keeps the query's id (its history); another gets the id with
    /// "~" and a hash of its targets, so neither reads the other's hosts. Returns the groups and each rule's group.
    /// </summary>
    private static (List<IGrouping<string, (Rule Rule, RuleFile File)>> Groups, Dictionary<(Rule, RuleFile), string> ReadOf) Group(
        List<(Rule Rule, RuleFile File)> rules)
    {
        var firstTargets = new Dictionary<string, string>(StringComparer.Ordinal);
        var readOf = new Dictionary<(Rule, RuleFile), string>();
        foreach (var (rule, file) in rules)
        {
            var targets = TargetsText(file.Targets);
            var id = rule.Query.Id;
            if (!firstTargets.TryAdd(id, targets) && firstTargets[id] != targets)
                id = $"{id}~{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(targets)))[..6]}";
            readOf[(rule, file)] = id;
        }
        return (rules.GroupBy(r => readOf[r], StringComparer.Ordinal).ToList(), readOf);
    }

    /// <summary>A target list as text, equal for equal lists whichever file they are in.</summary>
    private static string TargetsText(TargetSpec? spec) => spec is null ? "" :
        $"{spec.Entity}|{spec.Field}|{string.Join(",", spec.List)}|{ConditionText(spec.Where)}";

    private static string ConditionText(Condition? condition) => condition switch
    {
        null => "",
        LeafCondition l => $"({l.Field} {l.Op} {l.Value?.ToJsonString()} {l.Threshold} {l.Format} {l.Required})",
        AllCondition a => $"all[{string.Join(",", a.Items.Select(ConditionText))}]",
        AnyCondition a => $"any[{string.Join(",", a.Items.Select(ConditionText))}]",
        NotCondition n => $"not[{ConditionText(n.Item)}]",
        ElementCondition e => $"element[{e.Of} {e.All} {ConditionText(e.Where)}]",
        AlwaysCondition => "always",
        _ => condition.GetType().Name,
    };

    /// <summary>Reads of one host that a runner can serve with one read (registry values under one key) become that one read.</summary>
    private static List<Read> Merge(List<Read> reads)
    {
        var result = new List<Read>(reads.Count);
        var at = new Dictionary<Read, int>(ReferenceEqualityComparer.Instance);
        // The target as written, not the lane: a member must keep its own spelling of the host (its rows' host field,
        // and so its entity keys), so two files that spell one host differently read it twice over the one session.
        var groups = new Dictionary<(string Lane, string Target, string Protocol, string Key), List<Read>>();
        foreach (var read in reads)
        {
            if (read.Runner is IQueryMerger merger && merger.MergeKey(read.Query) is { } key)
            {
                var slot = (read.Lane.ToLowerInvariant(), read.Target ?? "", read.Query.Protocol, key);
                if (!groups.TryGetValue(slot, out var list))
                {
                    groups[slot] = list = [];
                    at[read] = result.Count;
                    result.Add(read);   // a placeholder in the first member's place, replaced below
                }
                list.Add(read);
                continue;
            }
            result.Add(read);
        }
        // Members that cannot be merged go back after their group's first, in order; inserting shifts the places
        // after it, so groups are handled from the last place to the first.
        foreach (var list in groups.Values.OrderByDescending(l => at[l[0]]))
        {
            var place = at[list[0]];
            if (list.Count == 1)
                continue;
            QuerySpec merged;
            try
            {
                merged = ((IQueryMerger)list[0].Runner).Merge([.. list.Select(r => r.Query)]);
            }
#pragma warning disable CA1031 // A merge that cannot be made leaves the reads as they were.
            catch (Exception)
#pragma warning restore CA1031
            {
                result.InsertRange(place + 1, list.Skip(1));
                continue;
            }
            result[place] = new Read([.. list.SelectMany(r => r.Members)], merged, list[0].Runner, list[0].Target, list[0].Lane);
        }
        return result;
    }

    /// <summary>One host's reads, one at a time; its sessions are closed when they are done. Returns the sessions opened.</summary>
    private async Task<int> ReadLane(string host, List<Read> reads, ScanRequest request, Pacer pacer,
        System.Collections.Concurrent.ConcurrentDictionary<(string Id, string? Target), RunnerResult> results, CancellationToken cancellationToken)
    {
        var connection = request.Connection;
        var pace = pacer.For(host);
        var sessions = new Dictionary<string, (IRunnerSession? Session, RunnerResult? Failure)>(StringComparer.Ordinal);
        var opened = 0;
        string? deniedHere = null;
        try
        {
            foreach (var read in reads)
            {
                var remote = read.Runner.IsRemote(connection);
                var context = Context(request, read.Target) with { Pace = remote ? pace : NoPace.Instance };
                RunnerResult result;
                if (remote && request.Guard.Refusal(connection) is { } refused)
                    result = RunnerResult.Failed(refused, FailureKind.Refused);
                else if (remote && pacer.Stopped(host) is { } stopped)
                    result = RunnerResult.Failed($"not read: {stopped}", FailureKind.Throttled);
                else if (remote && deniedHere is not null)
                    result = RunnerResult.Failed(deniedHere, FailureKind.Denied);
                else if (!remote)
                    result = await Safe(read.Runner.Protocol, () => read.Runner.RunAsync(read.Query, context, cancellationToken), cancellationToken).ConfigureAwait(false);
                else
                {
                    // Until the credential has been accepted once - a read that came back with data - credentialed work goes
                    // one host at a time across the scan: a wrong password meets one host, not every host the pace lets in.
                    // Opening a session is not proof: some runners sign in only on their first read.
                    // An integration that presents no secret (auth none, or negotiate as the Windows user Keeper runs as) has
                    // no password Keeper could have wrong, so nothing to lock.
                    var proving = LogonGuard.PresentsSecret(connection) && !request.Guard.Proven(connection);
                    if (proving)
                        await _proving.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var fresh = true;
                        if (proving && request.Guard.Refusal(connection) is { } refusedMeanwhile)
                        {
                            result = RunnerResult.Failed(refusedMeanwhile, FailureKind.Refused);
                            fresh = false;
                        }
                        else if (read.Runner is ISessionRunner sessionRunner)
                        {
                            var isNew = !sessions.TryGetValue(sessionRunner.SessionFamily, out var session);
                            if (isNew)
                            {
                                await pacer.WaitSessionAsync(cancellationToken).ConfigureAwait(false);
                                session = await Open(sessionRunner, context, cancellationToken).ConfigureAwait(false);
                                sessions[sessionRunner.SessionFamily] = session;
                                opened++;
                            }
                            if (session.Failure is { } failedOpen)
                            {
                                // One sign-in per host and family per scan: a session that could not be opened is not tried
                                // again, and only its first failure says anything about the credential.
                                result = failedOpen;
                                fresh = isNew;
                            }
                            else
                            {
                                await pacer.WaitAsync(host, cancellationToken).ConfigureAwait(false);   // the scanner checked Stopped before this read
                                result = await Safe(read.Runner.Protocol, () => sessionRunner.RunAsync(session.Session!, read.Query, context, cancellationToken), cancellationToken).ConfigureAwait(false);
                            }
                        }
                        else
                        {
                            await pacer.WaitAsync(host, cancellationToken).ConfigureAwait(false);   // the scanner checked Stopped before this read
                            result = await Safe(read.Runner.Protocol, () => read.Runner.RunAsync(read.Query, context, cancellationToken), cancellationToken).ConfigureAwait(false);
                        }
                        if (fresh)
                            deniedHere = Learn(request, pacer, host, read, result) ?? deniedHere;
                    }
                    finally
                    {
                        if (proving)
                            _proving.Release();
                    }
                }

                foreach (var (id, original, target) in read.Members)
                    results[(id, target)] = read.Members.Count == 1 ? result : Split((IQueryMerger)read.Runner, original, result);
            }
        }
        finally
        {
            foreach (var (session, _) in sessions.Values)
            {
                if (session is null)
                    continue;
                try
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                }
#pragma warning disable CA1031 // Closing a session that already broke is not a failure of the scan.
                catch (Exception)
#pragma warning restore CA1031
                {
                }
            }
        }
        return opened;
    }

    /// <summary>One sign-in at a time while the credential is unproven.</summary>
    private readonly SemaphoreSlim _proving = new(1, 1);

    /// <summary>An original query's part of a merged read; a split that throws is a failed read of that query, not a crashed scan.</summary>
    private static RunnerResult Split(IQueryMerger merger, QuerySpec original, RunnerResult merged)
    {
        try
        {
            return merger.Split(original, merged);
        }
#pragma warning disable CA1031 // A runner's failure is data: it becomes a failed coverage record.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return RunnerResult.Failed($"{original.Protocol}: the merged read could not be split: {ex.Message}", FailureKind.Error);
        }
    }

    private static async Task<(IRunnerSession? Session, RunnerResult? Failure)> Open(ISessionRunner runner, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            return (await runner.OpenAsync(context, cancellationToken).ConfigureAwait(false), null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A session that cannot be opened is a failed read of every query of that host and family.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return (null, RunnerResult.Failed($"{runner.Protocol}: {ex.Message}", Failures.Classify(ex)));
        }
    }

    /// <summary>
    /// What a read (or a sign-in) said about the credential and the host. A refusal stops the credential. Data coming
    /// back, or a host that answered as the account, proves it. While it is unproven, "access denied" from a runner
    /// where that can be a wrong password (DCOM) is ambiguous, so it counts towards a refusal and the rest of this host
    /// is not tried: returns why, for the lane. Elsewhere a denial is about one object and the host is read on.
    /// A push-back slows the host and, in a row, stops it.
    /// </summary>
    private static string? Learn(ScanRequest request, Pacer pacer, string host, Read read, RunnerResult result)
    {
        var connection = request.Connection;
        var target = read.Target;
        string? deniedHere = null;
        switch (result.Failure)
        {
            case FailureKind.Refused:
                request.Guard.Refuse(connection, target ?? host, Redactor.Clean(result.Reason) ?? "refused");
                break;
            case FailureKind.Denied when read.Runner.DeniedMayBeSignIn && !result.SignedIn
                                         && LogonGuard.PresentsSecret(connection) && !request.Guard.Proven(connection):
                var reason = Redactor.Clean(result.Reason) ?? "access denied";
                request.Guard.DeniedAtSignIn(connection, target ?? host, reason);
                deniedHere = $"not tried: {target ?? host} denied {connection.Identity ?? "the current user"} before any host accepted it ({reason}) - " +
                             "the rest of this host is skipped so a wrong password is not presented again";
                break;
            case FailureKind.Throttled or FailureKind.Timeout:
                pacer.Signal(host, result.Failure);
                break;
        }
        var answered = result.State is "ok" or "partial" && result.Failure is not (FailureKind.Refused or FailureKind.Denied);
        // An empty answer is not proof: some runners turn "could not read" into no rows (an event log service that is down).
        if (result.SignedIn || (answered && result.Rows.Count > 0))
            request.Guard.Accepted(connection);
        if (answered && result.Failure is not (FailureKind.Throttled or FailureKind.Timeout))
            pacer.Signal(host, FailureKind.None);
        return deniedHere;
    }

    /// <summary>
    /// A rule's settings for one entity: its own overrides first (each for the threshold it names - see
    /// <see cref="Rule.OverrideFor"/>), then the tenant's setting.
    /// </summary>
    private static Func<string, string?> Threshold(ScanRequest request, Rule rule, string entity)
    {
        var overrides = request.OverrideThresholds(rule.Id, entity);
        return name => overrides.Select(value => rule.OverrideFor(name, value)).FirstOrDefault(v => v is not null) ?? request.Threshold(name);
    }

    /// <summary>The row's own key, or null when the key field (or a part of a key template) is empty.</summary>
    private static string? OwnKey(QuerySpec query, JsonObject row)
    {
        if (!query.Key.Contains('{', StringComparison.Ordinal))
            return Values.Text(FieldPath.First(row, query.Key)) is { Length: > 0 } key ? key : null;
        // A template with an empty part ("{host}|{name}" with no name) would give every such row one key.
        return Templates.Placeholders(query.Key).All(p => Values.Text(FieldPath.First(row, p)) is { Length: > 0 })
            ? Templates.Render(query.Key, row) : null;
    }

    /// <summary>Keys given to rows without their own, by row: see <see cref="AssignKeyless"/>.</summary>
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<JsonObject, string> Keyless = [];

    /// <summary>
    /// Rows of one read and host that have no key of their own would all be one entity (the host, or "-"): five
    /// unnamed services one finding. When there are several, each gets the host and a hash of its content - the same
    /// while the row is the same. A single keyless row keeps the host as its key, as a singleton read always has.
    /// </summary>
    private static void AssignKeyless(QueryOutcome outcome, QuerySpec query)
    {
        foreach (var group in outcome.Rows.Where(r => OwnKey(query, r.Row) is null).GroupBy(r => r.Target ?? "", StringComparer.OrdinalIgnoreCase))
        {
            if (group.Count() < 2)
                continue;
            foreach (var (row, target) in group)
            {
                var content = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(CanonicalJson(row))))[..10];
                var name = $"(no {query.Key}: {content})";
                Keyless.AddOrUpdate(row, target is null ? name : $"{target}|{name}");
            }
        }
    }

    private static string CanonicalJson(JsonNode? node) => node switch
    {
        JsonObject o => "{" + string.Join(",", o.Where(p => !p.Key.StartsWith("_previous", StringComparison.Ordinal) && p.Key != "_new")
            .OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}:{CanonicalJson(p.Value)}")) + "}",
        JsonArray a => "[" + string.Join(",", a.Select(CanonicalJson)) + "]",
        null => "null",
        _ => node.ToJsonString(),
    };

    /// <summary>The host of an endpoint: a URL's host, or the endpoint itself (a host or a domain name).</summary>
    private static string EndpointHost(string? endpoint) =>
        string.IsNullOrWhiteSpace(endpoint) ? "(integration)"
        : Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host) ? uri.Host
        : endpoint.Split(':')[0];

    private (IReadOnlyList<string> Targets, string? Problem) ResolveTargets(RuleFile file, ScanRequest request)
    {
        var options = request.Connection.Options;
        // A list the rule author wrote into the file is their choice. A file that finds its hosts in the store (every
        // directory-driven pack) can be pointed at named hosts by the integration: one lab machine, one host to try.
        if (file.Targets is { List.Count: > 0 } fixedList)
            return (fixedList.List, null);
        if (options["targets"] is JsonArray fromOptions)
            return (fromOptions.Select(t => Values.Text(t)).OfType<string>().Where(t => t.Length > 0).ToList(), null);
        if (file.Targets is { } spec)
            return (request.ResolveTargets(spec), null);
        if (options["targetsFrom"]?.ToString() == "discovery" && options["targetsKind"]?.ToString() is { Length: > 0 } kinds)
            return DiscoveryTargets.Read(request.ImportsDir, kinds, request.Connection.Endpoint, request.Connection.Type, _clock.GetUtcNow());
        // For these types the endpoint is the scope they may talk to, not a host to read.
        if (request.Connection.Type is "ssh" or "printer")
            return ([], null);
        return (string.IsNullOrWhiteSpace(request.Connection.Endpoint) ? [] : [request.Connection.Endpoint], null);
    }

    private RunnerContext Context(ScanRequest request, string? target) =>
        new(request.Connection, target, request.ImportsDir, request.StoreFile, _clock.GetUtcNow(), request.Timeout,
            message => request.Log(target is null ? message : $"{target}: {message}"))
        {
            Threshold = request.Threshold,
        };

    /// <summary>A runner that throws is a failed query, never a crashed scan.</summary>
    private static async Task<RunnerResult> Safe(string protocol, Func<Task<RunnerResult>> read, CancellationToken cancellationToken)
    {
        try
        {
            return await read().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A runner's failure is data: it becomes a failed coverage record.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            return RunnerResult.Failed($"{protocol} runner error: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// The row's entity key: a field, or a template of fields ("{host}|{PartComponent}") when one field is not
    /// unique - several members of one host's Administrators group are several findings, not one.
    /// </summary>
    private static string KeyOf(QuerySpec query, JsonObject row, string? target)
    {
        if (Keyless.TryGetValue(row, out var assigned))
            return assigned;
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

    private int Evaluate(Rule rule, QueryOutcome outcome, ScanRequest request, RunWriter run, string instance, string system, string observedAt,
        Func<string?, bool?>? appliesTo = null)
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
        var unset = rule.RequiredSettings.Where(name => Threshold(request, rule, "-")(name) is not { Length: > 0 }).ToList();
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

        // A rule that applies only to some hosts is not judged on the others; a host whose kind is not known
        // is unknown for it - never a pass, never silently skipped.
        bool NotJudged(string? target, string key)
        {
            if (appliesTo is null)
                return false;
            switch (appliesTo(target))
            {
                case true:
                    return false;
                case false:
                    return true;
                default:
                    run.Result(new ResultRecord
                    {
                        Instance = instance, System = system, RuleId = rule.Id, EntityType = rule.EntityType, EntityKey = key,
                        State = "unknown", Why = "this rule applies to some hosts only, and what kind of host this is could not be read",
                        TtlMinutes = rule.TtlMinutes, At = observedAt,
                    });
                    return true;
            }
        }

        var findings = 0;
        // Whether every count of a partial read still settled its answer (see CountOne): then the rule saw enough.
        var settled = true;
        if (rule.Count is { } count)
        {
            // A per-host query counts per host: "no update installed in 45 days" and "more than 3 local
            // administrators" are about each machine. A host whose query failed is unknown, never a pass.
            if (outcome.Targets.Any(t => t.Target is not null))
            {
                var byTarget = outcome.Rows.ToLookup(r => r.Target, StringComparer.OrdinalIgnoreCase);
                foreach (var target in outcome.Targets.Where(t => t.Target is not null))
                {
                    if (NotJudged(target.Target!, target.Target!))
                        continue;
                    if (target.State == "failed")
                    {
                        settled = false;   // a host not counted: the rule's answer is not whole, whatever the others say
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
                if (NotJudged(target, key))
                    continue;
                var evaluator = new Evaluator(Threshold(request, rule, key), now) { Mask = outcome.Mask };
                var verdict = evaluator.Each(rule.Each!, row);
                Result(rule.EntityType, key, verdict);
                if (verdict.Fails != true)
                    continue;

                // Evidence, titles and check ids are written from the row as the scan keeps it, masked fields masked.
                var kept = outcome.Masked(row);
                var name = rule.Query.Name is { } nameField ? Values.Text(FieldPath.First(kept, nameField)) : null;
                var evidence = rule.Evidence is not null ? Templates.Render(rule.Evidence, kept)
                    : verdict.Value is null ? null
                    : hide ? "the value is masked"
                    : $"value {verdict.Value}{(verdict.Operand is null ? "" : $" (rule: {verdict.Operand})")}";
                run.Finding(BuildFinding(rule, instance, system, rule.EntityType, key, name, kept, evaluator, observedAt, evidence, severityRow: row));
                findings++;
            }
        }

        // A count rule whose every count was settled despite a partial read has its answer: its coverage is ok, so it
        // can read as correct. A rule judged object by object never is - an object not read could be the one that fails.
        if (outcome.State == "partial" && rule.Count is not null && settled)
            Coverage("ok", $"the read was partial, but the count already settles this rule: {outcome.Reason}", outcome.Rows.Count);
        else
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
            var evaluator = new Evaluator(Threshold(request, rule, target), now);
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

        // partial: why the read is incomplete. Its count is a floor - enough to fail a gt/ge limit or to pass an
        // lt/le one, never the other way; eq, ne and a share of a partial read say nothing either way.
        // Rows outside this count that could still belong to it (rows with no group, for a count by group): all of
        // them (they could join a share and dilute it), and those that could also match (they could add to it).
        int CountOne(List<(JsonObject Row, string? Target)> rows, string entityType, string target, string? partial, string? group,
            double mayJoin, double extraUnknown)
        {
            var count = rule.Count!;
            var evaluator = new Evaluator(Threshold(request, rule, target), now);
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
                settled = false;
                Result(entityType, target, new Verdict(null, verdict.Value, verdict.Operand,
                    $"{unjudged + (int)extraUnknown} rows could not be judged, and they could change the outcome"));
                return 0;
            }
            // A partial read's count is a floor: the real count is at least this, so only what more rows cannot
            // change is certain. Over a gt/ge limit it stays over (a failure stands); at or above an lt/le limit it
            // stays there (a pass stands: one policy found auditing logons already answers "no policy does").
            // The other way round, and eq, ne and shares, the rows not read could overturn it: unknown.
            var certain = !count.Percent && (count.Op is "gt" or "ge" ? verdict.Fails == true : count.Op is "lt" or "le" && verdict.Fails == false);
            if (partial is not null && !certain)
            {
                settled = false;
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
