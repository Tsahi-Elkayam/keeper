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
        var system = request.Files[0].System;
        var instance = request.Connection.Instance;
        var started = _clock.GetUtcNow();
        var observedAt = Iso.Utc(started);
        var notes = new List<string>();

        using var run = new RunWriter(request.RunsDir, instance, system, started);
        var rules = request.Files.SelectMany(f => f.Rules.Select(r => (Rule: r, File: f))).ToList();
        var queries = rules.GroupBy(r => r.Rule.Query.Id).ToList();
        var outcomes = new Dictionary<string, QueryOutcome>(StringComparer.Ordinal);

        foreach (var group in queries)
        {
            var (rule, file) = group.First();
            var outcome = await RunQuery(rule.Query, file, request, cancellationToken).ConfigureAwait(false);
            outcomes[group.Key] = outcome;

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
                    Attrs = row,
                    ObservedAt = observedAt,
                });
            foreach (var target in outcome.Targets)
                run.Coverage(new CoverageRecord
                {
                    Instance = instance,
                    System = system,
                    Scope = target.Target is null ? "query" : "target",
                    Item = target.Target is null ? group.Key : $"{group.Key}@{target.Target}",
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
        var manifest = run.Complete(status, _clock.GetUtcNow(), request.Connection.Identity, notes);
        return new ScanReport(manifest, rules.Count, queries.Count, outcomes.Values.Sum(o => o.Rows.Count), findings,
            states.Count(s => s == "failed"));
    }

    private sealed record TargetOutcome(string? Target, string State, string? Reason, int Count);

    private sealed record QueryOutcome(List<(JsonObject Row, string? Target)> Rows, List<TargetOutcome> Targets)
    {
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
            message => request.Log(target is null ? message : $"{target}: {message}"));

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

    private static string KeyOf(QuerySpec query, JsonObject row, string? target) =>
        Values.Text(FieldPath.First(row, query.Key)) is { Length: > 0 } key ? key : target ?? "-";

    private int Evaluate(Rule rule, QueryOutcome outcome, ScanRequest request, RunWriter run, string instance, string system, string observedAt)
    {
        var now = _clock.GetUtcNow();
        void Coverage(string state, string? reason, int count) => run.Coverage(new CoverageRecord
        {
            Instance = instance, System = system, Scope = "rule", Item = rule.Id, State = state,
            Reason = reason is null ? null : Redactor.Clean(reason), Count = count, ObservedAt = observedAt,
        });
        void Result(string entityType, string key, Verdict verdict, string? why = null) => run.Result(new ResultRecord
        {
            Instance = instance, System = system, RuleId = rule.Id, EntityType = entityType, EntityKey = key,
            State = verdict.State, Value = Truncate(verdict.Value), Operand = verdict.Operand, Why = why ?? verdict.Why,
            TtlMinutes = rule.TtlMinutes, At = observedAt,
        });

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
            var evaluator = new Evaluator(name => request.OverrideThreshold(rule.Id, "-") ?? request.Threshold(name), now);
            var verdict = evaluator.Count(count, outcome.Rows.Count);
            Result("instance", "-", verdict);
            if (verdict.Fails == true)
            {
                var sample = string.Join(", ", outcome.Rows.Take(10).Select(r => KeyOf(rule.Query, r.Row, r.Target)));
                run.Finding(BuildFinding(rule, instance, system, "instance", "-", null, null, evaluator, observedAt,
                    rule.Evidence is null
                        ? $"{verdict.Value} found (limit {verdict.Operand}){(sample.Length > 0 ? ": " + sample : "")}"
                        : Templates.Render(rule.Evidence, new JsonObject { ["count"] = outcome.Rows.Count, ["sample"] = sample })));
                findings++;
            }
        }
        else
        {
            foreach (var (row, target) in outcome.Rows)
            {
                var key = KeyOf(rule.Query, row, target);
                var evaluator = new Evaluator(name => request.OverrideThreshold(rule.Id, key) ?? request.Threshold(name), now);
                var verdict = evaluator.Each(rule.Each!, row);
                Result(rule.EntityType, key, verdict);
                if (verdict.Fails != true)
                    continue;

                var name = rule.Query.Name is { } nameField ? Values.Text(FieldPath.First(row, nameField)) : null;
                var evidence = rule.Evidence is null
                    ? verdict.Value is null ? null : $"value {verdict.Value}{(verdict.Operand is null ? "" : $" (rule: {verdict.Operand})")}"
                    : Templates.Render(rule.Evidence, row);
                run.Finding(BuildFinding(rule, instance, system, rule.EntityType, key, name, row, evaluator, observedAt, evidence));
                findings++;
            }
        }

        Coverage(outcome.State, outcome.State == "ok" ? null : outcome.Reason, outcome.Rows.Count);
        return findings;
    }

    private static FindingRecord BuildFinding(Rule rule, string instance, string system, string entityType, string target, string? name,
        JsonObject? row, Evaluator evaluator, string observedAt, string? evidence)
    {
        var emit = rule.Emit;
        var checkId = emit?.Check is { } template && row is not null ? Sanitize(Templates.Render(template, row)) : rule.Id;
        if (checkId.Length == 0)
            checkId = rule.Id;
        var severity = emit?.Severity is { } emitSeverity ? evaluator.Severity(emitSeverity, row)
            : rule.SeverityBy is { } map ? evaluator.Severity(map, row)
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
            Deadline = rule.Deadline is { } field && row is not null ? Values.IsoDate(Values.Text(FieldPath.First(row, field))) : null,
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
}
