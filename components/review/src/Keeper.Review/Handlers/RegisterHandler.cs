using System.Text.Json;
using Keeper.Common;
using Keeper.Queue;
using Keeper.Review.Track;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.register: { "file": "builds/&lt;id&gt;/register.json", "sha256" } - the findings, events and
/// entities keeper-track computed. Applied in one transaction: the register never shows half a run.
/// </summary>
public sealed class RegisterHandler : IRequestHandler
{
    public string Kind => "review.register";

    public void Apply(RequestContext context)
    {
        var file = Payload.VerifiedFile(context);
        RegisterFile register;
        try
        {
            register = JsonSerializer.Deserialize<RegisterFile>(File.ReadAllText(file), JsonLines.Options)
                ?? throw new RequestException("Empty register file.");
        }
        catch (JsonException ex)
        {
            throw new RequestException($"Register file is not valid: {ex.Message}");
        }

        foreach (var entity in register.Entities)
            UpsertEntity(context, entity);
        foreach (var finding in register.Findings)
            UpsertFinding(context, finding);
        foreach (var e in register.Events)
        {
            context.Execute(
                "INSERT INTO finding_event (finding_key, at, event, run_id, actor, note) VALUES (:key, :at, :event, :run, :actor, :note);",
                (":key", e.FindingKey), (":at", e.At), (":event", e.Event), (":run", e.RunId), (":actor", e.Actor), (":note", e.Note));
        }

        context.Execute(
            "INSERT OR REPLACE INTO build (build_id, stage, at, counts) VALUES (:id, 'track', :at, :counts);",
            (":id", register.BuildId), (":at", register.At), (":counts", JsonSerializer.Serialize(register.Counts, JsonLines.Options)));

        TrendSnapshot.Write(context);
    }

    private static void UpsertEntity(RequestContext context, EntityRow e) =>
        context.Execute(
            """
            INSERT INTO entity (instance, entity_type, entity_key, entity_name, system_id, mapped_by, first_seen, last_seen, gone_since)
            VALUES (:instance, :type, :key, :name, :system, :mapped, :first, :last, :gone)
            ON CONFLICT (instance, entity_type, entity_key) DO UPDATE SET
                entity_name = excluded.entity_name, system_id = excluded.system_id, mapped_by = excluded.mapped_by,
                last_seen = excluded.last_seen, gone_since = excluded.gone_since;
            """,
            (":instance", e.Instance), (":type", e.EntityType), (":key", e.EntityKey), (":name", e.EntityName),
            (":system", e.SystemId), (":mapped", e.MappedBy), (":first", e.FirstSeen), (":last", e.LastSeen), (":gone", e.GoneSince));

    private static void UpsertFinding(RequestContext context, FindingRow f) =>
        context.Execute(
            """
            INSERT INTO finding (finding_key, instance, system, system_id, rule_id, check_id, entity_type, target, entity_name,
                                 kind, lens, category, severity, security, title, evidence, why, fix, refs, deadline,
                                 status, lifecycle, first_seen, last_seen, resolved_at, run_id)
            VALUES (:key, :instance, :system, :systemId, :rule, :check, :type, :target, :name,
                    :kind, :lens, :category, :severity, :security, :title, :evidence, :why, :fix, :refs, :deadline,
                    :status, :lifecycle, :first, :last, :resolved, :run)
            ON CONFLICT (finding_key) DO UPDATE SET
                system_id = excluded.system_id, entity_name = excluded.entity_name, kind = excluded.kind, lens = excluded.lens,
                category = excluded.category, severity = excluded.severity, security = excluded.security, title = excluded.title,
                evidence = excluded.evidence, why = excluded.why, fix = excluded.fix, refs = excluded.refs, deadline = excluded.deadline,
                status = excluded.status, lifecycle = excluded.lifecycle, last_seen = excluded.last_seen,
                resolved_at = excluded.resolved_at, run_id = excluded.run_id;
            """,
            (":key", f.FindingKey), (":instance", f.Instance), (":system", f.System), (":systemId", f.SystemId),
            (":rule", f.RuleId), (":check", f.CheckId), (":type", f.EntityType), (":target", f.Target), (":name", f.EntityName),
            (":kind", f.Kind), (":lens", f.Lens), (":category", f.Category), (":severity", f.Severity), (":security", f.Security ? 1 : 0),
            (":title", f.Title), (":evidence", f.Evidence), (":why", f.Why), (":fix", f.Fix),
            (":refs", JsonSerializer.Serialize(f.Refs, JsonLines.Options)), (":deadline", f.Deadline),
            (":status", f.Status), (":lifecycle", f.Lifecycle), (":first", f.FirstSeen), (":last", f.LastSeen),
            (":resolved", f.ResolvedAt), (":run", f.RunId));
}

/// <summary>
/// review.rules-load: { "file": "builds/&lt;id&gt;/rules.json", "sha256" } - the rule catalogue as the
/// rule files define it now. Replaces the stored catalogue in one transaction.
/// </summary>
public sealed class RulesLoadHandler : IRequestHandler
{
    public string Kind => "review.rules-load";

    public sealed record RuleRow(string RuleId, string System, string Title, string Kind, string Lens, string Category,
        string Severity, string EntityType, string Protocol, int RefreshMinutes, string? Why, string? Fix,
        IReadOnlyList<string> Refs, string SourceFile);

    public void Apply(RequestContext context)
    {
        var file = Payload.VerifiedFile(context);
        List<RuleRow> rules;
        try
        {
            rules = JsonSerializer.Deserialize<List<RuleRow>>(File.ReadAllText(file), JsonLines.Options)
                ?? throw new RequestException("Empty rules file.");
        }
        catch (JsonException ex)
        {
            throw new RequestException($"Rules file is not valid: {ex.Message}");
        }

        context.Execute("DELETE FROM rule;");
        foreach (var r in rules)
        {
            context.Execute(
                """
                INSERT INTO rule (rule_id, system, title, kind, lens, category, severity, entity_type, protocol, refresh_min, why, fix, refs, source_file, loaded_at)
                VALUES (:id, :system, :title, :kind, :lens, :category, :severity, :type, :protocol, :refresh, :why, :fix, :refs, :source, :at);
                """,
                (":id", r.RuleId), (":system", r.System), (":title", r.Title), (":kind", r.Kind), (":lens", r.Lens),
                (":category", r.Category), (":severity", r.Severity), (":type", r.EntityType), (":protocol", r.Protocol),
                (":refresh", r.RefreshMinutes), (":why", r.Why), (":fix", r.Fix),
                (":refs", JsonSerializer.Serialize(r.Refs, JsonLines.Options)), (":source", r.SourceFile), (":at", context.NowText));
        }
    }
}
