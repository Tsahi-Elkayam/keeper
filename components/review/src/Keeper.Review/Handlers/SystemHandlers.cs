using System.Text.RegularExpressions;
using Keeper.Queue;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.system: { "op": "upsert", "systemId", "name", "team", "purpose", "owner", "ownerPerson", "route",
/// "criticality": 1|2|3, "active": true|false, "notes" } or { "op": "remove", "systemId" }.
/// </summary>
public sealed class SystemHandler : IRequestHandler
{
    private static readonly string[] Synthetic = ["KEEPER", "ORG", "UNMAPPED"];

    public string Kind => "review.system";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var id = Payload.Required(payload, "systemId");
        if (!Identifiers.IsRecordId(id))
            throw new RequestException("payload.systemId must be letters, digits, dots, dashes or underscores.");
        if (Synthetic.Contains(id, StringComparer.OrdinalIgnoreCase))
            throw new RequestException($"{id} is a built-in system and cannot be changed.");

        if (Payload.OneOf(payload, "op", "upsert", "remove") == "remove")
        {
            var used = Convert.ToInt64(context.Scalar("SELECT COUNT(*) FROM finding WHERE system_id = :id AND status = 'open';", (":id", id)) ?? 0L);
            if (used > 0)
                throw new RequestException($"{id} has {used} open findings; deactivate it instead (active: false).");
            if (context.Execute("DELETE FROM system WHERE system_id = :id;", (":id", id)) == 0)
                throw new RequestException($"No system {id}.");
            return;
        }

        var criticality = Payload.Int(payload, "criticality");
        if (criticality is not (null or 1 or 2 or 3))
            throw new RequestException("payload.criticality must be 1, 2 or 3.");

        context.Execute(
            """
            INSERT INTO system (system_id, name, team, purpose, owner, owner_person, route, criticality, active, notes, updated_by, updated_at)
            VALUES (:id, :name, :team, :purpose, :owner, :person, :route, :crit, :active, :notes, :actor, :at)
            ON CONFLICT (system_id) DO UPDATE SET
                name = excluded.name, team = excluded.team, purpose = excluded.purpose, owner = excluded.owner,
                owner_person = excluded.owner_person, route = excluded.route, criticality = excluded.criticality,
                active = excluded.active, notes = excluded.notes, updated_by = excluded.updated_by, updated_at = excluded.updated_at;
            """,
            (":id", id), (":name", Payload.Required(payload, "name")), (":team", Payload.Text(payload, "team")),
            (":purpose", Payload.Text(payload, "purpose")), (":owner", Payload.Text(payload, "owner")),
            (":person", Payload.Text(payload, "ownerPerson")), (":route", Payload.Text(payload, "route")),
            (":crit", criticality), (":active", Payload.Bool(payload, "active") == false ? 0 : 1),
            (":notes", Payload.Text(payload, "notes")), (":actor", context.Request.SubmittedBy), (":at", context.NowText));
    }
}

/// <summary>
/// review.system-rule: which entities belong to a system, applied in order, first match wins.
/// { "op": "upsert", "ruleId", "ord", "instance", "entityType", "field", "pattern", "systemId" } or { "op": "remove", "ruleId" }.
/// </summary>
public sealed class SystemRuleHandler : IRequestHandler
{
    public string Kind => "review.system-rule";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var id = Payload.Required(payload, "ruleId");
        if (!Identifiers.IsRecordId(id))
            throw new RequestException("payload.ruleId must be letters, digits, dots, dashes or underscores.");

        if (Payload.OneOf(payload, "op", "upsert", "remove") == "remove")
        {
            if (context.Execute("DELETE FROM system_rule WHERE rule_id = :id;", (":id", id)) == 0)
                throw new RequestException($"No system rule {id}.");
            return;
        }

        var pattern = Payload.Required(payload, "pattern");
        try
        {
            _ = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        }
        catch (ArgumentException ex)
        {
            throw new RequestException($"payload.pattern is not a valid regular expression: {ex.Message}");
        }

        context.Execute(
            """
            INSERT INTO system_rule (rule_id, ord, instance, entity_type, field, pattern, system_id, updated_by, updated_at)
            VALUES (:id, :ord, :instance, :type, :field, :pattern, :system, :actor, :at)
            ON CONFLICT (rule_id) DO UPDATE SET
                ord = excluded.ord, instance = excluded.instance, entity_type = excluded.entity_type, field = excluded.field,
                pattern = excluded.pattern, system_id = excluded.system_id, updated_by = excluded.updated_by, updated_at = excluded.updated_at;
            """,
            (":id", id), (":ord", Payload.Int(payload, "ord") ?? 100), (":instance", Payload.Text(payload, "instance") ?? "*"),
            (":type", Payload.Text(payload, "entityType") ?? "*"), (":field", Payload.Text(payload, "field") ?? "key"),
            (":pattern", pattern), (":system", Payload.Required(payload, "systemId")),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText));
    }
}
