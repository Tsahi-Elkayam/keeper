using System.Globalization;
using Keeper.Queue;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.override: disable a rule, change its threshold, or accept one entity as it is.
/// Add:    { "op": "add", "checkId", "decision": "disable|threshold|exception", "entity", "value", "until" }
/// Remove: { "op": "remove", "overrideId" }
/// The envelope's reason is recorded as why. Removing keeps the row. until (yyyy-MM-dd) is the last day the
/// override holds; after it the rule judges as before, and an accepted finding comes back.
/// </summary>
public sealed class OverrideHandler : IRequestHandler
{
    public string Kind => "review.override";

    public void Apply(RequestContext context)
    {
        if (Payload.OneOf(context.Request.Payload, "op", "add", "remove") == "add")
            Add(context);
        else
            Remove(context);
    }

    private static void Add(RequestContext context)
    {
        var payload = context.Request.Payload;
        var checkId = Payload.Required(payload, "checkId");
        var decision = Payload.OneOf(payload, "decision", "disable", "threshold", "exception");
        var entity = Payload.Text(payload, "entity") ?? "";
        var value = Payload.Text(payload, "value") ?? "";
        var until = Payload.Date(payload, "until");

        if (until is not null && string.CompareOrdinal(until, context.NowText[..10]) < 0)
            throw new RequestException($"until {until} has already passed.");
        if (decision == "disable" && entity.Length > 0)
            throw new RequestException("disable applies to the whole rule; leave payload.entity empty.");
        if (decision == "threshold" && value.Length == 0)
            throw new RequestException("A threshold override needs payload.value.");
        if (decision == "exception" && entity.Length == 0)
            throw new RequestException("An exception override needs payload.entity.");

        var number = Convert.ToInt64(context.Scalar("SELECT COALESCE(MAX(CAST(substr(override_id, 5) AS INTEGER)), 0) + 1 FROM override;"),
            CultureInfo.InvariantCulture);
        var id = "OVR-" + number.ToString("D4", CultureInfo.InvariantCulture);

        context.Execute(
            """
            INSERT INTO override (override_id, check_id, decision, entity, value, until, actor, at, why)
            VALUES (:id, :check, :decision, :entity, :value, :until, :actor, :at, :why);
            """,
            (":id", id), (":check", checkId), (":decision", decision), (":entity", entity), (":value", value), (":until", until),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
    }

    private static void Remove(RequestContext context)
    {
        var id = Payload.Required(context.Request.Payload, "overrideId");
        var changed = context.Execute(
            """
            UPDATE override SET active = 0, removed_by = :actor, removed_at = :at, removed_why = :why
            WHERE override_id = :id AND active = 1;
            """,
            (":id", id), (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
        if (changed == 0)
            throw new RequestException($"No active override {id}.");
    }
}
