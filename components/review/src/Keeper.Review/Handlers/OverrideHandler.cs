using System.Globalization;

namespace Keeper.Queue.Handlers;

/// <summary>
/// override: disable a check, change its threshold, or accept one entity as it is.
/// Add:    { "op": "add", "checkId", "decision": "disable|threshold|exception", "entity", "value" }
/// Remove: { "op": "remove", "overrideId" }
/// The envelope's reason is recorded as why. Removing keeps the row.
/// </summary>
public sealed class OverrideHandler : IRequestHandler
{
    public string Kind => "override";

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

        if (decision == "disable" && entity.Length > 0)
            throw new RequestException("disable applies to the whole check; leave payload.entity empty.");
        if (decision == "threshold" && value.Length == 0)
            throw new RequestException("A threshold override needs payload.value.");
        if (decision == "exception" && entity.Length == 0)
            throw new RequestException("An exception override needs payload.entity.");

        using var next = context.Command("SELECT COALESCE(MAX(CAST(substr(override_id, 5) AS INTEGER)), 0) + 1 FROM override;");
        var number = Convert.ToInt64(next.ExecuteScalar(), CultureInfo.InvariantCulture);
        var id = "OVR-" + number.ToString("D4", CultureInfo.InvariantCulture);

        using var insert = context.Command(
            """
            INSERT INTO override (override_id, check_id, decision, entity, value, actor, at, why)
            VALUES (:id, :check, :decision, :entity, :value, :actor, :at, :why);
            """,
            (":id", id), (":check", checkId), (":decision", decision), (":entity", entity), (":value", value),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
        insert.ExecuteNonQuery();
    }

    private static void Remove(RequestContext context)
    {
        var id = Payload.Required(context.Request.Payload, "overrideId");
        using var update = context.Command(
            """
            UPDATE override SET active = 0, removed_by = :actor, removed_at = :at, removed_why = :why
            WHERE override_id = :id AND active = 1;
            """,
            (":id", id), (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
        if (update.ExecuteNonQuery() == 0)
            throw new RequestException($"No active override {id}.");
    }
}
