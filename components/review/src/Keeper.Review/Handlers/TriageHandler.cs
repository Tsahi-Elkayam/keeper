namespace Keeper.Queue.Handlers;

/// <summary>
/// triage: today's decision about a finding - snooze it until a date, hand it to someone, or clear either.
/// { "findingKey", "decision": "snooze|delegate|clear", "owner", "until" }. Snooze and delegate also add a finding event.
/// </summary>
public sealed class TriageHandler : IRequestHandler
{
    public string Kind => "triage";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var key = Payload.Required(payload, "findingKey");
        var decision = Payload.OneOf(payload, "decision", "snooze", "delegate", "clear");
        var owner = Payload.Text(payload, "owner");
        var until = Payload.Text(payload, "until");

        if (decision == "snooze" && until is null)
            throw new RequestException("snooze needs payload.until (a date).");
        if (decision == "delegate" && owner is null)
            throw new RequestException("delegate needs payload.owner.");

        using var insert = context.Command(
            "INSERT INTO triage (finding_key, decision, owner, until, actor, at, why) VALUES (:key, :decision, :owner, :until, :actor, :at, :why);",
            (":key", key), (":decision", decision), (":owner", owner), (":until", until),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
        insert.ExecuteNonQuery();

        if (decision == "clear")
            return;

        using var evt = context.Command(
            "INSERT INTO finding_event (finding_key, at, event, actor, note) VALUES (:key, :at, :event, :actor, :note);",
            (":key", key), (":at", context.NowText), (":event", decision == "snooze" ? "snoozed" : "delegated"),
            (":actor", context.Request.SubmittedBy), (":note", context.Request.Reason));
        evt.ExecuteNonQuery();
    }
}
