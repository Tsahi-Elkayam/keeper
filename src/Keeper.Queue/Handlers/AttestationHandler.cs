namespace Keeper.Queue.Handlers;

/// <summary>
/// attestation: a person states evidence no machine has - a restore test was done, a DR drill ran.
/// { "obligationId" | "controlId", "entityKey", "state": "yes|no|na", "doneOn", "evidence", "expiresOn" }
/// </summary>
public sealed class AttestationHandler : IRequestHandler
{
    public string Kind => "attestation";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var obligation = Payload.Text(payload, "obligationId");
        var control = Payload.Text(payload, "controlId");
        if ((obligation is null) == (control is null))
            throw new RequestException("payload needs exactly one of obligationId or controlId.");

        using var insert = context.Command(
            """
            INSERT INTO attestation (obligation_id, control_id, entity_key, state, done_on, evidence, expires_on, actor, recorded_at)
            VALUES (:obligation, :control, :entity, :state, :doneOn, :evidence, :expiresOn, :actor, :at);
            """,
            (":obligation", obligation), (":control", control),
            (":entity", Payload.Text(payload, "entityKey") ?? "-"),
            (":state", Payload.OneOf(payload, "state", "yes", "no", "na")),
            (":doneOn", Payload.Text(payload, "doneOn")),
            (":evidence", Payload.Required(payload, "evidence")),
            (":expiresOn", Payload.Text(payload, "expiresOn")),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText));
        insert.ExecuteNonQuery();
    }
}
