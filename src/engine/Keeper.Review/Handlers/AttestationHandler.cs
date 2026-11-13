using Keeper.Queue;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.attestation: a person states evidence no machine has - a restore test was done, a DR drill ran.
/// { "obligation": "backup.restore-test", "target", "state": "yes|no|na", "doneOn", "evidence", "expiresOn" }.
/// Obligations are rules over these rows (rules/obligations.yaml), so a missing or expired one is a finding.
/// </summary>
public sealed class AttestationHandler : IRequestHandler
{
    public string Kind => "review.attestation";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var obligation = Payload.Required(payload, "obligation");
        if (!Identifiers.IsValid(obligation))
            throw new RequestException("payload.obligation must be lower-case letters, digits, dots and dashes.");

        context.Execute(
            """
            INSERT INTO attestation (obligation, target, state, done_on, evidence, expires_on, actor, recorded_at)
            VALUES (:obligation, :target, :state, :doneOn, :evidence, :expiresOn, :actor, :at);
            """,
            (":obligation", obligation),
            (":target", Payload.Text(payload, "target") ?? "-"),
            (":state", Payload.OneOf(payload, "state", "yes", "no", "na")),
            (":doneOn", Payload.Date(payload, "doneOn")),
            (":evidence", Payload.Required(payload, "evidence")),
            (":expiresOn", Payload.Date(payload, "expiresOn")),
            (":actor", context.Request.SubmittedBy), (":at", context.NowText));
    }
}
