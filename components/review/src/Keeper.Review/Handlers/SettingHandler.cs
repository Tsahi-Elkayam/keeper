using Keeper.Queue;

namespace Keeper.Review.Handlers;

/// <summary>
/// review.setting: { "key": "threshold.ad.stale-user-days", "value": "120" } sets a setting;
/// { "key", "remove": true } removes it. Keys are lower-case with dots and dashes.
/// </summary>
public sealed class SettingHandler : IRequestHandler
{
    public string Kind => "review.setting";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var key = Payload.Required(payload, "key");
        if (!Identifiers.IsValid(key))
            throw new RequestException("payload.key must be lower-case letters, digits, dots and dashes.");

        if (Payload.Bool(payload, "remove") == true)
        {
            if (context.Execute("DELETE FROM setting WHERE key = :k;", (":k", key)) == 0)
                throw new RequestException($"No setting {key}.");
            return;
        }

        var value = Payload.Required(payload, "value");
        if (value.Length > 500)
            throw new RequestException("payload.value is at most 500 characters.");

        context.Execute(
            """
            INSERT INTO setting (key, value, actor, at, why) VALUES (:k, :v, :actor, :at, :why)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value, actor = excluded.actor, at = excluded.at, why = excluded.why;
            """,
            (":k", key), (":v", value), (":actor", context.Request.SubmittedBy), (":at", context.NowText), (":why", context.Request.Reason));
    }
}
