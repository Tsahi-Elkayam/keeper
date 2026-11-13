using Keeper.Queue;

namespace Keeper.Vault;

/// <summary>
/// vault.create-key: { "keyId", "protector", "wrapped": "&lt;base64&gt;" } - stores a data key that is
/// already wrapped by the OS. The plain key never travels. Refused while another active key exists.
/// </summary>
public sealed class CreateKeyHandler : IRequestHandler
{
    public string Kind => "vault.create-key";

    public void Apply(RequestContext context)
    {
        var payload = context.Request.Payload;
        var keyId = Payload.Required(payload, "keyId");
        var protector = Payload.OneOf(payload, "protector", "dpapi-user", "keyfile");
        byte[] wrapped;
        try
        {
            wrapped = Convert.FromBase64String(Payload.Required(payload, "wrapped"));
        }
        catch (FormatException)
        {
            throw new RequestException("payload.wrapped must be base64.");
        }
        if (wrapped.Length is < 32 or > 4096)
            throw new RequestException("payload.wrapped is not a wrapped key.");

        if (context.Scalar("SELECT 1 FROM vault_key WHERE protector = :p AND retired_at IS NULL;", (":p", protector)) is not null)
            throw new RequestException("The vault already has an active key.");

        context.Execute(
            "INSERT INTO vault_key (key_id, protector, wrapped, created_by, created_at) VALUES (:id, :p, :w, :by, :at);",
            (":id", keyId), (":p", protector), (":w", wrapped), (":by", context.Request.SubmittedBy), (":at", context.NowText));
    }
}
