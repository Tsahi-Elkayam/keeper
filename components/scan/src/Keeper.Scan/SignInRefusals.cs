using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Runners;

namespace Keeper.Scan;

/// <summary>
/// Refused credentials kept in the Keeper home, so a refusal outlives the process: three separate
/// <c>keeper scan</c> commands (a schedule, or someone trying again) must not present a refused password three
/// times. A refusal holds until the credential changes - a secret set again, another identity or endpoint - or until
/// a scan is started with <c>--retry-sign-in</c>. No secret is written: the credential is named by a hash of the
/// integration's identity, endpoint, auth kind and when each secret was set.
/// </summary>
public sealed class SignInRefusals(string file)
{
    private sealed record Entry(string Credential, string Reason, string At);

    /// <summary>A name for the credential as it is now: changes when a secret is set again.</summary>
    public static string Fingerprint(string instance, string? identity, string endpoint, string authKind, IEnumerable<string> secretsSetAt)
    {
        var text = string.Join("\n", [instance, identity ?? "", endpoint, authKind, .. secretsSetAt.Order(StringComparer.Ordinal)]);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
    }

    /// <summary>Per integration: the credential fingerprint below says whether it is still the same one.</summary>
    private static string KeyOf(IConnection connection) => $"{connection.Instance}|{connection.Identity ?? "(current user)"}";

    /// <summary>The recorded refusal of this credential, or null (none, or the credential changed since).</summary>
    public string? Find(IConnection connection, string credential) =>
        Read().TryGetValue(KeyOf(connection), out var entry) && entry.Credential == credential
            ? $"{entry.Reason} [recorded {entry.At}; 'keeper integration set-secret' or 'keeper scan --retry-sign-in' tries again]"
            : null;

    public void Record(IConnection connection, string credential, string reason, DateTimeOffset at)
    {
        var all = Read();
        all[KeyOf(connection)] = new Entry(credential, reason, Iso.Utc(at));
        Write(all);
    }

    public void Clear(IConnection connection)
    {
        var all = Read();
        if (all.Remove(KeyOf(connection)))
            Write(all);
    }

    private Dictionary<string, Entry> Read()
    {
        try
        {
            return File.Exists(file)
                ? JsonSerializer.Deserialize<Dictionary<string, Entry>>(File.ReadAllText(file)) ?? []
                : [];
        }
        catch (JsonException)
        {
            return [];   // a damaged file forgets the refusals; the in-process guard still stops after one
        }
    }

    private void Write(Dictionary<string, Entry> all)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var temp = file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, file, overwrite: true);
    }
}
