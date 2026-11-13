using System.Globalization;
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
/// times. A refusal is kept under the account it locks - the logon guard's key, so one Windows account presented by
/// the ldap, cim and sql integrations is one entry - and under the integration whose credential was refused.
/// It holds until that credential changes (a secret set again, another identity or endpoint), or until a scan is
/// started with <c>--retry-sign-in</c>. An integration whose own secret was set after the refusal tries again: someone
/// entered a password since. No secret is written: a credential is named by a hash of the integration's identity,
/// endpoint, auth kind and when each secret was set.
/// Separate processes may write at once: a lock file serializes them.
/// </summary>
public sealed class SignInRefusals(string file)
{
    private sealed record Entry(string Account, string Instance, string Credential, string Reason, string At);

    /// <summary>A name for the credential as it is now: changes when a secret is set again.</summary>
    public static string Fingerprint(string instance, string? identity, string endpoint, string authKind, IEnumerable<string> secretsSetAt)
    {
        var text = string.Join("\n", [instance, identity ?? "", endpoint, authKind, .. secretsSetAt.Order(StringComparer.Ordinal)]);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..16];
    }

    private static string SlotOf(string account, string instance) => $"{account}\n{instance}";

    /// <summary>
    /// The refusal that holds for this integration's credential, or null. <paramref name="credentialOf"/> gives an
    /// integration's credential as it is now (null when it is gone); <paramref name="secretSetAt"/> is when this
    /// integration's newest secret was set.
    /// </summary>
    public string? Find(IConnection connection, Func<string, string?> credentialOf, DateTimeOffset? secretSetAt)
    {
        var account = LogonGuard.KeyOf(connection);
        foreach (var entry in Read().Values.Where(e => string.Equals(e.Account, account, StringComparison.OrdinalIgnoreCase)))
        {
            if (credentialOf(entry.Instance) != entry.Credential)
                continue;   // that credential changed or is gone
            var sameIntegration = string.Equals(entry.Instance, connection.Instance, StringComparison.OrdinalIgnoreCase);
            if (!sameIntegration && secretSetAt is { } setAt && DateTimeOffset.TryParse(entry.At, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at) && setAt > at)
                continue;   // this integration's password was entered after that refusal
            var through = sameIntegration ? "" : $" (refused through {entry.Instance})";
            return $"{entry.Reason}{through} [recorded {entry.At}; 'keeper integration set-secret' or 'keeper scan --retry-sign-in' tries again]";
        }
        return null;
    }

    public void Record(IConnection connection, string credential, string reason, DateTimeOffset at) =>
        Update(all => all[SlotOf(LogonGuard.KeyOf(connection), connection.Instance)] =
            new Entry(LogonGuard.KeyOf(connection), connection.Instance, credential, reason, Iso.Utc(at)));

    /// <summary>This integration's refusal is gone: its credential read data. Others of the same account stay.</summary>
    public void Clear(IConnection connection) =>
        Update(all => all.Remove(SlotOf(LogonGuard.KeyOf(connection), connection.Instance)));

    /// <summary>--retry-sign-in: every refusal of the account this integration signs in as is forgotten.</summary>
    public void ClearAccount(IConnection connection)
    {
        var account = LogonGuard.KeyOf(connection);
        Update(all =>
        {
            foreach (var slot in all.Where(p => string.Equals(p.Value.Account, account, StringComparison.OrdinalIgnoreCase)).Select(p => p.Key).ToList())
                all.Remove(slot);
        });
    }

    private Dictionary<string, Entry> Read()
    {
        try
        {
            if (!File.Exists(file))
                return [];
            var all = JsonSerializer.Deserialize<Dictionary<string, Entry>>(File.ReadAllText(file)) ?? [];
            // An entry without an account or integration is from an older layout: it names nothing this code can match.
            return all.Where(p => p.Value is { Account: not null, Instance: not null, Credential: not null })
                .ToDictionary(p => p.Key, p => p.Value);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return [];   // a damaged or busy file forgets the refusals; the in-process guard still stops after one
        }
    }

    /// <summary>Read, change and write under a lock file, so two scans writing at once do not lose each other's refusal.</summary>
    private void Update(Action<Dictionary<string, Entry>> change)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        using var held = Lock();
        var all = Read();
        change(all);
        var temp = $"{file}.{Environment.ProcessId}.tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, file, overwrite: true);
    }

    private FileStream Lock()
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (true)
        {
            try
            {
                return new FileStream(file + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.None);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }
        }
    }
}
