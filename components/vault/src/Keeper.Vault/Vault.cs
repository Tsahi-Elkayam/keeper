using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Vault;

public sealed class VaultException(string message) : Exception(message);

/// <summary>Protects the data key with something outside the store - so a copied store or backup is useless.</summary>
public interface IKeyProtector
{
    string Kind { get; }

    byte[] Protect(byte[] key);

    byte[] Unprotect(byte[] wrapped);
}

/// <summary>Windows DPAPI, current-user scope: only the Windows account that wrapped the key can unwrap it.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiUserProtector : IKeyProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Keeper.Vault/1");

    public string Kind => "dpapi-user";

    public byte[] Protect(byte[] key) => ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] wrapped)
    {
        try
        {
            return ProtectedData.Unprotect(wrapped, Entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            throw new VaultException("The vault key cannot be unwrapped by this Windows account. Secrets are bound to the account that set them; set them again as this account.");
        }
    }
}

public static class KeyProtectors
{
    /// <summary>The protector for this platform. Elsewhere the vault fails closed rather than guess.</summary>
    public static IKeyProtector Default() =>
        OperatingSystem.IsWindows()
            ? new DpapiUserProtector()
            : throw new VaultException("Secret storage needs Windows (DPAPI) in this version; on other platforms use integrations that need no stored secret.");
}

/// <summary>A secret as stored: AES-256-GCM ciphertext, its nonce and tag, and the key it was sealed with.</summary>
public sealed record SealedSecret(string KeyId, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// Seals and opens secrets with AES-256-GCM. The associated data binds a secret to where it may be used
/// (integration, name, endpoint): opened anywhere else, it fails. Key material is wiped after use.
/// </summary>
public sealed class Vault
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    private readonly Dictionary<string, byte[]> _wrapped;
    private readonly IKeyProtector _protector;

    private Vault(Dictionary<string, byte[]> wrapped, string? activeKeyId, IKeyProtector protector)
    {
        _wrapped = wrapped;
        ActiveKeyId = activeKeyId;
        _protector = protector;
    }

    public static MigrationSet Schema { get; } = MigrationSet.FromResources("vault", typeof(Vault).Assembly, "vault/");

    public string? ActiveKeyId { get; }

    public static Vault Load(SqliteConnection connection, IKeyProtector protector)
    {
        var rows = Sql.Rows(connection, "SELECT key_id, protector, wrapped, retired_at FROM vault_key;");
        var wrapped = rows.Where(r => (string)r["protector"]! == protector.Kind)
            .ToDictionary(r => (string)r["key_id"]!, r => (byte[])r["wrapped"]!, StringComparer.Ordinal);
        var active = rows.Where(r => r["retired_at"] is null && (string)r["protector"]! == protector.Kind)
            .Select(r => (string)r["key_id"]!).FirstOrDefault();
        return new Vault(wrapped, active, protector);
    }

    /// <summary>A new random data key, wrapped by the protector. The plain key never leaves this method.</summary>
    public static (string KeyId, byte[] Wrapped) NewKey(IKeyProtector protector)
    {
        var key = RandomNumberGenerator.GetBytes(KeyBytes);
        try
        {
            return ("k-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)), protector.Protect(key));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Seals with a key wrapped elsewhere (a key being created in the same request batch).</summary>
    public static SealedSecret Seal(IKeyProtector protector, string keyId, byte[] wrapped, string plaintext, string associatedData) =>
        new Vault(new Dictionary<string, byte[]> { [keyId] = wrapped }, keyId, protector).Seal(plaintext, associatedData);

    public SealedSecret Seal(string plaintext, string associatedData)
    {
        var keyId = ActiveKeyId ?? throw new VaultException("The vault has no key yet.");
        var key = Unwrap(keyId);
        var data = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[data.Length];
            var tag = new byte[TagBytes];
            using var aes = new AesGcm(key, TagBytes);
            aes.Encrypt(nonce, data, ciphertext, tag, Encoding.UTF8.GetBytes(associatedData));
            return new SealedSecret(keyId, nonce, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public string Open(SealedSecret secret, string associatedData)
    {
        var key = Unwrap(secret.KeyId);
        var data = new byte[secret.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(secret.Nonce, secret.Ciphertext, secret.Tag, data, Encoding.UTF8.GetBytes(associatedData));
            return Encoding.UTF8.GetString(data);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new VaultException("The secret does not open here: it was set for a different integration or endpoint, or it was altered. Set it again.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private byte[] Unwrap(string keyId) =>
        _wrapped.TryGetValue(keyId, out var wrapped)
            ? _protector.Unprotect(wrapped)
            : throw new VaultException($"Vault key {keyId} is not available to this protector.");
}
