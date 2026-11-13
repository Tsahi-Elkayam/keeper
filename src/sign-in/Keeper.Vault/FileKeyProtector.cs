using System.Security.Cryptography;
using System.Text;

namespace Keeper.Vault;

/// <summary>
/// Protects the data key with a random 32-byte key-encryption key kept in a file that only its owner can read
/// (vault.key beside the settings). It works on every OS, so Keeper's secrets are not tied to Windows. A copied
/// store or backup is useless without that file; like an SSH private key, it does not stop someone who already
/// is the user. Wrapped layout: nonce (12) + tag (16) + AES-256-GCM ciphertext of the data key.
/// </summary>
public sealed class FileKeyProtector(string path) : IKeyProtector
{
    private const int KekBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private static readonly byte[] Binding = Encoding.UTF8.GetBytes("Keeper.Vault/keyfile/1");

    public string Kind => "keyfile";

    public byte[] Protect(byte[] key)
    {
        var kek = LoadOrCreate();
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[key.Length];
            var tag = new byte[TagBytes];
            using var aes = new AesGcm(kek, TagBytes);
            aes.Encrypt(nonce, key, ciphertext, tag, Binding);
            return [.. nonce, .. tag, .. ciphertext];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    public byte[] Unprotect(byte[] wrapped)
    {
        if (wrapped.Length <= NonceBytes + TagBytes)
            throw new VaultException("The wrapped vault key is too short to be a key.");
        if (!File.Exists(path))
            throw new VaultException($"The vault key file {path} is missing. Secrets set with it cannot be opened; restore it from a backup, or set the secrets again.");

        var kek = Load();
        try
        {
            var plain = new byte[wrapped.Length - NonceBytes - TagBytes];
            using var aes = new AesGcm(kek, TagBytes);
            aes.Decrypt(wrapped.AsSpan(0, NonceBytes), wrapped.AsSpan(NonceBytes + TagBytes), wrapped.AsSpan(NonceBytes, TagBytes), plain, Binding);
            return plain;
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new VaultException($"The vault key file {path} does not match this store, or the wrapped key was altered. Restore the right vault.key, or set the secrets again.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private byte[] LoadOrCreate()
    {
        if (!File.Exists(path))
        {
            var folder = Path.GetDirectoryName(Path.GetFullPath(path))!;
            if (OperatingSystem.IsWindows())
                Directory.CreateDirectory(folder);
            else
                Directory.CreateDirectory(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using var file = new FileStream(path, options);
                var fresh = RandomNumberGenerator.GetBytes(KekBytes);
                file.Write(fresh);
                CryptographicOperations.ZeroMemory(fresh);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another process created it first: use theirs.
            }
        }
        return Load();
    }

    private byte[] Load()
    {
        var info = new FileInfo(path);
        if (info.LinkTarget is not null)
            throw new VaultException($"The vault key file {path} is a link; links are not followed.");
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((File.GetUnixFileMode(path) & others) != 0)
                throw new VaultException($"The vault key file {path} is readable by other users. Run: chmod 600 \"{path}\"");
        }
        var kek = File.ReadAllBytes(path);
        if (kek.Length != KekBytes)
        {
            CryptographicOperations.ZeroMemory(kek);
            throw new VaultException($"The vault key file {path} is not a Keeper key file ({info.Length} bytes, expected {KekBytes}).");
        }
        return kek;
    }
}
