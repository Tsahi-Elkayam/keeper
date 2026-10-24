using System.Security.Cryptography;
using Keeper.Store;

namespace Keeper.Vault.Tests;

public sealed class KeyFileProtectorTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-vault-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string KeyFile => Path.Combine(_dir, "vault.key");

    private FileKeyProtector New() => new(KeyFile);

    [Fact]
    public void A_wrapped_key_unwraps_to_the_same_key_even_from_a_new_instance()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var wrapped = New().Protect(key);

        Assert.NotEqual(key, wrapped);
        Assert.Equal(key, New().Unprotect(wrapped));
    }

    [Fact]
    public void Wrapping_the_same_key_twice_gives_different_bytes()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var protector = New();

        Assert.NotEqual(protector.Protect(key), protector.Protect(key));
    }

    [Fact]
    public void The_key_file_is_32_random_bytes_readable_only_by_its_owner()
    {
        New().Protect(RandomNumberGenerator.GetBytes(32));

        Assert.Equal(32, new FileInfo(KeyFile).Length);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(KeyFile));
    }

    [Fact]
    public void Another_key_file_cannot_unwrap_it()
    {
        var wrapped = New().Protect(RandomNumberGenerator.GetBytes(32));
        var other = new FileKeyProtector(Path.Combine(_dir, "other.key"));
        other.Protect(RandomNumberGenerator.GetBytes(32));

        Assert.Throws<VaultException>(() => other.Unprotect(wrapped));
    }

    [Fact]
    public void A_missing_key_file_fails_loudly_and_is_never_recreated_on_read()
    {
        var wrapped = New().Protect(RandomNumberGenerator.GetBytes(32));
        File.Delete(KeyFile);

        var ex = Assert.Throws<VaultException>(() => New().Unprotect(wrapped));

        Assert.Contains("vault.key", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(KeyFile));
    }

    [Fact]
    public void A_tampered_wrapped_key_is_refused()
    {
        var wrapped = New().Protect(RandomNumberGenerator.GetBytes(32));
        wrapped[^1] ^= 0xFF;

        Assert.Throws<VaultException>(() => New().Unprotect(wrapped));
    }

    [Fact]
    public void Something_too_short_to_be_a_wrapped_key_is_refused()
    {
        New().Protect(RandomNumberGenerator.GetBytes(32));

        Assert.Throws<VaultException>(() => New().Unprotect([1, 2, 3]));
    }

    [Fact]
    public void A_key_file_other_users_can_read_is_refused()
    {
        if (OperatingSystem.IsWindows())
            return;
        var wrapped = New().Protect(RandomNumberGenerator.GetBytes(32));
        File.SetUnixFileMode(KeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        var ex = Assert.Throws<VaultException>(() => New().Unprotect(wrapped));
        Assert.Contains("readable", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_key_file_of_the_wrong_size_is_refused_not_used()
    {
        File.WriteAllBytes(KeyFile, [1, 2, 3]);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(KeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        Assert.Throws<VaultException>(() => New().Protect(RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public void Default_is_the_key_file_beside_the_settings_off_Windows()
    {
        if (OperatingSystem.IsWindows())
            return;

        var protector = KeyProtectors.Default(_dir);

        Assert.Equal("keyfile", protector.Kind);
        protector.Protect(RandomNumberGenerator.GetBytes(32));
        Assert.True(File.Exists(KeyFile));
    }

    [Fact]
    public void A_secret_seals_and_opens_through_the_vault_with_the_key_file()
    {
        var protector = New();
        using var connection = new Database(Path.Combine(_dir, "keeper.db")).OpenReadWrite(create: true);
        SchemaManager.Apply(connection, [Vault.Schema]);
        var (keyId, wrapped) = Vault.NewKey(protector);
        Sql.Execute(connection,
            "INSERT INTO vault_key (key_id, protector, wrapped, created_by, created_at) VALUES (:id, :p, :w, 'test', '2026-10-24T00:00:00Z');",
            null, (":id", keyId), (":p", protector.Kind), (":w", wrapped));

        var vault = Vault.Load(connection, New());
        var sealedSecret = vault.Seal("s3cret-value", "integration|password|https://example.org");

        Assert.DoesNotContain("s3cret", Convert.ToHexString(sealedSecret.Ciphertext), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("s3cret-value", vault.Open(sealedSecret, "integration|password|https://example.org"));
        Assert.Throws<VaultException>(() => vault.Open(sealedSecret, "another|password|https://example.org"));
    }
}
