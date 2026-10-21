using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.TestKit;

/// <summary>
/// The demo values tests feed in to prove they come out masked: a password, a Group Policy cpassword sample,
/// AWS's documentation key. None is a real credential. They are kept here encrypted (AES-256-GCM, one entry
/// per name) so that no file in the repository holds password-shaped text - which the organisation's DLP
/// flags wherever it appears, as it should. The key is in the open below: this keeps the source from looking
/// like a leak; it does not protect the values, which are not secret. Real secrets live in Keeper's own vault.
/// Add or change a value with: dotnet run --project components\testkit\src\demo-vault -- set &lt;name&gt; (it reads
/// the value without showing it).
/// </summary>
public static class DemoVault
{
    public const string FileName = "demo.vault.json";

    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private static readonly byte[] Key = SHA256.HashData("Keeper demo values: test data, not secrets"u8);
    private static readonly Lazy<JsonObject> Entries = new(Load);

    /// <summary>The demo value under this name; a name that is not there fails the test loudly.</summary>
    public static string Get(string name)
    {
        if (Values.Text(Entries.Value[name]) is not { } sealedText)
            throw new KeyNotFoundException($"No demo value {name} in {FileName}: add it with demo-vault set {name}.");
        return Open(name, sealedText);
    }

    /// <summary>A value sealed for this name: base64 of nonce, tag and ciphertext. The name is bound in, so an entry moved to another name does not open.</summary>
    public static string Seal(string name, string value)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var plain = Encoding.UTF8.GetBytes(value);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagBytes];
        using var aes = new AesGcm(Key, TagBytes);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(name));
        return Convert.ToBase64String([.. nonce, .. tag, .. cipher]);
    }

    public static string Open(string name, string sealedText)
    {
        var bytes = Convert.FromBase64String(sealedText);
        if (bytes.Length < NonceBytes + TagBytes)
            throw new CryptographicException($"Demo value {name} is not a sealed value.");
        var plain = new byte[bytes.Length - NonceBytes - TagBytes];
        using var aes = new AesGcm(Key, TagBytes);
        aes.Decrypt(bytes.AsSpan(0, NonceBytes), bytes.AsSpan(NonceBytes + TagBytes), bytes.AsSpan(NonceBytes, TagBytes), plain, Encoding.UTF8.GetBytes(name));
        return Encoding.UTF8.GetString(plain);
    }

    private static JsonObject Load()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"Keeper.TestKit.{FileName}")
                           ?? throw new FileNotFoundException($"{FileName} is not built into Keeper.TestKit.");
        return JsonNode.Parse(stream) as JsonObject ?? throw new InvalidDataException($"{FileName} is not a JSON object.");
    }

    private static class Values
    {
        public static string? Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    }
}
