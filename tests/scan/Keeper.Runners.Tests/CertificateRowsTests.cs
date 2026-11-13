using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Keeper.Runners.Tests;

public sealed class CertificateRowsTests
{
    private static byte[] Property(uint id, byte[] data) =>
        [.. BitConverter.GetBytes(id), .. BitConverter.GetBytes(1u), .. BitConverter.GetBytes((uint)data.Length), .. data];

    [Fact]
    public void A_store_blob_holds_the_certificate_and_its_friendly_name_and_nothing_else_is_read()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Example Root, O=Example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var made = request.CreateSelfSigned(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero));
        byte[] blob = [.. Property(3, new byte[20]), .. Property(11, Encoding.Unicode.GetBytes("Example root\0")), .. Property(0x20, made.RawData)];

        var parsed = CertificateRows.FromStoreBlob(blob);

        Assert.NotNull(parsed);
        using var certificate = parsed.Value.Certificate;
        Assert.Equal("Example root", parsed.Value.FriendlyName);
        Assert.False(certificate.HasPrivateKey);
        var row = CertificateRows.Of(certificate, new DateTimeOffset(2026, 10, 21, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(("CN=Example Root, O=Example", true, 71.0), (row["subject"]!.ToString(), (bool)row["selfSigned"]!, (double)row["daysLeft"]!));
    }

    [Fact]
    public void A_certificate_minted_by_an_inspecting_proxy_is_told_apart_by_its_issuer()
    {
        using var key = RSA.Create(2048);
        using var proxied = new CertificateRequest("CN=www.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var options = new System.Text.Json.Nodes.JsonObject { ["inspectionIssuers"] = new System.Text.Json.Nodes.JsonArray("www.example.com") };

        Assert.NotNull(Keeper.Runners.Tls.TlsRunner.InspectedBy(proxied, options));
        Assert.Null(Keeper.Runners.Tls.TlsRunner.InspectedBy(proxied, []));
        Assert.Null(Keeper.Runners.Tls.TlsRunner.InspectedBy(proxied, new System.Text.Json.Nodes.JsonObject { ["inspectionIssuers"] = "Other CA" }));
    }

    [Fact]
    public void A_blob_cut_short_or_without_a_certificate_is_not_read()
    {
        byte[] noCertificate = [.. Property(11, Encoding.Unicode.GetBytes("x\0"))];
        byte[] cut = [.. BitConverter.GetBytes(0x20u), .. BitConverter.GetBytes(1u), .. BitConverter.GetBytes(4000u), 1, 2, 3];

        Assert.Null(CertificateRows.FromStoreBlob(noCertificate));
        Assert.Null(CertificateRows.FromStoreBlob(cut));
    }
}
