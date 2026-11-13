using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Runners;

/// <summary>
/// A certificate as a row, the same wherever it was found (a TLS endpoint, a host's certificate store):
/// subject, issuer, dates and days left, serial, thumbprint, key, signature, self-signed, DNS names and
/// extended key usages as OIDs. Never a private key: none is ever read.
/// </summary>
public static class CertificateRows
{
    public static JsonObject Of(X509Certificate2 certificate, DateTimeOffset now)
    {
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        var sans = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToArray();
        var keySize = certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize;
        return new JsonObject
        {
            ["subject"] = certificate.Subject,
            ["issuer"] = certificate.Issuer,
            ["notBefore"] = RowValues.Iso(new DateTimeOffset(certificate.NotBefore.ToUniversalTime())),
            ["notAfter"] = RowValues.Iso(notAfter),
            ["daysLeft"] = Math.Floor((notAfter - now).TotalDays),
            ["serial"] = certificate.SerialNumber,
            ["thumbprint"] = certificate.Thumbprint,
            ["keyAlgorithm"] = certificate.PublicKey.Oid.FriendlyName,
            ["keySize"] = keySize,
            ["signatureAlgorithm"] = certificate.SignatureAlgorithm.FriendlyName,
            ["selfSigned"] = certificate.Subject == certificate.Issuer,
            ["sans"] = new JsonArray([.. sans.Select(s => (JsonNode?)s)]),
            ["eku"] = new JsonArray([.. Ekus(certificate).Select(s => (JsonNode?)s)]),
        };
    }

    /// <summary>
    /// The certificate's extended key usages as OIDs (1.3.6.1.5.5.7.3.1 server authentication,
    /// 1.3.6.1.5.2.3.5 KDC authentication, ...). OIDs, not names: names differ by platform and language.
    /// </summary>
    public static IEnumerable<string> Ekus(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
            .Select(o => o.Value ?? "")
            .Where(v => v.Length > 0);

    private const uint CertificateProperty = 0x20;   // the encoded certificate itself
    private const uint FriendlyNameProperty = 11;

    /// <summary>
    /// The Blob value of a certificate under ...\SystemCertificates\&lt;store&gt;\Certificates\&lt;thumbprint&gt;: a list of
    /// properties (id, a reserved word, length, data), one of which is the certificate. Its friendly name too,
    /// when it has one. Null when the blob holds no readable certificate.
    /// </summary>
    public static (X509Certificate2 Certificate, string? FriendlyName)? FromStoreBlob(byte[] blob)
    {
        byte[]? encoded = null;
        string? friendlyName = null;
        for (var at = 0; at + 12 <= blob.Length;)
        {
            var id = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(at));
            var length = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(at + 8));
            at += 12;
            if (length > blob.Length - at)
                return null;
            var data = blob.AsSpan(at, (int)length);
            if (id == CertificateProperty)
                encoded = data.ToArray();
            else if (id == FriendlyNameProperty)
                friendlyName = Encoding.Unicode.GetString(data).TrimEnd('\0');
            at += (int)length;
        }
        if (encoded is null)
            return null;
        try
        {
            return (X509CertificateLoader.LoadCertificate(encoded), friendlyName);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
