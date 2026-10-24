using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Keeper.Integrations;

/// <summary>
/// Trusting a private certificate authority for one integration (a Kubernetes API server, an appliance). Only the
/// certificates the integration lists are roots: the machine's own trust store is not widened, the host name must
/// still match, and an expired or wrongly issued certificate is still refused.
/// </summary>
public static class CaTrust
{
    public const int MaxCertificates = 4;

    /// <summary>The certificates in a PEM option. A private key, or anything that is not a certificate, is refused.</summary>
    public static IReadOnlyList<X509Certificate2> Parse(string text)
    {
        // Pasted at a prompt or a command line, the line breaks may arrive as the two characters \n.
        var pem = text.Contains('\n', StringComparison.Ordinal) ? text : text.Replace("\\n", "\n", StringComparison.Ordinal);
        if (pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
            throw new FormatException("caCertificate holds a private key; it takes the authority's certificate only.");
        var collection = new X509Certificate2Collection();
        try
        {
            collection.ImportFromPem(pem);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            throw new FormatException("caCertificate is not a PEM certificate.");
        }
        if (collection.Count == 0)
            throw new FormatException("caCertificate has no PEM certificate (-----BEGIN CERTIFICATE-----).");
        if (collection.Count > MaxCertificates)
            throw new FormatException($"caCertificate has more than {MaxCertificates} certificates.");
        return [.. collection];
    }

    /// <summary>
    /// Whether the server's certificate chains to one of <paramref name="roots"/> and is valid now. A name
    /// mismatch or a missing certificate is refused outright. No revocation check: a private CA publishes none.
    /// </summary>
    public static bool Accepts(X509Certificate2? leaf, IEnumerable<X509Certificate2> intermediates, IReadOnlyList<X509Certificate2> roots, SslPolicyErrors errors)
    {
        if (leaf is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0)
            return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(intermediates.ToArray());
        return chain.Build(leaf);
    }

    /// <summary>The validation callback for a handler that trusts these roots.</summary>
    public static RemoteCertificateValidationCallback Callback(IReadOnlyList<X509Certificate2> roots) =>
        (_, certificate, chain, errors) =>
        {
            using var leaf = certificate is null ? null : new X509Certificate2(certificate);
            var extra = chain?.ChainElements.Select(e => e.Certificate) ?? [];
            return Accepts(leaf, extra, roots, errors);
        };
}
