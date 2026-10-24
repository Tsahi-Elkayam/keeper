using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keeper.Integrations.Tests;

public sealed class CaTrustTests
{
    private static (X509Certificate2 Ca, X509Certificate2 Leaf) Issue(string host, DateTimeOffset? notAfter = null, string caName = "CN=Example Cluster CA")
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(caName, caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(1));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest($"CN={host}", leafKey, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(host);
        leafRequest.CertificateExtensions.Add(names.Build());
        var leaf = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), notAfter ?? DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(8));
        return (ca, leaf);
    }

    private static string Pem(X509Certificate2 certificate) => certificate.ExportCertificatePem();

    [Fact]
    public void A_certificate_issued_by_the_trusted_ca_is_accepted_though_the_system_does_not_know_that_ca()
    {
        var (ca, leaf) = Issue("k8s.example.org");

        Assert.True(CaTrust.Accepts(leaf, [], [ca], SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void A_certificate_from_another_ca_is_refused()
    {
        var (ca, _) = Issue("k8s.example.org");
        var (_, impostor) = Issue("k8s.example.org", caName: "CN=Someone Else");

        Assert.False(CaTrust.Accepts(impostor, [], [ca], SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void The_right_ca_does_not_excuse_the_wrong_host_name()
    {
        var (ca, leaf) = Issue("k8s.example.org");

        Assert.False(CaTrust.Accepts(leaf, [], [ca], SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void An_expired_certificate_is_refused_even_from_the_trusted_ca()
    {
        var (ca, leaf) = Issue("k8s.example.org", notAfter: DateTimeOffset.UtcNow.AddMinutes(-5));

        Assert.False(CaTrust.Accepts(leaf, [], [ca], SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void No_certificate_at_all_is_refused()
    {
        var (ca, _) = Issue("k8s.example.org");

        Assert.False(CaTrust.Accepts(null, [], [ca], SslPolicyErrors.RemoteCertificateNotAvailable));
    }

    [Fact]
    public void One_or_several_pem_certificates_parse()
    {
        var (ca1, _) = Issue("a.example.org");
        var (ca2, _) = Issue("b.example.org");

        Assert.Single(CaTrust.Parse(Pem(ca1)));
        Assert.Equal(2, CaTrust.Parse(Pem(ca1) + "\n" + Pem(ca2)).Count);
    }

    [Fact]
    public void A_pem_pasted_with_its_line_breaks_as_text_still_parses()
    {
        var (ca, _) = Issue("a.example.org");

        Assert.Single(CaTrust.Parse(Pem(ca).Replace("\n", "\\n", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a certificate")]
    public void Text_that_is_not_a_certificate_is_refused(string text)
    {
        Assert.Throws<FormatException>(() => CaTrust.Parse(text));
    }

    [Fact]
    public void A_private_key_is_never_accepted_as_a_ca()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (ca, _) = Issue("a.example.org");

        var ex = Assert.Throws<FormatException>(() => CaTrust.Parse(Pem(ca) + "\n" + key.ExportPkcs8PrivateKeyPem()));
        Assert.Contains("private key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void More_than_a_handful_of_certificates_is_refused()
    {
        var (ca, _) = Issue("a.example.org");
        var many = string.Join("\n", Enumerable.Repeat(Pem(ca), 6));

        Assert.Throws<FormatException>(() => CaTrust.Parse(many));
    }
}
