using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Tls;

/// <summary>
/// tls: connects to host:port, completes a TLS handshake and reads the certificate - subject, issuer,
/// validity, key, protocol, and whether the chain and name are valid. One row per target.
/// The handshake accepts any certificate on purpose: nothing is sent over the connection, it is only
/// inspected, so an invalid certificate is a finding rather than an error. Revocation is not fetched
/// (no calls to the internet from a scan).
/// </summary>
public sealed class TlsRunner : IRunner
{
    public string Protocol => "tls";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (query.Text("port") is { } port && (!int.TryParse(port, out var p) || p is < 1 or > 65535))
            yield return "port must be 1 to 65535";
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(context.Target))
            return RunnerResult.Failed("tls needs a target host");

        var (host, port) = Split(context.Target, query.Int("port") ?? 443);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(context.Timeout);

        SslPolicyErrors errors = SslPolicyErrors.None;
        var chainStatus = new List<string>();
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);
            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, chain, policyErrors) =>
            {
                errors = policyErrors;
                if (chain is not null)
                    chainStatus.AddRange(chain.ChainStatus.Select(s => s.Status.ToString()));
                return true;   // inspect only: see the class comment
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, timeout.Token).ConfigureAwait(false);

            if (ssl.RemoteCertificate is null)
                return RunnerResult.Failed($"{host}:{port} sent no certificate");

            using var certificate = X509CertificateLoader.LoadCertificate(ssl.RemoteCertificate.GetRawCertData());
            return RunnerResult.Ok([Row(host, port, certificate, ssl, errors, chainStatus, context.Now)]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return RunnerResult.Failed($"{host}:{port} did not answer within {context.Timeout.TotalSeconds:0} s");
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException)
        {
            return RunnerResult.Failed($"{host}:{port}: {ex.Message}");
        }
    }

    public static (string Host, int Port) Split(string target, int defaultPort)
    {
        var colon = target.LastIndexOf(':');
        return colon > 0 && int.TryParse(target[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            ? (target[..colon], port)
            : (target, defaultPort);
    }

    public static JsonObject Row(string host, int port, X509Certificate2 certificate, SslStream ssl, SslPolicyErrors errors,
        IReadOnlyList<string> chainStatus, DateTimeOffset now)
    {
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        var sans = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(e => e.EnumerateDnsNames())
            .ToArray();
        var keySize = certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize;

        return new JsonObject
        {
            ["endpoint"] = $"{host}:{port}",
            ["host"] = host,
            ["port"] = port,
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
            ["protocol"] = ssl.SslProtocol.ToString(),
            ["cipherSuite"] = ssl.NegotiatedCipherSuite.ToString(),
            ["chainValid"] = (errors & SslPolicyErrors.RemoteCertificateChainErrors) == 0,
            ["nameMatches"] = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0,
            ["chainErrors"] = string.Join(", ", chainStatus.Distinct()),
            ["selfSigned"] = certificate.Subject == certificate.Issuer,
            ["sans"] = new JsonArray(sans.Select(s => (JsonNode)JsonValue.Create(s)).ToArray()),
            ["eku"] = new JsonArray(Ekus(certificate).Select(s => (JsonNode)JsonValue.Create(s)).ToArray()),
        };
    }

    /// <summary>
    /// The certificate's extended key usages as OIDs (1.3.6.1.5.5.7.3.1 server authentication,
    /// 1.3.6.1.5.2.3.5 KDC authentication, ...). OIDs, not names: names differ by platform and language.
    /// </summary>
    public static IEnumerable<string> Ekus(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>())
            .Select(o => o.Value ?? "")
            .Where(v => v.Length > 0);
}
