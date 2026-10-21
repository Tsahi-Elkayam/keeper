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
/// (no calls to the internet from a scan). Behind HTTPS inspection, an endpoint whose certificate comes from
/// one of the integration's inspectionIssuers is a failed read: the proxy's certificate is not the endpoint's.
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
            // Behind HTTPS inspection the certificate is the inspecting proxy's, minted for this host: judging it
            // would report on the proxy, never the endpoint. Its issuer gives it away (option inspectionIssuers).
            if (InspectedBy(certificate, context.Connection.Options) is { } proxy)
                return RunnerResult.Failed($"{host}:{port} was seen through HTTPS inspection (issuer {proxy}): its own certificate is not visible from here");
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

    /// <summary>
    /// The issuer that gives a certificate away as an inspecting proxy's: any of the integration's
    /// inspectionIssuers (parts of an issuer name, such as the name of the firewall's inspection CA) that the
    /// certificate's issuer contains, or null.
    /// </summary>
    public static string? InspectedBy(X509Certificate2 certificate, JsonObject options)
    {
        IEnumerable<string> issuers = options["inspectionIssuers"] switch
        {
            JsonArray list => list.Select(Values.Text).OfType<string>(),
            JsonValue text => (Values.Text(text) ?? "").Split(',', StringSplitOptions.TrimEntries),
            _ => [],
        };
        return issuers.Where(i => i.Length > 0).Any(i => certificate.Issuer.Contains(i, StringComparison.OrdinalIgnoreCase)) ? certificate.Issuer : null;
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
        var row = new JsonObject { ["endpoint"] = $"{host}:{port}", ["host"] = host, ["port"] = port };
        foreach (var (name, value) in CertificateRows.Of(certificate, now).ToList())
            row[name] = value?.DeepClone();
        row["protocol"] = ssl.SslProtocol.ToString();
        row["cipherSuite"] = ssl.NegotiatedCipherSuite.ToString();
        row["chainValid"] = (errors & SslPolicyErrors.RemoteCertificateChainErrors) == 0;
        row["nameMatches"] = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
        row["chainErrors"] = string.Join(", ", chainStatus.Distinct());
        return row;
    }

    /// <summary>The certificate's extended key usages as OIDs (see <see cref="CertificateRows.Ekus"/>).</summary>
    public static IEnumerable<string> Ekus(X509Certificate2 certificate) => CertificateRows.Ekus(certificate);
}
