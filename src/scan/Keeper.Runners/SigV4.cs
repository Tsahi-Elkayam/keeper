using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Keeper.Runners;

/// <summary>AWS credentials: an access key, or temporary ones (with their session token) from STS.</summary>
public sealed record AwsCredentials(string AccessKeyId, string SecretAccessKey, string? SessionToken, DateTimeOffset? Expires = null)
{
    /// <summary>The key id only: the secret and the token never reach a log or an error.</summary>
    public override string ToString() => $"AwsCredentials {{ AccessKeyId = {AccessKeyId} }}";
}

/// <summary>A connection that signs AWS requests: its credentials for one account, or its own (account null).</summary>
public interface IAwsConnection
{
    /// <summary>The accounts it reads (each through the integration's read-only role), or none: its own only.</summary>
    IReadOnlyList<string> AwsAccounts { get; }

    /// <summary>The regions a regional read goes to, and the home region (first) where global services are signed.</summary>
    IReadOnlyList<string> AwsRegions { get; }

    Task<AwsCredentials> AwsCredentialsAsync(string? account, CancellationToken cancellationToken);
}

/// <summary>
/// AWS Signature Version 4, by hand (no SDK), checked against AWS's own signing test suite. The request is
/// signed as it will be sent: its method, path, query, the headers named below and a hash of its body.
/// </summary>
public static class SigV4
{
    public const string Algorithm = "AWS4-HMAC-SHA256";

    /// <summary>Hex SHA-256 of an empty body.</summary>
    public static readonly string EmptyHash = Hex(SHA256.HashData([]));

    // Headers a proxy or the transport may change on the way: never signed.
    private static readonly HashSet<string> Unsigned = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "connection", "expect", "keep-alive", "proxy-authorization", "proxy-authenticate", "te", "trailer",
        "transfer-encoding", "upgrade", "user-agent", "x-amzn-trace-id",
    };

    /// <summary>
    /// Signs <paramref name="request"/> in place: X-Amz-Date, the session token when there is one, x-amz-content-sha256
    /// when <paramref name="hashHeader"/> (S3 wants it), and Authorization. <paramref name="body"/> is exactly what is sent.
    /// </summary>
    public static void Sign(HttpRequestMessage request, byte[]? body, AwsCredentials credentials, string region, string service,
        DateTimeOffset at, bool hashHeader = false)
    {
        var amzDate = at.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var payloadHash = Hex(SHA256.HashData(body ?? []));
        request.Headers.Remove("X-Amz-Date");
        request.Headers.TryAddWithoutValidation("X-Amz-Date", amzDate);
        if (credentials.SessionToken is { Length: > 0 } token)
        {
            request.Headers.Remove("X-Amz-Security-Token");
            request.Headers.TryAddWithoutValidation("X-Amz-Security-Token", token);
        }
        if (hashHeader)
        {
            request.Headers.Remove("x-amz-content-sha256");
            request.Headers.TryAddWithoutValidation("x-amz-content-sha256", payloadHash);
        }

        // The length is signed as it is sent: set, not left for the transport to work out after signing.
        if (request.Content is not null)
            request.Content.Headers.ContentLength = body?.Length ?? 0;
        var headers = new List<(string Name, string Value)>();
        var uri = request.RequestUri!;
        headers.Add(("host", uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}"));
        foreach (var (name, values) in request.Headers)
        {
            if (!name.Equals("host", StringComparison.OrdinalIgnoreCase))
                headers.Add((name, string.Join(",", values)));
        }
        if (request.Content is not null)
        {
            foreach (var (name, values) in request.Content.Headers)
                headers.Add((name, string.Join(",", values)));
        }
        request.Headers.TryAddWithoutValidation("Authorization",
            Authorization(request.Method.Method, uri, headers, payloadHash, credentials, region, service, at, s3: service == "s3"));
    }

    /// <summary>The Authorization header value for a request with these headers (host included) and this body hash.</summary>
    public static string Authorization(string method, Uri uri, IEnumerable<(string Name, string Value)> headers, string payloadHash,
        AwsCredentials credentials, string region, string service, DateTimeOffset at, bool s3 = false)
    {
        var amzDate = at.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var day = amzDate[..8];
        var signed = headers
            .Where(h => !Unsigned.Contains(h.Name))
            .GroupBy(h => h.Name.ToLowerInvariant(), StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => (Name: g.Key, Value: string.Join(",", g.Select(h => Collapse(h.Value)))))
            .ToList();
        var signedNames = string.Join(";", signed.Select(h => h.Name));

        var canonical = string.Join("\n",
            method.ToUpperInvariant(),
            CanonicalPath(uri, s3),
            CanonicalQuery(uri),
            string.Concat(signed.Select(h => $"{h.Name}:{h.Value}\n")),
            signedNames,
            payloadHash);
        var scope = $"{day}/{region}/{service}/aws4_request";
        var toSign = string.Join("\n", Algorithm, amzDate, scope, Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
        var signature = Hex(HMACSHA256.HashData(SigningKey(credentials.SecretAccessKey, day, region, service), Encoding.UTF8.GetBytes(toSign)));
        return $"{Algorithm} Credential={credentials.AccessKeyId}/{scope}, SignedHeaders={signedNames}, Signature={signature}";
    }

    public static byte[] SigningKey(string secret, string day, string region, string service)
    {
        var date = HMACSHA256.HashData(Encoding.UTF8.GetBytes("AWS4" + secret), Encoding.UTF8.GetBytes(day));
        var inRegion = HMACSHA256.HashData(date, Encoding.UTF8.GetBytes(region));
        var inService = HMACSHA256.HashData(inRegion, Encoding.UTF8.GetBytes(service));
        return HMACSHA256.HashData(inService, "aws4_request"u8.ToArray());
    }

    /// <summary>
    /// The path as sent, each segment encoded again - except for S3, whose object keys are signed as sent. An
    /// empty path is "/". Dot segments are already gone: the URI normalised them before anything was sent.
    /// </summary>
    private static string CanonicalPath(Uri uri, bool s3)
    {
        var path = uri.AbsolutePath;
        if (path.Length == 0)
            return "/";
        return s3 ? path : string.Join("/", path.Split('/').Select(Encode));
    }

    /// <summary>Each name and value decoded, encoded the AWS way, and sorted by name, then value.</summary>
    private static string CanonicalQuery(Uri uri)
    {
        var query = uri.Query.TrimStart('?');
        if (query.Length == 0)
            return "";
        return string.Join("&", query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair =>
            {
                var equals = pair.IndexOf('=', StringComparison.Ordinal);
                var name = equals < 0 ? pair : pair[..equals];
                var value = equals < 0 ? "" : pair[(equals + 1)..];
                return (Name: Encode(Uri.UnescapeDataString(name)), Value: Encode(Uri.UnescapeDataString(value)));
            })
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal)
            .Select(p => $"{p.Name}={p.Value}"));
    }

    /// <summary>Every byte but A-Z a-z 0-9 - . _ ~ as %XX, upper case; a space is %20, never +.</summary>
    public static string Encode(string text)
    {
        var builder = new StringBuilder(text.Length * 2);
        foreach (var b in Encoding.UTF8.GetBytes(text))
        {
            var c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~')
                builder.Append(c);
            else
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return builder.ToString();
    }

    /// <summary>A header value trimmed, its runs of spaces made one.</summary>
    private static string Collapse(string value) => string.Join(' ', value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries));

    public static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
}
