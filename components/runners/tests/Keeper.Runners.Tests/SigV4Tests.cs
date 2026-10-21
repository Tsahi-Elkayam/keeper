using System.Text;

namespace Keeper.Runners.Tests;

/// <summary>AWS's own SigV4 test suite (aws-c-auth, tests/aws-signing-test-suite/v4): its example key, never a real one.</summary>
public sealed class SigV4Tests
{
    private static readonly AwsCredentials Example = new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", null);
    private static readonly DateTimeOffset At = new(2015, 8, 30, 12, 36, 0, TimeSpan.Zero);
    private const string Scope = "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request";

    private static string Sign(string method, string url, string payloadHash, AwsCredentials credentials, params (string, string)[] headers) =>
        SigV4.Authorization(method, new Uri(url), [("Host", "example.amazonaws.com"), ("X-Amz-Date", "20150830T123600Z"), .. headers],
            payloadHash, credentials, "us-east-1", "service", At);

    [Fact]
    public void Get_vanilla()
    {
        Assert.Equal($"AWS4-HMAC-SHA256 Credential={Scope}, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            Sign("GET", "https://example.amazonaws.com/", SigV4.EmptyHash, Example));
    }

    [Fact]
    public void Query_parameters_are_signed_in_order_of_name()
    {
        Assert.EndsWith("Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
            Sign("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", SigV4.EmptyHash, Example), StringComparison.Ordinal);
    }

    [Fact]
    public void A_session_token_is_a_signed_header()
    {
        var token = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267";

        var header = Sign("GET", "https://example.amazonaws.com/", SigV4.EmptyHash, Example with { SessionToken = token }, ("X-Amz-Security-Token", token));

        Assert.Contains("SignedHeaders=host;x-amz-date;x-amz-security-token,", header, StringComparison.Ordinal);
        Assert.EndsWith("Signature=07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8", header, StringComparison.Ordinal);
    }

    [Fact]
    public void A_form_post_signs_its_body_and_content_headers()
    {
        // The request as it is sent: the signer adds the date and body hash itself.
        var body = Encoding.UTF8.GetBytes("Param1=value1");
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.amazonaws.com/") { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

        SigV4.Sign(request, body, Example, "us-east-1", "service", At, hashHeader: true);

        Assert.Equal("9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e", request.Headers.GetValues("x-amz-content-sha256").Single());
        var authorization = request.Headers.GetValues("Authorization").Single();
        Assert.Contains("SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date,", authorization, StringComparison.Ordinal);
        Assert.EndsWith("Signature=d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b", authorization, StringComparison.Ordinal);
    }

    [Fact]
    public void Credentials_never_print_their_secret()
    {
        Assert.DoesNotContain("EXAMPLEKEY", (Example with { SessionToken = "tok" }).ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("a b", "a%20b")]
    [InlineData("a+b/c", "a%2Bb%2Fc")]
    [InlineData("~-._", "~-._")]
    [InlineData("é", "%C3%A9")]
    public void Encoding_is_the_aws_kind(string text, string encoded) => Assert.Equal(encoded, SigV4.Encode(text));
}
