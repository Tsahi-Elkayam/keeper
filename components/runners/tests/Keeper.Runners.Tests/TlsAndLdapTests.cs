using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keeper.Runners.Ldap;
using Keeper.Runners.Sql;
using Keeper.Runners.Tls;
using Microsoft.Data.SqlClient;

namespace Keeper.Runners.Tests;

public sealed class TlsTests
{
    [Fact]
    public async Task Reads_the_certificate_of_a_live_endpoint_without_trusting_it()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(20);
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), notAfter);
        using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(client.GetStream());
            await ssl.AuthenticateAsServerAsync(certificate);
        });

        var result = await new TlsRunner().RunAsync(Context.Query("tls", "endpoint"),
            Context.For(new FakeConnection(""), target: $"localhost:{port}") with { Now = DateTimeOffset.UtcNow }, CancellationToken.None);
        await server;
        listener.Stop();

        Assert.Equal("ok", result.State);
        var row = Assert.Single(result.Rows);
        Assert.True(row["selfSigned"]!.GetValue<bool>());
        Assert.False(row["chainValid"]!.GetValue<bool>());
        Assert.Equal(2048, row["keySize"]!.GetValue<int>());
        Assert.InRange(row["daysLeft"]!.GetValue<double>(), 18, 20);
        Assert.Equal("[]", row["eku"]!.ToJsonString());   // a self-signed certificate made without EKUs
    }

    [Fact]
    public void Extended_key_usages_come_back_as_oids()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=dc1.example.org", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.2.3.5")], critical: false));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.2.3.5" }, TlsRunner.Ekus(certificate));
    }

    [Fact]
    public async Task A_closed_port_is_a_failure_for_that_target()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        var result = await new TlsRunner().RunAsync(Context.Query("tls", "endpoint"), Context.For(new FakeConnection(""), target: $"127.0.0.1:{port}"), CancellationToken.None);

        Assert.Equal("failed", result.State);
    }
}

public sealed class LdapTests
{
    [Fact]
    public void Filetime_and_generalized_time_become_iso_dates_and_never_stays_never()
    {
        Assert.Equal("2022-06-18T04:26:40Z", LdapValues.Convert("lastLogonTimestamp", ["133000000000000000"])!.ToString());
        Assert.Equal("0", LdapValues.Convert("pwdLastSet", ["0"])!.ToString());
        Assert.Equal("9223372036854775807", LdapValues.Convert("accountExpires", ["9223372036854775807"])!.ToString());
        Assert.Equal("2024-01-02T03:04:05Z", LdapValues.Convert("whenCreated", ["20240102030405.0Z"])!.ToString());
        Assert.Equal("42", LdapValues.Convert("maxPwdAge", ["-36288000000000"])!.ToString());
        Assert.Equal("never", LdapValues.Convert("maxPwdAge", ["-9223372036854775808"])!.ToString());
        Assert.Equal("never", LdapValues.Convert("lockoutDuration", ["-9223372036854775808"])!.ToString());
    }

    [Fact]
    public void A_delegation_descriptor_gives_the_allowed_sids()
    {
        byte[] sid = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x51, 4, 0, 0];   // S-1-5-21-1-2-3-1105
        var ace = new List<byte> { 0, 0 };                                 // ACCESS_ALLOWED_ACE, no flags
        ace.AddRange(BitConverter.GetBytes((ushort)(8 + sid.Length)));
        ace.AddRange(BitConverter.GetBytes(0x000F01FF));
        ace.AddRange(sid);
        var acl = new List<byte> { 2, 0 };
        acl.AddRange(BitConverter.GetBytes((ushort)(8 + ace.Count)));
        acl.AddRange(BitConverter.GetBytes((ushort)1));
        acl.AddRange([0, 0]);
        acl.AddRange(ace);
        var descriptor = new List<byte> { 1, 0, 0x04, 0x80 };              // revision 1, DACL present, self-relative
        descriptor.AddRange(BitConverter.GetBytes(0));                     // no owner
        descriptor.AddRange(BitConverter.GetBytes(0));                     // no group
        descriptor.AddRange(BitConverter.GetBytes(0));                     // no SACL
        descriptor.AddRange(BitConverter.GetBytes(20));                    // DACL right after the header
        descriptor.AddRange(acl);

        var node = LdapValues.Convert("msDS-AllowedToActOnBehalfOfOtherIdentity", [descriptor.ToArray()]);

        Assert.Equal("[\"S-1-5-21-1-2-3-1105\"]", node!.ToJsonString());
        Assert.Null(LdapValues.AllowedTrustees([1, 0, 0, 0]));
    }

    [Theory]
    [InlineData("member;range=0-1499", "member", 1499L)]
    [InlineData("member;range=1500-*", "member", null)]
    [InlineData("member", null, null)]
    public void Ranged_attribute_names_parse(string name, string? attribute, long? high)
    {
        var range = LdapRunner.RangeOf(name);
        Assert.Equal(attribute, range?.Attribute);
        Assert.Equal(high, range?.High);
    }

    [Fact]
    public void Sids_parse_without_windows_apis()
    {
        byte[] sid = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xF4, 1, 0, 0];

        Assert.Equal("S-1-5-21-1-2-3-500", LdapValues.Sid(sid));
    }

    [Fact]
    public void Multi_valued_attributes_are_arrays()
    {
        var node = LdapValues.Convert("memberOf", ["CN=Admins,DC=example,DC=org"]);

        Assert.IsType<System.Text.Json.Nodes.JsonArray>(node);
    }

    [Fact]
    public void Earlier_filter_macros_expand()
    {
        var contexts = new Dictionary<string, string> { ["domain"] = "DC=example,DC=org", ["config"] = "CN=Configuration,DC=example,DC=org" };
        var now = new DateTimeOffset(2026, 10, 20, 0, 0, 0, TimeSpan.Zero);

        var filter = LdapMacros.Expand("(&{USER}{ENABLED}{UAC:65536}(lastLogonTimestamp<={FT:90}){IFATTR:msLAPS-PasswordExpirationTime|(x=1)})",
            now, contexts, _ => false);

        Assert.Equal(
            "(&(&(objectCategory=person)(objectClass=user))(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
            $"(userAccountControl:1.2.840.113556.1.4.803:=65536)(lastLogonTimestamp<={now.AddDays(-90).UtcDateTime.ToFileTimeUtc()}))",
            filter);
        Assert.Equal("CN=x,DC=example,DC=org", LdapMacros.Expand("CN=x,{DOMAINDN}", now, contexts, _ => true));
        Assert.Throws<FormatException>(() => LdapMacros.Expand("({NOPE})", now, contexts, _ => true));
    }

    [Theory]
    [InlineData("ldaps://dc1.example.org", "dc1.example.org", 636, true)]
    [InlineData("ldap://dc1.example.org:3268", "dc1.example.org", 3268, false)]
    [InlineData("example.org", "example.org", 389, false)]
    public void Endpoints_parse(string endpoint, string server, int port, bool ssl)
    {
        Assert.Equal((server, port, ssl), LdapRunner.Endpoint(endpoint));
    }

    [Theory]
    [InlineData(@"u:EXAMPLE\reader", @"EXAMPLE\reader")]
    [InlineData("dn:CN=reader,DC=example,DC=org", "CN=reader,DC=example,DC=org")]
    [InlineData("reader", "reader")]
    public void Who_am_i_answers_become_plain_names(string answer, string expected)
    {
        Assert.Equal(expected, LdapRunner.AuthzId(answer));
    }

    [Fact]
    public void A_complete_answer_says_who_read_it_and_which_requested_attributes_no_entry_returned()
    {
        var rows = new List<System.Text.Json.Nodes.JsonObject>
        {
            new() { ["distinguishedName"] = "CN=u1,DC=example,DC=org", ["sAMAccountName"] = "u1" },
            new() { ["distinguishedName"] = "CN=u2,DC=example,DC=org", ["samaccountname"] = "u2", ["pwdLastSet"] = "2026-01-01" },
        };

        var notes = LdapRunner.Notes(@"EXAMPLE\reader", ["sAMAccountName", "pwdLastSet", "msDS-AllowedToDelegateTo", "ms-Mcs-AdmPwd"], rows);

        Assert.Equal(@"bound as EXAMPLE\reader; no entry returned msDS-AllowedToDelegateTo (unset everywhere, or hidden from this account)", notes);
        Assert.Null(LdapRunner.Notes(null, ["sAMAccountName"], []));   // no rows: nothing to say about attributes
    }

    [Fact]
    public void Secret_attributes_are_refused_at_load_time()
    {
        var problems = new LdapRunner().Validate(Context.Query("ldap", "cn",
            ("filter", "(objectCategory=computer)"), ("attributes", new System.Text.Json.Nodes.JsonArray("cn", "ms-Mcs-AdmPwd")))).ToList();

        Assert.Contains(problems, p => p.Contains("ms-Mcs-AdmPwd", StringComparison.Ordinal));
    }
}

public sealed class SqlTests
{
    [Fact]
    public void Connections_are_read_only_encrypted_and_checked()
    {
        var builder = new SqlConnectionStringBuilder(SqlRunner.ConnectionString("sql1.example.org", "master", Context.For(new FakeConnection(""))));

        Assert.Equal(ApplicationIntent.ReadOnly, builder.ApplicationIntent);
        Assert.Equal(SqlConnectionEncryptOption.Mandatory, builder.Encrypt);
        Assert.False(builder.TrustServerCertificate);
        Assert.True(builder.IntegratedSecurity);
    }
}
