using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Printer;

namespace Keeper.Runners.Tests;

internal sealed class PrinterFakeConnection(string endpoint = "127.0.0.1", string? community = "s3cret-community") : IConnection
{
    public string Instance => "office-printers";
    public string Type => "printer";
    public string Endpoint => endpoint;
    public string AuthKind => community is null ? "none" : "snmp-v2c";
    public string? Identity => null;
    public JsonObject Options { get; } = [];
    public string? Secret(string name) => name == "community" ? community : null;
    public NetworkCredential? WindowsCredential() => null;
    public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
    public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class PrinterRunnerTests : IDisposable
{
    private readonly List<IDisposable> _cleanup = [];

    public void Dispose()
    {
        foreach (var item in _cleanup)
            item.Dispose();
    }

    private static QuerySpec Q(params (string Name, JsonNode? Value)[] fields) => Context.Query("printer", "host", fields);

    private static Task<RunnerResult> Run(PrinterRunner runner, QuerySpec query, string? target = "127.0.0.1", string endpoint = "127.0.0.1", string? community = "s3cret-community") =>
        runner.RunAsync(query, Context.For(new PrinterFakeConnection(endpoint, community), target), CancellationToken.None);

    // ---------------------------------------------------------------- ports

    [Fact]
    public async Task Ports_are_reported_per_service_and_only_the_open_ones_are_true()
    {
        var open = new HashSet<int> { 80, 631, 9100 };
        var runner = new PrinterRunner((endpoint, _, _) => Task.FromResult(open.Contains(endpoint.Port)));

        var row = Assert.Single((await Run(runner, Q(("read", "ports")))).Rows);

        Assert.Equal(("127.0.0.1", "127.0.0.1"), (row["host"]!.ToString(), row["address"]!.ToString()));
        Assert.True((bool)row["http"]!);
        Assert.True((bool)row["ipp"]!);
        Assert.True((bool)row["jetdirect"]!);
        Assert.False((bool)row["telnet"]!);
        Assert.False((bool)row["ftp"]!);
        Assert.False((bool)row["https"]!);
        Assert.Equal([80, 631, 9100], row["openPorts"]!.AsArray().Select(n => (int)n!));
    }

    [Fact]
    public async Task Probing_a_port_connects_and_hangs_up_without_sending_a_single_byte()
    {
        // A raw print port treats any byte it receives as something to print. Keeper must connect, and leave.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        _cleanup.Add(new Stopper(listener.Stop));
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var received = new List<byte>();
        var served = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var buffer = new byte[1024];
            var read = await client.GetStream().ReadAsync(buffer);   // returns 0 when the other side closes without writing
            received.AddRange(buffer.Take(read));
        });

        var row = Assert.Single((await Run(new PrinterRunner(), Q(("read", "ports"), ("ports", new JsonArray(port))))).Rows);
        await served.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Empty(received);
        Assert.Contains(port, row["openPorts"]!.AsArray().Select(n => (int)n!));
    }

    [Fact]
    public async Task A_port_that_is_closed_is_closed_and_extra_ports_can_be_added()
    {
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var port = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();

        var row = Assert.Single((await Run(new PrinterRunner(), Q(("read", "ports"), ("ports", new JsonArray(port))))).Rows);

        Assert.DoesNotContain(port, row["openPorts"]!.AsArray().Select(n => (int)n!));
    }

    // ---------------------------------------------------------------- scope

    [Theory]
    [InlineData("203.0.113.9", "192.0.2.0/24")]
    [InlineData("printer9.evil.test", "*.example.org")]
    public async Task A_target_outside_the_integrations_scope_gets_nothing_sent(string target, string endpoint)
    {
        var sent = 0;
        var runner = new PrinterRunner((_, _, _) =>
        {
            sent++;
            return Task.FromResult(true);
        });

        var result = await Run(runner, Q(("read", "ports")), target, endpoint);

        Assert.Equal("failed", result.State);
        Assert.Contains("scope", result.Reason!, StringComparison.Ordinal);
        Assert.Equal(0, sent);
    }

    [Fact]
    public async Task A_read_needs_a_target_printer()
    {
        var result = await Run(new PrinterRunner(), Q(("read", "ports")), target: null);

        Assert.Equal("failed", result.State);
        Assert.Contains("targets", result.Reason!, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- IPP

    private sealed class Stopper(Action stop) : IDisposable
    {
        public void Dispose() => stop();
    }

    private HttpListener ServeIpp(byte[] answer, List<(string Method, string Type, byte[] Body)> seen, out int port)
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        _cleanup.Add(new Stopper(listener.Close));
        _ = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                try
                {
                    var context = await listener.GetContextAsync();
                    using var body = new MemoryStream();
                    await context.Request.InputStream.CopyToAsync(body);
                    seen.Add((context.Request.HttpMethod, context.Request.ContentType ?? "", body.ToArray()));
                    context.Response.ContentType = "application/ipp";
                    await context.Response.OutputStream.WriteAsync(answer);
                    context.Response.Close();
                }
                catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
                {
                    return;
                }
            }
        });
        return listener;
    }

    private static byte[] PrinterAnswer(int status = 0) => new IppResponseBuilder(status).PrinterGroup()
        .Text(0x41, "printer-make-and-model", "HP LaserJet Pro M404")
        .Text(0x41, "printer-firmware-string-version", "20240612")
        .Keyword("uri-security-supported", "none")
        .Keyword("uri-authentication-supported", "none")
        .Integer("marker-levels", 80, 4)
        .Keyword("marker-names", "Black Toner", "Fuser Kit")
        .Boolean("printer-is-accepting-jobs", true)
        .Build();

    [Fact]
    public async Task An_ipp_read_asks_the_printer_about_itself_and_returns_its_attributes_as_one_row()
    {
        var seen = new List<(string, string, byte[])>();
        ServeIpp(PrinterAnswer(), seen, out var port);

        var result = await Run(new PrinterRunner(), Q(("read", "ipp"), ("port", port)));

        Assert.Equal("ok", result.State);
        var row = Assert.Single(result.Rows);
        Assert.Equal("HP LaserJet Pro M404", row["printer-make-and-model"]!.ToString());
        Assert.Equal("20240612", row["printer-firmware-string-version"]!.ToString());
        Assert.Equal("none", row["uri-security-supported"]!.ToString());
        Assert.Equal([80L, 4L], row["marker-levels"]!.AsArray().Select(n => (long)n!));
        Assert.Equal(("127.0.0.1", false), (row["host"]!.ToString(), (bool)row["tls"]!));
        var (method, type, body) = Assert.Single(seen);
        Assert.Equal(("POST", "application/ipp"), (method, type));
        Assert.Equal([0x01, 0x01, 0x00, 0x0B], body[..4]);          // Get-Printer-Attributes and nothing else
    }

    [Fact]
    public async Task A_printer_that_refuses_is_a_failed_read_that_says_the_ipp_status()
    {
        ServeIpp(PrinterAnswer(status: 0x0406), [], out var port);

        var result = await Run(new PrinterRunner(), Q(("read", "ipp"), ("port", port)));

        Assert.Equal("failed", result.State);
        Assert.Contains("0406", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_answer_that_is_not_ipp_is_a_failed_read_not_an_empty_pass()
    {
        ServeIpp(Encoding.ASCII.GetBytes("<html>web admin page</html>"), [], out var port);

        var result = await Run(new PrinterRunner(), Q(("read", "ipp"), ("port", port)));

        Assert.Equal("failed", result.State);
    }

    [Fact]
    public async Task A_printer_with_nothing_listening_is_a_failed_read()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var result = await Run(new PrinterRunner(), Q(("read", "ipp"), ("port", port)));

        Assert.Equal("failed", result.State);
    }

    [Fact]
    public async Task An_ipps_read_records_the_certificate_the_printer_presents_even_a_self_signed_one()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=printer.example.org", key, HashAlgorithmName.SHA256);
        var made = request.CreateSelfSigned(Context.Now.AddDays(-30), Context.Now.AddDays(20));   // relative to the scan's clock
        using var certificate = X509CertificateLoader.LoadPkcs12(made.Export(X509ContentType.Pfx), null);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        _cleanup.Add(new Stopper(listener.Stop));
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var tls = new SslStream(client.GetStream());
                await tls.AuthenticateAsServerAsync(certificate);
                var buffer = new byte[8192];
                var read = 0;
                while (!Encoding.ASCII.GetString(buffer, 0, read).Contains("\r\n\r\n", StringComparison.Ordinal))
                    read += await tls.ReadAsync(buffer.AsMemory(read));
                var body = PrinterAnswer();
                await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                await tls.WriteAsync(body);
                await tls.FlushAsync();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or System.Security.Authentication.AuthenticationException)
            {
            }
        });

        var result = await Run(new PrinterRunner(), Q(("read", "ipp"), ("scheme", "ipps"), ("port", port)));

        Assert.Equal("ok", result.State);
        var row = Assert.Single(result.Rows);
        Assert.True((bool)row["tls"]!);
        Assert.True((bool)row["tlsSelfSigned"]!);
        Assert.Contains("printer.example.org", row["tlsSubject"]!.ToString(), StringComparison.Ordinal);
        Assert.InRange((int)row["tlsDaysLeft"]!, 19, 20);
    }

    // ---------------------------------------------------------------- SNMP

    private FakeSnmpAgent PrinterAgent(string community = "s3cret-community")
    {
        var agent = new FakeSnmpAgent(community, new()
        {
            ["1.3.6.1.2.1.1.1.0"] = "HP LaserJet Pro M404",
            ["1.3.6.1.2.1.1.3.0"] = 8_640_000L,                                 // 1 day in hundredths of a second
            ["1.3.6.1.2.1.1.4.0"] = "helpdesk",
            ["1.3.6.1.2.1.1.5.0"] = "REC-PRN-01",
            ["1.3.6.1.2.1.1.6.0"] = "Reception",
            ["1.3.6.1.2.1.25.3.2.1.3.1"] = "HP LaserJet Pro M404dn",
            ["1.3.6.1.2.1.25.3.5.1.1.1"] = 3L,                                  // idle
            ["1.3.6.1.2.1.25.3.5.1.2.1"] = new byte[] { 0x24, 0x00 },           // lowToner + jammed
            ["1.3.6.1.2.1.43.5.1.1.17.1"] = "PHBXY12345",
            ["1.3.6.1.2.1.43.10.2.1.3.1.1"] = 8L,                               // sheets
            ["1.3.6.1.2.1.43.10.2.1.4.1.1"] = 123_456L,
            ["1.3.6.1.2.1.43.11.1.1.5.1.1"] = 3L,                               // toner
            ["1.3.6.1.2.1.43.11.1.1.5.1.2"] = 15L,                              // fuser
            ["1.3.6.1.2.1.43.11.1.1.6.1.1"] = "Black Toner Cartridge",
            ["1.3.6.1.2.1.43.11.1.1.6.1.2"] = "Fuser Kit",
            ["1.3.6.1.2.1.43.11.1.1.7.1.1"] = 19L,                              // percent
            ["1.3.6.1.2.1.43.11.1.1.7.1.2"] = 19L,
            ["1.3.6.1.2.1.43.11.1.1.8.1.1"] = 100L,
            ["1.3.6.1.2.1.43.11.1.1.8.1.2"] = 100L,
            ["1.3.6.1.2.1.43.11.1.1.9.1.1"] = 7L,
            ["1.3.6.1.2.1.43.11.1.1.9.1.2"] = -3L,                              // "some remaining": not empty
            ["1.3.6.1.2.1.43.18.1.1.2.1.1"] = 3L,                               // critical
            ["1.3.6.1.2.1.43.18.1.1.7.1.1"] = 8L,
            ["1.3.6.1.2.1.43.18.1.1.8.1.1"] = "Paper jam in tray 2",
        });
        _cleanup.Add(agent);
        return agent;
    }

    private static QuerySpec Snmp(string what, int port) => Q(("read", "snmp"), ("what", what), ("port", port));

    [Fact]
    public async Task Snmp_info_is_one_row_with_the_model_serial_state_and_the_printed_page_count()
    {
        var row = Assert.Single((await Run(new PrinterRunner(), Snmp("info", PrinterAgent().Port))).Rows);

        Assert.Equal("HP LaserJet Pro M404", row["sysDescr"]!.ToString());
        Assert.Equal(("REC-PRN-01", "Reception"), (row["sysName"]!.ToString(), row["sysLocation"]!.ToString()));
        Assert.Equal("HP LaserJet Pro M404dn", row["model"]!.ToString());
        Assert.Equal("PHBXY12345", row["serialNumber"]!.ToString());
        Assert.Equal(123456L, (long)row["pageCount"]!);
        Assert.Equal("sheets", row["pageCountUnit"]!.ToString());
        Assert.Equal(86400L, (long)row["uptimeSeconds"]!);
        Assert.Equal("idle", row["status"]!.ToString());
        Assert.Equal(["lowToner", "jammed"], row["errors"]!.AsArray().Select(n => n!.ToString()));
    }

    [Fact]
    public async Task Snmp_supplies_are_a_row_each_with_how_full_they_are()
    {
        var result = await Run(new PrinterRunner(), Snmp("supplies", PrinterAgent().Port));

        var toner = result.Rows.Single(r => r["description"]!.ToString() == "Black Toner Cartridge");
        Assert.Equal(("toner", 7L, 100L, 7), (toner["type"]!.ToString(), (long)toner["level"]!, (long)toner["max"]!, (int)toner["percent"]!));
        var fuser = result.Rows.Single(r => r["description"]!.ToString() == "Fuser Kit");
        Assert.Null(fuser["percent"]);                                    // -3 means some remaining, not a number
        Assert.False((bool)fuser["levelKnown"]!);
    }

    [Fact]
    public async Task A_supply_the_printer_itself_calls_unknown_has_no_usable_level_even_if_it_reports_zero()
    {
        // A real tank printer: every ink at level 0 of 100 over SNMP, described as "cyan ink unknown", while IPP says 100%.
        var agent = new FakeSnmpAgent("s3cret-community", new()
        {
            ["1.3.6.1.2.1.1.1.0"] = "HP ETHERNET MULTI-ENVIRONMENT",
            ["1.3.6.1.2.1.43.11.1.1.5.1.1"] = 5L,
            ["1.3.6.1.2.1.43.11.1.1.6.1.1"] = "cyan ink unknown",
            ["1.3.6.1.2.1.43.11.1.1.8.1.1"] = 100L,
            ["1.3.6.1.2.1.43.11.1.1.9.1.1"] = 0L,
        });
        _cleanup.Add(agent);

        var supply = Assert.Single((await Run(new PrinterRunner(), Snmp("supplies", agent.Port))).Rows);

        Assert.False((bool)supply["levelKnown"]!);
        Assert.Null(supply["percent"]);
        Assert.Equal(0L, (long)supply["level"]!);                          // what it said is still kept
    }

    [Fact]
    public async Task Snmp_alerts_are_a_row_each_with_their_severity()
    {
        var alert = Assert.Single((await Run(new PrinterRunner(), Snmp("alerts", PrinterAgent().Port))).Rows);

        Assert.Equal(("critical", "Paper jam in tray 2"), (alert["severity"]!.ToString(), alert["description"]!.ToString()));
    }

    [Fact]
    public async Task A_printer_that_does_not_answer_is_a_failed_read_that_names_the_likely_causes()
    {
        var result = await Run(new PrinterRunner(), Snmp("info", PrinterAgent(community: "another").Port));

        Assert.Equal("failed", result.State);
        Assert.Contains("community", result.Reason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_snmp_read_without_a_stored_community_says_what_is_missing_and_sends_nothing()
    {
        var agent = PrinterAgent();

        var result = await Run(new PrinterRunner(), Snmp("info", agent.Port), community: null);

        Assert.Equal("failed", result.State);
        Assert.Contains("community", result.Reason!, StringComparison.Ordinal);
        Assert.Empty(agent.PduTags);
    }

    [Fact]
    public async Task The_public_community_check_tries_only_public_and_only_to_read_one_value()
    {
        var open = PrinterAgent(community: "public");
        var shut = PrinterAgent();

        var yes = Assert.Single((await Run(new PrinterRunner(), Snmp("public-community", open.Port), community: null)).Rows);
        var no = Assert.Single((await Run(new PrinterRunner(), Snmp("public-community", shut.Port), community: null)).Rows);

        Assert.True((bool)yes["answersPublicCommunity"]!);
        Assert.Equal("HP LaserJet Pro M404", yes["sysDescr"]!.ToString());
        Assert.False((bool)no["answersPublicCommunity"]!);
        Assert.All(open.PduTags, tag => Assert.Equal(0xA0, tag));      // a GET, never a walk or a write
    }

    // ---------------------------------------------------------------- validation

    [Fact]
    public void Queries_are_checked_when_the_rule_is_loaded()
    {
        var runner = new PrinterRunner();

        Assert.Empty(runner.Validate(Q(("read", "ports"))));
        Assert.Empty(runner.Validate(Q(("read", "ipp"), ("scheme", "ipps"), ("path", "/ipp/print"))));
        Assert.Empty(runner.Validate(Q(("read", "snmp"), ("what", "supplies"))));
        Assert.NotEmpty(runner.Validate(Q()));
        Assert.NotEmpty(runner.Validate(Q(("read", "print"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "snmp"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "snmp"), ("what", "set"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "ipp"), ("scheme", "ftp"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "ipp"), ("path", "ipp/print"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "ipp"), ("path", "/../etc"))));
        Assert.NotEmpty(runner.Validate(Q(("read", "ports"), ("ports", new JsonArray(0)))));
        Assert.NotEmpty(runner.Validate(Q(("read", "ports"), ("ports", new JsonArray(70000)))));
    }

    [Fact]
    public void The_runner_reads_one_printer_at_a_time()
    {
        Assert.Equal("printer", new PrinterRunner().Protocol);
        Assert.True(new PrinterRunner().PerTarget);
    }
}
