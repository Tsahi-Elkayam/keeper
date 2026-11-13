using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;
using Keeper.Runners.Host;
using Keeper.Runners.Printer;

namespace Keeper.Scan.Tests;

public sealed class PrinterPackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-printers-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Could not find Keeper.slnx");
    }

    private sealed class Estate : IConnection
    {
        public Estate(string type, string authKind, string[] protocols, JsonObject? options = null)
        {
            Type = type;
            AuthKind = authKind;
            Protocols = protocols;
            Options = options ?? [];
        }

        public string Instance => "estate";
        public string Type { get; }
        public string Endpoint => "10.0.0.0/24";
        public string AuthKind { get; }
        public string? Identity => null;
        public IReadOnlyList<string>? Protocols { get; }
        public JsonObject Options { get; }
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>Stands in for the printers on the network: answers each read with rows shaped like the real runner's.</summary>
    private sealed class FakePrinters : IRunner
    {
        public string Protocol => "printer";
        public bool PerTarget => true;
        public IEnumerable<string> Validate(QuerySpec query) => [];

        private static JsonObject Row(string host, object? more = null)
        {
            var row = new JsonObject { ["host"] = host, ["address"] = host };
            foreach (var (name, value) in JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(more ?? new { }))!.AsObject())
                row[name] = value?.DeepClone();
            return row;
        }

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            var host = context.Target!;
            var first = host == "10.0.0.1";
            var read = query.Text("read");
            if (read == "ports")
                return Ok(Row(host, first
                    ? new { ftp = false, telnet = true, http = true, https = false, lpd = true, ipp = true, jetdirect = true }
                    : new { ftp = false, telnet = false, http = true, https = true, lpd = false, ipp = true, jetdirect = false }));
            if (read == "ipp" && query.Text("scheme") == "ipps")
                return first ? Task.FromResult(RunnerResult.Failed("no ipps")) : Ok(Row(host, new { tls = true, tlsDaysLeft = 10, tlsSelfSigned = true }));
            if (read == "ipp")
                return Ok(first
                    ? Row(host, new Dictionary<string, object> { ["uri-security-supported"] = "none", ["printer-is-accepting-jobs"] = false })
                    : Row(host, new Dictionary<string, object> { ["uri-security-supported"] = new[] { "none", "tls" }, ["printer-is-accepting-jobs"] = true }));
            return query.Text("what") switch
            {
                "public-community" => Ok(Row(host, new { answersPublicCommunity = first })),
                "info" => Ok(Row(host, new { sysName = "prn", errors = first ? new[] { "jammed", "lowToner" } : Array.Empty<string>(), pageCount = first ? 123456 : 99, pageCountUnit = "sheets" })),
                "supplies" => first
                    ? Rows(Row(host, new { description = "Black Toner", type = "toner", level = 5, max = 100, percent = 5, levelKnown = true }),
                           Row(host, new { description = "Fuser Kit", type = "fuser", level = -3, max = 100, percent = (int?)null, levelKnown = false }),
                           Row(host, new { description = "Waste Toner", type = "wasteToner", level = 95, max = 100, percent = 95, levelKnown = true }))
                    : Rows(Row(host, new { description = "Black Toner", type = "toner", level = 80, max = 100, percent = 80, levelKnown = true }),
                           Row(host, new { description = "Waste Toner", type = "wasteToner", level = 2, max = 100, percent = 2, levelKnown = true })),   // nearly empty waste tank: good news, not a low supply
                "alerts" => first
                    ? Rows(Row(host, new { severity = "critical", code = 8, description = "Paper jam" }), Row(host, new { severity = "warning", code = 3, description = "Low toner" }))
                    : Rows(),
                _ => Task.FromResult(RunnerResult.Failed("unexpected read")),
            };
        }

        private static Task<RunnerResult> Ok(JsonObject row) => Task.FromResult(RunnerResult.Ok([row]));

        private static Task<RunnerResult> Rows(params JsonObject[] rows) => Task.FromResult(RunnerResult.Ok(rows));
    }

    private async Task<List<FindingRecord>> Scan(string pack, IRunner runner, IConnection connection)
    {
        var registry = new RunnerRegistry([runner]);
        var file = RuleLoader.LoadFile(Path.Combine(FindRepoRoot(), "rules", pack), "builtin", registry.Validators);
        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [file],
            Connection = connection,
            RunsDir = Path.Combine(_dir, "runs"),
            ImportsDir = Path.Combine(_dir, "imports"),
        }, CancellationToken.None);
        var path = Path.Combine(_dir, "runs", report.Manifest.RunId, RunFolder.Findings);
        return File.Exists(path) ? JsonLines.Read<FindingRecord>(path).ToList() : [];
    }

    private static string[] Flagged(List<FindingRecord> findings, string rule) =>
        [.. findings.Where(f => f.RuleId == rule).Select(f => f.Target ?? "").Order(StringComparer.Ordinal)];

    [Fact]
    public async Task Every_network_printer_rule_flags_the_printer_that_breaks_it_and_not_the_good_one()
    {
        var targets = new JsonObject { ["targets"] = new JsonArray("10.0.0.1", "10.0.0.2") };
        var findings = await Scan("printers.yaml", new FakePrinters(), new Estate("printer", "snmp-v2c", ["printer"], targets));

        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-TELNET-OPEN"));
        Assert.Empty(Flagged(findings, "PRN-FTP-OPEN"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-LPD-OPEN"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-RAW-PRINTING-OPEN"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-WEB-ADMIN-NOT-ENCRYPTED"));        // http and https both on is fine
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-SNMP-PUBLIC-COMMUNITY"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-IPP-NO-TLS"));
        Assert.Equal(["10.0.0.2"], Flagged(findings, "PRN-CERT-EXPIRING"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-NOT-ACCEPTING-JOBS"));
        Assert.Equal(["10.0.0.1"], Flagged(findings, "PRN-ERROR-STATE"));                    // lowToner alone would not be a fault
        Assert.Equal(["10.0.0.1|Paper jam"], Flagged(findings, "PRN-ALERT-CRITICAL"));      // a warning is not critical
        Assert.Equal(["10.0.0.1|Black Toner"], Flagged(findings, "PRN-SUPPLY-LOW"));        // not the fuser (amount unknown), not the waste tank
        Assert.Equal(["10.0.0.1|Waste Toner"], Flagged(findings, "PRN-WASTE-CONTAINER-FULL"));
    }

    [Fact]
    public async Task A_printer_that_cannot_be_read_is_unknown_for_that_rule_never_a_pass_or_a_finding()
    {
        var targets = new JsonObject { ["targets"] = new JsonArray("10.0.0.1", "10.0.0.2") };
        var findings = await Scan("printers.yaml", new FakePrinters(), new Estate("printer", "snmp-v2c", ["printer"], targets));

        Assert.DoesNotContain(findings, f => f.RuleId == "PRN-CERT-EXPIRING" && f.Target == "10.0.0.1");   // 10.0.0.1 has no ipps
    }

    // ---------------------------------------------------------------- printers on a computer

    private sealed class Computer(string? pageLog = null) : IHostSession
    {
        public string HostName => "front-desk";
        public string Normalize(string path) => path;
        public string ResolveInclude(string fromFile, string pattern) => pattern;
        public bool FileExists(string path) => pageLog is not null && path == "/var/log/cups/page_log";
        public string? ReadProblem(string path) => null;
        public string ReadAllText(string path) => pageLog ?? throw new FileNotFoundException(path);
        public HostStat Stat(string path) => new(false, false, false, 0, default, null);
        public IReadOnlyList<string> Glob(string folder, string pattern) => [];
        public JsonObject Facts() => [];
        public void Dispose() { }

        private static HostCommands.Output Lines(string text) =>
            new(true, 0, [.. text.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Trim().Length > 0)], false, false);

        public Task<HostCommands.Output> RunAsync(string name, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(name switch
            {
                "lpstat-devices" => Lines("""
                    device for Reception_Laser: usb://HP/LaserJet%20Pro%20M404?serial=PHBXY12345
                    device for Warehouse_Label: socket://192.0.2.50:9100
                    device for Finance_Shared: smb://svc-print:Hunter2Pass@fileserver.example.org/Finance
                    device for Old_Lpd: lpd://192.0.2.60/queue
                    device for To_File: file:///tmp/out.ps
                    device for Cloud_Ipp: ipps://print.example.org:631/ipp/print
                    """),
                "lpstat-printers" => Lines("""
                    printer Reception_Laser is idle.  enabled since Sat 24 Oct 2026 09:00:00
                    printer Warehouse_Label disabled since Sat 24 Oct 2026 08:00:00 -
                    printer Finance_Shared is idle.  enabled since Sat 24 Oct 2026 07:00:00
                    printer Old_Lpd is idle.  enabled since Sat 24 Oct 2026 07:00:00
                    printer To_File is idle.  enabled since Sat 24 Oct 2026 07:00:00
                    printer Cloud_Ipp is idle.  enabled since Sat 24 Oct 2026 07:00:00
                    """),
                "lpstat-accepting" => Lines("""
                    Reception_Laser accepting requests since Sat 24 Oct 2026 09:00:00
                    Warehouse_Label not accepting requests since Sat 24 Oct 2026 08:00:00 -
                    Finance_Shared accepting requests since Sat 24 Oct 2026 07:00:00
                    Old_Lpd accepting requests since Sat 24 Oct 2026 07:00:00
                    To_File accepting requests since Sat 24 Oct 2026 07:00:00
                    Cloud_Ipp accepting requests since Sat 24 Oct 2026 07:00:00
                    """),
                "cupsctl" => Lines("_debug_logging=1\n_remote_admin=1\n_remote_any=1\n_share_printers=1\n_user_cancel_any=0"),
                _ => throw new InvalidOperationException(name),
            });
    }

    [Fact]
    public async Task Every_local_printer_rule_flags_the_queue_or_setting_that_breaks_it()
    {
        var targets = new JsonObject { ["targets"] = new JsonArray("front-desk") };
        var findings = await Scan("printers-local.yaml", new HostRunner(_ => new Computer()), new Estate("ssh", "ssh-key", ["host"], targets));

        Assert.Equal(["front-desk"], Flagged(findings, "PRN-LOCAL-REMOTE-ANY"));
        Assert.Equal(["front-desk"], Flagged(findings, "PRN-LOCAL-REMOTE-ADMIN"));
        Assert.Equal(["front-desk"], Flagged(findings, "PRN-LOCAL-SHARING-ON"));
        Assert.Equal(["front-desk"], Flagged(findings, "PRN-LOCAL-DEBUG-LOGGING"));
        Assert.Equal(["front-desk|To_File"], Flagged(findings, "PRN-QUEUE-FILE-DEVICE"));
        Assert.Equal(["front-desk|Finance_Shared"], Flagged(findings, "PRN-QUEUE-PASSWORD-IN-ADDRESS"));
        Assert.Equal(["front-desk|Old_Lpd", "front-desk|Warehouse_Label"], Flagged(findings, "PRN-QUEUE-LEGACY-PROTOCOL"));
        Assert.Equal(["front-desk|Warehouse_Label"], Flagged(findings, "PRN-QUEUE-STOPPED"));
        Assert.Equal(["front-desk|Reception_Laser"], Flagged(findings, "PRN-USB-ATTACHED"));
        Assert.DoesNotContain("Hunter2Pass", string.Join("\n", findings.Select(f => f.Evidence)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_queue_that_has_not_printed_for_months_is_listed_and_one_that_printed_lately_is_not()
    {
        var old = DateTimeOffset.UtcNow.AddDays(-400).ToString("dd/MMM/yyyy:HH:mm:ss +0000", System.Globalization.CultureInfo.InvariantCulture);
        var now = DateTimeOffset.UtcNow.AddDays(-3).ToString("dd/MMM/yyyy:HH:mm:ss +0000", System.Globalization.CultureInfo.InvariantCulture);
        var log = $"Old_Lpd alice 1 [{old}] 1 5 - 192.0.2.7 Report old one-sided\nReception_Laser bob 2 [{now}] 1 1 - 192.0.2.7 Memo a4 one-sided\n";
        var targets = new JsonObject { ["targets"] = new JsonArray("front-desk") };

        var findings = await Scan("printers-local.yaml", new HostRunner(_ => new Computer(log)), new Estate("ssh", "ssh-key", ["host"], targets));

        var unused = Assert.Single(findings, f => f.RuleId == "PRN-QUEUE-UNUSED");
        Assert.Equal("front-desk|Old_Lpd", unused.Target);
        Assert.Contains("5 pages", unused.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", unused.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("Report old", unused.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_usb_inventory_finding_names_the_vendor_model_and_serial()
    {
        var targets = new JsonObject { ["targets"] = new JsonArray("front-desk") };
        var findings = await Scan("printers-local.yaml", new HostRunner(_ => new Computer()), new Estate("ssh", "ssh-key", ["host"], targets));

        var usb = Assert.Single(findings, f => f.RuleId == "PRN-USB-ATTACHED");
        Assert.Contains("HP", usb.Evidence, StringComparison.Ordinal);
        Assert.Contains("LaserJet Pro M404", usb.Evidence, StringComparison.Ordinal);
        Assert.Contains("PHBXY12345", usb.Evidence, StringComparison.Ordinal);
    }
}
