using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Printer;

/// <summary>
/// printer: one network printer at a time, read-only. read: ports (which services answer - a TCP connect and hang up,
/// never a byte sent, because a raw print port prints whatever it receives), ipp (Get-Printer-Attributes: make and model,
/// firmware, supplies, whether TLS and sign-in are offered), snmp (the Printer-MIB: model, serial, status, the printed
/// page count, supplies, alerts; or whether the well-known "public" community answers). A printer is only ever talked to
/// when the integration's scope names it.
/// </summary>
public sealed partial class PrinterRunner(Func<IPEndPoint, TimeSpan, CancellationToken, Task<bool>>? connect = null) : IRunner
{
    private static readonly (int Port, string Name)[] Services =
    [
        (21, "ftp"), (23, "telnet"), (80, "http"), (443, "https"), (445, "smb"), (515, "lpd"), (631, "ipp"),
        (8080, "httpAlt"), (8443, "httpsAlt"), (9100, "jetdirect"),
    ];

    private static readonly string[] Reads = ["ports", "ipp", "snmp"];
    private static readonly string[] SnmpKinds = ["info", "supplies", "alerts", "public-community"];
    private const int MaxExtraPorts = 20;

    [GeneratedRegex(@"^/[A-Za-z0-9/_.\-]*$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PathShape();

    public string Protocol => "printer";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        var read = query.Text("read");
        if (read is null || !Reads.Contains(read))
        {
            yield return $"read must be one of: {string.Join(", ", Reads)}";
            yield break;
        }
        if (Field(query, "port") is { } port && (!int.TryParse(port, out var n) || n is < 1 or > 65535))
            yield return "port must be a number from 1 to 65535";
        if (read == "ports")
        {
            var extra = query.List("ports");
            if (extra.Count > MaxExtraPorts || extra.Any(p => !int.TryParse(p, out var n) || n is < 1 or > 65535))
                yield return $"ports is a list of at most {MaxExtraPorts} numbers from 1 to 65535";
        }
        if (read == "ipp")
        {
            if ((query.Text("scheme") ?? "ipp") is not ("ipp" or "ipps"))
                yield return "scheme must be ipp or ipps";
            if (query.Text("path") is { } path && (!PathShape().IsMatch(path) || path.Contains("..", StringComparison.Ordinal)))
                yield return "path must start with / and hold only letters, digits and / _ . -";
        }
        if (read == "snmp" && !SnmpKinds.Contains(query.Text("what") ?? ""))
            yield return $"snmp needs what: {string.Join(", ", SnmpKinds)}";
    }

    /// <summary>A numeric or text field of the query as text (rule files give numbers typed, the command line as text).</summary>
    private static string? Field(QuerySpec query, string name) =>
        query.Fields[name] is JsonValue v ? v.TryGetValue<int>(out var n) ? n.ToString(System.Globalization.CultureInfo.InvariantCulture) : v.TryGetValue<string>(out var s) ? s : null : null;

    private static int Number(QuerySpec query, string name, int otherwise) =>
        Field(query, name) is { } text && int.TryParse(text, out var n) ? n : otherwise;

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (context.Target is not { Length: > 0 } target)
            return RunnerResult.Failed("a printer read looks at one printer: set the integration's targets option");
        if (!SshScope.Allows(target, context.Connection.Endpoint))
            return RunnerResult.Failed($"{target} is outside this integration's scope ({context.Connection.Endpoint}); nothing was sent");
        var address = await Resolve(target, cancellationToken).ConfigureAwait(false);
        if (address is null)
            return RunnerResult.Failed($"{target} could not be resolved to an address");

        try
        {
            return query.Text("read") switch
            {
                "ports" => await Ports(query, context, target, address, cancellationToken).ConfigureAwait(false),
                "ipp" => await ReadIpp(query, context, target, address, cancellationToken).ConfigureAwait(false),
                "snmp" => await ReadSnmp(query, context, target, address, cancellationToken).ConfigureAwait(false),
                _ => RunnerResult.Failed("printer: unknown read"),
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or SocketException or IOException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return RunnerResult.Failed($"{target} could not be read: {ex.Message}");
        }
    }

    private static async Task<IPAddress?> Resolve(string target, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(target, out var literal))
            return literal;
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(target, cancellationToken).ConfigureAwait(false);
            return addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
        }
        catch (SocketException)
        {
            return null;
        }
    }

    private static JsonObject Base(string target, IPAddress address) => new() { ["host"] = target, ["address"] = address.ToString() };

    private static TimeSpan Short(RunnerContext context, int seconds) => TimeSpan.FromSeconds(Math.Min(context.Timeout.TotalSeconds, seconds));

    // ---------------------------------------------------------------- ports

    private async Task<RunnerResult> Ports(QuerySpec query, RunnerContext context, string target, IPAddress address, CancellationToken cancellationToken)
    {
        var extra = query.List("ports").Select(int.Parse).Where(p => Services.All(s => s.Port != p)).Distinct().ToList();
        var wanted = Services.Select(s => s.Port).Concat(extra).ToList();
        var timeout = Short(context, 3);
        var open = await Task.WhenAll(wanted.Select(port => (connect ?? TcpConnect)(new IPEndPoint(address, port), timeout, cancellationToken))).ConfigureAwait(false);

        var row = Base(target, address);
        foreach (var (port, name) in Services)
            row[name] = open[wanted.IndexOf(port)];
        foreach (var port in extra)
            row[$"port{port}"] = open[wanted.IndexOf(port)];
        row["openPorts"] = new JsonArray(wanted.Where((_, i) => open[i]).Order().Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
        return RunnerResult.Ok([row]);
    }

    /// <summary>Connects and hangs up. Nothing is written: a raw print port would print it.</summary>
    private static async Task<bool> TcpConnect(IPEndPoint endpoint, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(endpoint.AddressFamily);
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        try
        {
            await client.ConnectAsync(endpoint, limit.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    // ---------------------------------------------------------------- IPP

    private static async Task<RunnerResult> ReadIpp(QuerySpec query, RunnerContext context, string target, IPAddress address, CancellationToken cancellationToken)
    {
        var scheme = query.Text("scheme") ?? "ipp";
        var port = Number(query, "port", 631);
        var path = query.Text("path") ?? "/ipp/print";
        var host = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
        var url = $"{(scheme == "ipps" ? "https" : "http")}://{host}:{port}{path}";

        // The request asks a printer about itself and carries no credential and no document, so a certificate the
        // machine does not trust (the usual self-signed one) costs nothing to accept: it is recorded instead.
        X509Certificate2? presented = null;
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectTimeout = Short(context, 5),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    presented = certificate is null ? null : new X509Certificate2(certificate);
                    return true;
                },
            },
        };
        using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Short(context, 10) };
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(Ipp.GetPrinterAttributesRequest($"{scheme}://{target}:{port}{path}")) };
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ipp");

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return RunnerResult.Failed($"{target} answered HTTP {(int)response.StatusCode} to the IPP request");
        if (response.Content.Headers.ContentType?.MediaType != "application/ipp")
            return RunnerResult.Failed($"{target} did not answer in IPP ({response.Content.Headers.ContentType?.MediaType ?? "no content type"}): it may not be a printer, or IPP is off");

        var body = await ReadCapped(response.Content, cancellationToken).ConfigureAwait(false);
        Ipp.Response parsed;
        try
        {
            parsed = Ipp.Parse(body);
        }
        catch (FormatException ex)
        {
            return RunnerResult.Failed($"{target}'s answer was not valid IPP: {ex.Message}");
        }
        if (!parsed.Successful)
            return RunnerResult.Failed($"{target} refused the request (IPP status 0x{parsed.StatusCode:X4})");

        var row = Base(target, address);
        foreach (var (name, value) in parsed.Attributes)
            row[name] = value?.DeepClone();
        row["tls"] = scheme == "ipps";
        if (presented is not null)
        {
            row["tlsSubject"] = presented.Subject;
            row["tlsIssuer"] = presented.Issuer;
            row["tlsNotBefore"] = RowValues.Iso(presented.NotBefore);
            row["tlsNotAfter"] = RowValues.Iso(presented.NotAfter);
            row["tlsDaysLeft"] = (int)Math.Floor((presented.NotAfter.ToUniversalTime() - context.Now).TotalDays);
            row["tlsSelfSigned"] = presented.Subject == presented.Issuer;
        }
        presented?.Dispose();
        return RunnerResult.Ok([row]);
    }

    private static async Task<byte[]> ReadCapped(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > Ipp.MaxBytes)
                break;
        }
        return buffer.ToArray();
    }

    // ---------------------------------------------------------------- SNMP

    private const string SysGroup = "1.3.6.1.2.1.1";
    private const string Marker = "1.3.6.1.2.1.43.10.2.1";
    private const string Supplies = "1.3.6.1.2.1.43.11.1.1";
    private const string Alerts = "1.3.6.1.2.1.43.18.1.1";

    private static readonly Dictionary<long, string> PageUnits = new()
    {
        [3] = "tenThousandthsOfInches", [4] = "micrometers", [5] = "characters", [6] = "lines", [7] = "impressions", [8] = "sheets",
        [9] = "dotRows", [11] = "hours", [12] = "feet", [13] = "meters",
    };

    private static readonly Dictionary<long, string> SupplyTypes = new()
    {
        [3] = "toner", [4] = "wasteToner", [5] = "ink", [6] = "inkCartridge", [7] = "inkRibbon", [8] = "wasteInk", [9] = "opc",
        [10] = "developer", [11] = "fuserOil", [12] = "solidWax", [13] = "ribbonWax", [14] = "wasteWax", [15] = "fuser", [16] = "coronaWire",
        [17] = "fuserOilWick", [18] = "cleanerUnit", [19] = "fuserCleaningPad", [20] = "transferUnit", [21] = "tonerCartridge", [22] = "fuserOiler",
    };

    private static readonly string[] ErrorBits0 = ["serviceRequested", "offline", "jammed", "doorOpen", "noToner", "lowToner", "noPaper", "lowPaper"];
    private static readonly string[] ErrorBits1 = ["overduePreventMaintenance", "inputTrayEmpty", "outputFull", "outputNearFull", "markerSupplyMissing", "outputTrayMissing", "inputTrayMissing"];

    private static async Task<RunnerResult> ReadSnmp(QuerySpec query, RunnerContext context, string target, IPAddress address, CancellationToken cancellationToken)
    {
        var what = query.Text("what")!;
        var endpoint = new IPEndPoint(address, Number(query, "port", 161));
        var timeout = Short(context, 3);

        if (what == "public-community")
        {
            // The one community every audit tries, asked for one value. No walk, nothing else.
            var answer = await SnmpV2c.GetAsync(endpoint, "public", $"{SysGroup}.1.0", timeout, cancellationToken).ConfigureAwait(false);
            var check = Base(target, address);
            check["answersPublicCommunity"] = answer is not null;
            if (answer is { } found)
                check["sysDescr"] = SnmpV2c.AsText(found.Value);
            return RunnerResult.Ok([check]);
        }

        if (context.Connection.Secret("community") is not { Length: > 0 } community)
            return RunnerResult.Failed("the integration has no SNMP community: set it with 'keeper integration set-secret <id> community'");
        var problems = new List<string>();

        async Task<IReadOnlyList<(string Oid, object? Value)>> Walk(string prefix)
        {
            var walk = await SnmpV2c.WalkAsync(endpoint, community, prefix, 256, timeout, cancellationToken).ConfigureAwait(false);
            if (!walk.Complete && walk.Problem is { } problem)
                problems.Add(problem);
            return walk.Rows;
        }

        // The device must at least answer for its own description, or nothing below can be believed.
        var description = await Walk($"{SysGroup}.1").ConfigureAwait(false);
        if (description.Count == 0)
            return RunnerResult.Failed($"{target} did not answer SNMP: {(problems.Count > 0 ? problems[0] : "no value for sysDescr")}");

        List<JsonObject> rows = what switch
        {
            "supplies" => await SupplyRows(target, address, Walk).ConfigureAwait(false),
            "alerts" => await AlertRows(target, address, Walk).ConfigureAwait(false),
            _ => [await InfoRow(target, address, description, Walk).ConfigureAwait(false)],
        };
        return problems.Count == 0 ? RunnerResult.Ok(rows) : RunnerResult.Partial(rows, string.Join("; ", problems.Distinct()));
    }

    private static object? First(IReadOnlyList<(string Oid, object? Value)> rows) => rows.Count > 0 ? rows[0].Value : null;

    private static string? Text(object? value) => value is null ? null : SnmpV2c.AsText(value);

    private static async Task<JsonObject> InfoRow(string target, IPAddress address, IReadOnlyList<(string Oid, object? Value)> system, Func<string, Task<IReadOnlyList<(string Oid, object? Value)>>> walk)
    {
        var row = Base(target, address);
        row["sysDescr"] = Text(First(system));
        row["sysName"] = Text(First(await walk($"{SysGroup}.5").ConfigureAwait(false)));
        row["sysLocation"] = Text(First(await walk($"{SysGroup}.6").ConfigureAwait(false)));
        row["sysContact"] = Text(First(await walk($"{SysGroup}.4").ConfigureAwait(false)));
        if (First(await walk($"{SysGroup}.3").ConfigureAwait(false)) is long ticks)
            row["uptimeSeconds"] = ticks / 100;
        row["model"] = Text(First(await walk("1.3.6.1.2.1.25.3.2.1.3").ConfigureAwait(false)));
        row["serialNumber"] = Text(First(await walk("1.3.6.1.2.1.43.5.1.1.17").ConfigureAwait(false)));
        if (First(await walk("1.3.6.1.2.1.25.3.5.1.1").ConfigureAwait(false)) is long status)
            row["status"] = status switch { 3 => "idle", 4 => "printing", 5 => "warmup", 1 => "other", _ => "unknown" };
        row["errors"] = new JsonArray(ErrorNames(First(await walk("1.3.6.1.2.1.25.3.5.1.2").ConfigureAwait(false))).Select(e => (JsonNode?)JsonValue.Create(e)).ToArray());
        if (First(await walk($"{Marker}.4").ConfigureAwait(false)) is long pages)
            row["pageCount"] = pages;
        if (First(await walk($"{Marker}.3").ConfigureAwait(false)) is long unit)
            row["pageCountUnit"] = PageUnits.GetValueOrDefault(unit, unit.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return row;
    }

    /// <summary>hrPrinterDetectedErrorState: two bytes of flags, named most significant bit first as RFC 2790 lists them.</summary>
    private static IEnumerable<string> ErrorNames(object? value)
    {
        if (value is not byte[] { Length: > 0 } bytes)
            yield break;
        for (var bit = 7; bit >= 0; bit--)
        {
            if ((bytes[0] & (1 << bit)) != 0)
                yield return ErrorBits0[bit];
        }
        if (bytes.Length > 1)
        {
            for (var bit = 7; bit >= 1; bit--)
            {
                if ((bytes[1] & (1 << bit)) != 0)
                    yield return ErrorBits1[bit - 1];
            }
        }
    }

    private static async Task<List<JsonObject>> SupplyRows(string target, IPAddress address, Func<string, Task<IReadOnlyList<(string Oid, object? Value)>>> walk)
    {
        async Task<Dictionary<string, object?>> Column(int number)
        {
            var prefix = $"{Supplies}.{number}";
            return (await walk(prefix).ConfigureAwait(false)).ToDictionary(r => r.Oid[(prefix.Length + 1)..], r => r.Value, StringComparer.Ordinal);
        }
        var descriptions = await Column(6).ConfigureAwait(false);
        var types = await Column(5).ConfigureAwait(false);
        var capacity = await Column(8).ConfigureAwait(false);
        var levels = await Column(9).ConfigureAwait(false);

        var rows = new List<JsonObject>();
        foreach (var (index, description) in descriptions)
        {
            var row = Base(target, address);
            row["description"] = Text(description);
            row["type"] = types.GetValueOrDefault(index) is long t ? SupplyTypes.GetValueOrDefault(t, t.ToString(System.Globalization.CultureInfo.InvariantCulture)) : "unknown";
            var level = levels.GetValueOrDefault(index) as long?;
            var max = capacity.GetValueOrDefault(index) as long?;
            row["level"] = level;
            row["max"] = max;
            // -1, -2 and -3 are "other", "unknown" and "some remaining": not amounts. A supply the printer itself calls
            // "unknown" reports nothing real either (some tank printers answer 0 for every ink): its level is not used.
            var known = level is >= 0 && !(Text(description)?.Contains("unknown", StringComparison.OrdinalIgnoreCase) ?? false);
            row["levelKnown"] = known;
            row["percent"] = known && max is > 0 ? (int)Math.Round(level!.Value * 100.0 / max.Value) : null;
            rows.Add(row);
        }
        return rows;
    }

    private static async Task<List<JsonObject>> AlertRows(string target, IPAddress address, Func<string, Task<IReadOnlyList<(string Oid, object? Value)>>> walk)
    {
        async Task<Dictionary<string, object?>> Column(int number)
        {
            var prefix = $"{Alerts}.{number}";
            return (await walk(prefix).ConfigureAwait(false)).ToDictionary(r => r.Oid[(prefix.Length + 1)..], r => r.Value, StringComparer.Ordinal);
        }
        var severities = await Column(2).ConfigureAwait(false);
        var codes = await Column(7).ConfigureAwait(false);
        var descriptions = await Column(8).ConfigureAwait(false);

        return [.. severities.Select(s =>
        {
            var row = Base(target, address);
            row["severity"] = s.Value is long level ? level switch { 3 => "critical", 4 => "warning", 1 => "other", _ => level.ToString(System.Globalization.CultureInfo.InvariantCulture) } : "unknown";
            row["code"] = codes.GetValueOrDefault(s.Key) as long?;
            row["description"] = Text(descriptions.GetValueOrDefault(s.Key));
            return row;
        })];
    }
}
