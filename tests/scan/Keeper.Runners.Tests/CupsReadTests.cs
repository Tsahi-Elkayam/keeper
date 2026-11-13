using System.Text.Json.Nodes;
using Keeper.Rules;
using Keeper.Runners.Host;

namespace Keeper.Runners.Tests;

public sealed class CupsReadTests
{
    private const string Devices = """
        device for Office_Inkjet__AB12CD_: dnssd://Office%20Inkjet%20Pro%20%5BAB12CD%5D._ipps._tcp.local./?uuid=0a1b2c3d
        device for Reception_Laser: usb://HP/LaserJet%20Pro%20M404?serial=PHBXY12345
        device for Warehouse_Label: socket://192.0.2.50:9100
        device for Finance_Shared: smb://svc-print:Hunter2Pass@fileserver.example.org/Finance
        device for Old_Lpd: lpd://192.0.2.60/queue
        device for To_File: file:///tmp/out.ps
        device for Cloud_Ipp: ipps://print.example.org:631/ipp/print
        """;

    private const string Printers = """
        printer Office_Inkjet__AB12CD_ is idle.  enabled since Fri 16 Oct 2026 19:18:00
        printer Reception_Laser now printing Reception_Laser-17.  enabled since Sat 24 Oct 2026 09:00:00
        printer Warehouse_Label disabled since Sat 24 Oct 2026 08:00:00 -
        	Paused
        printer Finance_Shared is idle.  enabled since Sat 24 Oct 2026 07:00:00
        printer Old_Lpd is idle.  enabled since Sat 24 Oct 2026 07:00:00
        printer To_File is idle.  enabled since Sat 24 Oct 2026 07:00:00
        printer Cloud_Ipp is idle.  enabled since Sat 24 Oct 2026 07:00:00
        """;

    private const string Accepting = """
        Office_Inkjet__AB12CD_ accepting requests since Fri 16 Oct 2026 19:18:00
        Reception_Laser accepting requests since Sat 24 Oct 2026 09:00:00
        Warehouse_Label not accepting requests since Sat 24 Oct 2026 08:00:00 -
        	Rejecting Jobs
        Finance_Shared accepting requests since Sat 24 Oct 2026 07:00:00
        Old_Lpd accepting requests since Sat 24 Oct 2026 07:00:00
        To_File accepting requests since Sat 24 Oct 2026 07:00:00
        Cloud_Ipp accepting requests since Sat 24 Oct 2026 07:00:00
        """;

    private static HostCommands.Output Lines(string text) => new(true, 0, text.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Trim().Length > 0).ToList(), false, false);

    private static FakeSession Host(Func<string, HostCommands.Output>? only = null) => new("print01", [], script: (name, _) => only is not null
        ? only(name)
        : name switch
        {
            "lpstat-devices" => Lines(Devices),
            "lpstat-printers" => Lines(Printers),
            "lpstat-accepting" => Lines(Accepting),
            "cupsctl" => Lines("_debug_logging=0\n_remote_admin=1\n_remote_any=0\n_share_printers=1\n_user_cancel_any=0\nBrowseLocalProtocols=dnssd\nDefaultAuthType=Basic"),
            _ => throw new InvalidOperationException(name),
        });

    private static QuerySpec Q(string what, params (string Name, JsonNode? Value)[] more) =>
        Context.Query("host", "name", [("read", "cups"), ("what", what), .. more]);

    private static Task<RunnerResult> Run(IHostSession session, QuerySpec query) =>
        new HostRunner(_ => session).RunAsync(query, Context.For(new SshFakeConnection(), "print01"), CancellationToken.None);

    private static JsonObject Printer(RunnerResult result, string name) => result.Rows.Single(r => r["name"]!.ToString() == name);

    [Fact]
    public async Task Each_queue_is_a_row_with_where_it_prints_how_it_is_attached_and_its_state()
    {
        var result = await Run(Host(), Q("printers"));

        Assert.Equal("ok", result.State);
        Assert.Equal(7, result.Rows.Count);
        Assert.All(result.Rows, r => Assert.Equal("print01", r["host"]!.ToString()));
        var usb = Printer(result, "Reception_Laser");
        Assert.Equal(("usb", true, false), (usb["scheme"]!.ToString(), (bool)usb["usb"]!, (bool)usb["network"]!));
        Assert.Equal(("HP", "LaserJet Pro M404", "PHBXY12345"), (usb["vendor"]!.ToString(), usb["model"]!.ToString(), usb["serial"]!.ToString()));
        Assert.Equal("printing", usb["state"]!.ToString());
        var airprint = Printer(result, "Office_Inkjet__AB12CD_");
        Assert.Equal(("dnssd", true, "idle"), (airprint["scheme"]!.ToString(), (bool)airprint["network"]!, airprint["state"]!.ToString()));
    }

    [Fact]
    public async Task A_disabled_queue_and_one_not_accepting_jobs_are_marked()
    {
        var label = Printer(await Run(Host(), Q("printers")), "Warehouse_Label");

        Assert.False((bool)label["enabled"]!);
        Assert.False((bool)label["accepting"]!);
        Assert.Equal("disabled", label["state"]!.ToString());
        Assert.True((bool)Printer(await Run(Host(), Q("printers")), "Reception_Laser")["accepting"]!);
    }

    [Fact]
    public async Task The_kind_of_connection_is_named_so_a_rule_can_ask_about_it()
    {
        var result = await Run(Host(), Q("printers"));

        Assert.Equal("socket", Printer(result, "Warehouse_Label")["scheme"]!.ToString());
        Assert.Equal("lpd", Printer(result, "Old_Lpd")["scheme"]!.ToString());
        Assert.Equal("file", Printer(result, "To_File")["scheme"]!.ToString());
        Assert.Equal("ipps", Printer(result, "Cloud_Ipp")["scheme"]!.ToString());
        Assert.Equal("192.0.2.50", Printer(result, "Warehouse_Label")["address"]!.ToString());
        Assert.Equal(9100, (int)Printer(result, "Warehouse_Label")["port"]!);
    }

    [Fact]
    public async Task A_password_in_a_device_address_never_reaches_a_row()
    {
        var result = await Run(Host(), Q("printers"));

        var finance = Printer(result, "Finance_Shared");
        Assert.Equal("smb", finance["scheme"]!.ToString());
        Assert.DoesNotContain("Hunter2Pass", result.Rows.Select(r => r.ToJsonString()).Aggregate((a, b) => a + b), StringComparison.Ordinal);
        Assert.Contains("svc-print:set@", finance["deviceUri"]!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cups_settings_are_one_row_of_named_values_with_the_sharing_ones_as_true_or_false()
    {
        var row = Assert.Single((await Run(Host(), Q("settings"))).Rows);

        Assert.True((bool)row["sharePrinters"]!);
        Assert.True((bool)row["remoteAdmin"]!);
        Assert.False((bool)row["remoteAny"]!);
        Assert.False((bool)row["debugLogging"]!);
        Assert.Equal("dnssd", row["BrowseLocalProtocols"]!.ToString());
        Assert.Equal("print01", row["host"]!.ToString());
    }

    [Fact]
    public async Task A_machine_without_cups_is_a_failed_read_unless_the_rule_says_it_may_be_absent()
    {
        var none = Host(_ => new HostCommands.Output(false, 127, [], false, false));

        Assert.Equal("failed", (await Run(none, Q("printers"))).State);
        var optional = await Run(none, Q("printers", ("optional", true)));
        Assert.Equal("ok", optional.State);
        Assert.Empty(optional.Rows);
    }

    [Fact]
    public async Task A_machine_with_cups_and_no_printers_has_no_rows_and_that_is_an_answer()
    {
        var empty = Host(name => name == "lpstat-devices"
            ? new HostCommands.Output(true, 0, [], false, false)
            : Lines(""));

        var result = await Run(empty, Q("printers"));

        Assert.Equal("ok", result.State);
        Assert.Empty(result.Rows);
    }

    [Fact]
    public void The_cups_commands_take_no_parameters_and_the_read_names_what_it_wants()
    {
        foreach (var name in new[] { "lpstat-devices", "lpstat-printers", "lpstat-accepting", "cupsctl" })
        {
            Assert.Null(HostCommands.Problem(name, []));
            Assert.NotNull(HostCommands.Problem(name, ["-a"]));
        }
        var runner = new HostRunner();
        Assert.Empty(runner.Validate(Q("printers")));
        Assert.NotEmpty(runner.Validate(Q("jobs")));
        Assert.NotEmpty(runner.Validate(Context.Query("host", "name", ("read", "cups"))));
    }
}
