using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;

namespace Keeper.Scan.Tests;

/// <summary>
/// Every problem the legacy fleet scan reported, run through the shipped workstation rules with rows shaped
/// like the live reads (CIM, event log, registry, Configuration Manager): the rule must fire on the problem
/// and stay silent on a healthy PC. A legacy signal with no case must be declined here with a reason.
/// </summary>
public sealed class FleetSignalCoverageTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    private const string Host = "pc01.example.org";

    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-tests-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>Answers every query with the case's rows, stamped with the host the way the real runners do.</summary>
    private sealed class CannedRunner(string protocol, bool perTarget, IReadOnlyList<JsonObject> rows) : IRunner
    {
        public string Protocol => protocol;
        public bool PerTarget => perTarget;
        public IEnumerable<string> Validate(QuerySpec query) => [];

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken) =>
            Task.FromResult(RunnerResult.Ok(rows.Select(r =>
            {
                var copy = (JsonObject)r.DeepClone();
                if (context.Target is not null)
                    copy["host"] = context.Target;
                return copy;
            }).ToList()));
    }

    private sealed record Case(string Signal, string RuleId, string Label, bool Fires, IReadOnlyList<JsonObject> Rows,
        (string Name, string Value)? Threshold)
    {
        public string Name => $"{Signal} | {RuleId} | {Label}";
    }

    // ---- the legacy scan's problem table (rule names are generic labels) ----------------------------------------

    private static readonly string[] Legacy =
    [
        "Commit", "NotRead", "AppHang", "ForcedOff", "DiskFull", "RamLow", "StuckSvc", "Link100", "DiskErrors", "GpSilent",
        "LowMemory", "PortExhaust", "IpConflict", "Hdd", "FileServers", "Patching", "TwoAv", "DomainContact", "CpuCapped",
        "Uptime", "ShutdownHang", "SlowBoot", "NicDrops", "Software", "LogFlood", "Piles", "NoSccm", "SvcExe", "Dwm",
        "DefenderOld", "DnsTimeout", "WifiJoined", "WmiErrors", "StaticIp", "ServiceFail", "NicPowerSave", "Hosts", "Wsd",
        "AppCrash", "SvcTimeout", "WifiSaved", "WifiEnabled", "DriverBlocked", "SlowGp", "RebootPending", "Wpad",
        "OfflineFiles", "StaticRoutes", "NewSoftware", "Dlp", "Extensions", "HarmonyExt", "NotChecked", "Virtual",
    ];

    private static readonly Dictionary<string, string> NotCovered = new(StringComparer.Ordinal)
    {
        ["NotRead"] = "Coverage, not a rule: a host that cannot be read is an unknown result and a coverage record, never a pass.",
        ["NotChecked"] = "Coverage, not a rule: a check that could not be read is an unknown result and a coverage record.",
        ["NicPowerSave"] = "Backlog (proposal not taken): the power-saving keywords are vendor specific and on by default on many adapters.",
        ["Hosts"] = "Backlog (engine gap): the hosts file is a file read over the admin share, which the CIM runner cannot do.",
        ["Wpad"] = "Backlog (registry): the auto-detect policy and the WinHTTP auto-proxy service are two keys that must be judged together.",
        ["WifiEnabled"] = "Backlog (engine gap): telling a wired desktop from a laptop needs the chassis type in the same row as the adapter.",
        ["Virtual"] = "Backlog (engine gap): a virtual adapter in use is only a problem for an on-site PC, which needs the site in the same row.",
        ["Extensions"] = "Backlog (registry): forced browser extensions are values named 1..n, which a condition cannot address.",
        ["HarmonyExt"] = "Information lead about one vendor's browser extension; no rule can judge it without the browser policy read above.",
        ["NewSoftware"] = "Information, not a defect: recent installs are an inventory fact, listed by the inventory views.",
        ["OfflineFiles"] = "GAP: no shipped rule and no backlog entry yet (Offline Files cache state); decide whether to add one.",
        ["WifiSaved"] = "GAP: no shipped rule and no backlog entry yet (saved Wi-Fi profiles on a wired desktop); needs the chassis fact too.",
    };

    // ---- rows shaped like the live reads --------------------------------------------------------------------------

    private static int _record;

    private static string Ago(double days) => Iso.Utc(Now.AddDays(-days));

    private static JsonNode? Node(object? value) => value switch
    {
        null => null,
        string s => JsonValue.Create(s),
        bool b => JsonValue.Create(b),
        int i => JsonValue.Create(i),
        long l => JsonValue.Create(l),
        double d => JsonValue.Create(d),
        string[] a => new JsonArray(a.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
        _ => throw new ArgumentException($"No JSON for {value.GetType().Name}."),
    };

    private static JsonObject Obj(params (string Name, object? Value)[] fields)
    {
        var row = new JsonObject();
        foreach (var (name, value) in fields)
            row[name] = Node(value);
        return row;
    }

    private static IReadOnlyList<JsonObject> Rows(params JsonObject[] rows) => rows;

    private static IReadOnlyList<JsonObject> Many(int count, Func<int, JsonObject> make) =>
        Enumerable.Range(0, count).Select(make).ToList();

    private static JsonObject EventAt(double daysAgo, int id, string provider, params (string Name, object? Value)[] data)
    {
        var row = Obj(("log", "System"), ("id", id), ("provider", provider), ("level", 2),
            ("recordId", Interlocked.Increment(ref _record)), ("time", Ago(daysAgo)));
        foreach (var (name, value) in data)
            row[name] = Node(value);
        return row;
    }

    private static IReadOnlyList<JsonObject> Events(int count, int id, string provider, params (string Name, object? Value)[] data) =>
        Many(count, _ => EventAt(1, id, provider, data));

    private static JsonObject Os(double upDays, long totalKb) =>
        Obj(("Caption", "Microsoft Windows 11 Enterprise"), ("Version", "10.0.26100"), ("BuildNumber", "26100"), ("OperatingSystemSKU", 4),
            ("LastBootUpTime", Ago(upDays)), ("FreePhysicalMemory", "4200000"), ("TotalVisibleMemorySize", totalKb.ToString(System.Globalization.CultureInfo.InvariantCulture)));

    private static JsonObject Service(string name, string state, string mode = "Auto") =>
        Obj(("Name", name), ("DisplayName", "Vendor " + name), ("PathName", @"C:\Program Files\Vendor\agent.exe"), ("StartName", "LocalSystem"),
            ("StartMode", mode), ("State", state), ("ExitCode", 0));

    private static JsonObject Process(string name, int pid, double startedDaysAgo = 1) =>
        Obj(("Name", name), ("ProcessId", pid), ("CreationDate", Ago(startedDaysAgo)));

    private static JsonObject Nic(string speed, bool fullDuplex) =>
        Obj(("Name", "Ethernet"), ("InterfaceDescription", "Vendor Gigabit Adapter"), ("Speed", speed), ("FullDuplex", fullDuplex),
            ("NdisPhysicalMedium", 14), ("MediaConnectState", 1), ("DriverVersionString", "1.0.0.1"), ("DriverDate", Ago(100)));

    private static JsonObject Reg(string key, bool exists) => Obj(("key", key), ("exists", exists));

    private static JsonObject Device(string name, int isClient, double logonDaysAgo) =>
        Obj(("ResourceID", 16777001), ("Name", name), ("IsClient", isClient), ("IsActive", isClient), ("IsObsolete", 0),
            ("ClientVersion", "5.00.9999.1000"), ("DeviceOS", "Microsoft Windows NT Workstation 10.0"), ("DeviceOSBuild", "10.0.26100.1"),
            ("ADLastLogonTime", Ago(logonDaysAgo)));

    private static JsonObject Program(string name) =>
        Obj(("ResourceID", 16777002), ("DisplayName", name), ("Version", "1.0"), ("Publisher", "Vendor"));

    private static readonly List<Case> Cases = BuildCases();

    private static List<Case> BuildCases()
    {
        var cases = new List<Case>();
        void Fire(string signal, string rule, string label, IReadOnlyList<JsonObject> rows, (string, string)? threshold = null) =>
            cases.Add(new Case(signal, rule, label, true, rows, threshold));
        void Quiet(string signal, string rule, string label, IReadOnlyList<JsonObject> rows, (string, string)? threshold = null) =>
            cases.Add(new Case(signal, rule, label, false, rows, threshold));

        const string Sys = "Service Control Manager";

        // Health: memory, uptime, services, processes
        Fire("Commit", "WS-COMMIT-HIGH", "commit 83 percent", Rows(Obj(("PercentCommittedBytesInUse", 83), ("AvailableMBytes", 1900))));
        Quiet("Commit", "WS-COMMIT-HIGH", "commit 45 percent", Rows(Obj(("PercentCommittedBytesInUse", 45), ("AvailableMBytes", 9000))));

        Fire("Uptime", "WS-UPTIME-LONG", "up 31.7 days", Rows(Os(31.7, 16000000)));
        Quiet("Uptime", "WS-UPTIME-LONG", "up 5 days", Rows(Os(5, 16000000)));
        Fire("Uptime", "WSF-UPTIME-LONG", "inventory shows 31.7 days", Rows(Obj(("ResourceID", 16777003), ("Caption", "Microsoft Windows 11 Enterprise"), ("BuildNumber", "26100"), ("LastBootUpTime", Ago(31.7)))));
        Quiet("Uptime", "WSF-UPTIME-LONG", "inventory shows 5 days", Rows(Obj(("ResourceID", 16777003), ("Caption", "Microsoft Windows 11 Enterprise"), ("BuildNumber", "26100"), ("LastBootUpTime", Ago(5)))));

        Fire("RamLow", "WS-MEMORY-LOW-TOTAL", "7.7 GB visible", Rows(Os(2, 8074035)));
        Fire("RamLow", "WS-MEMORY-LOW-TOTAL", "3.9 GB visible", Rows(Os(2, 4089446)));
        Quiet("RamLow", "WS-MEMORY-LOW-TOTAL", "15.7 GB visible", Rows(Os(2, 16461000)));

        Fire("StuckSvc", "WS-SVC-STUCK", "service stopping", Rows(Obj(("Name", "vendorsvc"), ("DisplayName", "Vendor Service"), ("State", "Stop Pending"), ("StartMode", "Auto"), ("ProcessId", 4321))));
        Quiet("StuckSvc", "WS-SVC-STUCK", "no pending service", Rows());

        Fire("Piles", "WS-PROC-PILED-UP", "45 copies of a listed program", Many(45, i => Process("Photos.exe", 1000 + i)));
        Fire("Piles", "WS-PROC-PILED-UP", "tenant lists a viewer add-in", Many(20, i => Process("vendorviewer.exe", 1000 + i)),
            ("workstations.piled-process-pattern", @"^vendorviewer\.exe$"));
        Quiet("Piles", "WS-PROC-PILED-UP", "3 copies of a listed program", Many(3, i => Process("schtasks.exe", 1000 + i)));
        Quiet("Piles", "WS-PROC-PILED-UP", "45 copies of an unlisted program", Many(45, i => Process("vendorviewer.exe", 1000 + i)));

        Fire("SvcExe", "WS-SERVICES-EXE-BUSY", "59 percent of a core", Rows(Obj(("Name", "services.exe"), ("ProcessId", 700), ("CreationDate", Ago(2)),
            ("KernelModeTime", "1020000000000"), ("UserModeTime", "50000000"))));
        Quiet("SvcExe", "WS-SERVICES-EXE-BUSY", "2 percent of a core", Rows(Obj(("Name", "services.exe"), ("ProcessId", 700), ("CreationDate", Ago(2)),
            ("KernelModeTime", "35000000000"), ("UserModeTime", "20000000000"))));

        Fire("Dwm", "WS-PROC-HANDLES-HIGH", "32074 handles", Rows(Obj(("Name", "dwm.exe"), ("ProcessId", 1234), ("HandleCount", 32074))));
        Quiet("Dwm", "WS-PROC-HANDLES-HIGH", "15000 handles", Rows(Obj(("Name", "dwm.exe"), ("ProcessId", 1234), ("HandleCount", 15000))));

        Fire("LogFlood", "WS-EVT-APP-LOG-FLOOD", "3500 events in a day", Events(3500, 1, "VendorSource"));
        Quiet("LogFlood", "WS-EVT-APP-LOG-FLOOD", "300 events in a day", Events(300, 1, "VendorSource"));

        Fire("Dlp", "WS-WATCHED-AGENT-RUNNING", "tenant watches a content-inspection agent", Rows(Service("vendordlpagent", "Running")),
            ("workstations.watch-agent-pattern", "^Vendor.*dlp"));
        Quiet("Dlp", "WS-WATCHED-AGENT-RUNNING", "empty default watch list", Rows(Service("vendordlpagent", "Running")));

        // Hardware
        Fire("DiskFull", "WS-SYSTEM-DRIVE-FREE-PCT-LOW", "8 percent free", Rows(Obj(("Name", "C:"), ("PercentFreeSpace", 8), ("FreeMegabytes", 20070))));
        Quiet("DiskFull", "WS-SYSTEM-DRIVE-FREE-PCT-LOW", "45 percent free", Rows(Obj(("Name", "C:"), ("PercentFreeSpace", 45), ("FreeMegabytes", 110000))));
        Fire("DiskFull", "WS-SYSTEM-DRIVE-FREE-LOW", "4.1 GB free", Rows(Obj(("DeviceID", "C:"), ("FreeSpace", "4400000000"), ("Size", "256000000000"))));
        Quiet("DiskFull", "WS-SYSTEM-DRIVE-FREE-LOW", "60 GB free", Rows(Obj(("DeviceID", "C:"), ("FreeSpace", "60000000000"), ("Size", "256000000000"))));
        Fire("DiskFull", "WSF-C-FREE-LOW", "inventory shows 4.1 GB free", Rows(Obj(("ResourceID", 16777004), ("DeviceID", "C:"), ("Size", 244000), ("FreeSpace", 4198), ("DriveType", 3))));
        Quiet("DiskFull", "WSF-C-FREE-LOW", "inventory shows 50 GB free", Rows(Obj(("ResourceID", 16777004), ("DeviceID", "C:"), ("Size", 244000), ("FreeSpace", 51200), ("DriveType", 3))));

        Fire("Hdd", "WS-DISK-HDD-SYSTEM", "internal spinning disk", Rows(Obj(("DeviceId", "0"), ("FriendlyName", "Vendor HDD"), ("MediaType", 3), ("BusType", 11), ("HealthStatus", 0))));
        Quiet("Hdd", "WS-DISK-HDD-SYSTEM", "NVMe solid-state disk", Rows(Obj(("DeviceId", "0"), ("FriendlyName", "Vendor SSD"), ("MediaType", 4), ("BusType", 17), ("HealthStatus", 0))));

        Fire("DiskErrors", "WS-EVT-DISK-ERROR", "6 disk errors", Events(6, 7, "disk"));
        Quiet("DiskErrors", "WS-EVT-DISK-ERROR", "retries only", Events(4, 129, "disk"));
        Quiet("DiskErrors", "WS-EVT-DISK-ERROR", "no events", Rows());

        Fire("LowMemory", "WS-EVT-OUT-OF-MEMORY", "3 low-memory events", Events(3, 2004, "Microsoft-Windows-Resource-Exhaustion-Detector"));
        Quiet("LowMemory", "WS-EVT-OUT-OF-MEMORY", "no events", Rows());

        Fire("CpuCapped", "WS-EVT-CPU-THROTTLED", "7 throttling reports", Events(7, 37, "Microsoft-Windows-Kernel-Processor-Power"));
        Quiet("CpuCapped", "WS-EVT-CPU-THROTTLED", "no events", Rows());

        // Patching, restarts, shutdowns
        Fire("Patching", "WS-PATCH-NONE-RECENT", "newest update 376 days old",
            Rows(Obj(("HotFixID", "KB5000001"), ("Description", "Update"), ("InstalledOn", Ago(376))),
                Obj(("HotFixID", "KB5000002"), ("Description", "Update"), ("InstalledOn", Ago(500)))));
        Quiet("Patching", "WS-PATCH-NONE-RECENT", "an update 10 days old",
            Rows(Obj(("HotFixID", "KB5000001"), ("Description", "Update"), ("InstalledOn", Ago(10))),
                Obj(("HotFixID", "KB5000002"), ("Description", "Update"), ("InstalledOn", Ago(500)))));

        Fire("ForcedOff", "WS-EVT-UNEXPECTED-SHUTDOWN", "kernel power loss", Events(1, 41, "Microsoft-Windows-Kernel-Power", ("BugcheckCode", "0")));
        Fire("ForcedOff", "WS-EVT-UNEXPECTED-SHUTDOWN", "event log reports a dirty shutdown", Events(1, 6008, "EventLog"));
        Quiet("ForcedOff", "WS-EVT-UNEXPECTED-SHUTDOWN", "same id from another source", Events(1, 41, "VendorSource"));
        Quiet("ForcedOff", "WS-EVT-UNEXPECTED-SHUTDOWN", "no events", Rows());

        Fire("RebootPending", "WS-REG-REBOOT-PENDING", "component servicing key present", Rows(Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", true)));
        Quiet("RebootPending", "WS-REG-REBOOT-PENDING", "key absent", Rows(Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", false)));
        Fire("RebootPending", "WS-REG-REBOOT-REQUIRED-WU", "Windows Update key present", Rows(Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", true)));
        Quiet("RebootPending", "WS-REG-REBOOT-REQUIRED-WU", "key absent", Rows(Reg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", false)));
        Fire("RebootPending", "WS-REG-REBOOT-PENDING-CCM", "client restart data present", Rows(Reg(@"SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData", true)));
        Quiet("RebootPending", "WS-REG-REBOOT-PENDING-CCM", "key absent", Rows(Reg(@"SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData", false)));
        Fire("RebootPending", "WS-REG-PENDING-RENAMES", "300 queued replacements",
            Rows(Obj(("key", @"SYSTEM\CurrentControlSet\Control\Session Manager"), ("exists", true),
                ("PendingFileRenameOperations", Enumerable.Range(0, 300).Select(i => $@"\??\C:\Windows\Temp\file{i}.tmp").ToArray()))));
        Quiet("RebootPending", "WS-REG-PENDING-RENAMES", "10 queued replacements",
            Rows(Obj(("key", @"SYSTEM\CurrentControlSet\Control\Session Manager"), ("exists", true),
                ("PendingFileRenameOperations", Enumerable.Range(0, 10).Select(i => $@"\??\C:\Windows\Temp\file{i}.tmp").ToArray()))));

        Fire("ShutdownHang", "WS-EVT-SERVICE-SHUTDOWN-HANG", "a service did not stop", Events(1, 7043, Sys, ("param1", "Vendor Agent Service")));
        Quiet("ShutdownHang", "WS-EVT-SERVICE-SHUTDOWN-HANG", "a start failure only", Events(1, 7000, Sys, ("param1", "Vendor Agent Service")));

        Fire("SlowBoot", "WS-EVT-BOOT-SLOW", "two startups of 125 s", Events(2, 100, "Microsoft-Windows-Diagnostics-Performance", ("BootTime", "125000"), ("BootPostBootTime", "79100")));
        Quiet("SlowBoot", "WS-EVT-BOOT-SLOW", "two startups of 60 s", Events(2, 100, "Microsoft-Windows-Diagnostics-Performance", ("BootTime", "60000"), ("BootPostBootTime", "20000")));
        Fire("SlowBoot", "WS-EVT-POST-BOOT-SLOW", "two settle times of 79 s", Events(2, 100, "Microsoft-Windows-Diagnostics-Performance", ("BootTime", "60000"), ("BootPostBootTime", "79100")));
        Quiet("SlowBoot", "WS-EVT-POST-BOOT-SLOW", "two settle times of 20 s", Events(2, 100, "Microsoft-Windows-Diagnostics-Performance", ("BootTime", "60000"), ("BootPostBootTime", "20000")));

        // Services and programs
        Fire("ServiceFail", "WS-EVT-SERVICE-FAIL", "7 crashes of a service", Events(7, 7031, Sys, ("param1", "Vendor Security Service"), ("param2", "1")));
        Quiet("ServiceFail", "WS-EVT-SERVICE-FAIL", "only the ignored diagnostic host", Events(5, 7000, Sys, ("param1", "Diagnostic Service Host")));

        Fire("SvcTimeout", "WS-EVT-SERVICE-TIMEOUT", "7 timeouts", Events(7, 7009, Sys, ("param1", "30000"), ("param2", "Vendor Agent Service")));
        Quiet("SvcTimeout", "WS-EVT-SERVICE-TIMEOUT", "a crash only", Events(1, 7031, Sys, ("param1", "Vendor Agent Service")));

        Fire("AppHang", "WS-EVT-APP-HANG", "7 hangs in a week", Events(7, 1002, "Application Hang", ("AppName", "vendorapp.exe")));
        Fire("AppHang", "WS-EVT-APP-HANG", "one hang when the tenant limit is 1", Events(1, 1002, "Application Hang", ("AppName", "vendorapp.exe")),
            ("workstations.app-hangs-max-7d", "1"));
        Quiet("AppHang", "WS-EVT-APP-HANG", "2 hangs", Events(2, 1002, "Application Hang", ("AppName", "vendorapp.exe")));

        Fire("AppCrash", "WS-EVT-APP-CRASH", "10 crashes", Events(10, 1000, "Application Error", ("AppName", "vendoragent.exe")));
        Quiet("AppCrash", "WS-EVT-APP-CRASH", "2 crashes", Events(2, 1000, "Application Error", ("AppName", "vendoragent.exe")));

        Fire("DriverBlocked", "WS-EVT-DRIVER-BLOCKED", "a driver was refused", Events(1, 1060, "Application Popup"));
        Quiet("DriverBlocked", "WS-EVT-DRIVER-BLOCKED", "no events", Rows());

        Fire("WmiErrors", "WS-EVT-WMI-ERRORS", "60 WMI errors", Events(60, 5858, "Microsoft-Windows-WMI-Activity", ("ResultCode", "0x80041032")));
        Quiet("WmiErrors", "WS-EVT-WMI-ERRORS", "10 WMI errors", Events(10, 5858, "Microsoft-Windows-WMI-Activity", ("ResultCode", "0x80041032")));

        Fire("Software", "WSF-SW-UNAPPROVED-64", "remote-access tool, 64-bit view", Rows(Program("AnyDesk 8.0")));
        Quiet("Software", "WSF-SW-UNAPPROVED-64", "office suite", Rows(Program("Vendor Office Suite")));
        Fire("Software", "WSF-SW-UNAPPROVED-32", "remote-access tool, 32-bit view", Rows(Program("TeamViewer 15")));
        Quiet("Software", "WSF-SW-UNAPPROVED-32", "office suite", Rows(Program("Vendor Office Suite")));
        Fire("Software", "WSF-SW-UNAPPROVED-64", "tenant lists a signing tool", Rows(Program("Vendor Signing Desktop 1.11")),
            ("workstations.unapproved-software-pattern", "^Vendor Signing"));
        Fire("Software", "WS-PROC-UNAPPROVED", "remote-access tool running", Rows(Process("AnyDesk.exe", 2222)));
        Quiet("Software", "WS-PROC-UNAPPROVED", "ordinary program running", Rows(Process("vendorapp.exe", 2222)));

        Fire("Wsd", "WS-PRINTER-WSD", "auto-installed printer", Rows(Obj(("Name", "Vendor Printer 100"), ("PortName", "WSD-0123"), ("WorkOffline", false))));
        Quiet("Wsd", "WS-PRINTER-WSD", "no WSD printer", Rows());

        // Configuration Manager client
        Fire("NoSccm", "WS-SVC-AGENT-STOPPED", "client service stopped", Rows(Service("CcmExec", "Stopped")));
        Quiet("NoSccm", "WS-SVC-AGENT-STOPPED", "another service stopped", Rows(Service("vendorsvc", "Stopped")));
        Fire("NoSccm", "WS-CCM-SERVICE-MISSING", "no client service installed", Rows(Service("Dnscache", "Running"), Service("Spooler", "Running")));
        Quiet("NoSccm", "WS-CCM-SERVICE-MISSING", "client service installed", Rows(Service("Dnscache", "Running"), Service("CcmExec", "Running")));
        Fire("NoSccm", "WSF-NO-CLIENT", "site has no client for a PC in use", Rows(Device("PC01", 0, 3)));
        Quiet("NoSccm", "WSF-NO-CLIENT", "site has a client", Rows(Device("PC01", 1, 3)));

        // Network
        Fire("Link100", "WS-NIC-SLOW-LINK", "100 Mbps", Rows(Nic("100000000", true)));
        Quiet("Link100", "WS-NIC-SLOW-LINK", "1 Gbps", Rows(Nic("1000000000", true)));

        Fire("StaticIp", "WS-IP-STATIC", "hand-set address", Rows(Obj(("Index", 7), ("Description", "Vendor Gigabit Ethernet"), ("IPEnabled", true), ("DHCPEnabled", false),
            ("DNSServerSearchOrder", new[] { "192.0.2.53" }), ("TcpipNetbiosOptions", 2), ("IPAddress", new[] { "192.0.2.10" }), ("DefaultIPGateway", new[] { "192.0.2.1" }))));
        Quiet("StaticIp", "WS-IP-STATIC", "DHCP", Rows(Obj(("Index", 7), ("Description", "Vendor Gigabit Ethernet"), ("IPEnabled", true), ("DHCPEnabled", true),
            ("DNSServerSearchOrder", new[] { "192.0.2.53" }), ("TcpipNetbiosOptions", 2), ("IPAddress", new[] { "192.0.2.10" }), ("DefaultIPGateway", new[] { "192.0.2.1" }))));

        Fire("StaticRoutes", "WS-STATIC-ROUTES", "persistent route", Rows(Obj(("DestinationPrefix", "198.51.100.0/24"), ("NextHop", "192.0.2.1"), ("InterfaceAlias", "Ethernet"), ("Protocol", 3))));
        Quiet("StaticRoutes", "WS-STATIC-ROUTES", "default route only", Rows(Obj(("DestinationPrefix", "0.0.0.0/0"), ("NextHop", "192.0.2.1"), ("InterfaceAlias", "Ethernet"), ("Protocol", 3))));

        Fire("DnsTimeout", "WS-EVT-DNS-TIMEOUT", "51 lookups timed out", Events(51, 1014, "Microsoft-Windows-DNS-Client", ("QueryName", "app.example.org")));
        Quiet("DnsTimeout", "WS-EVT-DNS-TIMEOUT", "5 lookups timed out", Events(5, 1014, "Microsoft-Windows-DNS-Client", ("QueryName", "app.example.org")));

        Fire("DomainContact", "WS-EVT-NO-DC", "secure channel failure", Events(1, 5719, "NETLOGON"));
        Quiet("DomainContact", "WS-EVT-NO-DC", "same id from another source", Events(1, 5719, "VendorSource"));

        Fire("IpConflict", "WS-EVT-IP-CONFLICT", "address in use", Events(1, 4199, "Tcpip"));
        Quiet("IpConflict", "WS-EVT-IP-CONFLICT", "port exhaustion only", Events(2, 4231, "Tcpip"));

        Fire("PortExhaust", "WS-EVT-PORT-EXHAUSTION", "ports ran out", Events(2, 4231, "Tcpip"));
        Quiet("PortExhaust", "WS-EVT-PORT-EXHAUSTION", "address conflict only", Events(1, 4199, "Tcpip"));

        Fire("NicDrops", "WS-EVT-NIC-LINK-DOWN", "12 link drops", Events(12, 27, "e1dexpress"));
        Fire("NicDrops", "WS-EVT-NIC-LINK-DOWN", "2 link drops when the tenant limit is 2", Events(2, 27, "e1dexpress"), ("workstations.nic-linkdown-max-7d", "2"));
        Quiet("NicDrops", "WS-EVT-NIC-LINK-DOWN", "3 link drops", Events(3, 27, "e1dexpress"));
        Fire("NicDrops", "WS-EVT-NIC-RESET", "2 adapter resets", Events(2, 10400, "Microsoft-Windows-NDIS"));
        Quiet("NicDrops", "WS-EVT-NIC-RESET", "1 adapter reset", Events(1, 10400, "Microsoft-Windows-NDIS"));

        Fire("WifiJoined", "WS-EVT-WIFI-HOTSPOT", "joined a phone hotspot", Events(1, 8001, "Microsoft-Windows-WLAN-AutoConfig", ("SSID", "DIRECT-ab-vendorphone")));
        Quiet("WifiJoined", "WS-EVT-WIFI-HOTSPOT", "joined an ordinary network", Events(1, 8001, "Microsoft-Windows-WLAN-AutoConfig", ("SSID", "OfficeNet")));

        // File servers
        Fire("FileServers", "WS-EVT-SMB-NAME-UNRESOLVED", "a retired server name", Events(1, 30800, "Microsoft-Windows-SMBClient", ("ServerName", "oldfs.example.org")));
        Quiet("FileServers", "WS-EVT-SMB-NAME-UNRESOLVED", "connection failures only", Events(2, 30803, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Fire("FileServers", "WS-EVT-SMB-CONNECT-FAIL", "3 failed connections", Events(3, 30803, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Quiet("FileServers", "WS-EVT-SMB-CONNECT-FAIL", "2 failed connections", Events(2, 30803, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Fire("FileServers", "WS-EVT-SMB-SESSION-DROP", "5 dropped sessions", Events(5, 30805, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Quiet("FileServers", "WS-EVT-SMB-SESSION-DROP", "2 dropped sessions", Events(2, 30805, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Fire("FileServers", "WS-EVT-SMB-AUTH-FAIL", "10 failed sign-ins", Events(10, 31001, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));
        Quiet("FileServers", "WS-EVT-SMB-AUTH-FAIL", "3 failed sign-ins", Events(3, 31001, "Microsoft-Windows-SMBClient", ("ServerName", "fs01.example.org")));

        // Group Policy
        Fire("GpSilent", "WS-EVT-GP-SILENT", "last completed run 31 days ago", Rows(EventAt(31, 8000, "Microsoft-Windows-GroupPolicy")));
        Fire("GpSilent", "WS-EVT-GP-SILENT", "no policy events at all", Rows());
        Quiet("GpSilent", "WS-EVT-GP-SILENT", "completed run 5 hours ago", Rows(EventAt(0.2, 8001, "Microsoft-Windows-GroupPolicy")));

        Fire("SlowGp", "WS-EVT-GP-LOGON-SLOW", "two user policy runs of 37 s", Events(2, 8001, "Microsoft-Windows-GroupPolicy", ("PolicyElaspedTimeInSeconds", "37"), ("DCName", "dc01.example.org")));
        Quiet("SlowGp", "WS-EVT-GP-LOGON-SLOW", "two user policy runs of 12 s", Events(2, 8001, "Microsoft-Windows-GroupPolicy", ("PolicyElaspedTimeInSeconds", "12"), ("DCName", "dc01.example.org")));
        Fire("SlowGp", "WS-EVT-GP-STARTUP-SLOW", "two computer policy runs of 45 s", Events(2, 8000, "Microsoft-Windows-GroupPolicy", ("PolicyElaspedTimeInSeconds", "45"), ("DCName", "dc01.example.org")));
        Quiet("SlowGp", "WS-EVT-GP-STARTUP-SLOW", "two computer policy runs of 2 s", Events(2, 8000, "Microsoft-Windows-GroupPolicy", ("PolicyElaspedTimeInSeconds", "2"), ("DCName", "dc01.example.org")));
        Fire("SlowGp", "WS-EVT-GP-EXTENSION-SLOW", "an extension of 6.8 s twice", Events(2, 5016, "Microsoft-Windows-GroupPolicy", ("CSEExtensionName", "Group Policy Files"), ("CSEElaspedTimeInMilliSeconds", "6800")));
        Quiet("SlowGp", "WS-EVT-GP-EXTENSION-SLOW", "an extension of 0.4 s twice", Events(2, 5016, "Microsoft-Windows-GroupPolicy", ("CSEExtensionName", "Group Policy Files"), ("CSEElaspedTimeInMilliSeconds", "400")));

        // Anti-malware
        Fire("TwoAv", "WS-AV-MULTIPLE", "Defender and a second engine both on",
            Rows(Obj(("displayName", "Windows Defender"), ("productState", 397568), ("pathToSignedProductExe", "windowsdefender://")),
                Obj(("displayName", "Vendor Endpoint"), ("productState", 266240), ("pathToSignedProductExe", @"C:\Program Files\Vendor\endpoint.exe"))));
        Quiet("TwoAv", "WS-AV-MULTIPLE", "Defender passive next to a second engine",
            Rows(Obj(("displayName", "Windows Defender"), ("productState", 393472), ("pathToSignedProductExe", "windowsdefender://")),
                Obj(("displayName", "Vendor Endpoint"), ("productState", 266240), ("pathToSignedProductExe", @"C:\Program Files\Vendor\endpoint.exe"))));

        Fire("DefenderOld", "WS-DEFENDER-SIG-OLD", "signatures 113 days old", Rows(Obj(("AMServiceEnabled", true), ("AntivirusSignatureAge", 113), ("AntivirusSignatureLastUpdated", Ago(113)))));
        Quiet("DefenderOld", "WS-DEFENDER-SIG-OLD", "signatures 1 day old", Rows(Obj(("AMServiceEnabled", true), ("AntivirusSignatureAge", 1), ("AntivirusSignatureLastUpdated", Ago(1)))));
        Fire("DefenderOld", "WS-AV-DEFS-OUTDATED", "Security Center flags old definitions", Rows(Obj(("displayName", "Windows Defender"), ("productState", 397584), ("pathToSignedProductExe", "windowsdefender://"))));
        Quiet("DefenderOld", "WS-AV-DEFS-OUTDATED", "definitions current", Rows(Obj(("displayName", "Windows Defender"), ("productState", 397568), ("pathToSignedProductExe", "windowsdefender://"))));

        return cases;
    }

    // ---- running a case through the real scanner ------------------------------------------------------------------

    private static string RulesFolder
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Keeper.slnx")))
                    return Path.Combine(dir.FullName, "rules");
            }
            throw new DirectoryNotFoundException("The repo's rules folder was not found above the test binaries.");
        }
    }

    private static readonly Lazy<Dictionary<string, (Rule Rule, RuleFile File)>> Shipped = new(() =>
    {
        var validators = Runners.Registry().Validators;
        var rules = new Dictionary<string, (Rule, RuleFile)>(StringComparer.Ordinal);
        foreach (var name in new[] { "workstations.yaml", "workstations-sccm.yaml" })
        {
            var file = RuleLoader.LoadFile(Path.Combine(RulesFolder, name), "builtin", validators);
            foreach (var rule in file.Rules)
                rules[rule.Id] = (rule, file);
        }
        return rules;
    });

    private async Task<(List<FindingRecord> Findings, List<ResultRecord> Results)> Run(Case c)
    {
        Assert.True(Shipped.Value.TryGetValue(c.RuleId, out var shipped), $"{c.RuleId} is not a shipped rule.");
        var (rule, file) = shipped;
        var registry = new RunnerRegistry(
        [
            new CannedRunner("cim", true, c.Rows),
            new CannedRunner("eventlog", true, c.Rows),
            new CannedRunner("registry", true, c.Rows),
            new CannedRunner("http", false, c.Rows),
        ]);
        var folder = Path.Combine(_dir, Guid.NewGuid().ToString("N"));
        var report = await new Scanner(registry, new Clock(Now)).RunAsync(new ScanRequest
        {
            Files = [file with { Rules = [rule] }],
            Connection = new FilesConnection(),
            RunsDir = Path.Combine(folder, "runs"),
            ImportsDir = Path.Combine(folder, "imports"),
            ResolveTargets = _ => [Host],
            Threshold = name => c.Threshold is { } t && t.Name == name ? t.Value : null,
        }, CancellationToken.None);

        Assert.Equal("ok", report.Manifest.Status);
        List<T> Read<T>(string name) =>
            File.Exists(Path.Combine(folder, "runs", report.Manifest.RunId, name))
                ? JsonLines.Read<T>(Path.Combine(folder, "runs", report.Manifest.RunId, name)).ToList()
                : [];
        return (Read<FindingRecord>(RunFolder.Findings), Read<ResultRecord>(RunFolder.Results));
    }

    public static IEnumerable<object[]> CaseNames => Cases.Select(c => new object[] { c.Name });

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task The_shipped_rule_judges_rows_shaped_like_the_live_read_as_the_legacy_scan_did(string name)
    {
        var c = Cases.Single(x => x.Name == name);

        var (findings, results) = await Run(c);

        if (c.Fires)
        {
            Assert.NotEmpty(findings);
            Assert.All(findings, f => Assert.Equal(c.RuleId, f.RuleId));
            Assert.All(findings, f => Assert.False(string.IsNullOrWhiteSpace(f.Evidence), $"{f.RuleId} gave a finding without evidence."));
        }
        else
        {
            Assert.Empty(findings);
            // A healthy PC passes: a row the rule could not judge (wrong field, wrong shape) is not a pass.
            Assert.All(results, r => Assert.True(r.State == "pass", $"{r.RuleId} {r.EntityKey}: {r.State} {r.Why}"));
        }
    }

    [Fact]
    public void Every_legacy_signal_has_a_case_that_fires_or_is_declined_with_a_reason()
    {
        var covered = Cases.Where(c => c.Fires).Select(c => c.Signal).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(Legacy.Length, Legacy.Distinct(StringComparer.Ordinal).Count());
        Assert.Empty(Legacy.Except(covered).Except(NotCovered.Keys));
        Assert.Empty(covered.Intersect(NotCovered.Keys));
        Assert.Empty(covered.Except(Legacy));
        Assert.Empty(NotCovered.Keys.Except(Legacy));
        Assert.All(NotCovered, p => Assert.False(string.IsNullOrWhiteSpace(p.Value), $"{p.Key} has no reason."));
    }

    [Fact]
    public void Every_rule_with_a_firing_case_also_has_a_healthy_case()
    {
        var fired = Cases.Where(c => c.Fires).Select(c => (c.Signal, c.RuleId)).Distinct();
        var quiet = Cases.Where(c => !c.Fires).Select(c => (c.Signal, c.RuleId)).ToHashSet();

        Assert.All(fired, p => Assert.True(quiet.Contains(p), $"{p.Signal} / {p.RuleId} has no healthy case."));
    }

    [Fact]
    public void Case_names_are_unique()
    {
        Assert.Equal(Cases.Count, Cases.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count());
    }
}
