namespace Keeper.Discover;

/// <summary>
/// Maps protocol evidence (answered protocols, service banners, HTTP titles, SNMP sysDescr/sysObjectId)
/// to an asset kind (domain-controller, windows, hypervisor, printer, network-device, linux-unix, unknown)
/// and records the human-readable reason (kindWhy).
/// </summary>
public static class Classifier
{
    public static readonly IReadOnlySet<string> ManagementProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winrm", "ssh", "snmp", "rpc", "ldap", "https", "http", "rdp",
    };

    public static bool HasManagementProtocol(IReadOnlyList<string> answered) =>
        answered.Any(ManagementProtocols.Contains);

    public static (string Kind, string? Why) Classify(
        IReadOnlyList<string> answered,
        IReadOnlyList<AssetService> services,
        SnmpInfo? snmp)
    {
        var protoSet = new HashSet<string>(answered, StringComparer.OrdinalIgnoreCase);
        var reasons = new List<string>();

        // 1. Domain controller: LDAP RootDSE or LDAP + Kerberos (88) + SMB
        var hasLdap = protoSet.Contains("ldap") || services.Any(s => s.Port is 389 or 636 or 3268 or 3269);
        var hasKerberos = protoSet.Contains("kerberos") || services.Any(s => s.Port == 88);
        var ldapRootDse = services.FirstOrDefault(s => s.Service is "ldap" or "ldap-gc" && s.Detail is not null)?.Detail;
        if (hasLdap && (hasKerberos || ldapRootDse?["defaultNamingContext"] is not null || ldapRootDse?["domainControllerFunctionality"] is not null))
        {
            if (hasKerberos)
                reasons.Add("kerberos");
            reasons.Add("ldap");
            if (protoSet.Contains("smb"))
                reasons.Add("smb");
            return ("domain-controller", string.Join(" + ", reasons));
        }

        // 2. Hypervisor: VMware ESXi / vSphere / Proxmox / Hyper-V indicators in HTTP/SNMP
        var snmpDescr = snmp?.SysDescr ?? "";
        var httpText = string.Join(" ", services.Select(s => $"{s.Detail?["server"]} {s.Detail?["title"]}"));
        if (snmpDescr.Contains("VMware ESXi", StringComparison.OrdinalIgnoreCase)
            || httpText.Contains("ESXi", StringComparison.OrdinalIgnoreCase)
            || httpText.Contains("VMware", StringComparison.OrdinalIgnoreCase)
            || httpText.Contains("Proxmox", StringComparison.OrdinalIgnoreCase))
        {
            return ("hypervisor", snmpDescr.Contains("VMware", StringComparison.OrdinalIgnoreCase) ? "snmp (VMware ESXi)" : "http/tls hypervisor banner");
        }

        // 3. Printer: JetDirect (9100), LPD (515), IPP (631), or printer SNMP description
        var hasJetDirect = services.Any(s => s.Port is >= 9100 and <= 9107);
        var hasLpd = services.Any(s => s.Port == 515);
        var hasIpp = services.Any(s => s.Port == 631);
        var isPrinterSnmp = snmpDescr.Contains("LaserJet", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Printer", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("JETDIRECT", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Canon", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Brother", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Xerox", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Ricoh", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Kyocera", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Epson", StringComparison.OrdinalIgnoreCase);

        if (hasJetDirect || hasLpd || hasIpp || isPrinterSnmp)
        {
            if (hasJetDirect)
                reasons.Add("jetdirect (9100)");
            if (hasIpp)
                reasons.Add("ipp (631)");
            if (hasLpd)
                reasons.Add("lpd (515)");
            if (isPrinterSnmp)
                reasons.Add("snmp printer");
            return ("printer", string.Join(" + ", reasons));
        }

        // 4. Windows: WinRM, or SMB + RPC/RDP, or Windows SSH/SNMP
        var hasWinRm = protoSet.Contains("winrm");
        var hasSmb = protoSet.Contains("smb");
        var hasRpc = protoSet.Contains("rpc");
        var hasRdp = protoSet.Contains("rdp");
        var isWindowsSsh = services.Any(s => s.Service == "ssh"
            && s.Detail?["banner"]?.GetValue<string>()?.Contains("OpenSSH_for_Windows", StringComparison.OrdinalIgnoreCase) == true);
        var isWindowsSnmp = snmpDescr.Contains("Windows", StringComparison.OrdinalIgnoreCase);

        if (hasWinRm || (hasSmb && (hasRpc || hasRdp)) || isWindowsSsh || isWindowsSnmp)
        {
            if (hasSmb)
                reasons.Add("smb2");
            if (hasRpc)
                reasons.Add("rpc");
            if (hasWinRm)
                reasons.Add("winrm");
            if (hasRdp)
                reasons.Add("rdp");
            if (isWindowsSsh)
                reasons.Add("ssh (Windows)");
            if (isWindowsSnmp)
                reasons.Add("snmp (Windows)");
            return ("windows", string.Join(" + ", reasons));
        }

        // 5. Network device: SNMP router/switch/firewall or SNMP + SSH/Telnet/HTTP without SMB/RPC/WinRM
        var isNetSnmp = snmpDescr.Contains("Cisco", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Juniper", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("JUNOS", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("FortiGate", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Fortinet", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Check Point", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Aruba", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("ProCurve", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("MikroTik", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("RouterOS", StringComparison.OrdinalIgnoreCase)
            || snmpDescr.Contains("Palo Alto", StringComparison.OrdinalIgnoreCase);

        if (isNetSnmp || (snmp is not null && !hasSmb && !hasRpc && !hasWinRm && !snmpDescr.Contains("Linux", StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add("snmp");
            if (protoSet.Contains("ssh"))
                reasons.Add("ssh");
            if (protoSet.Contains("telnet"))
                reasons.Add("telnet");
            if (protoSet.Contains("http"))
                reasons.Add("http");
            return ("network-device", string.Join(" + ", reasons));
        }

        // 6. Linux / Unix: SSH (non-Windows) or Linux SNMP without Windows management ports
        if (protoSet.Contains("ssh") || snmpDescr.Contains("Linux", StringComparison.OrdinalIgnoreCase))
        {
            if (protoSet.Contains("ssh"))
            {
                var sw = services.FirstOrDefault(s => s.Service == "ssh")?.Detail?["software"]?.GetValue<string>();
                reasons.Add(string.IsNullOrEmpty(sw) ? "ssh" : $"ssh ({sw})");
            }
            if (snmpDescr.Contains("Linux", StringComparison.OrdinalIgnoreCase))
                reasons.Add("snmp (Linux)");
            if (hasSmb)
                reasons.Add("smb (Samba)");
            return ("linux-unix", string.Join(" + ", reasons));
        }

        // 7. SMB alone (without RPC/WinRM/SSH) defaults to windows
        if (hasSmb)
            return ("windows", "smb2");

        return ("unknown", answered.Count > 0 ? string.Join(" + ", answered) : null);
    }
}
