namespace Keeper.Discover.Probes;

public sealed record PortProfile(
    int Port,
    string Service,
    string? Probe = null,
    bool SendNothing = false,
    bool Tls = false);

/// <summary>
/// Port profiles for TCP connect and credential-free handshake probes.
/// Raw print ports (515, 9100..9107) are permanently forced to SendNothing.
/// </summary>
public static class PortProfiles
{
    public static bool IsRawPrintPort(int port) => port == 515 || port is >= 9100 and <= 9107;

    public static readonly IReadOnlyList<PortProfile> Defaults =
    [
        new(22, "ssh", Probe: "ssh"),
        new(23, "telnet", SendNothing: true),
        new(80, "http", Probe: "http"),
        new(88, "kerberos", SendNothing: true),
        new(135, "rpc", SendNothing: true),
        new(139, "netbios-ssn", SendNothing: true),
        new(389, "ldap", Probe: "ldap"),
        new(443, "https", Probe: "http", Tls: true),
        new(445, "smb", Probe: "smb2"),
        new(515, "lpd", SendNothing: true),
        new(631, "ipp", Probe: "http"),
        new(636, "ldaps", Probe: "tls", Tls: true),
        new(3268, "ldap-gc", Probe: "ldap"),
        new(3269, "ldaps-gc", Probe: "tls", Tls: true),
        new(3389, "rdp", SendNothing: true),
        new(5985, "winrm", Probe: "winrm"),
        new(5986, "winrms", Probe: "winrm", Tls: true),
        new(8080, "http-alt", Probe: "http"),
        new(8443, "https-alt", Probe: "http", Tls: true),
        new(9100, "jetdirect", SendNothing: true),
    ];

    public static PortProfile Sanitize(PortProfile profile) =>
        IsRawPrintPort(profile.Port) ? profile with { Probe = null, SendNothing = true, Tls = false } : profile;
}
