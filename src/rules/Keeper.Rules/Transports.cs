namespace Keeper.Rules;

/// <summary>
/// The ways the engine can reach a Windows host to run a cim or registry query (both are WMI): WinRM (wsman, TCP 5985/5986)
/// and RPC over DCOM (dcom, TCP 135 and dynamic ports). Auto mode tries them in <see cref="Default"/> order; a rule's
/// fallback_chain replaces that order for its own query. SMB is not a transport for these: a file share cannot answer
/// a WQL query or a registry key, so a chain naming it is refused when the rule file is loaded.
/// </summary>
public static class Transports
{
    public const string WsMan = "wsman";
    public const string Dcom = "dcom";

    /// <summary>What Auto mode tries, in order.</summary>
    public static IReadOnlyList<string> Default { get; } = [WsMan, Dcom];

    /// <summary>The query protocols that reach a host through one of these transports. eventlog reads over its own RPC session, so it has no choice to make.</summary>
    public static bool Carries(string protocol) => protocol is "cim" or "registry";

    /// <summary>The canonical name (winrm is wsman, rpc is dcom), or null when this is no transport that can carry a query.</summary>
    public static string? Canonical(string name) => name.Trim().ToLowerInvariant() switch
    {
        "wsman" or "winrm" => WsMan,
        "dcom" or "rpc" => Dcom,
        _ => null,
    };
}
