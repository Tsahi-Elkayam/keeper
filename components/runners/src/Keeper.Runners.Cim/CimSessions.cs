using System.Collections.Concurrent;
using System.Security;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace Keeper.Runners.Cim;

/// <summary>
/// A CIM session to one host: Kerberos as the current user, or the integration's credential. WinRM (WSMan)
/// first; WinRM is often off on workstations, so with the integration option cimProtocol: auto (the default)
/// a host WinRM cannot reach is read over DCOM instead - the same classes, in-process, with packet privacy.
/// Only an unreachable WinRM falls back: a refused credential is reported as it is, never tried again over
/// another protocol. cimProtocol: wsman or dcom pins one. The route is remembered per host for the scan.
/// </summary>
internal static class CimSessions
{
    private enum Route { WsMan, Dcom, Unreachable }

    private static readonly ConcurrentDictionary<string, (Route Route, CimException? Error)> Routes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How long a first contact may take; the queries themselves get the integration's timeout.</summary>
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(10);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CimSession Open(string host, RunnerContext context)
    {
        var mode = context.Connection.Options["cimProtocol"]?.ToString() ?? "auto";
        if (mode is not ("auto" or "wsman" or "dcom"))
            throw new InvalidOperationException($"cimProtocol must be auto, wsman or dcom, not '{mode}'.");
        if (mode != "auto")
            return Create(host, context, mode == "dcom" ? Route.Dcom : Route.WsMan, context.Timeout);

        var (route, error) = Routes.GetOrAdd(host, _ => Probe(host, context));
        if (route == Route.Unreachable)
            throw error!;   // fails fast with WinRM's own reason, instead of waiting out two timeouts per query
        if (route == Route.Dcom)
            context.Log("WinRM did not answer; reading over DCOM");
        return Create(host, context, route, context.Timeout);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (Route, CimException?) Probe(string host, RunnerContext context)
    {
        var wsman = Test(host, context, Route.WsMan);
        if (wsman is null)
            return (Route.WsMan, null);
        if (!Unreachable(wsman))
            return (Route.WsMan, null);   // reachable but refused (credential, Kerberos): the query reports it
        return Test(host, context, Route.Dcom) is null ? (Route.Dcom, null) : (Route.Unreachable, wsman);
    }

    /// <summary>Null when the host answered over this route; otherwise why not.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static CimException? Test(string host, RunnerContext context, Route route)
    {
        using var probe = Create(host, context, route, ProbeTimeout < context.Timeout ? ProbeTimeout : context.Timeout);
        try
        {
            return probe.TestConnection(out _, out var error) ? null : error;
        }
        catch (CimException ex)
        {
            return ex;
        }
    }

    /// <summary>
    /// Nothing answered (no listener, a firewall, a timeout, no route): worth another protocol. A host that
    /// answered and refused - access denied, a Kerberos or logon failure - is not: trying again elsewhere would
    /// only double the failed logons.
    /// </summary>
    private static bool Unreachable(CimException? error) =>
        error is not null
        && error.NativeErrorCode is not (NativeErrorCode.AccessDenied or NativeErrorCode.InvalidNamespace or NativeErrorCode.InvalidClass)
        && !error.Message.Contains("access is denied", StringComparison.OrdinalIgnoreCase)
        && !error.Message.Contains("kerberos", StringComparison.OrdinalIgnoreCase)
        && !error.Message.Contains("logon failure", StringComparison.OrdinalIgnoreCase);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static CimSession Create(string host, RunnerContext context, Route route, TimeSpan timeout)
    {
        using CimSessionOptions options = route == Route.Dcom
            ? new DComSessionOptions
            {
                Timeout = timeout,
                PacketPrivacy = true,
                PacketIntegrity = true,
                Impersonation = ImpersonationType.Impersonate,
            }
            : new WSManSessionOptions { Timeout = timeout };

        var credential = context.Connection.WindowsCredential();
        if (credential is null)
            return CimSession.Create(host, options);

        using var password = new SecureString();
        foreach (var c in credential.Password)
            password.AppendChar(c);
        password.MakeReadOnly();
        var mechanism = route == Route.Dcom ? PasswordAuthenticationMechanism.Default : PasswordAuthenticationMechanism.Kerberos;
        options.AddDestinationCredentials(new CimCredential(mechanism, credential.Domain, credential.UserName, password));
        return CimSession.Create(host, options);
    }
}
