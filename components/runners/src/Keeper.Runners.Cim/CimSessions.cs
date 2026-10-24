using System.Collections.Concurrent;
using System.Security;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace Keeper.Runners.Cim;

/// <summary>
/// A CIM session to one host: Kerberos as the current user, or the integration's credential. Which transports are
/// tried, and in what order, is the connection strategy:
///   Auto (the default): the chain WinRM (wsman), then RPC over DCOM (dcom) - the same classes, in-process, with packet
///     privacy. A host WinRM cannot reach (it is often off on workstations) is read over DCOM instead.
///   Manual, for one rule: its fallback_chain replaces the order for that rule's query only.
///   Pinned, for the whole integration: cimProtocol wsman or dcom tries that one transport and no other.
/// A transport that answers and refuses (access denied, a Kerberos or logon failure) ends the walk: the refusal is
/// reported as it is, remembered for the host, and never retried - over another transport or by the next query -
/// which would only repeat the failed logon towards a lockout.
/// The route found is remembered per host and chain for the scan.
/// </summary>
internal static class CimSessions
{
    private static readonly ConcurrentDictionary<string, (string? Transport, CimException? Error)> Routes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How long a first contact may take; the queries themselves get the integration's timeout.</summary>
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The transports to try for a query: its rule's fallback_chain, else the integration's pin, else Auto.</summary>
    public static IReadOnlyList<string> ChainFor(RunnerContext context, IReadOnlyList<string> ruleChain)
    {
        if (ruleChain.Count > 0)
            return ruleChain;
        var mode = context.Connection.Options["cimProtocol"]?.ToString() ?? "auto";
        return mode switch
        {
            "auto" => Transports.Default,
            Transports.WsMan or Transports.Dcom => [mode],
            _ => throw new InvalidOperationException($"cimProtocol must be auto, wsman or dcom, not '{mode}'."),
        };
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CimSession Open(string host, RunnerContext context, IReadOnlyList<string>? ruleChain = null)
    {
        var chain = ChainFor(context, ruleChain ?? []);
        var (transport, error) = Routes.GetOrAdd($"{host}|{string.Join(',', chain)}", _ => Probe(host, context, chain));
        if (transport is null)
            throw error!;   // fails fast with the first transport's own reason, instead of waiting out a timeout per query
        if (transport != chain[0])
            context.Log($"{chain[0]} did not answer; reading over {transport}");
        return Create(host, context, transport, context.Timeout);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (string?, CimException?) Probe(string host, RunnerContext context, IReadOnlyList<string> chain)
    {
        CimException? first = null, refused = null;
        var result = TransportChain.Resolve(chain, transport =>
        {
            var error = Test(host, context, transport);
            if (error is null)
                return (Reach.Answered, null);
            if (!Unreachable(error))
            {
                refused = error;
                return (Reach.Refused, error.Message);
            }
            first ??= error;
            return (Reach.Unreachable, error.Message);
        });
        // A refusal is remembered for the host: every later query fails fast with it instead of presenting the same
        // wrong credential again, once per query - which is how an account gets locked out.
        return refused is not null ? (null, refused) : (result.Transport, first);
    }

    /// <summary>Null when the host answered over this transport; otherwise why not.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static CimException? Test(string host, RunnerContext context, string transport)
    {
        using var probe = Create(host, context, transport, ProbeTimeout < context.Timeout ? ProbeTimeout : context.Timeout);
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
    private static CimSession Create(string host, RunnerContext context, string transport, TimeSpan timeout)
    {
        using CimSessionOptions options = transport == Transports.Dcom
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
        var mechanism = transport == Transports.Dcom ? PasswordAuthenticationMechanism.Default : PasswordAuthenticationMechanism.Kerberos;
        options.AddDestinationCredentials(new CimCredential(mechanism, credential.Domain, credential.UserName, password));
        return CimSession.Create(host, options);
    }
}
