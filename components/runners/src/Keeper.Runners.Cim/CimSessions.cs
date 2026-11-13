using System.Collections.Concurrent;
using System.Globalization;
using System.Security;
using Keeper.Rules;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace Keeper.Runners.Cim;

/// <summary>
/// What a failed CIM call said, as a <see cref="FailureKind"/>. Pure: it takes the numbers and the message out of a
/// CimException, so it is tested without Windows. Codes come first (they are the same in every Windows language),
/// the message last (English only).
/// </summary>
public static class CimErrors
{
    // MI_RESULT values (CimException.NativeErrorCode).
    private const int MiAccessDenied = 2;
    private const int MiServerLimitsExceeded = 27;
    private const int MiServerIsShuttingDown = 28;

    /// <summary>
    /// MI results that mean the host answered and found fault with the request itself (bad namespace, class or query):
    /// the credential was accepted, so there is nothing to retry over another transport.
    /// </summary>
    private static readonly HashSet<int> QueryFaults = [3, 4, 5, 6, 7, 15, 16, 17];

    /// <summary>The kind of a CimException.</summary>
    public static FailureKind Of(CimException error)
    {
        long? code = null;
        try
        {
            // The WMI/WinRM error behind the exception: error_Code holds a Win32 error, an HRESULT or a WS-Management code.
            if (error.ErrorData?.CimInstanceProperties["error_Code"]?.Value is { } value)
                code = Convert.ToInt64(value, CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException or CimException)
        {
            // No usable code in the error data: the HRESULT and the message still tell.
        }
        return Classify((int)error.NativeErrorCode, code, error.HResult, error.Message);
    }

    /// <summary>Whether a CimException is the host faulting the request (query, namespace, class) after it accepted the caller.</summary>
    public static bool IsQueryFault(CimException error) => QueryFaults.Contains((int)error.NativeErrorCode);

    /// <summary>
    /// Whether a failure from a first contact ends the walk over the transports. A refusal, a denial or a push-back
    /// came from a host that answered: another transport would present the same credential again.
    /// </summary>
    public static bool EndsWalk(FailureKind kind, int nativeErrorCode) =>
        kind is FailureKind.Refused or FailureKind.Denied or FailureKind.Throttled || QueryFaults.Contains(nativeErrorCode);

    public static FailureKind Classify(int nativeErrorCode, long? errorCode, int hresult, string? message)
    {
        if (errorCode is { } code && OfCode(unchecked((int)code)) is { } fromCode)
            return fromCode;
        if (OfCode(hresult) is { } fromHresult)
            return fromHresult;
        if (message is not null && message.Contains("maximum number of concurrent operations", StringComparison.OrdinalIgnoreCase))
            return FailureKind.Throttled;
        // SEC_E_LOGON_DENIED in the text (WinRM words a wrong password over Kerberos that way): the account, not the host.
        if (message is not null && message.Contains("8009030c", StringComparison.OrdinalIgnoreCase))
            return FailureKind.Refused;
        // Kerberos trouble is about this host (its name, a ticket, the clock), not the account: the credential is not blamed.
        // Checked before the refusal phrases, which would catch "authentication failed" in the same message.
        if (message is not null && message.Contains("kerberos", StringComparison.OrdinalIgnoreCase))
            return FailureKind.Denied;
        if (Failures.SaysRefused(message))
            return FailureKind.Refused;
        switch (nativeErrorCode)
        {
            case MiAccessDenied:
                return FailureKind.Denied;
            case MiServerLimitsExceeded:
                return FailureKind.Throttled;
            case MiServerIsShuttingDown:
                return FailureKind.Unreachable;
        }
        if (message is not null && message.Contains("access is denied", StringComparison.OrdinalIgnoreCase))
            return FailureKind.Denied;
        if (message is not null && message.Contains("timed out", StringComparison.OrdinalIgnoreCase))
            return FailureKind.Timeout;
        return FailureKind.Error;
    }

    /// <summary>Win32 errors and HRESULTs, plus the WMI and WS-Management codes that are not Win32.</summary>
    private static FailureKind? OfCode(int code) => unchecked((uint)code) switch
    {
        0x803381A6 => FailureKind.Throttled,    // WinRM: the maximum number of concurrent operations for this user was exceeded
        0x80338029 => FailureKind.Timeout,      // WinRM: the operation did not complete within OperationTimeout
        0x80338126 => FailureKind.Unreachable,  // WinRM: the server cannot be reached
        0x80041003 => FailureKind.Denied,       // WBEM_E_ACCESS_DENIED
        _ => Failures.OfWin32(code),
    };
}

/// <summary>An open CIM session of the cim/registry family: one sign-in to one host, shared by every query of that host.</summary>
internal sealed class CimRunnerSession(CimSession session, IReadOnlyList<string> chain, string transport) : IRunnerSession
{
    public CimSession Session { get; } = session;

    /// <summary>The transports the session was opened with (the integration's), to tell when a rule asks for another.</summary>
    public IReadOnlyList<string> Chain { get; } = chain;

    public string Transport { get; } = transport;

    public ValueTask DisposeAsync()
    {
        Session.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>The CIM session one query reads over; disposed only when the query had to open its own.</summary>
internal sealed class CimLease(CimSession session, bool owned) : IDisposable
{
    public CimSession Session { get; } = session;

    public void Dispose()
    {
        if (owned)
            Session.Dispose();
    }
}

/// <summary>
/// A CIM session to one host: Kerberos as the current user, or the integration's credential. Which transports are
/// tried, and in what order, is the connection strategy:
///   Auto (the default): the chain WinRM (wsman), then RPC over DCOM (dcom) - the same classes, in-process, with packet
///     privacy. A host WinRM cannot reach (it is often off on workstations) is read over DCOM instead.
///   Manual, for one rule: its fallback_chain replaces the order for that rule's query only.
///   Pinned, for the whole integration: cimProtocol wsman or dcom tries that one transport and no other.
/// A transport that answers and refuses (access denied, a Kerberos or logon failure, a locked or expired account)
/// ends the walk: the refusal is reported as it is, with its kind, and never presented over another transport,
/// which would only repeat the failed logon towards a lockout. Remembering a refusal for the rest of the scan is the
/// scanner's job (LogonGuard and the failed open), not this class's.
/// The scan opens one session per host and every cim and registry query of the host reads over it; a probe
/// (TestConnection) on the way in is that session's first use, not a second sign-in.
/// The transport found is remembered per integration, identity, host and chain, so a second scan in the same process
/// does not try transports that already failed.
/// </summary>
internal static class CimSessions
{
    // Only the transport that worked. A failure is never cached here: a refusal must not be kept under a key that
    // outlives the credential, and an unreachable host is handled by the scanner (one failed open per host and scan).
    private static readonly ConcurrentDictionary<string, string> Routes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How long a first contact may take; the queries themselves get the integration's timeout per operation.</summary>
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

    /// <summary>The cache key of a route: one integration's identity on one host over one chain.</summary>
    public static string RouteKey(RunnerContext context, string host, IReadOnlyList<string> chain) =>
        $"{LogonGuard.KeyOf(context.Connection)}|{host}|{string.Join(',', chain)}";

    /// <summary>Opens the host's session for the scan (the cim and registry runners' OpenAsync).</summary>
    public static Task<IRunnerSession> OpenAsync(string protocol, RunnerContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            throw new RunnerFailureException($"{protocol} needs Windows", FailureKind.Error);
        if (string.IsNullOrWhiteSpace(context.Target))
            throw new RunnerFailureException($"{protocol} needs a target host", FailureKind.Error);
        return Task.Run(() => OperatingSystem.IsWindows() ? (IRunnerSession)Open(context.Target, context, null) : throw new PlatformNotSupportedException(), cancellationToken);
    }

    /// <summary>
    /// The session a query reads over. Normally the host's shared one. A rule whose fallback_chain differs from the
    /// chain the session was opened with gets a session of its own for that one query - rare, and one more sign-in,
    /// but ignoring the rule's chain would read it over a transport the rule excluded.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CimLease Lease(CimRunnerSession shared, string host, RunnerContext context, IReadOnlyList<string> ruleChain)
    {
        if (ruleChain.Count == 0 || ruleChain.SequenceEqual(shared.Chain, StringComparer.OrdinalIgnoreCase))
            return new CimLease(shared.Session, owned: false);
        return new CimLease(Open(host, context, ruleChain).Session, owned: true);
    }

    /// <summary>
    /// The stateless path (a runner used outside a scan): open a session, run the query on it, close it. Open failures
    /// come back as failed results with their kind.
    /// </summary>
    public static async Task<RunnerResult> OneShot(string protocol, RunnerContext context, CancellationToken cancellationToken,
        Func<IRunnerSession, Task<RunnerResult>> run)
    {
        IRunnerSession session;
        try
        {
            session = await OpenAsync(protocol, context, cancellationToken).ConfigureAwait(false);
        }
        catch (RunnerFailureException ex)
        {
            return RunnerResult.Failed(ex.Message, ex.Kind);
        }
        await using (session.ConfigureAwait(false))
            return await run(session).ConfigureAwait(false);
    }

    /// <summary>Signs in once and returns the session. Throws <see cref="RunnerFailureException"/> with the kind of the refusal.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static CimRunnerSession Open(string host, RunnerContext context, IReadOnlyList<string>? ruleChain)
    {
        var chain = ChainFor(context, ruleChain ?? []);
        var key = RouteKey(context, host, chain);
        var walk = Routes.TryGetValue(key, out var known) ? [known] : chain;

        CimSession? kept = null;
        CimException? first = null;
        RunnerFailureException? stop = null;
        var firstKind = FailureKind.Unreachable;
        var result = TransportChain.Resolve(walk, transport =>
        {
            var (session, error) = Connect(host, context, transport);
            if (error is null)
            {
                kept = session;
                return (Reach.Answered, null);
            }
            var kind = CimErrors.Of(error);
            if (CimErrors.EndsWalk(kind, (int)error.NativeErrorCode))
            {
                // The host answered: refused, denied, asked to slow down or found the request wrong. The same
                // credential is not presented again over the next transport.
                stop = new RunnerFailureException($"{host}: {error.Message}", kind, error);
                return (Reach.Refused, error.Message);
            }
            if (first is null)
            {
                first = error;
                firstKind = kind is FailureKind.Timeout ? FailureKind.Timeout : FailureKind.Unreachable;
            }
            return (Reach.Unreachable, error.Message);
        });
        if (stop is not null)
            throw stop;
        if (kept is null)
        {
            Routes.TryRemove(key, out _);
            throw new RunnerFailureException($"{host}: {first!.Message}", firstKind, first);
        }
        Routes[key] = result.Transport!;
        if (result.Transport != chain[0])
            context.Log($"{chain[0]} did not answer; reading over {result.Transport}");
        return new CimRunnerSession(kept, chain, result.Transport!);
    }

    /// <summary>
    /// Creates the session and makes first contact (this is the sign-in). Returns the session on success, otherwise why
    /// not. The session is created with a short timeout; every query then sets its own through CimOperationOptions.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static (CimSession? Session, CimException? Error) Connect(string host, RunnerContext context, string transport)
    {
        CimSession? session = null;
        try
        {
            session = Create(host, context, transport, ProbeTimeout < context.Timeout ? ProbeTimeout : context.Timeout);
            if (session.TestConnection(out _, out var error))
                return (session, null);
            session.Dispose();
            return (null, error);
        }
        catch (CimException ex)
        {
            session?.Dispose();
            return (null, ex);
        }
    }

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
