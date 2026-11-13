using System.Collections.Concurrent;
using System.Net;

namespace Keeper.Discover;

public sealed class ScanWindowClosedException(string message) : Exception(message);

/// <summary>
/// Single safety gate for all discovery network activity.
/// Checks scan window, always-excluded classes, configured exclusions (by CIDR and hostname),
/// scope, credential CIDR scope, gentle-host rules, concurrency caps, and token-bucket rate limits
/// at the exact moment of dialing.
/// </summary>
public sealed class ProbeGate : IDisposable
{
    private readonly IDialer _dialer;
    private readonly DiscoveryTargets _targets;
    private readonly TimeProvider _clock;
    private readonly TimeZoneInfo _timeZone;
    private readonly bool _ignoreWindow;
    private readonly SemaphoreSlim _globalSemaphore;
    private readonly ConcurrentDictionary<IPAddress, SemaphoreSlim> _hostSemaphores = new();
    private readonly Lock _rateLock = new();
    private DateTimeOffset _nextTokenAt;

    public ProbeGate(
        IDialer dialer,
        DiscoveryTargets targets,
        TimeProvider? clock = null,
        TimeZoneInfo? timeZone = null,
        bool ignoreWindow = false)
    {
        _dialer = dialer;
        _targets = targets;
        _clock = clock ?? TimeProvider.System;
        _timeZone = timeZone ?? TimeZoneInfo.Utc;
        _ignoreWindow = ignoreWindow;
        _globalSemaphore = new SemaphoreSlim(Math.Max(1, targets.Rate.Concurrent), Math.Max(1, targets.Rate.Concurrent));
        _nextTokenAt = TimeProvider.System.GetUtcNow();
    }

    public TimeSpan Timeout => TimeSpan.FromMilliseconds(_targets.Rate.TimeoutMs);

    public bool IsGentle(IPAddress address) =>
        _targets.Gentle.Any(g => Addresses.Contains(g, address));

    public bool IsWithinWindow()
    {
        if (_ignoreWindow || _targets.Windows.Count == 0)
            return true;
        var localNow = TimeZoneInfo.ConvertTime(_clock.GetUtcNow(), _timeZone);
        return _targets.Windows.Any(w => w.Contains(localNow));
    }

    public void EnsureWindowOpen()
    {
        if (!IsWithinWindow())
            throw new ScanWindowClosedException("Current time is outside the configured discovery scan windows.");
    }

    /// <summary>Checks whether a hostname or address is excluded or out of scope before or at dial time.</summary>
    public (ProbeOutcomeKind? Refusal, string? Reason) CheckTarget(IPAddress? address, IEnumerable<string>? names = null)
    {
        if (names is not null)
        {
            foreach (var name in names)
            {
                if (MatchExcludedName(name, out var why))
                    return (ProbeOutcomeKind.Excluded, why);
            }
        }

        if (address is null)
            return (null, null);

        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (Addresses.IsAlwaysExcluded(norm, out var reservedReason))
            return (ProbeOutcomeKind.Excluded, $"reserved address class ({reservedReason})");

        foreach (var ex in _targets.Exclude)
        {
            if (ex.Cidr is { } cidr && Addresses.Contains(cidr, norm))
                return (ProbeOutcomeKind.Excluded, ex.Why ?? $"matches exclude CIDR {cidr}");
        }

        if ((_targets.Mode == "free" || _targets.Scope.Count > 0) && !_targets.Scope.Any(s => Addresses.Contains(s, norm)))
            return (ProbeOutcomeKind.OutOfScope, $"address {Addresses.Canonical(norm)} is outside configured scope");

        return (null, null);
    }

    /// <summary>
    /// A credential goes only where an 'approve' rule names that address range, that integration and that
    /// protocol (an approve rule with no protocols covers every protocol). No rule, no credential.
    /// </summary>
    public bool IsApproved(IPAddress address, string integrationId, string protocol)
    {
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return _targets.Approve.Any(rule =>
            rule.Integration.Equals(integrationId, StringComparison.OrdinalIgnoreCase)
            && Addresses.Contains(rule.Cidr, norm)
            && (rule.Protocols.Count == 0 || rule.Protocols.Contains(protocol, StringComparer.OrdinalIgnoreCase)));
    }

    /// <summary>Verifies that a credential scoped to an endpoint CIDR is allowed to be sent to <paramref name="address"/>.</summary>
    public bool AllowsCredential(IPAddress address, IPNetwork credentialScope, IEnumerable<string>? names, out string? reason)
    {
        var (refusal, refusalReason) = CheckTarget(address, names);
        if (refusal is not null)
        {
            reason = refusalReason;
            return false;
        }
        if (!Addresses.Contains(credentialScope, address))
        {
            reason = $"address {Addresses.Canonical(address)} is outside credential scope {credentialScope}";
            return false;
        }
        reason = null;
        return true;
    }

    public async Task<TcpDialResult> ConnectTcpAsync(
        IPAddress address,
        int port,
        IEnumerable<string>? names = null,
        CancellationToken cancellationToken = default)
    {
        EnsureWindowOpen();
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        var (refusal, reason) = CheckTarget(norm, names);
        if (refusal is not null)
            return new TcpDialResult(DialStates.RefusedByGate, null, null, reason);

        var hostSem = GetHostSemaphore(norm);
        await _globalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await hostSem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var attempts = 1 + Math.Max(0, _targets.Rate.Retries);
                TcpDialResult last = new(DialStates.Filtered, null, null, "not dialed");
                for (var attempt = 0; attempt < attempts; attempt++)
                {
                    EnsureWindowOpen();
                    await AcquireRateTokenAsync(cancellationToken).ConfigureAwait(false);
                    last = await _dialer.ConnectTcpAsync(norm, port, Timeout, cancellationToken).ConfigureAwait(false);
                    if (last.State != DialStates.Filtered)
                        return last;
                }
                return last;
            }
            finally
            {
                hostSem.Release();
            }
        }
        finally
        {
            _globalSemaphore.Release();
        }
    }

    public async Task<UdpDialResult> ExchangeUdpAsync(
        IPAddress address,
        int port,
        ReadOnlyMemory<byte> request,
        IPNetwork? credentialScope = null,
        IEnumerable<string>? names = null,
        CancellationToken cancellationToken = default)
    {
        EnsureWindowOpen();
        var norm = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (credentialScope is { } scope)
        {
            if (!AllowsCredential(norm, scope, names, out var credReason))
                return new UdpDialResult(DialStates.RefusedByGate, null, null, credReason);
        }
        else
        {
            var (refusal, reason) = CheckTarget(norm, names);
            if (refusal is not null)
                return new UdpDialResult(DialStates.RefusedByGate, null, null, reason);
        }

        if (IsGentle(norm))
            return new UdpDialResult(DialStates.RefusedByGate, null, null, "gentle range allows TCP connect only");

        var hostSem = GetHostSemaphore(norm);
        await _globalSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await hostSem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var attempts = 1 + Math.Max(0, _targets.Rate.Retries);
                UdpDialResult last = new(DialStates.Filtered, null, null, "not dialed");
                for (var attempt = 0; attempt < attempts; attempt++)
                {
                    EnsureWindowOpen();
                    await AcquireRateTokenAsync(cancellationToken).ConfigureAwait(false);
                    last = await _dialer.ExchangeUdpAsync(norm, port, request, Timeout, cancellationToken).ConfigureAwait(false);
                    if (last.State != DialStates.Filtered)
                        return last;
                }
                return last;
            }
            finally
            {
                hostSem.Release();
            }
        }
        finally
        {
            _globalSemaphore.Release();
        }
    }

    private SemaphoreSlim GetHostSemaphore(IPAddress address)
    {
        var maxPerHost = IsGentle(address) ? 1 : Math.Max(1, _targets.Rate.PerHost);
        return _hostSemaphores.GetOrAdd(address, _ => new SemaphoreSlim(maxPerHost, maxPerHost));
    }

    private async ValueTask AcquireRateTokenAsync(CancellationToken cancellationToken)
    {
        var cps = Math.Max(1, _targets.Rate.ConnectionsPerSecond);
        var step = TimeSpan.FromSeconds(1.0 / cps);
        TimeSpan wait;
        lock (_rateLock)
        {
            var now = TimeProvider.System.GetUtcNow();
            if (_nextTokenAt <= now)
            {
                _nextTokenAt = now + step;
                wait = TimeSpan.Zero;
            }
            else
            {
                wait = _nextTokenAt - now;
                _nextTokenAt += step;
            }
        }
        if (wait > TimeSpan.Zero)
            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
    }

    private bool MatchExcludedName(string name, out string? why)
    {
        var lower = name.Trim().ToLowerInvariant();
        foreach (var ex in _targets.Exclude)
        {
            if (ex.NamePattern is not { } pat)
                continue;
            var matches = pat.StartsWith("*.", StringComparison.Ordinal)
                ? lower.EndsWith(pat[1..], StringComparison.Ordinal) && lower.Length > pat.Length - 1
                : lower.Equals(pat, StringComparison.Ordinal);
            if (matches)
            {
                why = ex.Why ?? $"matches exclude name '{pat}'";
                return true;
            }
        }
        why = null;
        return false;
    }

    public void Dispose()
    {
        _globalSemaphore.Dispose();
        foreach (var sem in _hostSemaphores.Values)
            sem.Dispose();
    }
}
