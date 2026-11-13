using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners;

/// <summary>Why a read failed, as far as the scan's pace and the logon guard are concerned.</summary>
public enum FailureKind
{
    /// <summary>No failure, or one that says nothing about the host or the credential.</summary>
    None,

    /// <summary>Nothing answered: no listener, a firewall, no route, the name does not resolve.</summary>
    Unreachable,

    /// <summary>The credential itself was turned away: wrong password, locked, expired or disabled account. Never presented again.</summary>
    Refused,

    /// <summary>Signed in, but not allowed to read this here: access denied on one host or object.</summary>
    Denied,

    /// <summary>The host asked to slow down: 429, 503, busy, a quota, a reset connection.</summary>
    Throttled,

    /// <summary>The host did not answer in time.</summary>
    Timeout,

    /// <summary>Any other failure.</summary>
    Error,
}

/// <summary>A runner's failure with its kind, for code that has no <see cref="RunnerResult"/> to return (opening a session).</summary>
public sealed class RunnerFailureException(string message, FailureKind kind, Exception? inner = null) : Exception(message, inner)
{
    public FailureKind Kind { get; } = kind;
}

/// <summary>
/// The kind of a failure from the exceptions every runner meets: HTTP status, sockets, timeouts and Win32 codes.
/// A runner with its own codes (LDAP 49, SQL 18456, SSH authentication) classifies those itself first.
/// </summary>
public static class Failures
{
    /// <summary>Win32 errors that mean the account was turned away - each one a failed logon that counts towards a lockout.</summary>
    private static readonly HashSet<int> RefusedWin32 =
    [
        1326,   // ERROR_LOGON_FAILURE: unknown user name or bad password
        1327,   // ERROR_ACCOUNT_RESTRICTION
        1328,   // ERROR_INVALID_LOGON_HOURS
        1329,   // ERROR_INVALID_WORKSTATION
        1330,   // ERROR_PASSWORD_EXPIRED
        1331,   // ERROR_ACCOUNT_DISABLED
        1793,   // ERROR_ACCOUNT_EXPIRED
        1907,   // ERROR_PASSWORD_MUST_CHANGE
        1909,   // ERROR_ACCOUNT_LOCKED_OUT
        1385,   // ERROR_LOGON_TYPE_NOT_GRANTED
        1311,   // ERROR_NO_LOGON_SERVERS
    ];

    private static readonly HashSet<int> UnreachableWin32 = [53, 67, 1203, 1214, 1722, 1727, 1753, 2250];
    private static readonly HashSet<int> TimeoutWin32 = [121, 1460];
    private static readonly HashSet<int> ThrottledWin32 = [1450, 1453, 1454, 1723, 1818];

    /// <summary>Phrases (English Windows and common servers) that name a refused account. Codes are preferred; these catch wrapped messages.</summary>
    private static readonly string[] RefusedPhrases =
    [
        "logon failure", "user name or password is incorrect", "invalid credentials", "account is locked", "account has been locked",
        "locked out", "password has expired", "password expired", "account is disabled", "account disabled", "account has expired",
        "authentication failed", "permission denied (publickey", "login failed for user",
    ];

    /// <summary>The kind of a Win32 or HRESULT error code, or null when the code says nothing.</summary>
    public static FailureKind? OfWin32(int code)
    {
        // SSPI SEC_E_LOGON_DENIED: the logon was denied - a wrong password over Kerberos or NTLM.
        if (code == unchecked((int)0x8009030C))
            return FailureKind.Refused;
        // An HRESULT that wraps a Win32 error (0x8007xxxx) carries the Win32 code in its low word.
        if ((code & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000))
            code &= 0xFFFF;
        if (RefusedWin32.Contains(code))
            return FailureKind.Refused;
        if (code == 5)
            return FailureKind.Denied;
        if (UnreachableWin32.Contains(code))
            return FailureKind.Unreachable;
        if (TimeoutWin32.Contains(code))
            return FailureKind.Timeout;
        if (ThrottledWin32.Contains(code))
            return FailureKind.Throttled;
        return null;
    }

    /// <summary>The kind of an HTTP status.</summary>
    public static FailureKind OfStatus(int status) => status switch
    {
        401 => FailureKind.Refused,
        403 => FailureKind.Denied,
        408 or 504 => FailureKind.Timeout,
        429 or 503 => FailureKind.Throttled,
        _ => FailureKind.Error,
    };

    /// <summary>Whether a message names a refused account, in the phrases servers commonly use.</summary>
    public static bool SaysRefused(string? message) =>
        message is not null && RefusedPhrases.Any(p => message.Contains(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The kind of an exception, walking its inner exceptions. A typed answer anywhere in the chain (a status, a code,
    /// a kind a runner set) wins over words in a message: an outer message often repeats an inner one's text. A TLS
    /// handshake that failed ("authentication failed because the remote party sent a TLS alert") never presented a
    /// credential, so it is not a refusal.
    /// </summary>
    public static FailureKind Classify(Exception? exception)
    {
        if (Typed(exception) is { } typed)
            return typed;
        for (var ex = exception; ex is not null; ex = ex.InnerException)
        {
            if (ex is System.Security.Authentication.AuthenticationException)
                return FailureKind.Error;
        }
        for (var ex = exception; ex is not null; ex = ex.InnerException)
        {
            if (SaysRefused(ex.Message))
                return FailureKind.Refused;
        }
        return FailureKind.Error;
    }

    private static FailureKind? Typed(Exception? exception)
    {
        for (var ex = exception; ex is not null; ex = ex.InnerException)
        {
            switch (ex)
            {
                case RunnerFailureException failure:
                    return failure.Kind;
                case HttpRequestException { StatusCode: { } status }:
                    return OfStatus((int)status);
                case TimeoutException or TaskCanceledException:
                    return FailureKind.Timeout;
                case SocketException socket:
                    return socket.SocketErrorCode switch
                    {
                        SocketError.TimedOut => FailureKind.Timeout,
                        SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.TooManyOpenSockets => FailureKind.Throttled,
                        _ => FailureKind.Unreachable,
                    };
                case UnauthorizedAccessException:
                    return FailureKind.Denied;
                case Win32Exception win32 when OfWin32(win32.NativeErrorCode) is { } kind:
                    return kind;
                case IOException io when OfWin32(io.HResult) is { } kind:
                    return kind;
            }
        }
        return null;
    }
}

/// <summary>
/// How hard a scan may read an estate. What set off the pilot's defences was logons and new connections, so
/// those have their own rate; calls on an open session have a looser one.
/// </summary>
public sealed record PaceProfile(string Name, int Hosts, double SessionsPerSecond, double RequestsPerSecond, int StopAfter)
{
    public static readonly PaceProfile Gentle = new("gentle", 4, 1, 10, 3);
    public static readonly PaceProfile Normal = new("normal", 8, 4, 25, 5);
    public static readonly PaceProfile Fast = new("fast", 16, 16, 100, 8);

    /// <summary>No waiting at all: for tests and for runners that read local files.</summary>
    public static readonly PaceProfile Unlimited = new("unlimited", 64, 0, 0, int.MaxValue);

    /// <summary>The longest a host's interval grows to when it keeps pushing back.</summary>
    public static readonly TimeSpan MaxInterval = TimeSpan.FromSeconds(30);

    public static PaceProfile Named(string name) => name.ToLowerInvariant() switch
    {
        "gentle" => Gentle,
        "normal" => Normal,
        "fast" => Fast,
        _ => throw new ArgumentException($"pace must be gentle, normal or fast, not '{name}'."),
    };

    /// <summary>
    /// The profile an integration asks for: option <c>pace</c> (a name), then single keys <c>pace.hosts</c>,
    /// <c>pace.sessionsPerSecond</c>, <c>pace.requestsPerSecond</c>, <c>pace.stopAfter</c>. Gentle when nothing is set.
    /// <paramref name="overrideName"/> (the command line's --pace) wins over the option's name; single keys still apply.
    /// </summary>
    public static PaceProfile From(JsonObject options, string? overrideName = null)
    {
        var name = overrideName ?? options["pace"]?.ToString();
        var profile = string.IsNullOrWhiteSpace(name) ? Gentle : Named(name);
        if (Number(options, "pace.hosts", 1, 256) is { } hosts)
            profile = profile with { Name = profile.Name + "*", Hosts = (int)hosts };
        if (Number(options, "pace.sessionsPerSecond", 0.01, 1000) is { } sessions)
            profile = profile with { Name = profile.Name.TrimEnd('*') + "*", SessionsPerSecond = sessions };
        if (Number(options, "pace.requestsPerSecond", 0.01, 10000) is { } requests)
            profile = profile with { Name = profile.Name.TrimEnd('*') + "*", RequestsPerSecond = requests };
        if (Number(options, "pace.stopAfter", 1, 1000) is { } stop)
            profile = profile with { Name = profile.Name.TrimEnd('*') + "*", StopAfter = (int)stop };
        return profile;
    }

    private static double? Number(JsonObject options, string key, double min, double max)
    {
        if (options[key] is not { } node)
            return null;
        if (!double.TryParse(node.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || value < min || value > max)
            throw new ArgumentException($"{key} must be a number from {min} to {max}, not '{node}'.");
        return value;
    }

    public override string ToString() => this == Unlimited
        ? "unlimited"
        : $"{Name} ({Hosts} hosts at once, {SessionsPerSecond:0.##} new sessions/s, {RequestsPerSecond:0.##} requests/s per host, stop a host after {StopAfter} push-backs)";
}

/// <summary>What a runner calls before each network request it sends to its host, and tells about the answers.</summary>
public interface IPace
{
    /// <summary>Waits until the host may be sent the next request. Call before each request, page or method call.</summary>
    Task WaitAsync(CancellationToken cancellationToken);

    /// <summary>What an answer said about the host: Throttled or Timeout slow it down; None lets it speed up again.</summary>
    void Signal(FailureKind kind);
}

/// <summary>No pacing: what a runner sees outside a scan (tests, one-off reads).</summary>
public sealed class NoPace : IPace
{
    public static readonly NoPace Instance = new();

    public Task WaitAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Signal(FailureKind kind)
    {
    }
}

/// <summary>
/// The scan's pace: a minimum interval between requests to one host that doubles while the host pushes back and
/// eases off again, a global rate of new sessions, and a host stopped after <see cref="PaceProfile.StopAfter"/>
/// push-backs in a row. Thread-safe.
/// </summary>
public sealed class Pacer(PaceProfile profile, TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Dictionary<string, HostState> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();
    private DateTimeOffset _nextSession = DateTimeOffset.MinValue;

    public PaceProfile Profile { get; } = profile;

    /// <summary>
    /// When the integration's scan window closes: from then on every host counts as stopped, so the reads not made by
    /// then are failed (never empty) and a read in flight ends at its next request. Null: no window.
    /// </summary>
    public DateTimeOffset? Until { get; init; }

    /// <summary>Whether the scan window closed while hosts were still to be read.</summary>
    public bool WindowClosed { get; private set; }

    private sealed class HostState
    {
        public DateTimeOffset Next = DateTimeOffset.MinValue;
        public double Factor = 1;
        public int Streak;
        public int Signals;
        public int AtMax;
        public string? Stopped;
    }

    /// <summary>
    /// Requests in a row a host may be read at the longest interval before it is stopped. A host whose reads succeed
    /// only after a runner's own retries never builds a streak of failed reads, but must not hold the scan for hours.
    /// </summary>
    public const int MaxSlowRequests = 20;

    private TimeSpan BaseInterval => Profile.RequestsPerSecond <= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(1 / Profile.RequestsPerSecond);

    /// <summary>The pace one host's requests go through.</summary>
    public IPace For(string host) => new HostPace(this, host);

    /// <summary>Waits for a slot to open a new session (a logon, a new connection), across the whole scan.</summary>
    public async Task WaitSessionAsync(CancellationToken cancellationToken)
    {
        if (Profile.SessionsPerSecond <= 0)
            return;
        TimeSpan wait;
        lock (_lock)
        {
            var now = _clock.GetUtcNow();
            var slot = _nextSession > now ? _nextSession : now;
            _nextSession = slot + TimeSpan.FromSeconds(1 / Profile.SessionsPerSecond);
            wait = slot - now;
        }
        if (wait > TimeSpan.Zero)
            await Task.Delay(wait, _clock, cancellationToken).ConfigureAwait(false);
    }

    public async Task WaitAsync(string host, CancellationToken cancellationToken)
    {
        TimeSpan wait;
        lock (_lock)
        {
            var state = State(host);
            var now = _clock.GetUtcNow();
            var slot = state.Next > now ? state.Next : now;
            var interval = BaseInterval * state.Factor;
            // Only a host that pushed the interval up counts: an operator's own slow pace (requestsPerSecond 0.01) is not a push-back.
            if (interval >= PaceProfile.MaxInterval && BaseInterval > TimeSpan.Zero && state.Factor > 1)
            {
                interval = PaceProfile.MaxInterval;
                if (++state.AtMax >= MaxSlowRequests && state.Stopped is null)
                    state.Stopped = $"{host} kept asking to slow down: {state.AtMax} requests in a row {PaceProfile.MaxInterval.TotalSeconds:0} s apart - " +
                                    "Keeper stopped reading it to spare it";
            }
            else
                state.AtMax = 0;
            state.Next = slot + interval;
            wait = slot - now;
        }
        if (wait > TimeSpan.Zero)
            await Task.Delay(wait, _clock, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// What an answer said about the host. <paramref name="countsTowardsStop"/>: the scanner's verdict on a whole read
    /// counts towards stopping the host; a runner's own signal (a 429 it retries) only slows the host down, so one
    /// throttled read retried three times is one push-back, not three.
    /// </summary>
    public void Signal(string host, FailureKind kind, bool countsTowardsStop = true)
    {
        lock (_lock)
        {
            var state = State(host);
            // A runner's clean answer inside one long read (a for_each child) lets the host speed up again, without
            // touching the scanner's streak of failed whole reads.
            if (kind is FailureKind.None && !countsTowardsStop)
            {
                state.Factor = Math.Max(1, state.Factor * 0.75);
                return;
            }
            if (kind is FailureKind.Throttled or FailureKind.Timeout && !countsTowardsStop)
            {
                if (BaseInterval > TimeSpan.Zero)
                    state.Factor = Math.Min(state.Factor * 2, Math.Max(1, PaceProfile.MaxInterval / BaseInterval));
                return;
            }
            if (kind is FailureKind.Throttled or FailureKind.Timeout)
            {
                state.Signals++;
                state.Streak++;
                if (BaseInterval > TimeSpan.Zero)
                    state.Factor = Math.Min(state.Factor * 2, Math.Max(1, PaceProfile.MaxInterval / BaseInterval));
                if (state.Streak >= Profile.StopAfter && state.Stopped is null)
                    state.Stopped = $"{host} pushed back {state.Streak} times in a row ({(kind == FailureKind.Timeout ? "no answer in time" : "asked to slow down")}) - " +
                                    "Keeper stopped reading it to spare it";
            }
            else if (kind is FailureKind.None)
            {
                state.Streak = 0;
                state.Factor = Math.Max(1, state.Factor * 0.75);
            }
        }
    }

    /// <summary>Why the host is no longer read in this scan, or null.</summary>
    public string? Stopped(string host)
    {
        lock (_lock)
        {
            if (_hosts.TryGetValue(host, out var state) && state.Stopped is not null)
                return state.Stopped;
            if (Until is { } until && _clock.GetUtcNow() >= until)
            {
                WindowClosed = true;
                return $"the integration's scan window closed at {until:yyyy-MM-dd HH:mm zzz}";
            }
            return null;
        }
    }

    /// <summary>Why the host itself made the pace stop reading it (push-backs), or null - not the scan window.</summary>
    public string? StoppedByHost(string host)
    {
        lock (_lock)
            return _hosts.TryGetValue(host, out var state) ? state.Stopped : null;
    }

    /// <summary>Stops reading a host for a reason found before this scan (an earlier scan of the run stopped it).</summary>
    public void Stop(string host, string reason)
    {
        lock (_lock)
            State(host).Stopped ??= reason;
    }

    /// <summary>Hosts that pushed back at least once, with the number of times, and whether they were stopped.</summary>
    public IReadOnlyList<(string Host, int Signals, bool Stopped)> PushedBack()
    {
        lock (_lock)
            return [.. _hosts.Where(h => h.Value.Signals > 0 || h.Value.Stopped is not null).OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase)
                .Select(h => (h.Key, h.Value.Signals, h.Value.Stopped is not null))];
    }

    private HostState State(string host)
    {
        if (!_hosts.TryGetValue(host, out var state))
            _hosts[host] = state = new HostState();
        return state;
    }

    /// <summary>
    /// The pace a runner gets. Once the host is stopped, a read still in flight (a for_each with hundreds of children)
    /// is ended too: its next request throws a Throttled failure instead of waiting its turn.
    /// </summary>
    private sealed class HostPace(Pacer pacer, string host) : IPace
    {
        public Task WaitAsync(CancellationToken cancellationToken) =>
            pacer.Stopped(host) is { } stopped
                ? throw new RunnerFailureException($"not read: {stopped}", FailureKind.Throttled)
                : pacer.WaitAsync(host, cancellationToken);

        public void Signal(FailureKind kind) => pacer.Signal(host, kind, countsTowardsStop: false);
    }
}

/// <summary>
/// Credentials that were turned away. A refused credential is never presented again while the process lives -
/// so across the systems of one <c>keeper run</c> - because every further try counts towards the account's
/// lockout, and AD may lock at three. Thread-safe.
/// </summary>
public sealed class LogonGuard
{
    /// <summary>The guard of this process: what <c>keeper scan</c> and <c>keeper run</c> share.</summary>
    public static LogonGuard Process { get; } = new();

    private readonly Dictionary<string, string> _refused = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _strikes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _accepted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _deniedAllowed = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _earlierStrikes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    /// <summary>
    /// Sign-ins answered "access denied", on different hosts in a row and with no sign-in accepted in between, that
    /// make a refusal. Over DCOM a wrong password can come back as plain access denied: without this, every host
    /// would see the wrong password once.
    /// </summary>
    public const int DeniedSignInsBeforeRefusal = 2;

    /// <summary>
    /// The credential's key. A Windows account is one account whichever integration presents it (ldap, cim, smb and
    /// sql integrations often share one reader): EXAMPLE\reader and reader@example.org are the same key. Other
    /// identities are per integration - "admin" on two appliances are two accounts.
    /// </summary>
    public static string KeyOf(IConnection connection)
    {
        if (connection.Identity is { Length: > 0 } identity && connection.AuthKind is "windows-credential" or "negotiate")
        {
            var name = identity.Contains('\\', StringComparison.Ordinal) ? identity[(identity.LastIndexOf('\\') + 1)..]
                : identity.Contains('@', StringComparison.Ordinal) ? identity[..identity.IndexOf('@')]
                : identity;
            return $"windows|{name.ToLowerInvariant()}";
        }
        return $"{connection.Instance}|{connection.Identity ?? "(current user)"}";
    }

    /// <summary>
    /// Whether the integration presents a secret Keeper holds - a password, a key, a token - so a wrong one counts
    /// towards a lockout. Not for auth none (nothing is presented) or negotiate (the Windows user Keeper runs as,
    /// whose ticket is not a password Keeper could have wrong): the guard leaves those alone.
    /// </summary>
    public static bool PresentsSecret(IConnection connection) => connection.AuthKind is not ("none" or "negotiate" or "");

    /// <summary>
    /// What a proof is kept under: the integration and its credential key. A refusal is per account (the account is
    /// what locks), but a proof is per integration: two integrations may hold different passwords for one account,
    /// and one that works says nothing about the other.
    /// </summary>
    private static string ProofOf(IConnection connection) => $"{connection.Instance}|{KeyOf(connection)}";

    /// <summary>
    /// The account's domain locks after so few bad passwords that <see cref="DeniedSignInsBeforeRefusal"/> denials could
    /// lock it: at most <paramref name="allowed"/> are risked (never fewer than one - Keeper cannot tell a denial from a
    /// wrong password without trying once). From the lockout policy an Active Directory scan stored.
    /// </summary>
    public void LimitDeniedSignIns(IConnection connection, int allowed)
    {
        // Only ever lowered: EXAMPLE\reader and OTHER\reader are one key, and the stricter domain must win.
        var limit = Math.Clamp(allowed, 1, DeniedSignInsBeforeRefusal);
        lock (_lock)
            _deniedAllowed[KeyOf(connection)] = Math.Min(limit, _deniedAllowed.GetValueOrDefault(KeyOf(connection), limit));
    }

    /// <summary>
    /// Called when a sign-in is answered "access denied" and that did not (yet) make a refusal: the binary keeps the
    /// strike in the Keeper home, so the next process counts it. Otherwise a wrong password that DCOM answers as plain
    /// access denied would cost one bad logon per scheduled scan, for ever, and lock the account.
    /// </summary>
    public Action<IConnection, string>? OnStrike { get; set; }

    /// <summary>
    /// Denied sign-ins earlier processes met with this integration's credential, none accepted since. Taken once per
    /// process and integration: the strikes this process adds are counted as they happen.
    /// </summary>
    public void RestoreStrikes(IConnection connection, int earlier)
    {
        if (!PresentsSecret(connection))
            return;
        string? text = null;
        lock (_lock)
        {
            // The baseline is taken once even when it is none: a later scan of this process would otherwise read back
            // the strikes this process wrote and count them twice.
            var key = ProofOf(connection);
            if (_accepted.Contains(key) || !_earlierStrikes.TryAdd(key, Math.Max(0, earlier)))
                return;
            if (earlier > 0 && earlier >= _deniedAllowed.GetValueOrDefault(KeyOf(connection), DeniedSignInsBeforeRefusal))
                text = $"not tried: {connection.Identity ?? "the current user"} was denied at sign-in {earlier} time(s) by earlier scans with no host " +
                       "accepting it - a wrong password can look like that, so Keeper stops using it so the account is not locked out; " +
                       "check the credential and its rights, then scan again";
        }
        if (text is not null)
            Record(connection, text);
    }

    /// <summary>How many sign-ins answered "access denied" make this account's credential refused.</summary>
    public int DeniedSignInsFor(IConnection connection)
    {
        lock (_lock)
            return _deniedAllowed.GetValueOrDefault(KeyOf(connection), DeniedSignInsBeforeRefusal);
    }

    /// <summary>Called once per credential, when it is first refused: the binary keeps it in the Keeper home right away.</summary>
    public Action<IConnection, string>? OnRefused { get; set; }

    /// <summary>Whether a sign-in with this credential has been accepted in this process: until then, sign-ins go one at a time.</summary>
    public bool Proven(IConnection connection)
    {
        lock (_lock)
            return _accepted.Contains(ProofOf(connection));
    }

    /// <summary>A sign-in was accepted: the credential works, and "access denied" at sign-in is from now on about the host.</summary>
    public void Accepted(IConnection connection)
    {
        bool first;
        lock (_lock)
        {
            first = _accepted.Add(ProofOf(connection));
            _strikes.Remove(ProofOf(connection));
            _earlierStrikes[ProofOf(connection)] = 0;
        }
        if (first)
            OnProven?.Invoke(connection);
    }

    /// <summary>Called the first time a credential is accepted: the binary forgets its kept strikes right away.</summary>
    public Action<IConnection>? OnProven { get; set; }

    /// <summary>A sign-in was answered "access denied". Returns true when that made the credential refused.</summary>
    public bool DeniedAtSignIn(IConnection connection, string host, string reason)
    {
        if (!PresentsSecret(connection))
            return false;
        string? text;
        lock (_lock)
        {
            var key = ProofOf(connection);
            // Once a sign-in was accepted the password is right: a host that denies it is one where the account lacks the right.
            if (_accepted.Contains(key))
                return false;
            if (!_strikes.TryGetValue(key, out var hosts))
                _strikes[key] = hosts = [];
            if (hosts.Contains(host, StringComparer.OrdinalIgnoreCase))
                return false;   // the lane does not sign in to a host twice; nothing new was presented
            hosts.Add(host);
            var earlier = _earlierStrikes.GetValueOrDefault(key);
            if (earlier + hosts.Count < _deniedAllowed.GetValueOrDefault(KeyOf(connection), DeniedSignInsBeforeRefusal))
            {
                text = null;
            }
            else
            {
                text = $"not tried: {connection.Identity ?? "the current user"} was denied at sign-in by {string.Join(" and ", hosts)}" +
                       (earlier > 0 ? $" and {earlier} time(s) by earlier scans" : "") + $" with no host accepting it ({reason}) - " +
                       "a wrong password can look like that, so Keeper stops using it so the account is not locked out; check the credential and its rights, then scan again";
            }
        }
        if (text is null)
        {
            OnStrike?.Invoke(connection, host);
            return false;
        }
        Record(connection, text);
        return true;
    }

    /// <summary>Why this integration's credential is not used again, or null when it may be.</summary>
    public string? Refusal(IConnection connection)
    {
        lock (_lock)
            return _refused.TryGetValue(KeyOf(connection), out var reason) ? reason : null;
    }

    /// <summary>Records a refusal; the first one is the one reported.</summary>
    public void Refuse(IConnection connection, string? host, string reason)
    {
        if (PresentsSecret(connection))
            Record(connection, $"not tried: {connection.Identity ?? "the current user"} was refused{(host is null ? "" : $" by {host}")} ({reason}) - " +
                   "Keeper stops using it so the account is not locked out; fix the credential, then scan again");
    }

    private void Record(IConnection connection, string text)
    {
        bool added;
        lock (_lock)
            added = _refused.TryAdd(KeyOf(connection), text);
        if (added)
            OnRefused?.Invoke(connection, text);
    }

    /// <summary>A refusal recorded by an earlier process (the Keeper home keeps them), restored as it was written.</summary>
    public void Restore(IConnection connection, string reason)
    {
        lock (_lock)
            _refused.TryAdd(KeyOf(connection), reason);
    }

    public IReadOnlyList<string> Refusals
    {
        get
        {
            lock (_lock)
                return [.. _refused.Values];
        }
    }
}

/// <summary>
/// A runner that keeps one session per host (or per integration, when it is not per-target) for the whole scan:
/// one logon, then every query of that host over it. Runners whose sessions are interchangeable share a family -
/// the registry and cim runners share one CIM session.
/// </summary>
public interface ISessionRunner : IRunner
{
    /// <summary>Runners with the same family share a host's session.</summary>
    string SessionFamily { get; }

    /// <summary>Opens and signs in. Throws <see cref="RunnerFailureException"/> (or the protocol's own exception) when it cannot.</summary>
    Task<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken cancellationToken);

    /// <summary>Runs a query over an open session of this runner's family.</summary>
    Task<RunnerResult> RunAsync(IRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken);
}

/// <summary>An open, signed-in session. Disposed when its host's queries are done.</summary>
public interface IRunnerSession : IAsyncDisposable;

/// <summary>
/// A runner that can serve several queries of one host with fewer reads: registry queries on the same key become
/// one read of the union of their values. The scanner cuts each original query's rows back out with <see cref="Split"/>.
/// </summary>
public interface IQueryMerger
{
    /// <summary>A grouping key: queries with the same key may be merged; null when this query is read on its own.</summary>
    string? MergeKey(QuerySpec query);

    /// <summary>The one query that reads what all of these read (all have the same merge key).</summary>
    QuerySpec Merge(IReadOnlyList<QuerySpec> queries);

    /// <summary>The original query's part of the merged result: its own fields only, and partial only for its own reasons.</summary>
    RunnerResult Split(QuerySpec original, RunnerResult merged);
}
