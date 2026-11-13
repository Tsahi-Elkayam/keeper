using Keeper.Runners;

namespace Keeper.Scan;

/// <summary>
/// The sessions one <c>keeper run</c> shares between its scans. A Windows host read by the baseline, services and
/// event-log systems through one integration is signed in to once, not once per system. A session goes back to the
/// pool when its host's reads are done; the next scan through the same integration takes it.
/// <para>
/// A session idle longer than <see cref="MaxIdle"/> is closed instead of reused (directories, sshd and SQL servers drop
/// idle connections, and a read over a dropped one fails); so is a session a read failed on. A session that could
/// not be opened is remembered for the same time: a host that did not answer is not asked again by every system.
/// </para>
/// Shared things that are not sessions (an integration's signed-in connection) are kept with <see cref="Shared{T}"/>
/// and ended, in the order they were added, when the run's scans are done.
/// </summary>
public sealed class RunSessions(TimeProvider? clock = null) : IAsyncDisposable
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly Lock _lock = new();
    private readonly Dictionary<(string Instance, string Host, string Family), Entry> _idle = [];
    private readonly Dictionary<string, (object Value, Func<ValueTask> End)> _shared = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _sharedOrder = [];
    private bool _disposed;

    /// <summary>The run being scanned in this process, if any: <c>keeper run</c> sets it around its scans.</summary>
    public static RunSessions? Current { get; set; }

    public TimeSpan MaxIdle { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Sessions handed out again (not opened again) over the run.</summary>
    public int Reused { get; private set; }

    private sealed record Entry(IRunnerSession? Session, RunnerResult? Failure, DateTimeOffset At);

    private static (string, string, string) Key(IConnection connection, string host, string family) =>
        (connection.Instance, host.ToUpperInvariant(), family);

    /// <summary>
    /// A session of this integration, host and family an earlier scan of the run left, or the failure its sign-in met;
    /// null when there is none, or it was idle too long (then it is closed here). A session is taken out: until it is
    /// handed back with <see cref="ReturnAsync"/> nobody else uses it. A failure stays for the next asker.
    /// </summary>
    public async Task<(IRunnerSession? Session, RunnerResult? Failure)?> TakeAsync(IConnection connection, string host, string family)
    {
        Entry? entry;
        var key = Key(connection, host, family);
        lock (_lock)
        {
            if (!_idle.TryGetValue(key, out entry))
                return null;
            var stale = _clock.GetUtcNow() - entry.At > MaxIdle;
            if (entry.Session is not null || stale)
                _idle.Remove(key);
            if (!stale)
            {
                Reused++;
                return (entry.Session, entry.Failure);
            }
        }
        await Close(entry.Session).ConfigureAwait(false);
        return null;
    }

    /// <summary>
    /// Hands a host's session back when its reads are done (or keeps the failure its sign-in met). A session a read
    /// failed on (<paramref name="healthy"/> false) is closed: the next scan signs in afresh.
    /// </summary>
    public async Task ReturnAsync(IConnection connection, string host, string family, IRunnerSession? session, RunnerResult? failure, bool healthy)
    {
        var key = Key(connection, host, family);
        IRunnerSession? close = null;
        lock (_lock)
        {
            if (_disposed || (session is not null && !healthy))
                close = session;
            else if (_idle.TryGetValue(key, out var there) && there.Session is not null && session is not null)
                close = session;   // two lanes of one scan reached the same host: keep one
            else if (session is not null || !_idle.ContainsKey(key))
                _idle[key] = new Entry(session, failure, _clock.GetUtcNow());
        }
        await Close(close).ConfigureAwait(false);
    }

    /// <summary>The value kept under <paramref name="key"/> for the run, made by <paramref name="create"/> the first time.</summary>
    public T Shared<T>(string key, Func<T> create, Func<T, ValueTask> end) where T : class
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_shared.TryGetValue(key, out var kept))
                return (T)kept.Value;
            var value = create();
            _shared[key] = (value, () => end(value));
            _sharedOrder.Add(key);
            return value;
        }
    }

    /// <summary>Whether <paramref name="value"/> is one this run keeps (and so ends itself).</summary>
    public bool Keeps(object value)
    {
        lock (_lock)
            return _shared.Values.Any(v => ReferenceEquals(v.Value, value));
    }

    /// <summary>Closes every session, then ends the shared values (sign-outs) - sessions first, they may use them.</summary>
    public async ValueTask DisposeAsync()
    {
        List<IRunnerSession> sessions;
        List<Func<ValueTask>> ends;
        lock (_lock)
        {
            if (_disposed)
                return;
            _disposed = true;
            sessions = [.. _idle.Values.Select(e => e.Session).OfType<IRunnerSession>()];
            _idle.Clear();
            ends = [.. _sharedOrder.Select(k => _shared[k].End)];
            _shared.Clear();
        }
        foreach (var session in sessions)
            await Close(session).ConfigureAwait(false);
        foreach (var end in ends)
        {
            try
            {
                await end().ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Ending a shared value (a sign-out) is best effort; its own end says what went wrong.
            catch (Exception)
#pragma warning restore CA1031
            {
            }
        }
    }

    private static async Task Close(IRunnerSession? session)
    {
        if (session is null)
            return;
        try
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Closing a session that already broke is not a failure of the run.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }
}
