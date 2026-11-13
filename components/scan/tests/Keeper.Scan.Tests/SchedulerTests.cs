using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Contracts;
using Keeper.Rules;
using Keeper.Runners;

namespace Keeper.Scan.Tests;

/// <summary>
/// The scan's pace and logon safety: one session per host, a refused credential never presented again, a host that
/// pushes back slowed and then stopped, merged reads, hosts read once. What locked the first pilot out.
/// </summary>
public sealed class SchedulerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-sched-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Runs => Path.Combine(_dir, "runs");

    private sealed class Connection(string identity = "EXAMPLE\\reader", string authKind = "windows-credential") : IConnection
    {
        public string Instance => "win-main";
        public string Type => "cim";
        public string Endpoint => "";
        public string AuthKind => authKind;
        public string? Identity => identity;
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    /// <summary>
    /// A per-host runner with sessions that records every open, read and close. <paramref name="open"/> decides how a
    /// host's sign-in goes; <paramref name="read"/> how a read goes. Optionally merges queries with the same "path".
    /// </summary>
    private sealed class SessionRunner(Func<string, FailureKind> open, Func<string, QuerySpec, RunnerResult>? read = null, bool merge = false,
        bool deniedMayBeSignIn = true)
        : ISessionRunner, IQueryMerger
    {
        /// <summary>Like CIM over DCOM by default: access denied can be a wrong password.</summary>
        public bool DeniedMayBeSignIn => deniedMayBeSignIn;

        public ConcurrentQueue<string> Log { get; } = new();
        public int Opens => Log.Count(l => l.StartsWith("open ", StringComparison.Ordinal));
        public int Reads => Log.Count(l => l.StartsWith("read ", StringComparison.Ordinal));
        public int Closes => Log.Count(l => l.StartsWith("close ", StringComparison.Ordinal));
        private int _inFlight;
        private readonly ConcurrentDictionary<string, int> _perHost = new();
        public int MaxInFlight { get; private set; }
        public int MaxPerHost { get; private set; }

        public string Protocol => "winreg";
        public bool PerTarget => true;
        public string SessionFamily => "cim";
        public IEnumerable<string> Validate(QuerySpec query) => [];

        public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("a session runner is read over its session");

        private sealed class Session(string host, ConcurrentQueue<string> log) : IRunnerSession
        {
            public string Host { get; } = host;
            public bool Closed { get; private set; }

            public ValueTask DisposeAsync()
            {
                Assert.False(Closed);   // closed once, by whoever owns it
                Closed = true;
                log.Enqueue($"close {Host}");
                return ValueTask.CompletedTask;
            }
        }

        public Task<IRunnerSession> OpenAsync(RunnerContext context, CancellationToken cancellationToken)
        {
            var host = context.Target!;
            Log.Enqueue($"open {host}");
            var kind = open(host);
            if (kind != FailureKind.None)
                throw new RunnerFailureException($"{host}: sign-in failed ({kind})", kind);
            return Task.FromResult<IRunnerSession>(new Session(host, Log));
        }

        public async Task<RunnerResult> RunAsync(IRunnerSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
        {
            var host = ((Session)session).Host;
            Assert.False(((Session)session).Closed);
            Assert.Equal(context.Target, host, ignoreCase: true);   // one session per host, whichever spelling opened it
            var now = Interlocked.Increment(ref _inFlight);
            var onHost = _perHost.AddOrUpdate(host, 1, (_, n) => n + 1);
            lock (Log)
            {
                MaxInFlight = Math.Max(MaxInFlight, now);
                MaxPerHost = Math.Max(MaxPerHost, onHost);
            }
            await Task.Delay(2, cancellationToken);
            Log.Enqueue($"read {context.Target} {query.Text("path")} {string.Join(",", query.List("values"))}");
            _perHost.AddOrUpdate(host, 0, (_, n) => n - 1);
            Interlocked.Decrement(ref _inFlight);
            return read?.Invoke(host, query) ?? RunnerResult.Ok(
                [new JsonObject { ["host"] = context.Target, ["key"] = query.Text("path"), ["value"] = 1 }]);
        }

        public string? MergeKey(QuerySpec query) => merge ? query.Text("path") : null;

        public QuerySpec Merge(IReadOnlyList<QuerySpec> queries)
        {
            var fields = (JsonObject)queries[0].Fields.DeepClone();
            fields["values"] = new JsonArray([.. queries.SelectMany(q => q.List("values")).Distinct().Select(v => (JsonNode)v)]);
            return new QuerySpec(queries[0].Protocol, fields, queries[0].Key, queries[0].Name);
        }

        public RunnerResult Split(QuerySpec original, RunnerResult merged) =>
            merged with { Rows = [.. merged.Rows.Select(r => new JsonObject { ["host"] = r["host"]?.DeepClone(), ["key"] = r["key"]?.DeepClone(), ["mine"] = string.Join(",", original.List("values")) })] };
    }

    /// <summary>A file of <paramref name="queries"/> registry-like rules on <paramref name="hosts"/>; the first two share a path when <paramref name="sharedPath"/>.</summary>
    private RuleFile Rules(int queries, IReadOnlyList<string> hosts, RunnerRegistry registry, bool sharedPath = false)
    {
        var rules = string.Join("\n", Enumerable.Range(1, queries).Select(i => $$"""
              - id: R-{{i}}
                title: Rule {{i}}
                query: { protocol: winreg, path: '{{(sharedPath && i <= 2 ? "SHARED" : $"P{i}")}}', values: ['V{{i}}'], key: host }
                each: { field: value, op: eq, value: 0 }
            """));
        var path = Path.Combine(_dir, "rules.yaml");
        File.WriteAllText(path, $$"""
            schema: keeper.rules/1
            system: winbase
            integration: cim
            targets: { list: [{{string.Join(", ", hosts)}}] }
            defaults: { lens: security, refresh: 1d, category: CFG, kind: misconfigured, severity: medium, entity: computer }
            rules:
            {{rules}}
            """);
        return RuleLoader.LoadFile(path, "test", registry.Validators);
    }

    private async Task<ScanReport> Scan(SessionRunner runner, int queries, IReadOnlyList<string> hosts, PaceProfile? pace = null,
        LogonGuard? guard = null, bool sharedPath = false, IConnection? connection = null, RunSessions? sessions = null)
    {
        var registry = new RunnerRegistry([runner]);
        return await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [Rules(queries, hosts, registry, sharedPath)],
            Connection = connection ?? new Connection(),
            RunsDir = Runs,
            ImportsDir = _dir,
            Pace = pace ?? PaceProfile.Unlimited,
            Guard = guard ?? new LogonGuard(),
            Sessions = sessions,
        }, CancellationToken.None);
    }

    private List<CoverageRecord> Coverage(ScanReport report) =>
        [.. JsonLines.Read<CoverageRecord>(Path.Combine(Runs, report.Manifest.RunId, "coverage.jsonl"))];

    private static readonly string[] ThreeHosts = ["pc01.example.org", "pc02.example.org", "pc03.example.org"];

    [Fact]
    public async Task Every_query_of_a_host_goes_over_one_session_opened_once()
    {
        var runner = new SessionRunner(_ => FailureKind.None);

        var report = await Scan(runner, queries: 40, ThreeHosts);

        Assert.Equal("ok", report.Manifest.Status);
        Assert.Equal(3, runner.Opens);                       // one sign-in per host, not one per query (was 120)
        Assert.Equal(120, runner.Reads);
        Assert.Equal(3, report.Cost.Sessions);
        Assert.Contains(report.Manifest.Notes, n => n.Contains("3 session(s) opened on 3 host(s)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_systems_of_one_run_share_a_host_s_session()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var run = new RunSessions();

        await Scan(runner, queries: 5, ThreeHosts, sessions: run);           // the baseline system
        var second = await Scan(runner, queries: 5, ThreeHosts, sessions: run);   // the services system, same integration

        Assert.Equal(3, runner.Opens);                       // one sign-in per host in the run, not per system (was 6)
        Assert.Equal(30, runner.Reads);
        Assert.Equal(0, runner.Closes);                      // the run keeps them until its scans are done
        Assert.Equal(0, second.Cost.Sessions);
        Assert.Equal(3, second.Cost.Reused);
        Assert.Contains(second.Manifest.Notes, n => n.Contains("3 kept from this run's earlier scans", StringComparison.Ordinal));

        await run.DisposeAsync();
        Assert.Equal(3, runner.Closes);
    }

    [Fact]
    public async Task A_scan_of_its_own_closes_its_sessions()
    {
        var runner = new SessionRunner(_ => FailureKind.None);

        await Scan(runner, queries: 2, ThreeHosts);

        Assert.Equal(3, runner.Closes);
    }

    [Fact]
    public async Task A_session_idle_too_long_is_closed_and_signed_in_again()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var clock = new Settable();
        await using var run = new RunSessions(clock) { MaxIdle = TimeSpan.FromMinutes(5) };

        await Scan(runner, queries: 2, ["pc01.example.org"], sessions: run);
        clock.Now += TimeSpan.FromMinutes(6);                 // a directory drops a connection idle this long
        await Scan(runner, queries: 2, ["pc01.example.org"], sessions: run);

        Assert.Equal(2, runner.Opens);
        Assert.Equal(1, runner.Closes);                       // the stale one, before signing in again
    }

    [Fact]
    public async Task A_session_a_read_failed_on_is_not_handed_to_the_next_system()
    {
        var calls = 0;
        var runner = new SessionRunner(_ => FailureKind.None,
            read: (_, _) => Interlocked.Increment(ref calls) == 1 ? RunnerResult.Failed("connection reset", FailureKind.Error) : null!);
        await using var run = new RunSessions();

        await Scan(runner, queries: 1, ["pc01.example.org"], sessions: run);
        await Scan(runner, queries: 1, ["pc01.example.org"], sessions: run);

        Assert.Equal(2, runner.Opens);
        Assert.Equal(1, runner.Closes);
    }

    [Fact]
    public async Task A_host_that_did_not_answer_is_not_asked_again_by_every_system()
    {
        var runner = new SessionRunner(host => host.StartsWith("pc02", StringComparison.Ordinal) ? FailureKind.Unreachable : FailureKind.None);
        await using var run = new RunSessions();

        await Scan(runner, queries: 2, ThreeHosts, sessions: run);
        var second = await Scan(runner, queries: 2, ThreeHosts, sessions: run);

        Assert.Equal(3, runner.Opens);                       // pc02 once in the run
        var pc02 = Coverage(second).Where(c => c.Scope == "target" && c.Item.Contains("pc02", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(pc02);
        Assert.All(pc02, c => Assert.Equal("failed", c.State));   // still a failed read, never empty
    }

    [Fact]
    public async Task A_scan_stops_reading_when_its_window_closes()
    {
        var clock = new Settable { Now = new DateTimeOffset(2026, 11, 13, 5, 50, 0, TimeSpan.Zero) };
        var reads = 0;
        // The window closes during the second read of the first host.
        var runner = new SessionRunner(_ => FailureKind.None, read: (_, _) =>
        {
            if (Interlocked.Increment(ref reads) == 2)
                clock.Now = clock.Now.AddMinutes(15);
            return null!;
        });
        var registry = new RunnerRegistry([runner]);
        var window = ScanWindow.From(new JsonObject { ["window"] = "20:00-06:00" }, TimeZoneInfo.Utc);

        var report = await new Scanner(registry, clock).RunAsync(new ScanRequest
        {
            Files = [Rules(5, ThreeHosts, registry)],
            Connection = new Connection(),
            RunsDir = Runs,
            ImportsDir = _dir,
            Pace = PaceProfile.Unlimited with { Hosts = 1 },
            Window = window,
        }, CancellationToken.None);

        Assert.Equal(2, runner.Reads);                        // nothing is read after 06:00
        var targets = Coverage(report).Where(c => c.Scope == "target").ToList();
        Assert.Equal(15, targets.Count);
        Assert.Equal(13, targets.Count(c => c.State == "failed"));   // not empty: nothing is retired by a read not made
        Assert.Contains(report.Manifest.Notes, n => n.Contains("scan window (20:00-06:00) closed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_scan_started_outside_its_window_reads_nothing()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var registry = new RunnerRegistry([runner]);
        var clock = new Settable { Now = new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero) };

        await new Scanner(registry, clock).RunAsync(new ScanRequest
        {
            Files = [Rules(2, ThreeHosts, registry)],
            Connection = new Connection(),
            RunsDir = Runs,
            ImportsDir = _dir,
            Window = ScanWindow.From(new JsonObject { ["window"] = "20:00-06:00" }, TimeZoneInfo.Utc),
        }, CancellationToken.None);

        Assert.Empty(runner.Log);
    }

    [Fact]
    public async Task A_session_no_later_system_reads_is_closed_after_its_idle_time()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var clock = new Settable();
        await using var run = new RunSessions(clock);

        await Scan(runner, queries: 1, ThreeHosts, sessions: run);
        clock.Now += TimeSpan.FromMinutes(6);
        await run.SweepAsync();                               // the next system, through another integration, starts

        Assert.Equal(3, runner.Closes);
    }

    [Fact]
    public async Task A_host_stopped_for_pushing_back_is_not_read_by_the_run_s_next_system()
    {
        var runner = new SessionRunner(_ => FailureKind.None,
            read: (host, _) => host.StartsWith("pc01", StringComparison.Ordinal) ? RunnerResult.Failed("busy", FailureKind.Throttled) : null!);
        await using var run = new RunSessions();
        var pace = PaceProfile.Unlimited with { Hosts = 1, StopAfter = 2 };

        await Scan(runner, queries: 5, ThreeHosts, pace: pace, sessions: run);
        var pc01Reads = runner.Log.Count(l => l.StartsWith("read pc01", StringComparison.Ordinal));
        var second = await Scan(runner, queries: 5, ThreeHosts, pace: pace, sessions: run);

        Assert.Equal(2, pc01Reads);
        Assert.Equal(pc01Reads, runner.Log.Count(l => l.StartsWith("read pc01", StringComparison.Ordinal)));   // not pressed again
        Assert.Equal(1, runner.Log.Count(l => l.StartsWith("open pc01", StringComparison.Ordinal)));
        Assert.Contains(second.Manifest.Notes, n => n.Contains("earlier in this run", StringComparison.Ordinal));
        Assert.All(Coverage(second).Where(c => c.Scope == "target" && c.Item.Contains("pc01", StringComparison.Ordinal)),
            c => Assert.Equal("failed", c.State));
    }

    private sealed class Settable : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task A_host_is_read_one_query_at_a_time_and_no_more_hosts_than_the_pace_allows()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        string[] hosts = [.. Enumerable.Range(1, 6).Select(i => $"pc{i:00}.example.org")];

        await Scan(runner, queries: 10, hosts, pace: PaceProfile.Unlimited with { Hosts = 2 });

        Assert.Equal(1, runner.MaxPerHost);
        Assert.True(runner.MaxInFlight <= 2, $"{runner.MaxInFlight} reads at once");
    }

    [Fact]
    public async Task A_refused_credential_is_never_presented_again_on_any_host()
    {
        var runner = new SessionRunner(host => host.StartsWith("pc01", StringComparison.Ordinal) ? FailureKind.Refused : FailureKind.None);

        var report = await Scan(runner, queries: 20, ThreeHosts, pace: PaceProfile.Unlimited with { Hosts = 1 });

        Assert.Equal(1, runner.Opens);                       // pc01 refused: pc02 and pc03 never see the credential
        Assert.Equal(0, runner.Reads);
        Assert.Equal("failed", report.Manifest.Status);
        var targets = Coverage(report).Where(c => c.Scope == "target").ToList();
        Assert.Equal(60, targets.Count);                     // every query and host has a record: nothing is retired
        Assert.All(targets, c => Assert.Equal("failed", c.State));
        Assert.All(targets.Where(c => !c.Item.EndsWith("@pc01.example.org", StringComparison.Ordinal)),
            c => Assert.Contains("not tried", c.Reason, StringComparison.Ordinal));
        Assert.Contains(report.Manifest.Notes, n => n.Contains("so the account is not locked out", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Until_a_sign_in_is_accepted_hosts_sign_in_one_at_a_time()
    {
        // pc01 refuses; with four hosts allowed at once, the others must not have tried the same password meanwhile.
        var runner = new SessionRunner(host => host.StartsWith("pc01", StringComparison.Ordinal) ? FailureKind.Refused : FailureKind.None);
        string[] hosts = ["pc01.example.org", "pc02.example.org", "pc03.example.org", "pc04.example.org"];

        await Scan(runner, queries: 5, hosts, pace: PaceProfile.Unlimited with { Hosts = 4 });

        Assert.Equal(1, runner.Opens);
    }

    [Fact]
    public async Task Access_denied_at_sign_in_on_two_hosts_with_none_accepted_stops_the_credential()
    {
        // Over DCOM a wrong password can answer "access denied": two such hosts in a row, and the rest are spared.
        var runner = new SessionRunner(_ => FailureKind.Denied);
        string[] hosts = [.. Enumerable.Range(1, 6).Select(i => $"pc{i:00}.example.org")];

        var report = await Scan(runner, queries: 3, hosts, pace: PaceProfile.Unlimited with { Hosts = 1 });

        Assert.Equal(2, runner.Opens);
        Assert.Contains(report.Manifest.Notes, n => n.Contains("denied at sign-in by pc01.example.org and pc02.example.org", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_domain_that_locks_at_two_risks_one_denied_sign_in()
    {
        var runner = new SessionRunner(_ => FailureKind.Denied);
        string[] hosts = [.. Enumerable.Range(1, 6).Select(i => $"pc{i:00}.example.org")];
        var guard = new LogonGuard();
        guard.LimitDeniedSignIns(new Connection(), allowed: 1);   // lockoutThreshold 2: a second wrong password would lock

        var report = await Scan(runner, queries: 3, hosts, pace: PaceProfile.Unlimited with { Hosts = 1 }, guard: guard);

        Assert.Equal(1, runner.Opens);
        Assert.Contains(report.Manifest.Notes, n => n.Contains("denied at sign-in by pc01.example.org with no host", StringComparison.Ordinal));
    }

    [Fact]
    public void A_denial_limit_is_only_ever_lowered()
    {
        var guard = new LogonGuard();
        Assert.Equal(2, guard.DeniedSignInsFor(new Connection()));

        guard.LimitDeniedSignIns(new Connection("EXAMPLE\\reader"), 1);    // a domain that locks at two
        guard.LimitDeniedSignIns(new Connection("OTHER\\reader"), 4);      // same account name, laxer domain

        Assert.Equal(1, guard.DeniedSignInsFor(new Connection("reader@example.org")));
    }

    [Fact]
    public void A_denied_sign_in_counts_in_the_next_process_too()
    {
        // A wrong password DCOM answers as access denied, one reachable server, a scan every few minutes.
        var first = new LogonGuard();
        var kept = new List<string>();
        first.OnStrike = (_, host) => kept.Add(host);

        Assert.False(first.DeniedAtSignIn(new Connection(), "srv1", "access denied"));
        Assert.Equal(["srv1"], kept);

        var next = new LogonGuard();                        // the next scheduled scan
        next.RestoreStrikes(new Connection(), kept.Count);
        Assert.True(next.DeniedAtSignIn(new Connection(), "srv1", "access denied"));   // two bad logons in all, then stop
        Assert.Contains("1 time(s) by earlier scans", next.Refusal(new Connection()), StringComparison.Ordinal);

        var third = new LogonGuard();
        third.RestoreStrikes(new Connection(), 2);
        Assert.NotNull(third.Refusal(new Connection()));    // nothing is presented at all
    }

    [Fact]
    public void A_process_does_not_count_its_own_strikes_twice_and_a_proof_forgets_them()
    {
        var guard = new LogonGuard();
        var proven = 0;
        guard.OnProven = _ => proven++;
        guard.LimitDeniedSignIns(new Connection(), 2);
        guard.RestoreStrikes(new Connection(), 0);          // the run's first scan: none kept
        Assert.False(guard.DeniedAtSignIn(new Connection(), "srv1", "access denied"));
        guard.RestoreStrikes(new Connection(), 1);          // its second scan reads back the strike it wrote itself
        Assert.Null(guard.Refusal(new Connection()));

        guard.Accepted(new Connection());
        guard.Accepted(new Connection());
        Assert.Equal(1, proven);                            // once: the kept strikes are cleared then
    }

    [Fact]
    public async Task Access_denied_on_hosts_after_an_accepted_sign_in_is_about_those_hosts()
    {
        var runner = new SessionRunner(host => host.StartsWith("pc01", StringComparison.Ordinal) ? FailureKind.None : FailureKind.Denied);
        string[] hosts = [.. Enumerable.Range(1, 5).Select(i => $"pc{i:00}.example.org")];

        await Scan(runner, queries: 2, hosts, pace: PaceProfile.Unlimited with { Hosts = 1 });

        Assert.Equal(5, runner.Opens);                       // the credential works: a host that denies it lacks the right
    }

    [Fact]
    public async Task A_session_that_signs_in_on_its_first_read_is_not_proof_the_password_works()
    {
        // Event log, HTTP, AWS: opening sends nothing; the first read is the sign-in. Four hosts at once must still
        // meet the wrong password one at a time - the first refusal stops the rest.
        var runner = new SessionRunner(_ => FailureKind.None, (host, _) => RunnerResult.Failed($"{host}: logon failure", FailureKind.Refused));
        string[] hosts = ["pc01.example.org", "pc02.example.org", "pc03.example.org", "pc04.example.org"];

        await Scan(runner, queries: 5, hosts, pace: PaceProfile.Unlimited with { Hosts = 4 });

        Assert.Equal(1, runner.Reads);
    }

    [Fact]
    public async Task Access_denied_before_any_host_accepted_skips_the_rest_of_that_host()
    {
        var runner = new SessionRunner(_ => FailureKind.None,
            (host, _) => host.StartsWith("pc01", StringComparison.Ordinal)
                ? RunnerResult.Failed($"{host}: access denied", FailureKind.Denied)
                : RunnerResult.Ok([new JsonObject { ["host"] = host, ["value"] = 1 }]));

        var report = await Scan(runner, queries: 6, ["pc01.example.org", "pc02.example.org"], pace: PaceProfile.Unlimited with { Hosts = 1 });

        Assert.Equal(1, runner.Log.Count(l => l.StartsWith("read pc01", StringComparison.Ordinal)));
        Assert.Equal(6, runner.Log.Count(l => l.StartsWith("read pc02", StringComparison.Ordinal)));
        Assert.Equal(5, Coverage(report).Count(c => c.Item.EndsWith("@pc01.example.org", StringComparison.Ordinal)
                                                    && c.Reason!.Contains("before any host accepted it", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Access_denied_where_it_cannot_be_a_wrong_password_skips_only_that_read()
    {
        // A Graph 403 or an LDAP 50 on one object: the sign-in was accepted. The rest of the host is read, nothing is refused.
        var runner = new SessionRunner(_ => FailureKind.None,
            (host, query) => query.Text("path") == "P1"
                ? RunnerResult.Failed($"{host}: forbidden", FailureKind.Denied)
                : RunnerResult.Ok([new JsonObject { ["host"] = host, ["value"] = 1 }]),
            deniedMayBeSignIn: false);
        var guard = new LogonGuard();

        await Scan(runner, queries: 4, ["pc01.example.org", "pc02.example.org"], pace: PaceProfile.Unlimited with { Hosts = 1 }, guard: guard);

        Assert.Equal(8, runner.Reads);
        Assert.Null(guard.Refusal(new Connection()));
    }

    [Fact]
    public async Task Access_denied_from_a_host_that_answered_as_the_account_proves_the_credential()
    {
        // StdRegProv returning 5 on one key: the provider ran as the account, so the password is right.
        var runner = new SessionRunner(_ => FailureKind.None,
            (host, query) => query.Text("path") == "P1"
                ? RunnerResult.Failed($"{host}: EnumValues returned 5", FailureKind.Denied) with { SignedIn = true }
                : RunnerResult.Ok([new JsonObject { ["host"] = host, ["value"] = 1 }]));
        var guard = new LogonGuard();

        await Scan(runner, queries: 3, ["pc01.example.org", "pc02.example.org"], pace: PaceProfile.Unlimited with { Hosts = 1 }, guard: guard);

        Assert.Equal(6, runner.Reads);
        Assert.True(guard.Proven(new Connection()));
        Assert.Null(guard.Refusal(new Connection()));
    }

    [Fact]
    public async Task An_empty_answer_is_not_proof_the_password_works()
    {
        // An event log whose service is down answers no rows: the scan must stay one sign-in at a time.
        var runner = new SessionRunner(_ => FailureKind.None, (_, _) => RunnerResult.Ok([]));
        var guard = new LogonGuard();

        await Scan(runner, queries: 2, ThreeHosts, pace: PaceProfile.Unlimited with { Hosts = 3 }, guard: guard);

        Assert.False(guard.Proven(new Connection()));
        Assert.Equal(1, runner.MaxInFlight);
    }

    [Fact]
    public void A_tls_handshake_that_failed_is_not_a_refused_password()
    {
        var tls = new HttpRequestException("The SSL connection could not be established, see inner exception.",
            new System.Security.Authentication.AuthenticationException("Authentication failed because the remote party sent a TLS alert: 'HandshakeFailure'."));

        Assert.Equal(FailureKind.Error, Failures.Classify(tls));
    }

    [Fact]
    public void A_kind_inside_the_chain_wins_over_the_words_of_an_outer_message()
    {
        var signIn = new HttpRequestException("sign-in: authentication failed (503)", new RunnerFailureException("busy", FailureKind.Throttled));

        Assert.Equal(FailureKind.Throttled, Failures.Classify(signIn));
        Assert.Equal(FailureKind.Refused, Failures.Classify(new InvalidOperationException("Login failed for user 'reader'.")));
    }

    [Fact]
    public async Task A_partial_read_that_met_a_refusal_still_stops_the_credential()
    {
        // A for_each that read some children before one was refused answers partial: the refusal must still count.
        var runner = new SessionRunner(_ => FailureKind.None,
            (host, _) => RunnerResult.Partial([new JsonObject { ["host"] = host, ["value"] = 1 }], "child 2 refused") with { Failure = FailureKind.Refused });

        var report = await Scan(runner, queries: 4, ["pc01.example.org", "pc02.example.org"], pace: PaceProfile.Unlimited with { Hosts = 1 });

        Assert.Equal(1, runner.Reads);
        Assert.Contains(report.Manifest.Notes, n => n.Contains("so the account is not locked out", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Hosts_spelled_differently_in_two_files_merge_without_losing_a_result()
    {
        var runner = new SessionRunner(_ => FailureKind.None, merge: true);
        var registry = new RunnerRegistry([runner]);
        var first = Rules(2, ["SRV1.example.org"], registry, sharedPath: true);
        var path = Path.Combine(_dir, "second.yaml");
        File.WriteAllText(path, File.ReadAllText(first.Path).Replace("SRV1.example.org", "srv1.example.org", StringComparison.Ordinal)
            .Replace("R-1", "S-1", StringComparison.Ordinal).Replace("R-2", "S-2", StringComparison.Ordinal).Replace("'V1'", "'V3'", StringComparison.Ordinal));
        var second = RuleLoader.LoadFile(path, "test", registry.Validators);

        var report = await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [first, second], Connection = new Connection(), RunsDir = Runs, ImportsDir = _dir,
        }, CancellationToken.None);

        Assert.Equal("ok", report.Manifest.Status);
        // One session for the host, but each spelling is read on its own, so each keeps its own host field.
        Assert.Equal(1, runner.Opens);
        Assert.Equal(2, runner.Reads);
        Assert.Contains(runner.Log, l => l.StartsWith("read SRV1.example.org ", StringComparison.Ordinal));
        Assert.Contains(runner.Log, l => l.StartsWith("read srv1.example.org ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_host_list_of_blank_names_is_a_failed_read_not_an_empty_one()
    {
        var runner = new SessionRunner(_ => FailureKind.None);

        var report = await Scan(runner, queries: 1, ["''"]);

        Assert.Equal("failed", report.Manifest.Status);
        Assert.Equal(0, runner.Reads);
    }

    [Fact]
    public void A_throttle_a_runner_retries_slows_the_host_but_only_whole_reads_stop_it()
    {
        var pacer = new Pacer(PaceProfile.Gentle);
        var pace = pacer.For("graph.example.org");
        for (var i = 0; i < 10; i++)
            pace.Signal(FailureKind.Throttled);

        Assert.Null(pacer.Stopped("graph.example.org"));
        Assert.Empty(pacer.PushedBack());
    }

    [Fact]
    public async Task With_no_credential_hosts_that_do_not_answer_are_tried_side_by_side()
    {
        // auth none (TLS handshakes, open printers): no account to lock, so no one-at-a-time proving - offline hosts
        // must not each wait out their timeout in turn.
        var runner = new SessionRunner(_ => FailureKind.None, (host, _) => RunnerResult.Failed($"{host}: no answer", FailureKind.Unreachable));
        string[] hosts = [.. Enumerable.Range(1, 8).Select(i => $"pc{i:00}.example.org")];

        await Scan(runner, queries: 3, hosts, pace: PaceProfile.Unlimited with { Hosts = 4 }, connection: new Connection("", "none"));

        Assert.True(runner.MaxInFlight > 1, "reads ran one at a time");
    }

    [Fact]
    public async Task A_refusal_holds_for_the_next_scan_of_the_same_run()
    {
        var guard = new LogonGuard();
        var first = new SessionRunner(_ => FailureKind.Refused);
        await Scan(first, queries: 3, ["pc01.example.org"], guard: guard);
        var second = new SessionRunner(_ => FailureKind.None);

        var report = await Scan(second, queries: 3, ThreeHosts, guard: guard);

        Assert.Equal(1, first.Opens);
        Assert.Equal(0, second.Opens);
        Assert.Equal("failed", report.Manifest.Status);
    }

    [Fact]
    public async Task Another_identity_is_not_held_back_by_a_refusal()
    {
        var guard = new LogonGuard();
        await Scan(new SessionRunner(_ => FailureKind.Refused), queries: 1, ["pc01.example.org"], guard: guard);
        var other = new SessionRunner(_ => FailureKind.None);

        await Scan(other, queries: 1, ["pc01.example.org"], guard: guard, connection: new Connection("EXAMPLE\\other"));

        Assert.Equal(1, other.Opens);
    }

    [Fact]
    public async Task A_host_that_cannot_be_reached_is_signed_in_to_once_and_the_others_go_on()
    {
        var runner = new SessionRunner(host => host.StartsWith("pc02", StringComparison.Ordinal) ? FailureKind.Unreachable : FailureKind.None);

        var report = await Scan(runner, queries: 10, ThreeHosts);

        Assert.Equal(3, runner.Opens);
        Assert.Equal(20, runner.Reads);
        Assert.Equal("partial", report.Manifest.Status);
        Assert.All(Coverage(report).Where(c => c.Item.EndsWith("@pc02.example.org", StringComparison.Ordinal)), c => Assert.Equal("failed", c.State));
    }

    [Fact]
    public async Task A_host_that_keeps_pushing_back_is_stopped_and_its_rest_is_failed_not_empty()
    {
        var runner = new SessionRunner(_ => FailureKind.None,
            (host, _) => host.StartsWith("pc01", StringComparison.Ordinal)
                ? RunnerResult.Failed($"{host}: the server is busy", FailureKind.Throttled)
                : RunnerResult.Ok([new JsonObject { ["host"] = host, ["value"] = 1 }]));

        var report = await Scan(runner, queries: 10, ThreeHosts, pace: PaceProfile.Unlimited with { StopAfter = 3 });

        Assert.Equal(3, runner.Log.Count(l => l.StartsWith("read pc01", StringComparison.Ordinal)));   // stopped after three
        Assert.Equal(20, runner.Reads - 3);
        var pc01 = Coverage(report).Where(c => c.Item.EndsWith("@pc01.example.org", StringComparison.Ordinal)).ToList();
        Assert.Equal(10, pc01.Count);
        Assert.All(pc01, c => Assert.Equal("failed", c.State));
        Assert.Equal(7, pc01.Count(c => c.Reason!.Contains("stopped reading it", StringComparison.Ordinal)));
        Assert.Contains(report.Manifest.Notes, n => n.Contains("pc01.example.org pushed back 3 times", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Reads_of_one_key_are_merged_and_each_rule_sees_only_its_own_part()
    {
        var runner = new SessionRunner(_ => FailureKind.None, merge: true);

        var report = await Scan(runner, queries: 4, ["pc01.example.org"], sharedPath: true);

        Assert.Equal(3, runner.Reads);                       // R-1 and R-2 share SHARED: one read of V1,V2
        Assert.Contains(runner.Log, l => l == "read pc01.example.org SHARED V1,V2");
        Assert.Equal(1, report.Cost.MergedAway);
        var rows = JsonLines.Read<RowRecord>(Path.Combine(Runs, report.Manifest.RunId, "rows.jsonl")).ToList();
        Assert.Equal(4, rows.Count);                         // still one row per original query
        Assert.Equal(["V1", "V2"], rows.Where(r => r.Attrs["key"]?.ToString() == "SHARED").Select(r => r.Attrs["mine"]!.ToString()).Order());
        Assert.Equal(4, Coverage(report).Count(c => c.Scope == "target"));
    }

    [Fact]
    public async Task A_host_listed_twice_is_read_once()
    {
        var runner = new SessionRunner(_ => FailureKind.None);

        var report = await Scan(runner, queries: 2, ["pc01.example.org", "PC01.example.org"]);

        Assert.Equal(1, runner.Opens);
        Assert.Equal(2, runner.Reads);
        Assert.Equal(2, Coverage(report).Count(c => c.Scope == "target"));
    }

    [Fact]
    public void A_plan_counts_reads_and_sign_ins_per_host_without_reading_anything()
    {
        var runner = new SessionRunner(_ => FailureKind.None, merge: true);
        var registry = new RunnerRegistry([runner]);

        var plan = new Scanner(registry).Plan(new ScanRequest
        {
            Files = [Rules(40, ThreeHosts, registry, sharedPath: true)], Connection = new Connection(), RunsDir = Runs, ImportsDir = _dir,
            Pace = PaceProfile.Gentle,
        });

        Assert.Empty(runner.Log);
        Assert.Equal(40, plan.Queries);
        Assert.Equal(120, plan.UnmergedReads);
        Assert.Equal(117, plan.Reads);                       // the two SHARED reads merge on each of three hosts
        Assert.Equal(3, plan.Sessions);
        Assert.All(plan.Hosts, h => Assert.Equal(TimeSpan.FromSeconds(3.9), h.Time));   // 39 reads at 10/s
    }

    [Fact]
    public async Task A_connection_test_reads_one_host()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var registry = new RunnerRegistry([runner]);

        await new Scanner(registry).RunAsync(new ScanRequest
        {
            Files = [Rules(1, ThreeHosts, registry)], Connection = new Connection(), RunsDir = Runs, ImportsDir = _dir, TargetLimit = 1,
        }, CancellationToken.None);

        Assert.Equal(["open pc01.example.org"], runner.Log.Where(l => l.StartsWith("open", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task The_pace_spaces_requests_to_one_host_and_new_sessions_across_the_scan()
    {
        var runner = new SessionRunner(_ => FailureKind.None);
        var watch = Stopwatch.StartNew();

        await Scan(runner, queries: 6, ["pc01.example.org", "pc02.example.org"], pace: new PaceProfile("test", 2, 10, 20, 3));

        // Six reads a host at 20/s take at least 5 x 50 ms; the second session waits 100 ms for its slot.
        Assert.True(watch.Elapsed >= TimeSpan.FromMilliseconds(240), $"took {watch.Elapsed.TotalMilliseconds} ms");
    }
}

public sealed class PaceTests
{
    [Theory]
    [InlineData(1326, FailureKind.Refused)]
    [InlineData(1909, FailureKind.Refused)]
    [InlineData(1330, FailureKind.Refused)]
    [InlineData(1331, FailureKind.Refused)]
    [InlineData(5, FailureKind.Denied)]
    [InlineData(1722, FailureKind.Unreachable)]
    [InlineData(1460, FailureKind.Timeout)]
    [InlineData(unchecked((int)0x8007052E), FailureKind.Refused)]   // HRESULT for 1326
    public void Win32_codes_are_classified(int code, FailureKind kind) => Assert.Equal(kind, Failures.OfWin32(code));

    [Theory]
    [InlineData(401, FailureKind.Refused)]
    [InlineData(403, FailureKind.Denied)]
    [InlineData(429, FailureKind.Throttled)]
    [InlineData(503, FailureKind.Throttled)]
    [InlineData(504, FailureKind.Timeout)]
    [InlineData(500, FailureKind.Error)]
    public void Http_statuses_are_classified(int status, FailureKind kind) =>
        Assert.Equal(kind, Failures.Classify(new HttpRequestException("x", null, (HttpStatusCode)status)));

    [Fact]
    public void Wrapped_and_worded_failures_are_classified()
    {
        Assert.Equal(FailureKind.Refused, Failures.Classify(new InvalidOperationException("outer", new System.ComponentModel.Win32Exception(1909))));
        Assert.Equal(FailureKind.Refused, Failures.Classify(new Exception("The user name or password is incorrect.")));
        Assert.Equal(FailureKind.Timeout, Failures.Classify(new TimeoutException()));
        Assert.Equal(FailureKind.Denied, Failures.Classify(new UnauthorizedAccessException()));
        Assert.Equal(FailureKind.Throttled, Failures.Classify(new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionReset)));
        Assert.Equal(FailureKind.Error, Failures.Classify(new FormatException("bad")));
    }

    [Fact]
    public void A_profile_comes_from_the_integration_options()
    {
        Assert.Equal(PaceProfile.Gentle, PaceProfile.From([]));
        Assert.Equal(PaceProfile.Normal, PaceProfile.From(new JsonObject { ["pace"] = "normal" }));
        Assert.Equal(PaceProfile.Fast, PaceProfile.From(new JsonObject { ["pace"] = "normal" }, "fast"));
        var tuned = PaceProfile.From(new JsonObject { ["pace"] = "gentle", ["pace.hosts"] = "2", ["pace.requestsPerSecond"] = "0.5" });
        Assert.Equal(2, tuned.Hosts);
        Assert.Equal(0.5, tuned.RequestsPerSecond);
        Assert.Equal(PaceProfile.Gentle.SessionsPerSecond, tuned.SessionsPerSecond);
        Assert.Throws<ArgumentException>(() => PaceProfile.From(new JsonObject { ["pace"] = "ludicrous" }));
        Assert.Throws<ArgumentException>(() => PaceProfile.From(new JsonObject { ["pace.hosts"] = "0" }));
    }

    /// <summary>A clock that moves on <paramref name="seconds"/> each time it is read, past any interval: no wait ever has to be slept.</summary>
    private sealed class Jumping(int seconds = 31) : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => _now = _now.AddSeconds(seconds);
    }

    [Fact]
    public async Task A_host_held_at_the_longest_interval_is_stopped_and_a_read_in_flight_ends()
    {
        // Reads that succeed only after a runner's own retries never fail as a whole: without a bound the host would
        // be read 30 s apart for as long as it has requests.
        var pacer = new Pacer(PaceProfile.Gentle, new Jumping());
        var pace = pacer.For("vc.example.org");
        for (var i = 0; i < 10; i++)
            pace.Signal(FailureKind.Throttled);

        for (var i = 1; i < Pacer.MaxSlowRequests; i++)
            await pace.WaitAsync(CancellationToken.None);
        Assert.Null(pacer.Stopped("vc.example.org"));
        await pace.WaitAsync(CancellationToken.None);
        Assert.Contains("kept asking to slow down", pacer.Stopped("vc.example.org"), StringComparison.Ordinal);

        var ended = await Assert.ThrowsAsync<RunnerFailureException>(() => pace.WaitAsync(CancellationToken.None));
        Assert.Equal(FailureKind.Throttled, ended.Kind);
    }

    [Fact]
    public async Task An_operator_s_own_slow_pace_is_not_a_push_back()
    {
        var pacer = new Pacer(PaceProfile.Gentle with { RequestsPerSecond = 0.01 }, new Jumping(101));   // 100 s apart, by choice
        var pace = pacer.For("fragile.example.org");

        for (var i = 0; i < 3 * Pacer.MaxSlowRequests; i++)
            await pace.WaitAsync(CancellationToken.None);

        Assert.Null(pacer.Stopped("fragile.example.org"));
    }

    [Fact]
    public async Task Clean_answers_inside_one_long_read_let_the_host_speed_up_and_a_stop_is_listed()
    {
        var pacer = new Pacer(PaceProfile.Gentle, new Jumping());
        var pace = pacer.For("vc.example.org");
        for (var i = 0; i < 10; i++)
            pace.Signal(FailureKind.Throttled);
        for (var i = 0; i < 3 * Pacer.MaxSlowRequests; i++)
        {
            await pace.WaitAsync(CancellationToken.None);
            pace.Signal(FailureKind.None);                       // a for_each child that came back clean
        }
        Assert.Null(pacer.Stopped("vc.example.org"));

        var other = pacer.For("slow.example.org");
        for (var i = 0; i < 10; i++)
            other.Signal(FailureKind.Throttled);
        for (var i = 0; i < Pacer.MaxSlowRequests; i++)
            await other.WaitAsync(CancellationToken.None);
        Assert.Contains(("slow.example.org", 0, true), pacer.PushedBack());   // the manifest names the stopped host
    }

    [Fact]
    public async Task A_host_that_speeds_up_again_is_not_stopped()
    {
        var pacer = new Pacer(PaceProfile.Gentle, new Jumping());
        var pace = pacer.For("vc.example.org");
        for (var i = 0; i < 10; i++)
            pace.Signal(FailureKind.Throttled);

        for (var i = 0; i < 3 * Pacer.MaxSlowRequests; i++)
        {
            await pace.WaitAsync(CancellationToken.None);
            if (i % 10 == 9)
            {
                pacer.Signal("vc.example.org", FailureKind.None);   // a clean read: the interval drops below the longest
                await pace.WaitAsync(CancellationToken.None);       // one request at the shorter interval
                pace.Signal(FailureKind.Throttled);                  // and the host pushes back again
            }
        }

        Assert.Null(pacer.Stopped("vc.example.org"));
    }

    [Fact]
    public void A_host_that_pushes_back_is_slowed_then_stopped_and_a_clean_answer_resets_the_streak()
    {
        var pacer = new Pacer(PaceProfile.Gentle);
        pacer.Signal("a", FailureKind.Throttled);
        pacer.Signal("a", FailureKind.Timeout);
        pacer.Signal("a", FailureKind.None);
        pacer.Signal("a", FailureKind.Throttled);
        pacer.Signal("a", FailureKind.Throttled);
        Assert.Null(pacer.Stopped("a"));
        pacer.Signal("a", FailureKind.Throttled);
        Assert.NotNull(pacer.Stopped("a"));
        Assert.Null(pacer.Stopped("b"));
        Assert.Equal([("a", 5, true)], pacer.PushedBack());
    }
}

public sealed class SignInRefusalsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("keeper-refusals-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private sealed class Connection(string instance = "lab-ssh", string? identity = "reader", string authKind = "ssh-password") : IConnection
    {
        public string Instance => instance;
        public string Type => "ssh";
        public string Endpoint => "192.0.2.0/24";
        public string AuthKind => authKind;
        public string? Identity => identity;
        public JsonObject Options { get; } = [];
        public string? Secret(string name) => null;
        public NetworkCredential? WindowsCredential() => null;
        public HttpMessageHandler CreateHttpHandler() => new HttpClientHandler();
        public Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private string File_ => Path.Combine(_dir, "state", "sign-in-refusals.json");

    [Fact]
    public void A_refusal_outlives_the_process_until_the_secret_is_set_again()
    {
        var connection = new Connection();
        var before = SignInRefusals.Fingerprint("lab-ssh", "reader", "192.0.2.0/24", "ssh-password", ["password=2026-11-13T10:00:00Z"]);
        new SignInRefusals(File_).Record(connection, before, "not tried: reader was refused", DateTimeOffset.UnixEpoch);

        var again = new SignInRefusals(File_);             // a later process
        var after = SignInRefusals.Fingerprint("lab-ssh", "reader", "192.0.2.0/24", "ssh-password", ["password=2026-11-13T11:00:00Z"]);

        Assert.StartsWith("not tried: reader was refused", again.Find(connection, _ => before, null), StringComparison.Ordinal);
        Assert.Null(again.Find(connection, _ => after, null));        // the password was set again: try it
        again.Clear(connection);
        Assert.Null(again.Find(connection, _ => before, null));
        Assert.DoesNotContain("Right-Pass", File.ReadAllText(File_), StringComparison.Ordinal);
    }

    [Fact]
    public void Strikes_are_kept_for_the_credential_and_are_not_a_refusal()
    {
        var connection = new Connection();
        var file = new SignInRefusals(File_);
        file.RecordStrike(connection, "cred-1", "srv1", DateTimeOffset.UnixEpoch);
        file.RecordStrike(connection, "cred-1", "srv2", DateTimeOffset.UnixEpoch);

        var later = new SignInRefusals(File_);
        var soon = DateTimeOffset.UnixEpoch.AddHours(1);
        Assert.Equal(2, later.Strikes(connection, "cred-1", soon));
        Assert.Equal(0, later.Strikes(connection, "cred-1", DateTimeOffset.UnixEpoch.AddDays(2)));   // a day on, they count for nothing
        Assert.Null(later.Find(connection, _ => "cred-1", null));        // a strike is not a refusal by itself
        Assert.Equal(0, later.Strikes(connection, "cred-2", soon));      // the secret was set again
        later.ClearStrikes(connection);                                  // a host accepted it
        Assert.Equal(0, later.Strikes(connection, "cred-1", soon));

        later.RecordStrike(connection, "cred-1", "srv1", DateTimeOffset.UnixEpoch);
        later.ClearAccount(connection);                                  // --retry-sign-in
        Assert.Equal(0, later.Strikes(connection, "cred-1", soon));
    }

    [Fact]
    public void A_windows_account_refused_through_one_integration_is_not_tried_by_another_process_through_another()
    {
        // The scheduler scans each system in its own process: ldap, then cim, both signing in as EXAMPLE\reader.
        var ldap = new Connection("ad-main", "EXAMPLE\\reader", "windows-credential");
        var cim = new Connection("win-servers", "reader@example.org", "windows-credential");
        var credentials = new Dictionary<string, string> { ["ad-main"] = "ldap-1", ["win-servers"] = "cim-1" };
        new SignInRefusals(File_).Record(ldap, "ldap-1", "not tried: EXAMPLE\\reader was refused", new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero));

        var later = new SignInRefusals(File_);
        var setBefore = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        var setAfter = new DateTimeOffset(2026, 11, 13, 13, 0, 0, TimeSpan.Zero);

        Assert.Contains("refused through ad-main", later.Find(cim, id => credentials.GetValueOrDefault(id), setBefore), StringComparison.Ordinal);
        Assert.Null(later.Find(cim, id => credentials.GetValueOrDefault(id), setAfter));          // its password was entered since
        Assert.Null(later.Find(cim, id => id == "ad-main" ? "ldap-2" : "cim-1", setBefore));      // ad-main's password was set again
        Assert.Null(later.Find(new Connection("other", "EXAMPLE\\writer", "windows-credential"), id => credentials.GetValueOrDefault(id), setBefore));

        later.Clear(cim);                                  // cim read data: its own record only
        Assert.NotNull(later.Find(cim, id => credentials.GetValueOrDefault(id), setBefore));
        later.ClearAccount(cim);                           // --retry-sign-in: the account's records
        Assert.Null(later.Find(ldap, id => credentials.GetValueOrDefault(id), null));
    }

    [Fact]
    public void Two_processes_recording_at_once_keep_both_refusals()
    {
        Parallel.For(0, 20, i => new SignInRefusals(File_).Record(new Connection($"lab-{i}"), $"c{i}", "refused", DateTimeOffset.UnixEpoch));

        var all = new SignInRefusals(File_);
        for (var i = 0; i < 20; i++)
            Assert.NotNull(all.Find(new Connection($"lab-{i}"), id => id == $"lab-{i}" ? $"c{i}" : null, null));
    }

    [Fact]
    public void A_restored_refusal_keeps_a_scan_from_signing_in()
    {
        var guard = new LogonGuard();
        var connection = new Connection();
        guard.Restore(connection, "not tried: recorded earlier");

        Assert.Equal("not tried: recorded earlier", guard.Refusal(connection));
        Assert.False(guard.Proven(connection));
    }

    [Fact]
    public void Nothing_is_refused_for_a_credential_keeper_does_not_hold()
    {
        var guard = new LogonGuard();
        var none = new Connection("open-api", null, "none");
        var negotiate = new Connection("shares", null, "negotiate");

        guard.Refuse(none, "api.example.org", "401");
        guard.Refuse(negotiate, "srv1", "1326");
        Assert.False(guard.DeniedAtSignIn(negotiate, "srv1", "denied"));
        Assert.False(guard.DeniedAtSignIn(negotiate, "srv2", "denied"));

        Assert.Null(guard.Refusal(none));
        Assert.Null(guard.Refusal(negotiate));
    }

    [Fact]
    public void A_proof_is_per_integration_but_a_refusal_is_per_account()
    {
        var guard = new LogonGuard();
        var right = new Connection("ad-main", "EXAMPLE\\reader", "windows-credential");
        var wrong = new Connection("win-servers", "EXAMPLE\\reader", "windows-credential");

        guard.Accepted(right);
        Assert.True(guard.Proven(right));
        Assert.False(guard.Proven(wrong));                 // its own password has not worked yet: one host at a time

        guard.Refuse(wrong, "srv1", "1326");
        Assert.NotNull(guard.Refusal(right));              // the account is what locks
    }
}
