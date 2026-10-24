using System.Net;
using Keeper.Common;
using Keeper.Discover.Probes;
using Keeper.Discover.Sources;
using Microsoft.Data.Sqlite;

namespace Keeper.Discover;

public sealed record DiscoverRequest
{
    public required DiscoveryTargets Targets { get; init; }
    public required string ImportsDir { get; init; }
    public IDialer? Dialer { get; init; }
    public IResolver? Resolver { get; init; }
    public SqliteConnection? StoreConnection { get; init; }
    public IReadOnlyList<PortProfile>? Profiles { get; init; }
    public IReadOnlyList<SnmpCredential>? SnmpCredentials { get; init; }
    public TimeZoneInfo? TimeZone { get; init; }
    public bool Fresh { get; init; }
    public bool IgnoreWindow { get; init; }
    public bool DryRun { get; init; }
    public Action<string>? Log { get; init; }
}

public sealed record DiscoverPlanSummary(
    string Mode,
    int CandidateAssets,
    int TotalAddresses,
    TimeSpan EstimatedDuration,
    IReadOnlyList<DiscoveryCoverageEntry> SourceCoverage,
    IReadOnlyList<string> Notes);

public sealed record DiscoverRunReport(
    InventoryDocument Document,
    string? InventoryPath,
    DiscoverPlanSummary Plan);

/// <summary>
/// Orchestrates network discovery (T11):
/// 1. Collects candidates from targets, AD, DNS, and previous inventory (in free mode).
/// 2. Resolves hostnames and widens subnets within scope and caps.
/// 3. Sweeps each candidate through <see cref="ProbeGate"/> (TCP connect + handshakes + SNMP + SNMP neighbours).
/// 4. Evaluates scan health, updates asset lifecycles, classifies kinds, records coverage, and writes inventory.json.
/// </summary>
public sealed class Discoverer(TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<DiscoverRunReport> RunAsync(DiscoverRequest request, CancellationToken cancellationToken = default)
    {
        var targets = request.Targets;
        var dialer = request.Dialer ?? new SocketDialer();
        var resolver = request.Resolver ?? new SystemDnsResolver();
        var snmpCreds = request.SnmpCredentials ?? [];
        var now = _clock.GetUtcNow();
        var observedAt = Iso.Utc(now);
        var notes = new List<string>();
        var coverageEntries = new List<DiscoveryCoverageEntry>();

        if (targets.Snmp.AllowCleartext && targets.Snmp.V2c.Count > 0)
            notes.Add("WARNING: SNMP v2c is enabled (allow-cleartext: true); community strings cross the network in clear text.");

        using var gate = new ProbeGate(dialer, targets, _clock, request.TimeZone, request.IgnoreWindow);
        if (!request.DryRun)
            gate.EnsureWindowOpen();

        if (request.Fresh && !request.DryRun)
            InventoryFile.RotateForFresh(request.ImportsDir);

        var previousDoc = request.Fresh ? null : InventoryFile.LoadIfExists(request.ImportsDir);
        var previousAssets = previousDoc?.Assets ?? [];

        // 1. Gather seeds from targets.yaml
        var seeds = new List<CandidateSeed>();
        var targetCount = 0;
        foreach (var entry in targets.Targets)
        {
            if (entry.Host is { } host)
            {
                seeds.Add(new CandidateSeed(host, null, "targets", observedAt));
                targetCount++;
            }
            else if (entry.Network is { } net)
            {
                foreach (var ip in Addresses.Expand(net))
                {
                    seeds.Add(new CandidateSeed(null, ip, "targets", observedAt));
                    targetCount++;
                }
            }
        }
        coverageEntries.Add(new DiscoveryCoverageEntry
        {
            Scope = "source",
            Item = "targets",
            State = "ok",
            Count = targetCount,
        });

        // 2. Gather AD computer names in free mode
        var adIncomplete = false;
        if (targets.Mode == "free")
        {
            var (adHosts, adCov) = DiscoverySources.ReadAdComputers(request.StoreConnection, targets.Sources.Ad.Enabled, now);
            coverageEntries.Add(adCov);
            adIncomplete = adCov.State == "partial";
            if (adIncomplete && adCov.Reason is not null)
                notes.Add($"AD source partial: {adCov.Reason}");
            foreach (var h in adHosts)
                seeds.Add(new CandidateSeed(h, null, "ad", observedAt));
        }
        else
        {
            coverageEntries.Add(new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "ad",
                State = "skipped",
                Count = 0,
                Reason = "manual mode ignores external sources",
            });
        }

        // 3. Forward DNS resolution for named seeds and previous named assets
        // Manual mode probes only what 'targets' lists: names the last inventory happened to know are not re-seeded.
        var allNames = seeds.Select(s => s.Name)
            .Concat(targets.Mode == "manual" ? [] : previousAssets.SelectMany(a => a.Names))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n!.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var resolvedByName = new Dictionary<string, IReadOnlyList<IPAddress>>(StringComparer.Ordinal);
        var dnsResolvedCount = 0;
        if (targets.Sources.Dns.Forward || targets.Mode == "manual")
        {
            foreach (var name in allNames)
            {
                var ips = await resolver.ResolveAddressesAsync(name, cancellationToken).ConfigureAwait(false);
                if (ips.Count > 0)
                {
                    resolvedByName[name] = ips;
                    dnsResolvedCount += ips.Count;
                    // Also record resolved IPs so widening from-dns or from-ad can see them
                    var isAd = seeds.Any(s => s.Name == name && s.SourceKind == "ad");
                    foreach (var ip in ips)
                    {
                        seeds.Add(new CandidateSeed(name, ip, isAd ? "ad" : "dns", observedAt));
                    }
                }
                else
                {
                    resolvedByName[name] = [];
                }
            }
            coverageEntries.Add(new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "dns",
                State = "ok",
                Count = dnsResolvedCount,
            });
        }
        else
        {
            coverageEntries.Add(new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "dns",
                State = "skipped",
                Count = 0,
                Reason = "sources.dns.forward is false",
            });
        }

        // 4. Widening from AD and DNS in free mode
        var widenedTotal = 0;
        var knownIps = seeds.Where(s => s.Address is not null).Select(s => s.Address!).ToHashSet();
        if (targets.Mode == "free")
        {
            var remainingCap = targets.Widen.MaxNewAddresses;
            var (adWidened, adWidenCov) = DiscoverySources.ExpandWidening(
                seeds, "ad", targets.Widen.FromAd, targets.Scope, knownIps, remainingCap, observedAt);
            if (adWidenCov is not null)
            {
                coverageEntries.Add(adWidenCov);
                seeds.AddRange(adWidened);
                foreach (var w in adWidened)
                    knownIps.Add(w.Address!);
                remainingCap -= adWidened.Count;
                widenedTotal += adWidened.Count;
            }

            var (dnsWidened, dnsWidenCov) = DiscoverySources.ExpandWidening(
                seeds, "dns", targets.Widen.FromDns, targets.Scope, knownIps, Math.Max(0, remainingCap), observedAt);
            if (dnsWidenCov is not null)
            {
                coverageEntries.Add(dnsWidenCov);
                seeds.AddRange(dnsWidened);
                foreach (var w in dnsWidened)
                    knownIps.Add(w.Address!);
                widenedTotal += dnsWidened.Count;
            }
        }

        // 5. Optional reverse DNS lookup in free mode
        var reverseNames = new Dictionary<IPAddress, string>();
        if (targets.Mode == "free" && targets.Sources.Dns.Reverse)
        {
            foreach (var ip in knownIps)
            {
                if (await resolver.ResolveReverseNameAsync(ip, cancellationToken).ConfigureAwait(false) is { } ptr)
                    reverseNames[ip] = ptr;
            }
        }

        var mergedCandidates = DiscoverySources.MergeCandidates(
            targets.Mode == "manual" ? [] : previousAssets,
            seeds,
            resolvedByName,
            reverseNames);

        var totalAddresses = mergedCandidates.Sum(c => Math.Max(1, c.Addresses.Count));
        var portsPerAddress = (request.Profiles ?? PortProfiles.Defaults).Count;
        var cps = Math.Max(1, targets.Rate.ConnectionsPerSecond);
        var estimatedSeconds = (double)(totalAddresses * portsPerAddress) / cps;
        var planSummary = new DiscoverPlanSummary(
            targets.Mode,
            mergedCandidates.Count,
            totalAddresses,
            TimeSpan.FromSeconds(Math.Ceiling(estimatedSeconds)),
            coverageEntries,
            notes);

        if (request.DryRun)
        {
            var dryDoc = new InventoryDocument
            {
                GeneratedAt = observedAt,
                Mode = targets.Mode,
                ScanHealth = ScanHealthStates.Ok,
                Notes = notes,
                Coverage = new DiscoveryCoverage { Sources = coverageEntries },
                Assets = mergedCandidates,
            };
            return new DiscoverRunReport(dryDoc, null, planSummary);
        }

        // 6. Probe candidates (and discover SNMP neighbours if enabled in free mode)
        var outcomes = new Dictionary<string, ProbeAttemptOutcome>(StringComparer.Ordinal);
        var snmpNeighbourIps = new List<IPAddress>();
        var windowCutShort = false;

        foreach (var candidate in mergedCandidates)
        {
            if (cancellationToken.IsCancellationRequested || !gate.IsWithinWindow())
            {
                windowCutShort = true;
                outcomes[candidate.Id] = new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted);
                continue;
            }

            try
            {
                var (outcome, neighbours) = await ProbeCandidateAsync(
                    gate,
                    candidate,
                    targets,
                    request.Profiles,
                    snmpCreds,
                    now,
                    cancellationToken).ConfigureAwait(false);
                outcomes[candidate.Id] = outcome;
                snmpNeighbourIps.AddRange(neighbours);
            }
            catch (ScanWindowClosedException)
            {
                windowCutShort = true;
                outcomes[candidate.Id] = new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                windowCutShort = true;
                outcomes[candidate.Id] = new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted);
            }
        }

        // 7. If SNMP neighbours were discovered in free mode, merge and probe any newly discovered neighbour IPs
        if (targets.Mode == "free" && targets.Sources.SnmpNeighbours.Enabled)
        {
            var newNeighbourSeeds = new List<CandidateSeed>();
            foreach (var nip in snmpNeighbourIps.Distinct())
            {
                if (knownIps.Add(nip))
                    newNeighbourSeeds.Add(new CandidateSeed(null, nip, "snmp-neighbours", observedAt));
            }

            coverageEntries.Add(new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "snmp-neighbours",
                State = "ok",
                Count = snmpNeighbourIps.Distinct().Count(),
            });

            if (newNeighbourSeeds.Count > 0 && !windowCutShort)
            {
                var remainingCap = Math.Max(0, targets.Widen.MaxNewAddresses - widenedTotal);
                var (snmpWidened, snmpWidenCov) = DiscoverySources.ExpandWidening(
                    newNeighbourSeeds, "snmp-neighbours", targets.Widen.FromSnmpNeighbours, targets.Scope, knownIps, remainingCap, observedAt);
                if (snmpWidenCov is not null)
                {
                    coverageEntries.Add(snmpWidenCov);
                    newNeighbourSeeds.AddRange(snmpWidened);
                    widenedTotal += snmpWidened.Count;
                }

                mergedCandidates = DiscoverySources.MergeCandidates(mergedCandidates, newNeighbourSeeds, resolvedByName, reverseNames);
                foreach (var candidate in mergedCandidates.Where(c => !outcomes.ContainsKey(c.Id)))
                {
                    if (cancellationToken.IsCancellationRequested || !gate.IsWithinWindow())
                    {
                        windowCutShort = true;
                        outcomes[candidate.Id] = new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted);
                        continue;
                    }
                    try
                    {
                        var (outcome, _) = await ProbeCandidateAsync(gate, candidate, targets, request.Profiles, snmpCreds, now, cancellationToken).ConfigureAwait(false);
                        outcomes[candidate.Id] = outcome;
                    }
                    catch (ScanWindowClosedException)
                    {
                        windowCutShort = true;
                        outcomes[candidate.Id] = new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted);
                    }
                }
            }
        }

        // 8. Evaluate scan health and transition lifecycles
        var answeredIds = outcomes
            .Where(kv => kv.Value.Kind == ProbeOutcomeKind.Answered)
            .Select(kv => kv.Key)
            .ToHashSet(StringComparer.Ordinal);

        string scanHealth;
        if (windowCutShort)
        {
            scanHealth = ScanHealthStates.Partial;
            notes.Add("Scan cut short by scan window or cancellation; unreached assets recorded no attempt.");
        }
        else
        {
            var (health, healthReason) = Lifecycle.EvaluateHealth(previousAssets, answeredIds);
            scanHealth = health;
            if (healthReason is not null)
                notes.Add(healthReason);
        }

        var finalAssets = new List<DiscoveredAsset>(mergedCandidates.Count);
        foreach (var candidate in mergedCandidates)
        {
            var outcome = outcomes.GetValueOrDefault(candidate.Id, new ProbeAttemptOutcome(ProbeOutcomeKind.NotAttempted));
            var next = Lifecycle.Transition(
                candidate,
                outcome,
                 request.Fresh ? ScanHealthStates.Degraded : scanHealth,
                targets.Staleness,
                now,
                targets.History.Keep);
            finalAssets.Add(next);
        }

        var summary = new DiscoveryCoverageSummary
        {
            TotalCandidates = finalAssets.Count,
            Attempted = outcomes.Values.Count(o => o.Kind is ProbeOutcomeKind.Answered or ProbeOutcomeKind.Missed),
            Answering = finalAssets.Count(a => a.State == AssetStates.Answering),
            NotAnswering = finalAssets.Count(a => a.State == AssetStates.NotAnswering),
            LikelyGone = finalAssets.Count(a => a.State == AssetStates.LikelyGone),
            Unresolved = finalAssets.Count(a => a.State == AssetStates.Unresolved),
            Excluded = finalAssets.Count(a => a.State == AssetStates.Excluded),
            OutOfScope = finalAssets.Count(a => a.State == AssetStates.OutOfScope),
            WithManagementProtocol = finalAssets.Count(a => a.State == AssetStates.Answering && Classifier.HasManagementProtocol(a.Answered)),
            WidenedAddresses = widenedTotal,
        };

        var document = new InventoryDocument
        {
            GeneratedAt = observedAt,
            Mode = targets.Mode,
            ScanHealth = scanHealth,
            Notes = notes,
            Coverage = new DiscoveryCoverage
            {
                Sources = coverageEntries,
                Summary = summary,
            },
            Assets = finalAssets,
        };

        var writtenPath = InventoryFile.Write(request.ImportsDir, document, targets.History.Keep);
        return new DiscoverRunReport(document, writtenPath, planSummary);
    }

    private static async Task<(ProbeAttemptOutcome Outcome, IReadOnlyList<IPAddress> Neighbours)> ProbeCandidateAsync(
        ProbeGate gate,
        DiscoveredAsset candidate,
        DiscoveryTargets targets,
        IReadOnlyList<PortProfile>? profiles,
        IReadOnlyList<SnmpCredential> snmpCreds,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Check name-based exclusion first
        var (nameRefusal, nameReason) = gate.CheckTarget(null, candidate.Names);
        if (nameRefusal is not null)
            return (new ProbeAttemptOutcome(nameRefusal.Value, Note: nameReason), []);

        if (candidate.Addresses.Count == 0)
            return (new ProbeAttemptOutcome(ProbeOutcomeKind.Unresolved, Note: "hostname did not resolve to an A or AAAA record"), []);

        var parsedAddresses = candidate.Addresses
            .Select(a => Addresses.TryParseAddress(a, out var ip) ? ip : null)
            .Where(ip => ip is not null)
            .Select(ip => ip!)
            .ToList();

        // Check address exclusions and scope across the candidate's addresses
        var allowedAddresses = new List<IPAddress>();
        ProbeOutcomeKind? firstRefusal = null;
        string? firstRefusalReason = null;
        foreach (var ip in parsedAddresses)
        {
            var (refusal, reason) = gate.CheckTarget(ip, candidate.Names);
            if (refusal is null)
            {
                allowedAddresses.Add(ip);
            }
            else if (firstRefusal is null)
            {
                firstRefusal = refusal;
                firstRefusalReason = reason;
            }
        }

        if (allowedAddresses.Count == 0 && firstRefusal is not null)
            return (new ProbeAttemptOutcome(firstRefusal.Value, Note: firstRefusalReason), []);

        var allProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allServices = new List<AssetService>();
        var allTls = new List<System.Text.Json.Nodes.JsonObject>();
        var neighbours = new List<IPAddress>();
        SnmpInfo? snmpInfo = null;
        var anyAnswered = false;
        int? bestRtt = null;

        var fetchNeighbours = targets.Mode == "free" && targets.Sources.SnmpNeighbours.Enabled;

        foreach (var ip in allowedAddresses)
        {
            var sweep = await HandshakeProbes.SweepHostAsync(gate, ip, candidate.Names, profiles, now, cancellationToken).ConfigureAwait(false);
            if (sweep.Answered)
                anyAnswered = true;
            if (sweep.BestRttMs is { } rtt && (bestRtt is null || rtt < bestRtt.Value))
                bestRtt = rtt;
            foreach (var p in sweep.AnsweredProtocols)
                allProtocols.Add(p);
            allServices.AddRange(sweep.Services);
            allTls.AddRange(sweep.TlsCertificates);

            if (!gate.IsGentle(ip))
            {
                var snmpOutcome = await SnmpProbe.ProbeHostAsync(
                    gate, ip, candidate.Names, targets.Snmp, snmpCreds, fetchNeighbours, SnmpProbe.DefaultPort, cancellationToken,
                    targets.Sources.SnmpNeighbours.Credentials ?? []).ConfigureAwait(false);
                if (snmpOutcome.Info is not null)
                {
                    anyAnswered = true;
                    snmpInfo ??= snmpOutcome.Info;
                    allProtocols.Add("snmp");
                    if (snmpOutcome.RttMs is { } srtt && (bestRtt is null || srtt < bestRtt.Value))
                        bestRtt = srtt;
                }
                neighbours.AddRange(snmpOutcome.NeighbourAddresses);
            }
        }

        if (!anyAnswered)
            return (new ProbeAttemptOutcome(ProbeOutcomeKind.Missed), []);

        var orderedProtocols = allProtocols.OrderBy(p => p, StringComparer.Ordinal).ToList();
        var dedupServices = allServices
            .GroupBy(s => (s.Port, s.Transport))
            .Select(g => g.First())
            .OrderBy(s => s.Port)
            .ToList();

        var (kind, kindWhy) = Classifier.Classify(orderedProtocols, dedupServices, snmpInfo);
        var outcome = new ProbeAttemptOutcome(
            ProbeOutcomeKind.Answered,
            orderedProtocols,
            dedupServices,
            snmpInfo,
            allTls,
            bestRtt,
            kind,
            kindWhy);

        return (outcome, neighbours);
    }
}
