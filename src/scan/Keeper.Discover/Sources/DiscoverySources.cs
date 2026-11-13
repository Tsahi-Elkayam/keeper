using System.Net;
using System.Net.Sockets;
using Keeper.Common;
using Keeper.Rules;
using Keeper.Scan;
using Microsoft.Data.Sqlite;

namespace Keeper.Discover.Sources;

/// <summary>Abstracts forward (A/AAAA) and reverse (PTR) DNS lookups so discovery is deterministic in tests.</summary>
public interface IResolver
{
    Task<IReadOnlyList<IPAddress>> ResolveAddressesAsync(string hostName, CancellationToken cancellationToken = default);

    Task<string?> ResolveReverseNameAsync(IPAddress address, CancellationToken cancellationToken = default);
}

public sealed class SystemDnsResolver : IResolver
{
    public async Task<IReadOnlyList<IPAddress>> ResolveAddressesAsync(string hostName, CancellationToken cancellationToken = default)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(hostName, cancellationToken).ConfigureAwait(false);
            return addresses
                .Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Distinct()
                .ToList();
        }
        catch (SocketException)
        {
            return [];
        }
    }

    public async Task<string?> ResolveReverseNameAsync(IPAddress address, CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(address.ToString(), cts.Token).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName.Trim().TrimEnd('.').ToLowerInvariant();
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }
}

public sealed record CandidateSeed(
    string? Name,
    IPAddress? Address,
    string SourceKind,
    string ObservedAt);

/// <summary>
/// Collects candidate assets from targets, Active Directory (via StoreInputs), DNS resolution,
/// SNMP neighbours, and subnet widening, then merges IP-only candidates into named assets.
/// </summary>
public static class DiscoverySources
{
    public static (IReadOnlyList<string> HostNames, DiscoveryCoverageEntry Coverage) ReadAdComputers(
        SqliteConnection? storeConnection,
        bool enabled,
        DateTimeOffset now)
    {
        if (!enabled)
        {
            return ([], new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "ad",
                State = "skipped",
                Count = 0,
                Reason = "sources.ad.enabled is false",
            });
        }
        if (storeConnection is null)
        {
            return ([], new DiscoveryCoverageEntry
            {
                Scope = "source",
                Item = "ad",
                State = "failed",
                Count = 0,
                Reason = "store is not available",
            });
        }

        var inputs = new StoreInputs(storeConnection, Iso.Date(now));
        var spec = new TargetSpec("computer", null, "dNSHostName", []);
        var hosts = inputs.Targets(spec, now)
            .Select(h => h.Trim().TrimEnd('.').ToLowerInvariant())
            .Where(h => h.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var incomplete = inputs.TargetsIncomplete(spec);

        return (hosts, new DiscoveryCoverageEntry
        {
            Scope = "source",
            Item = "ad",
            State = incomplete is not null ? "partial" : "ok",
            Count = hosts.Count,
            Reason = incomplete,
        });
    }

    public static (IReadOnlyList<CandidateSeed> Widened, DiscoveryCoverageEntry? Coverage) ExpandWidening(
        IReadOnlyList<CandidateSeed> seeds,
        string sourceKind,
        WidenRule? rule,
        IReadOnlyList<IPNetwork> scope,
        IReadOnlySet<IPAddress> alreadyKnown,
        int remainingCap,
        string observedAt)
    {
        if (rule?.Ipv4Prefix is not { } prefix)
            return ([], null);

        var sourceAddresses = seeds
            .Where(s => s.SourceKind == sourceKind && s.Address is { AddressFamily: AddressFamily.InterNetwork })
            .Select(s => s.Address!)
            .Distinct()
            .ToList();

        if (sourceAddresses.Count == 0)
            return ([], null);

        var networks = sourceAddresses
            .Select(ip => Addresses.Widen(ip, prefix))
            .Distinct()
            .ToList();

        var added = new List<CandidateSeed>();
        var seen = new HashSet<IPAddress>(alreadyKnown);
        var capped = false;

        foreach (var net in networks)
        {
            foreach (var ip in Addresses.Expand(net))
            {
                if (scope.Count > 0 && !scope.Any(s => Addresses.Contains(s, ip)))
                    continue;
                if (!seen.Add(ip))
                    continue;
                if (added.Count >= remainingCap)
                {
                    capped = true;
                    break;
                }
                added.Add(new CandidateSeed(null, ip, $"widened-from:{sourceKind}", observedAt));
            }
            if (capped)
                break;
        }

        var cov = new DiscoveryCoverageEntry
        {
            Scope = "widening",
            Item = $"from-{sourceKind}:/{prefix}",
            State = capped ? "partial" : "ok",
            Count = added.Count,
            Reason = capped ? $"capped at widen.max-new-addresses ({remainingCap})" : null,
        };
        return (added, cov);
    }

    /// <summary>
    /// Merges previous inventory assets with new candidate seeds:
    /// - Named assets use their lower-cased hostname as Id.
    /// - IP-only assets use "ip:&lt;address&gt;" as Id, and are merged into a named asset when a named asset resolves to that IP.
    /// - Preserves dual-stack (IPv4 + IPv6) addresses and combines source timestamps.
    /// - Preserves existing "ad" source entries when the current AD read is incomplete.
    /// </summary>
    public static List<DiscoveredAsset> MergeCandidates(
        IReadOnlyList<DiscoveredAsset> previousAssets,
        IReadOnlyList<CandidateSeed> seeds,
        IReadOnlyDictionary<string, IReadOnlyList<IPAddress>> resolvedByName,
        IReadOnlyDictionary<IPAddress, string> reverseNames)
    {
        // Map IP -> primary hostname if any named seed or reverse DNS claims that IP
        var ipToName = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, ips) in resolvedByName.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            foreach (var ip in ips)
                ipToName.TryAdd(Addresses.Canonical(ip), name.ToLowerInvariant());
        }
        foreach (var (ip, revName) in reverseNames.OrderBy(kv => kv.Value, StringComparer.Ordinal))
            ipToName.TryAdd(Addresses.Canonical(ip), revName.ToLowerInvariant());
        foreach (var prev in previousAssets.Where(a => a.Names.Count > 0))
        {
            foreach (var addr in prev.Addresses)
                ipToName.TryAdd(addr, prev.Names[0].ToLowerInvariant());
        }

        var byId = new Dictionary<string, DiscoveredAsset>(StringComparer.Ordinal);
        foreach (var prev in previousAssets)
        {
            // If a previously IP-only asset now has a known hostname for its IP, re-key it under the hostname
            var targetId = prev.Id;
            if (prev.Id.StartsWith("ip:", StringComparison.Ordinal) && prev.Addresses.Count > 0
                && ipToName.TryGetValue(prev.Addresses[0], out var mappedName))
            {
                targetId = mappedName;
            }

            if (byId.TryGetValue(targetId, out var existing))
                byId[targetId] = CombineAssets(existing, prev with { Id = targetId });
            else
                byId[targetId] = prev with
                {
                    Id = targetId,
                    Names = targetId.StartsWith("ip:", StringComparison.Ordinal)
                        ? prev.Names
                        : MergeStrings(prev.Names, [targetId]),
                };
        }

        foreach (var seed in seeds)
        {
            var canonicalIp = seed.Address is not null ? Addresses.Canonical(seed.Address) : null;
            var name = seed.Name?.ToLowerInvariant()
                ?? (canonicalIp is not null && ipToName.TryGetValue(canonicalIp, out var mapped) ? mapped : null);

            var id = name ?? $"ip:{canonicalIp}";
            var resolvedStrings = name is not null && resolvedByName.TryGetValue(name, out var ips)
                ? ips.Select(Addresses.Canonical).ToList()
                : [];
            if (canonicalIp is not null && !resolvedStrings.Contains(canonicalIp, StringComparer.Ordinal))
                resolvedStrings.Add(canonicalIp);

            var seedSource = new AssetSource
            {
                Kind = seed.SourceKind,
                FirstListed = seed.ObservedAt,
                LastListed = seed.ObservedAt,
            };

            if (!byId.TryGetValue(id, out var current))
            {
                byId[id] = new DiscoveredAsset
                {
                    Id = id,
                    Names = name is not null ? [name] : [],
                    Addresses = resolvedStrings,
                    Sources = [seedSource],
                    State = AssetStates.Pending,
                };
            }
            else
            {
                byId[id] = current with
                {
                    Names = name is not null ? MergeStrings(current.Names, [name]) : current.Names,
                    Addresses = resolvedStrings.Count > 0 ? MergeStrings(current.Addresses, resolvedStrings) : current.Addresses,
                    Sources = MergeSources(current.Sources, [seedSource]),
                };
            }
        }

        return byId.Values.OrderBy(a => a.Id, StringComparer.Ordinal).ToList();
    }

    private static DiscoveredAsset CombineAssets(DiscoveredAsset primary, DiscoveredAsset secondary) =>
        primary with
        {
            Names = MergeStrings(primary.Names, secondary.Names),
            Addresses = MergeStrings(primary.Addresses, secondary.Addresses),
            Sources = MergeSources(primary.Sources, secondary.Sources),
            EverAnswered = primary.EverAnswered || secondary.EverAnswered,
            FirstSeen = EarliestIso(primary.FirstSeen, secondary.FirstSeen),
            LastSeen = LatestIso(primary.LastSeen, secondary.LastSeen),
            Flaps = Math.Max(primary.Flaps, secondary.Flaps),
            Services = primary.Services.Count > 0 ? primary.Services : secondary.Services,
            Answered = primary.Answered.Count > 0 ? primary.Answered : secondary.Answered,
            Snmp = primary.Snmp ?? secondary.Snmp,
            Tls = primary.Tls.Count > 0 ? primary.Tls : secondary.Tls,
            History = primary.History.Count >= secondary.History.Count ? primary.History : secondary.History,
        };

    private static IReadOnlyList<string> MergeStrings(IReadOnlyList<string> a, IReadOnlyList<string> b) =>
        a.Concat(b).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal).ToList();

    private static IReadOnlyList<AssetSource> MergeSources(IReadOnlyList<AssetSource> a, IReadOnlyList<AssetSource> b)
    {
        var map = new Dictionary<string, AssetSource>(StringComparer.Ordinal);
        foreach (var src in a.Concat(b))
        {
            if (!map.TryGetValue(src.Kind, out var cur))
            {
                map[src.Kind] = src;
            }
            else
            {
                map[src.Kind] = new AssetSource
                {
                    Kind = src.Kind,
                    FirstListed = EarliestIso(cur.FirstListed, src.FirstListed) ?? src.FirstListed,
                    LastListed = LatestIso(cur.LastListed, src.LastListed) ?? src.LastListed,
                };
            }
        }
        return map.Values.OrderBy(s => s.Kind, StringComparer.Ordinal).ToList();
    }

    private static string? EarliestIso(string? a, string? b) =>
        a is null ? b : b is null ? a : string.CompareOrdinal(a, b) <= 0 ? a : b;

    private static string? LatestIso(string? a, string? b) =>
        a is null ? b : b is null ? a : string.CompareOrdinal(a, b) >= 0 ? a : b;
}
