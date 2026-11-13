using System.Globalization;
using System.Text.Json.Nodes;
using Keeper.Common;

namespace Keeper.Discover;

public enum ProbeOutcomeKind
{
    NotAttempted,
    Answered,
    Missed,
    Unresolved,
    Excluded,
    OutOfScope,
}

public sealed record ProbeAttemptOutcome(
    ProbeOutcomeKind Kind,
    IReadOnlyList<string>? AnsweredProtocols = null,
    IReadOnlyList<AssetService>? Services = null,
    SnmpInfo? Snmp = null,
    IReadOnlyList<JsonObject>? Tls = null,
    int? BestRttMs = null,
    string? ClassifiedKind = null,
    string? ClassifiedWhy = null,
    string? Note = null);

/// <summary>
/// Pure asset lifecycle transitions and scan-health evaluation.
/// Never deletes an asset; requires both scan count and elapsed days before moving to likely-gone;
/// freezes misses when scan health is degraded (&lt; 50% of previously answering assets answered).
/// </summary>
public static class Lifecycle
{
    public const double DefaultHealthRatio = 0.5;

    /// <summary>Fewer answering assets than this last time is too small a baseline to call an outage.</summary>
    public const int MinimumBaseline = 4;

    /// <summary>
    /// Evaluates whether the scan is healthy enough to count misses.
    /// When fewer than <paramref name="healthRatio"/> of last scan's answering assets answered, returns Degraded.
    /// </summary>
    public static (string Health, string? Reason) EvaluateHealth(
        IReadOnlyList<DiscoveredAsset> previousAssets,
        IReadOnlySet<string> answeredIds,
        double healthRatio = DefaultHealthRatio)
    {
        var previouslyAnswering = previousAssets
            .Where(a => a.State == AssetStates.Answering)
            .Select(a => a.Id)
            .ToList();

        if (previouslyAnswering.Count < MinimumBaseline)
            return (ScanHealthStates.Ok, null);

        var answeredCount = previouslyAnswering.Count(answeredIds.Contains);
        var ratio = (double)answeredCount / previouslyAnswering.Count;
        if (ratio < healthRatio)
        {
            return (
                ScanHealthStates.Degraded,
                $"Only {answeredCount} of {previouslyAnswering.Count} previously answering assets ({ratio:P0}) answered, below the {healthRatio:P0} health threshold; misses were not counted.");
        }

        return (ScanHealthStates.Ok, null);
    }

    public static DiscoveredAsset Transition(
        DiscoveredAsset asset,
        ProbeAttemptOutcome outcome,
        string scanHealth,
        StalenessSettings staleness,
        DateTimeOffset now,
        int historyKeep = 20)
    {
        var nowIso = Iso.Utc(now);

        switch (outcome.Kind)
        {
            case ProbeOutcomeKind.NotAttempted:
                return asset;

            case ProbeOutcomeKind.Excluded:
                return asset with
                {
                    State = AssetStates.Excluded,
                    Note = outcome.Note ?? asset.Note,
                };

            case ProbeOutcomeKind.OutOfScope:
                return asset with
                {
                    State = AssetStates.OutOfScope,
                    Note = outcome.Note ?? asset.Note,
                };

            case ProbeOutcomeKind.Unresolved:
                return asset with
                {
                    State = AssetStates.Unresolved,
                    Note = outcome.Note ?? asset.Note,
                };

            case ProbeOutcomeKind.Answered:
            {
                var flapped = asset.State is AssetStates.NotAnswering or AssetStates.LikelyGone;
                var answered = outcome.AnsweredProtocols ?? [];
                var entry = new AssetHistoryEntry
                {
                    At = nowIso,
                    Outcome = "answered",
                    Answered = answered,
                    RttMs = outcome.BestRttMs,
                };
                return asset with
                {
                    State = AssetStates.Answering,
                    EverAnswered = true,
                    FirstSeen = asset.FirstSeen ?? nowIso,
                    LastSeen = nowIso,
                    Misses = 0,
                    MissingSince = null,
                    Flaps = flapped ? asset.Flaps + 1 : asset.Flaps,
                    Kind = outcome.ClassifiedKind ?? asset.Kind,
                    KindWhy = outcome.ClassifiedWhy ?? asset.KindWhy,
                    Note = outcome.Note,
                    Answered = answered,
                    Services = outcome.Services ?? asset.Services,
                    Snmp = outcome.Snmp ?? asset.Snmp,
                    Tls = outcome.Tls ?? asset.Tls,
                    History = AppendHistory(asset.History, entry, historyKeep),
                };
            }

            case ProbeOutcomeKind.Missed:
            {
                var entry = new AssetHistoryEntry
                {
                    At = nowIso,
                    Outcome = "missed",
                    Answered = [],
                    RttMs = null,
                };

                // Degraded or partial scans do not advance miss counters or mark assets gone.
                if (scanHealth != ScanHealthStates.Ok)
                {
                    return asset with
                    {
                        History = AppendHistory(asset.History, entry, historyKeep),
                    };
                }

                var misses = asset.Misses + 1;
                var missingSinceIso = asset.MissingSince ?? nowIso;
                var missingDays = TryParseUtc(missingSinceIso, out var since)
                    ? (now - since).TotalDays
                    : 0.0;

                var isLikelyGone = asset.State == AssetStates.LikelyGone
                    || (misses >= staleness.GoneAfterScans && missingDays >= staleness.GoneAfterDays);

                return asset with
                {
                    State = isLikelyGone ? AssetStates.LikelyGone : AssetStates.NotAnswering,
                    Misses = misses,
                    MissingSince = missingSinceIso,
                    History = AppendHistory(asset.History, entry, historyKeep),
                };
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(outcome));
        }
    }

    private static IReadOnlyList<AssetHistoryEntry> AppendHistory(IReadOnlyList<AssetHistoryEntry> existing, AssetHistoryEntry next, int keep)
    {
        var list = new List<AssetHistoryEntry>(existing.Count + 1);
        list.AddRange(existing);
        list.Add(next);
        if (keep > 0 && list.Count > keep)
            list.RemoveRange(0, list.Count - keep);
        return list;
    }

    private static bool TryParseUtc(string iso, out DateTimeOffset value) =>
        DateTimeOffset.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value);
}
