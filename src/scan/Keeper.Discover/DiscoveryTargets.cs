using System.Net;
using System.Text.RegularExpressions;
using Keeper.Contracts;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Keeper.Discover;

public sealed record TargetEntry(IPNetwork? Network, string? Host)
{
    public static TargetEntry ForNetwork(IPNetwork network) => new(network, null);
    public static TargetEntry ForHost(string host) => new(null, host.ToLowerInvariant());
}

public sealed record ExcludeRule(IPNetwork? Cidr, string? NamePattern, string? Why);

public sealed record ApproveRule(IPNetwork Cidr, IReadOnlyList<string> Protocols, string Integration);

public sealed record AdSourceSettings(bool Enabled = false);

public sealed record DnsSourceSettings(bool Forward = true, bool Reverse = false);

public sealed record SnmpNeighboursSettings(bool Enabled = false, IReadOnlyList<string>? Credentials = null)
{
    public IReadOnlyList<string> CredentialList => Credentials ?? [];
}

public sealed record SourcesSettings
{
    public AdSourceSettings Ad { get; init; } = new();
    public DnsSourceSettings Dns { get; init; } = new();
    public SnmpNeighboursSettings SnmpNeighbours { get; init; } = new();
}

public sealed record WidenRule(int? Ipv4Prefix);

public sealed record WidenSettings
{
    public WidenRule? FromAd { get; init; }
    public WidenRule? FromDns { get; init; }
    public WidenRule? FromSnmpNeighbours { get; init; }
    public int MaxNewAddresses { get; init; } = 4096;
}

public sealed record SnmpSettings
{
    public IReadOnlyList<string> V3 { get; init; } = [];
    public IReadOnlyList<string> V2c { get; init; } = [];
    public bool AllowCleartext { get; init; }
}

public sealed record RateSettings
{
    public int ConnectionsPerSecond { get; init; } = 50;
    public int Concurrent { get; init; } = 64;
    public int PerHost { get; init; } = 2;
    public int TimeoutMs { get; init; } = 1500;
    public int Retries { get; init; } = 1;
}

public sealed record StalenessSettings
{
    public int GoneAfterScans { get; init; } = 3;
    public int GoneAfterDays { get; init; } = 14;
}

public sealed record ScanWindow(IReadOnlySet<DayOfWeek> Days, TimeOnly From, TimeOnly To)
{
    public bool Contains(DateTimeOffset localTime)
    {
        var day = localTime.DayOfWeek;
        var time = TimeOnly.FromTimeSpan(localTime.TimeOfDay);
        if (From <= To)
            return Days.Contains(day) && time >= From && time < To;

        // Overnight window (e.g. sat 20:00 -> 06:00 covers sat >= 20:00 and sun < 06:00).
        if (time >= From && Days.Contains(day))
            return true;
        var previousDay = (DayOfWeek)(((int)day + 6) % 7);
        return time < To && (Days.Contains(day) || Days.Contains(previousDay));
    }
}

public sealed record HistorySettings(int Keep = 20);

public sealed record DiscoveryTargets
{
    public string Schema { get; init; } = Schemas.DiscoveryTargets;
    public required string Mode { get; init; }
    public IReadOnlyList<IPNetwork> Scope { get; init; } = [];
    public IReadOnlyList<TargetEntry> Targets { get; init; } = [];
    public IReadOnlyList<ExcludeRule> Exclude { get; init; } = [];
    public IReadOnlyList<IPNetwork> Gentle { get; init; } = [];
    public IReadOnlyList<ApproveRule> Approve { get; init; } = [];
    public SourcesSettings Sources { get; init; } = new();
    public WidenSettings Widen { get; init; } = new();
    public SnmpSettings Snmp { get; init; } = new();
    public RateSettings Rate { get; init; } = new();
    public StalenessSettings Staleness { get; init; } = new();
    public IReadOnlyList<ScanWindow> Windows { get; init; } = [];
    public HistorySettings History { get; init; } = new();
}
