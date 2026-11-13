using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Keeper.Contracts;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Keeper.Discover;

/// <summary>Loads and strictly validates settings/discovery.yaml.</summary>
public static partial class TargetsLoader
{
    public const long MaxBytes = 1024 * 1024;

    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal)
    {
        "schema", "mode", "scope", "targets", "exclude", "gentle", "approve",
        "sources", "widen", "snmp", "rate", "staleness", "windows", "history",
    };

    private static readonly Dictionary<string, DayOfWeek> DayNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sun"] = DayOfWeek.Sunday, ["sunday"] = DayOfWeek.Sunday,
        ["mon"] = DayOfWeek.Monday, ["monday"] = DayOfWeek.Monday,
        ["tue"] = DayOfWeek.Tuesday, ["tuesday"] = DayOfWeek.Tuesday,
        ["wed"] = DayOfWeek.Wednesday, ["wednesday"] = DayOfWeek.Wednesday,
        ["thu"] = DayOfWeek.Thursday, ["thursday"] = DayOfWeek.Thursday,
        ["fri"] = DayOfWeek.Friday, ["friday"] = DayOfWeek.Friday,
        ["sat"] = DayOfWeek.Saturday, ["saturday"] = DayOfWeek.Saturday,
    };

    public static DiscoveryTargets Load(string file)
    {
        var info = new FileInfo(file);
        if (!info.Exists)
            throw new ArgumentException($"Discovery targets file not found: {file}");
        if (info.LinkTarget is not null)
            throw new ArgumentException($"Discovery targets file '{file}' is a symbolic link; links are not followed.");
        if (info.Length > MaxBytes)
            throw new ArgumentException($"Discovery targets file '{file}' exceeds 1 MB.");

        return Parse(File.ReadAllText(file), file);
    }

    public static DiscoveryTargets Parse(string yaml, string file = "discovery.yaml")
    {
        var errors = new List<string>();
        var stream = new YamlStream();
        try
        {
            using var reader = new StringReader(yaml);
            stream.Load(reader);
        }
        catch (YamlException ex)
        {
            throw new ArgumentException($"{file}:{ex.Start.Line}:{ex.Start.Column}: invalid YAML: {ex.Message}");
        }

        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode rootNode)
            throw new ArgumentException($"{file}: must contain a single YAML mapping document.");

        RefuseAnchors(rootNode, file, errors);
        var root = Fields(rootNode, "discovery", RootFields, file, errors) ?? new();

        var schema = Text(root, "schema", "discovery", file, errors, required: true);
        if (schema is not null && schema != Schemas.DiscoveryTargets)
            errors.Add($"{file}: unsupported schema '{schema}' (expected '{Schemas.DiscoveryTargets}').");

        var mode = Text(root, "mode", "discovery", file, errors, required: true)?.ToLowerInvariant();
        if (mode is not null && mode is not ("free" or "manual"))
            errors.Add($"{file}: 'mode' must be 'free' or 'manual' (got '{mode}').");

        var scope = ParseNetworkList(root, "scope", file, errors, checkIpv6SweepWidth: true);
        if (mode == "free" && scope.Count == 0)
            errors.Add($"{file}: free mode requires a non-empty 'scope' list of allowed networks.");

        var targets = ParseTargets(root, scope, mode, file, errors);
        var exclude = ParseExcludes(root, file, errors);
        var gentle = ParseNetworkList(root, "gentle", file, errors, checkIpv6SweepWidth: true);
        var approve = ParseApproves(root, file, errors);
        var sources = ParseSources(root, file, errors);
        var widen = ParseWiden(root, file, errors);
        var snmp = ParseSnmp(root, file, errors);
        var rate = ParseRate(root, file, errors);
        var staleness = ParseStaleness(root, file, errors);
        var windows = ParseWindows(root, file, errors);
        var history = ParseHistory(root, file, errors);

        if (errors.Count > 0)
            throw new ArgumentException(string.Join(Environment.NewLine, errors));

        return new DiscoveryTargets
        {
            Schema = schema ?? Schemas.DiscoveryTargets,
            Mode = mode ?? "manual",
            Scope = scope,
            Targets = targets,
            Exclude = exclude,
            Gentle = gentle,
            Approve = approve,
            Sources = sources,
            Widen = widen,
            Snmp = snmp,
            Rate = rate,
            Staleness = staleness,
            Windows = windows,
            History = history,
        };
    }

    private static List<IPNetwork> ParseNetworkList(Dictionary<string, YamlNode> fields, string name, string file, List<string> errors, bool checkIpv6SweepWidth)
    {
        if (!fields.TryGetValue(name, out var node))
            return [];
        if (node is not YamlSequenceNode seq)
        {
            Error(node, $"'{name}' must be a list of CIDR ranges or IP addresses.", file, errors);
            return [];
        }
        var list = new List<IPNetwork>();
        foreach (var item in seq.Children)
        {
            if (item is not YamlScalarNode { Value: { } text })
            {
                Error(item, $"'{name}': entry must be a string.", file, errors);
                continue;
            }
            if (!Addresses.TryParseNetwork(text, out var net, out var err))
            {
                Error(item, $"'{name}': invalid network '{text}': {err}", file, errors);
                continue;
            }
            if (checkIpv6SweepWidth && net.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6 && net.PrefixLength < Addresses.MinIpv6Prefix)
            {
                Error(item, $"'{name}': IPv6 range '{text}' is wider than /{Addresses.MinIpv6Prefix}.", file, errors);
                continue;
            }
            list.Add(net);
        }
        return list;
    }

    private static List<TargetEntry> ParseTargets(Dictionary<string, YamlNode> fields, List<IPNetwork> scope, string? mode, string file, List<string> errors)
    {
        if (!fields.TryGetValue("targets", out var node))
            return [];
        if (node is not YamlSequenceNode seq)
        {
            Error(node, "'targets' must be a list.", file, errors);
            return [];
        }
        var list = new List<TargetEntry>();
        foreach (var item in seq.Children)
        {
            if (item is YamlScalarNode { Value: { } text })
            {
                if (!Addresses.TryParseNetwork(text, out var net, out var err))
                {
                    Error(item, $"'targets': '{text}' is not a valid address or CIDR ({err}). Use '{{ host: <name> }}' for hostnames.", file, errors);
                    continue;
                }
                if (net.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6 && net.PrefixLength < Addresses.MinIpv6Prefix)
                {
                    Error(item, $"'targets': IPv6 range '{text}' is wider than /{Addresses.MinIpv6Prefix}.", file, errors);
                    continue;
                }
                if (mode == "free" && scope.Count > 0 && !scope.Any(s => Addresses.ContainsNetwork(s, net)))
                {
                    Error(item, $"'targets': '{text}' is outside 'scope'.", file, errors);
                    continue;
                }
                list.Add(TargetEntry.ForNetwork(net));
            }
            else if (item is YamlMappingNode map)
            {
                var mapFields = Fields(map, "targets item", ["host"], file, errors);
                if (mapFields is null)
                    continue;
                var host = Text(mapFields, "host", "targets item", file, errors, required: true);
                if (host is not null)
                {
                    if (!IsValidHostName(host))
                        Error(map, $"'targets': '{host}' is not a valid hostname.", file, errors);
                    else
                        list.Add(TargetEntry.ForHost(host));
                }
            }
            else
            {
                Error(item, "'targets' entries must be CIDR/IP strings or '{ host: <name> }'.", file, errors);
            }
        }
        return list;
    }

    private static List<ExcludeRule> ParseExcludes(Dictionary<string, YamlNode> fields, string file, List<string> errors)
    {
        if (!fields.TryGetValue("exclude", out var node))
            return [];
        if (node is not YamlSequenceNode seq)
        {
            Error(node, "'exclude' must be a list.", file, errors);
            return [];
        }
        var list = new List<ExcludeRule>();
        foreach (var item in seq.Children)
        {
            var map = Fields(item, "exclude", ["cidr", "name", "why"], file, errors);
            if (map is null)
                continue;
            var cidrText = Text(map, "cidr", "exclude", file, errors);
            var namePattern = Text(map, "name", "exclude", file, errors);
            var why = Text(map, "why", "exclude", file, errors);
            if (cidrText is null && namePattern is null)
            {
                Error(item, "'exclude' entry must specify 'cidr' or 'name'.", file, errors);
                continue;
            }
            IPNetwork? cidr = null;
            if (cidrText is not null)
            {
                if (!Addresses.TryParseNetwork(cidrText, out var parsed, out var err))
                {
                    Error(item, $"'exclude.cidr': {err}", file, errors);
                    continue;
                }
                cidr = parsed;
            }
            if (namePattern is not null && !IsValidNamePattern(namePattern))
            {
                Error(item, $"'exclude.name': invalid hostname pattern '{namePattern}'.", file, errors);
                continue;
            }
            list.Add(new ExcludeRule(cidr, namePattern?.ToLowerInvariant(), why));
        }
        return list;
    }

    private static List<ApproveRule> ParseApproves(Dictionary<string, YamlNode> fields, string file, List<string> errors)
    {
        if (!fields.TryGetValue("approve", out var node))
            return [];
        if (node is not YamlSequenceNode seq)
        {
            Error(node, "'approve' must be a list.", file, errors);
            return [];
        }
        var list = new List<ApproveRule>();
        foreach (var item in seq.Children)
        {
            var map = Fields(item, "approve", ["cidr", "protocols", "integration"], file, errors);
            if (map is null)
                continue;
            var cidrText = Text(map, "cidr", "approve", file, errors, required: true);
            var protocols = Strings(map, "protocols", "approve", file, errors);
            var integration = Text(map, "integration", "approve", file, errors, required: true);
            if (cidrText is not null && integration is not null)
            {
                if (!Addresses.TryParseNetwork(cidrText, out var net, out var err))
                    Error(item, $"'approve.cidr': {err}", file, errors);
                else
                    list.Add(new ApproveRule(net, protocols, integration));
            }
        }
        return list;
    }

    private static SourcesSettings ParseSources(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("sources", out var node))
            return new();
        var map = Fields(node, "sources", ["ad", "dns", "snmp-neighbours"], file, errors);
        if (map is null)
            return new();

        var ad = new AdSourceSettings();
        if (map.TryGetValue("ad", out var adNode) && Fields(adNode, "sources.ad", ["enabled"], file, errors) is { } adMap)
            ad = new AdSourceSettings(Bool(adMap, "enabled", "sources.ad", false, file, errors));

        var dns = new DnsSourceSettings();
        if (map.TryGetValue("dns", out var dnsNode) && Fields(dnsNode, "sources.dns", ["forward", "reverse"], file, errors) is { } dnsMap)
            dns = new DnsSourceSettings(
                Bool(dnsMap, "forward", "sources.dns", true, file, errors),
                Bool(dnsMap, "reverse", "sources.dns", false, file, errors));

        var snmp = new SnmpNeighboursSettings();
        if (map.TryGetValue("snmp-neighbours", out var snmpNode) && Fields(snmpNode, "sources.snmp-neighbours", ["enabled", "credentials"], file, errors) is { } snmpMap)
            snmp = new SnmpNeighboursSettings(
                Bool(snmpMap, "enabled", "sources.snmp-neighbours", false, file, errors),
                Strings(snmpMap, "credentials", "sources.snmp-neighbours", file, errors));

        return new SourcesSettings { Ad = ad, Dns = dns, SnmpNeighbours = snmp };
    }

    private static WidenSettings ParseWiden(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("widen", out var node))
            return new();
        var map = Fields(node, "widen", ["from-ad", "from-dns", "from-snmp-neighbours", "max-new-addresses"], file, errors);
        if (map is null)
            return new();

        WidenRule? Rule(string key)
        {
            if (!map.TryGetValue(key, out var rNode))
                return null;
            if (Fields(rNode, $"widen.{key}", ["ipv4-prefix"], file, errors) is not { } rMap)
                return null;
            var prefix = Int(rMap, "ipv4-prefix", $"widen.{key}", 24, 16, 32, file, errors);
            return new WidenRule(prefix);
        }

        return new WidenSettings
        {
            FromAd = Rule("from-ad"),
            FromDns = Rule("from-dns"),
            FromSnmpNeighbours = Rule("from-snmp-neighbours"),
            MaxNewAddresses = Int(map, "max-new-addresses", "widen", 4096, 0, 1_000_000, file, errors),
        };
    }

    private static SnmpSettings ParseSnmp(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("snmp", out var node))
            return new();
        var map = Fields(node, "snmp", ["v3", "v2c", "allow-cleartext"], file, errors);
        if (map is null)
            return new();

        var v3 = Strings(map, "v3", "snmp", file, errors);
        var v2c = Strings(map, "v2c", "snmp", file, errors);
        var allowCleartext = Bool(map, "allow-cleartext", "snmp", false, file, errors);
        if (v2c.Count > 0 && !allowCleartext)
            Error(node, "snmp: 'v2c' requires 'allow-cleartext: true' because SNMP v2c sends community strings in clear text.", file, errors);

        return new SnmpSettings { V3 = v3, V2c = v2c, AllowCleartext = allowCleartext };
    }

    private static RateSettings ParseRate(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("rate", out var node))
            return new();
        var map = Fields(node, "rate", ["connections-per-second", "concurrent", "per-host", "timeout-ms", "retries"], file, errors);
        if (map is null)
            return new();

        return new RateSettings
        {
            ConnectionsPerSecond = Int(map, "connections-per-second", "rate", 50, 1, 10_000, file, errors),
            Concurrent = Int(map, "concurrent", "rate", 64, 1, 2048, file, errors),
            PerHost = Int(map, "per-host", "rate", 2, 1, 64, file, errors),
            TimeoutMs = Int(map, "timeout-ms", "rate", 1500, 50, 60_000, file, errors),
            Retries = Int(map, "retries", "rate", 1, 0, 5, file, errors),
        };
    }

    private static StalenessSettings ParseStaleness(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("staleness", out var node))
            return new();
        var map = Fields(node, "staleness", ["gone-after-scans", "gone-after-days"], file, errors);
        if (map is null)
            return new();

        return new StalenessSettings
        {
            GoneAfterScans = Int(map, "gone-after-scans", "staleness", 3, 1, 100, file, errors),
            GoneAfterDays = Int(map, "gone-after-days", "staleness", 14, 0, 3650, file, errors),
        };
    }

    private static List<ScanWindow> ParseWindows(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("windows", out var node))
            return [];
        if (node is not YamlSequenceNode seq)
        {
            Error(node, "'windows' must be a list.", file, errors);
            return [];
        }
        var list = new List<ScanWindow>();
        foreach (var item in seq.Children)
        {
            var map = Fields(item, "windows", ["days", "from", "to"], file, errors);
            if (map is null)
                continue;
            var dayStrings = Strings(map, "days", "windows", file, errors);
            if (dayStrings.Count == 0)
            {
                Error(item, "'windows.days' must list at least one day (e.g. sat, sun).", file, errors);
                continue;
            }
            var days = new HashSet<DayOfWeek>();
            foreach (var d in dayStrings)
            {
                if (!DayNames.TryGetValue(d, out var dow))
                    Error(item, $"'windows.days': unknown day '{d}'.", file, errors);
                else
                    days.Add(dow);
            }
            var fromText = Text(map, "from", "windows", file, errors, required: true);
            var toText = Text(map, "to", "windows", file, errors, required: true);
            if (fromText is null || toText is null)
                continue;
            if (!TimeOnly.TryParseExact(fromText, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var from))
            {
                Error(item, $"'windows.from': '{fromText}' must be HH:mm (00:00..23:59).", file, errors);
                continue;
            }
            if (!TimeOnly.TryParseExact(toText, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var to))
            {
                Error(item, $"'windows.to': '{toText}' must be HH:mm (00:00..23:59).", file, errors);
                continue;
            }
            if (from == to)
            {
                Error(item, "'windows': 'from' and 'to' cannot be identical.", file, errors);
                continue;
            }
            list.Add(new ScanWindow(days, from, to));
        }
        return list;
    }

    private static HistorySettings ParseHistory(Dictionary<string, YamlNode> root, string file, List<string> errors)
    {
        if (!root.TryGetValue("history", out var node))
            return new();
        var map = Fields(node, "history", ["keep"], file, errors);
        if (map is null)
            return new();
        return new HistorySettings(Int(map, "keep", "history", 20, 1, 365, file, errors));
    }

    private static void RefuseAnchors(YamlNode node, string file, List<string> errors)
    {
        if (!node.Anchor.IsEmpty)
        {
            Error(node, "YAML anchors and aliases are not allowed in discovery.yaml.", file, errors);
            return;
        }
        switch (node)
        {
            case YamlMappingNode map:
                foreach (var (k, v) in map.Children)
                {
                    RefuseAnchors(k, file, errors);
                    RefuseAnchors(v, file, errors);
                }
                break;
            case YamlSequenceNode seq:
                foreach (var item in seq.Children)
                    RefuseAnchors(item, file, errors);
                break;
        }
    }

    private static Dictionary<string, YamlNode>? Fields(YamlNode node, string what, IReadOnlyCollection<string> allowed, string file, List<string> errors)
    {
        if (node is not YamlMappingNode map)
        {
            Error(node, $"{what} must be a mapping.", file, errors);
            return null;
        }
        var dict = new Dictionary<string, YamlNode>(StringComparer.Ordinal);
        foreach (var (k, v) in map.Children)
        {
            if (k is not YamlScalarNode { Value: { } name })
            {
                Error(k, $"{what}: keys must be plain strings.", file, errors);
                continue;
            }
            if (!allowed.Contains(name))
            {
                Error(k, $"{what}: unknown field '{name}'. Allowed: {string.Join(", ", allowed)}.", file, errors);
                continue;
            }
            if (!dict.TryAdd(name, v))
                Error(k, $"{what}: duplicate field '{name}'.", file, errors);
        }
        return dict;
    }

    private static string? Text(Dictionary<string, YamlNode> fields, string name, string what, string file, List<string> errors, bool required = false)
    {
        if (!fields.TryGetValue(name, out var node))
        {
            if (required)
                errors.Add($"{file}: {what}: '{name}' is required.");
            return null;
        }
        if (node is YamlScalarNode { Value: { } val } && !string.IsNullOrWhiteSpace(val))
            return val.Trim();
        Error(node, $"{what}: '{name}' must be a non-empty string.", file, errors);
        return null;
    }

    private static List<string> Strings(Dictionary<string, YamlNode> fields, string name, string what, string file, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return [];
        if (node is YamlSequenceNode seq)
        {
            var list = new List<string>();
            foreach (var item in seq.Children)
            {
                if (item is YamlScalarNode { Value: { } val } && !string.IsNullOrWhiteSpace(val))
                    list.Add(val.Trim());
                else
                    Error(item, $"{what}: '{name}' items must be strings.", file, errors);
            }
            return list;
        }
        Error(node, $"{what}: '{name}' must be a list.", file, errors);
        return [];
    }

    private static bool Bool(Dictionary<string, YamlNode> fields, string name, string what, bool fallback, string file, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return fallback;
        if (node is YamlScalarNode { Value: { } val } && bool.TryParse(val, out var b))
            return b;
        Error(node, $"{what}: '{name}' must be true or false.", file, errors);
        return fallback;
    }

    private static int Int(Dictionary<string, YamlNode> fields, string name, string what, int fallback, int min, int max, string file, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return fallback;
        if (node is YamlScalarNode { Value: { } val }
            && int.TryParse(val, NumberStyles.None, CultureInfo.InvariantCulture, out var n)
            && n >= min && n <= max)
        {
            return n;
        }
        Error(node, $"{what}: '{name}' must be an integer between {min} and {max}.", file, errors);
        return fallback;
    }

    private static void Error(YamlNode node, string message, string file, List<string> errors) =>
        errors.Add($"{file}:{node.Start.Line}:{node.Start.Column}: {message}");

    private static bool IsValidHostName(string name) =>
        name.Length is > 0 and <= 253 && !Addresses.TryParseAddress(name, out _) && HostRegex().IsMatch(name);

    private static bool IsValidNamePattern(string pattern) =>
        pattern.Length is > 0 and <= 253 && NamePatternRegex().IsMatch(pattern);

    [GeneratedRegex(@"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", RegexOptions.CultureInvariant)]
    private static partial Regex HostRegex();

    [GeneratedRegex(@"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePatternRegex();
}
