using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Security;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Keeper.Rules;

namespace Keeper.Runners.Cim;

/// <summary>
/// eventlog: the events of one log on each target host, over the remote Event Log protocol, in-process -
/// the same read Event Viewer does. Filtered on the host (ids, providers, a time window) and capped, so a
/// flooded log cannot flood the scan. Read-only: logs are never cleared, exported or subscribed to.
/// </summary>
public sealed partial class EventLogRunner : IRunner
{
    private const int DefaultDays = 7;
    private const int DefaultMax = 500;

    public string Protocol => "eventlog";

    public bool PerTarget => true;

    public IEnumerable<string> Validate(QuerySpec query)
    {
        if (query.Text("log") is not { } log || !LogName().IsMatch(log))
            yield return "log is required: a log or channel name such as System or Microsoft-Windows-GroupPolicy/Operational";
        foreach (var id in query.List("ids"))
        {
            if (!int.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n > 65535)
                yield return $"ids: '{id}' is not an event id";
        }
        foreach (var provider in query.List("providers"))
        {
            if (!ProviderName().IsMatch(provider))
                yield return $"providers: '{provider}' is not a provider name";
        }
        if (query.Text("days") is { } days && (!int.TryParse(days, NumberStyles.None, CultureInfo.InvariantCulture, out var d) || d is < 1 or > 90))
            yield return "days must be 1 to 90";
        if (query.Text("max") is { } max && (!int.TryParse(max, NumberStyles.None, CultureInfo.InvariantCulture, out var m) || m is < 1 or > 5000))
            yield return "max must be 1 to 5000";
    }

    /// <summary>The XPath the host evaluates: ids, providers and the window, so only matching events cross the wire.</summary>
    public static string XPath(QuerySpec query)
    {
        var parts = new List<string>();
        var ids = query.List("ids");
        if (ids.Count > 0)
            parts.Add("(" + string.Join(" or ", ids.Select(i => $"EventID={int.Parse(i, CultureInfo.InvariantCulture)}")) + ")");
        var providers = query.List("providers");
        if (providers.Count > 0)
            parts.Add("Provider[" + string.Join(" or ", providers.Select(p => $"@Name='{p}'")) + "]");
        var days = query.Int("days") ?? DefaultDays;
        parts.Add($"TimeCreated[timediff(@SystemTime) <= {(long)TimeSpan.FromDays(days).TotalMilliseconds}]");
        return $"*[System[{string.Join(" and ", parts)}]]";
    }

    public Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(RunnerResult.Failed("eventlog needs Windows"));
        if (string.IsNullOrWhiteSpace(context.Target))
            return Task.FromResult(RunnerResult.Failed("eventlog needs a target host"));
        return Task.Run(() => OperatingSystem.IsWindows() ? Run(query, context, cancellationToken) : RunnerResult.Failed("eventlog needs Windows"),
            cancellationToken);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static RunnerResult Run(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var host = context.Target!;
        var log = query.Text("log")!;
        var max = query.Int("max") ?? DefaultMax;
        try
        {
            using var session = Session(host, context.Connection.WindowsCredential());
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, XPath(query))
            {
                Session = session,
                ReverseDirection = true,       // newest first, so the cap keeps the recent ones
            });
            var rows = new List<JsonObject>();
            for (var record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (record)
                    rows.Add(Row(host, log, record));
                if (rows.Count >= max)
                    return RunnerResult.Partial(rows, $"{host}: stopped at {max} events of {log} (raise max, or narrow ids)");
            }
            return RunnerResult.Ok(rows);
        }
        catch (EventLogNotFoundException)
        {
            // A channel that does not exist on this host has no events: an empty answer, not a failure.
            return RunnerResult.Ok([]);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            return RunnerResult.Failed($"{host}: {log}: {ex.Message}");
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static EventLogSession Session(string host, NetworkCredential? credential)
    {
        if (credential is null)
            return new EventLogSession(host);
        var password = new SecureString();
        foreach (var c in credential.Password)
            password.AppendChar(c);
        password.MakeReadOnly();
        return new EventLogSession(host, credential.Domain, credential.UserName, password, SessionAuthentication.Negotiate);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static JsonObject Row(string host, string log, EventRecord record)
    {
        var row = new JsonObject
        {
            ["host"] = host,
            ["log"] = log,
            ["id"] = record.Id,
            ["provider"] = record.ProviderName,
            ["level"] = record.Level,
            ["recordId"] = record.RecordId,
            ["time"] = record.TimeCreated is { } t ? RowValues.Iso(new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero)) : null,
        };
        foreach (var (name, value) in EventData(record.ToXml()))
        {
            if (!row.ContainsKey(name))
                row[name] = value;
        }
        return row;
    }

    /// <summary>The event's named data fields (EventData/Data[@Name], or UserData leaves), at most 40, values cut to 500 characters.</summary>
    public static IEnumerable<(string Name, string Value)> EventData(string xml)
    {
        XElement root;
        try
        {
            root = XElement.Parse(xml);
        }
        catch (System.Xml.XmlException)
        {
            yield break;
        }
        var data = root.Elements().FirstOrDefault(e => e.Name.LocalName is "EventData" or "UserData");
        if (data is null)
            yield break;
        var count = 0;
        var leaves = data.Name.LocalName == "EventData"
            ? data.Elements().Select(e => (Name: e.Attribute("Name")?.Value, e.Value))
            : data.Descendants().Where(e => !e.HasElements).Select(e => (Name: (string?)e.Name.LocalName, e.Value));
        foreach (var (name, value) in leaves)
        {
            if (string.IsNullOrEmpty(name) || ++count > 40)
                continue;
            yield return (name, value.Length > 500 ? value[..500] : value);
        }
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,254}$", RegexOptions.CultureInvariant)]
    private static partial Regex LogName();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex ProviderName();
}
