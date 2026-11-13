using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Keeper.Runners.Host;

/// <summary>
/// Printers as CUPS (Linux, macOS) knows them, from its listing commands: one row per queue with how it is attached
/// (USB with its vendor, model and serial; or a network address by protocol), its state, and whether it takes jobs;
/// and CUPS's own sharing settings. A password in a device address is replaced before a row exists.
/// </summary>
public static class CupsReader
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(1);
    private static readonly string[] NetworkSchemes = ["socket", "lpd", "ipp", "ipps", "http", "https", "dnssd", "mdns", "smb", "ipp14"];
    private static readonly Regex Device = new(@"^device for (?<name>.+?): (?<uri>\S.*)$", RegexOptions.CultureInvariant, Limit);
    private static readonly Regex Printer = new(@"^printer (?<name>\S+) (?<rest>.*)$", RegexOptions.CultureInvariant, Limit);
    private static readonly Regex Accepting = new(@"^(?<name>\S+) (?<not>not )?accepting requests", RegexOptions.CultureInvariant, Limit);
    private static readonly Regex UserInfo = new(@"(?<=://)(?<user>[^:/@\s]*):(?<pass>[^@/\s]+)@", RegexOptions.CultureInvariant, Limit);

    public static List<JsonObject> Printers(string host, IEnumerable<string> devices, IEnumerable<string> states, IEnumerable<string> accepting)
    {
        var rows = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var line in devices)
        {
            var match = Device.Match(line);
            if (!match.Success)
                continue;
            var row = Describe(match.Groups["uri"].Value);
            row["host"] = host;
            row["name"] = match.Groups["name"].Value;
            row["state"] = "unknown";
            row["enabled"] = true;
            row["accepting"] = true;
            rows[match.Groups["name"].Value] = row;
        }
        foreach (var line in states)
        {
            var match = Printer.Match(line);
            if (!match.Success || !rows.TryGetValue(match.Groups["name"].Value, out var row))
                continue;
            var rest = match.Groups["rest"].Value;
            var disabled = rest.StartsWith("disabled", StringComparison.Ordinal);
            row["enabled"] = !disabled;
            row["state"] = disabled ? "disabled" : rest.StartsWith("now printing", StringComparison.Ordinal) ? "printing" : rest.StartsWith("is idle", StringComparison.Ordinal) ? "idle" : "unknown";
        }
        foreach (var line in accepting)
        {
            var match = Accepting.Match(line);
            if (match.Success && rows.TryGetValue(match.Groups["name"].Value, out var row))
                row["accepting"] = !match.Groups["not"].Success;
        }
        return [.. rows.Values];
    }

    /// <summary>The address of a queue taken apart: scheme, address and port for a network one, vendor, model and serial for USB.</summary>
    private static JsonObject Describe(string uri)
    {
        var row = new JsonObject();
        var colon = uri.IndexOf(':', StringComparison.Ordinal);
        var scheme = colon > 0 ? uri[..colon].ToLowerInvariant() : "";
        row["scheme"] = scheme;
        row["usb"] = scheme == "usb";
        row["network"] = NetworkSchemes.Contains(scheme);
        var clean = SecretProperties.MaskUrls(UserInfo.Replace(uri, "${user}:set@"));
        row["deviceUri"] = clean;

        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            return row;
        if (scheme == "usb")
        {
            // The vendor as written (Uri lowercases a host): the part between "usb://" and the next slash.
            var afterScheme = uri["usb://".Length..];
            var slash = afterScheme.IndexOf('/', StringComparison.Ordinal);
            row["vendor"] = Uri.UnescapeDataString(slash < 0 ? afterScheme.Split('?')[0] : afterScheme[..slash]);
            row["model"] = Uri.UnescapeDataString(parsed.AbsolutePath.TrimStart('/'));
            var serial = System.Web.HttpUtility.ParseQueryString(parsed.Query)["serial"];
            if (!string.IsNullOrEmpty(serial))
                row["serial"] = serial;
        }
        else if (row["network"]!.GetValue<bool>() && scheme is not "dnssd" and not "mdns" && parsed.Host.Length > 0)
        {
            row["address"] = parsed.Host;
            var port = parsed.IsDefaultPort ? DefaultPort(scheme) : parsed.Port;
            if (port > 0)
                row["port"] = port;
        }
        return row;
    }

    private static int DefaultPort(string scheme) => scheme switch
    {
        "socket" => 9100,
        "lpd" => 515,
        "ipp" or "ipps" or "ipp14" => 631,
        "http" => 80,
        "https" => 443,
        "smb" => 445,
        _ => 0,
    };

    // printer user job-id [date tz] page-or-total copies-or-count billing host job-name media sides: the job name has spaces,
    // so only the fields before it are read, and nothing from the user, host or job name is kept.
    private static readonly Regex PageLine = new(@"^(?<printer>\S+) (?<user>\S+) (?<job>\d+) \[(?<date>[^\]]+)\] (?<page>\S+) (?<count>\d+) ", RegexOptions.CultureInvariant, Limit);

    /// <summary>
    /// Pages printed through this machine, per printer, from CUPS's page_log: pages (copies counted, a job's "total"
    /// line counted once), jobs, how many different users, and the first and last time. It never keeps a user name,
    /// a job name or an address - a document's title can be sensitive. It is what this machine printed, not the
    /// printer's lifetime counter.
    /// </summary>
    public static List<JsonObject> PageCounts(string host, IEnumerable<string> lines)
    {
        var printers = new Dictionary<string, (long Pages, HashSet<string> Jobs, HashSet<string> Users, DateTimeOffset First, DateTimeOffset Last)>(StringComparer.Ordinal);
        foreach (var line in lines)
        {
            var match = PageLine.Match(line);
            if (!match.Success || !DateTimeOffset.TryParseExact(match.Groups["date"].Value, "dd/MMM/yyyy:HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var at))
                continue;
            var name = match.Groups["printer"].Value;
            var count = long.Parse(match.Groups["count"].Value, System.Globalization.CultureInfo.InvariantCulture);
            var entry = printers.TryGetValue(name, out var existing) ? existing : (0, [], [], at, at);
            entry.Pages += count;
            entry.Jobs.Add(match.Groups["job"].Value);
            entry.Users.Add(match.Groups["user"].Value);
            entry.First = at < entry.First ? at : entry.First;
            entry.Last = at > entry.Last ? at : entry.Last;
            printers[name] = entry;
        }
        return [.. printers.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new JsonObject
        {
            ["host"] = host,
            ["name"] = p.Key,
            ["pages"] = p.Value.Pages,
            ["jobs"] = p.Value.Jobs.Count,
            ["users"] = p.Value.Users.Count,
            ["firstPrinted"] = RowValues.Iso(p.Value.First),
            ["lastPrinted"] = RowValues.Iso(p.Value.Last),
        })];
    }

    /// <summary>cupsctl's key=value lines as one row; the sharing settings are also named for what they mean.</summary>
    public static JsonObject Settings(string host, IEnumerable<string> lines)
    {
        var row = new JsonObject { ["host"] = host };
        foreach (var line in lines)
        {
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
                continue;
            var (key, value) = (line[..equals].Trim(), line[(equals + 1)..].Trim());
            row[key] = value;
            var named = key switch
            {
                "_share_printers" => "sharePrinters",
                "_remote_admin" => "remoteAdmin",
                "_remote_any" => "remoteAny",
                "_debug_logging" => "debugLogging",
                "_user_cancel_any" => "userCancelAny",
                _ => null,
            };
            if (named is not null)
                row[named] = value == "1";
        }
        return row;
    }
}
