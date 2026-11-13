using System.Net;
using System.Text;

namespace Keeper.Runners.Host;

/// <summary>
/// Where an ssh integration's credential may be used: the integration's endpoint lists CIDR ranges, host names
/// and *.suffix patterns, separated by commas. A rule file cannot point a credential anywhere else.
/// </summary>
public static class SshScope
{
    public static bool Allows(string target, string scope)
    {
        if (string.IsNullOrWhiteSpace(target))
            return false;
        var isAddress = IPAddress.TryParse(target.Trim(), out var address);
        foreach (var entry in scope.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPNetwork.TryParse(entry, out var network))
            {
                // A name never matches a range: resolving it would trust DNS with a credential.
                if (isAddress && network.Contains(address!))
                    return true;
            }
            else if (entry.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = entry[1..];
                if (!isAddress && target.Length > suffix.Length && target.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (entry.Equals(target.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}

/// <summary>
/// Whether to trust the key a host presented. A key is trusted only when its fingerprint is pinned in the
/// integration's hostKeys option (a changed key is refused whatever else is set), or when the integration
/// explicitly accepts any key - and then the read says the host was not verified.
/// </summary>
public static class HostKeyPolicy
{
    public sealed record Decision(bool Trust, string? Reason);

    public static Decision Decide(string host, string seenFingerprint, IReadOnlyDictionary<string, string> pinned, bool acceptAny)
    {
        var seen = Normalize(seenFingerprint);
        var known = pinned.FirstOrDefault(p => p.Key.Equals(host, StringComparison.OrdinalIgnoreCase));
        if (known.Key is not null)
        {
            // A host presents a different key per algorithm, so one host may pin several fingerprints (comma separated).
            var fingerprints = known.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Normalize).ToList();
            return fingerprints.Contains(seen, StringComparer.Ordinal)
                ? new Decision(true, null)
                : new Decision(false, $"the host key of {host} changed: pinned {string.Join(", ", fingerprints.Select(f => "SHA256:" + f))}, presented SHA256:{seen}. Unless the host was rebuilt, something may be impersonating it; no credential was sent.");
        }
        return acceptAny
            ? new Decision(true, $"the host key of {host} was not verified (the integration accepts any key): SHA256:{seen}")
            : new Decision(false, $"the host key of {host} is not pinned, so no credential was sent. Check this fingerprint with the host's owner "
                + $"(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the host), then add it to the integration's hostKeys option: {host} = SHA256:{seen}");
    }

    public static string Normalize(string fingerprint)
    {
        var text = fingerprint.Trim();
        if (text.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
            text = text[7..];
        return text.TrimEnd('=');
    }
}

/// <summary>The ssh integration's options. They arrive typed from a file and as text from the command line.</summary>
public static class SshOptions
{
    public static int? Port(System.Text.Json.Nodes.JsonNode? node) => node switch
    {
        System.Text.Json.Nodes.JsonValue v when v.TryGetValue<int>(out var n) && n is >= 1 and <= 65535 => n,
        System.Text.Json.Nodes.JsonValue v when v.TryGetValue<string>(out var s) && int.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) && n is >= 1 and <= 65535 => n,
        _ => null,
    };

    /// <summary>true/false, or null when the value is not one of them.</summary>
    public static bool? Flag(System.Text.Json.Nodes.JsonNode? node) => node switch
    {
        System.Text.Json.Nodes.JsonValue v when v.TryGetValue<bool>(out var b) => b,
        System.Text.Json.Nodes.JsonValue v when v.TryGetValue<string>(out var s) && s.Equals("true", StringComparison.OrdinalIgnoreCase) => true,
        System.Text.Json.Nodes.JsonValue v when v.TryGetValue<string>(out var s) && s.Equals("false", StringComparison.OrdinalIgnoreCase) => false,
        _ => null,
    };
}

/// <summary>An allowlisted command as one remote command line: nothing the rule wrote is ever interpreted by a shell.</summary>
public static class RemoteCommand
{
    private const string Environment = "env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ";

    public static string Line(string name, IReadOnlyList<string> args)
    {
        var (program, arguments) = HostCommands.Plan(name, args);
        return Environment + string.Join(' ', new[] { program }.Concat(arguments).Select(Quote));
    }

    /// <summary>Single quotes around the text, with each quote inside it written as '\'' - the one form no shell reads as anything else.</summary>
    public static string Quote(string text) => "'" + text.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
}

/// <summary>Paths on a remote machine are POSIX paths whatever the scanner runs on.</summary>
public static class PosixPath
{
    public static string Normalize(string path)
    {
        var parts = new List<string>();
        foreach (var part in path.Split('/'))
        {
            if (part is "" or ".")
                continue;
            if (part == "..")
            {
                if (parts.Count > 0)
                    parts.RemoveAt(parts.Count - 1);
                continue;
            }
            parts.Add(part);
        }
        return "/" + string.Join('/', parts);
    }

    public static string Directory(string path)
    {
        var cut = path.LastIndexOf('/');
        return cut <= 0 ? "/" : path[..cut];
    }

    public static string ResolveInclude(string from, string include) =>
        include.StartsWith('/') ? Normalize(include) : Normalize(Directory(from) + "/" + include);
}
