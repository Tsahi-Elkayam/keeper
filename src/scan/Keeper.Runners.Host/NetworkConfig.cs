using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Keeper.Runners.Host;

/// <summary>
/// The running configuration of a Cisco-style device (IOS, IOS-XE, NX-OS, Arista EOS): commands with their
/// indentation as hierarchy. Secrets are scrubbed from every line before any row exists, so no row, result or
/// finding can carry one; what a rule needs to judge them (the keyword, the encryption type, a well-known default
/// community) stays.
/// </summary>
public static class NetworkConfig
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(1);
    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    private static readonly string[] DefaultCommunities = ["public", "private", "cisco", "secret", "admin", "community", "test", "snmp", "default"];

    private static readonly Regex Community = new(@"^(?<pre>(?:no )?snmp-server community )(?<name>\S+)(?<rest>.*)$", Options, Limit);
    private static readonly Regex SnmpUser = new(@"\b(?<alg>md5|sha-512|sha-256|sha256|sha|aes(?: (?:128|192|256))?|3des|des) (?<v>\S+)", Options, Limit);
    private static readonly Regex Password = new(@"\b(?<k>enable (?:password|secret)(?: level \d+)?|password|secret|key-string|pre-shared-key(?: local| remote)?)(?<t> (?:0|5|6|7|8|9))? (?<v>\S+)", Options, Limit);
    private static readonly Regex NumberedKey = new(@"\b(?<k>(?:authentication|message-digest)-key \d+ md5)(?<t> [0-9])? (?<v>\S+)", Options, Limit);
    private static readonly Regex ServerKey = new(@"\b(?<k>key)(?<t> [0-9])? (?<v>\S+)", Options, Limit);
    private static readonly Regex SnmpHost = new(@"^(?<k>(?:no )?snmp-server host \S+(?: (?:traps|informs))?(?: version (?:1|2c))?) (?<v>\S+)", Options, Limit);
    private static readonly Regex RoutingKey = new(@"^(?<k>(?:no )?(?:ip|ipv6) (?:ospf|isis|rip) authentication-key)(?<t> [0-9])? (?<v>\S+)", Options, Limit);
    private static readonly Regex GatewayKey = new(@"^(?<k>(?:no )?(?:standby|vrrp|glbp) \d+ authentication(?: text)?) (?<v>(?!md5\b)\S+)", Options, Limit);
    private static readonly Regex BareKey = new(@"^(?<k>key)(?<t> [0-9]) (?<v>\S+)$", Options, Limit);

    /// <summary>The line with every credential in it replaced by "set" (a well-known default community by "&lt;default&gt;").</summary>
    public static string Scrub(string line)
    {
        try
        {
            var community = Community.Match(line);
            if (community.Success)
            {
                var word = DefaultCommunities.Contains(community.Groups["name"].Value, StringComparer.OrdinalIgnoreCase) ? "<default>" : "set";
                return community.Groups["pre"].Value + word + community.Groups["rest"].Value;
            }
            if (line.StartsWith("snmp-server user", StringComparison.OrdinalIgnoreCase))
                return SnmpUser.Replace(line, "${alg} set");

            // A trap receiver's community follows the host; for version 3 what follows is a user name.
            var scrubbed = line.Contains(" version 3", StringComparison.OrdinalIgnoreCase) ? line : SnmpHost.Replace(line, "${k} set");
            scrubbed = RoutingKey.Replace(scrubbed, "${k}${t} set");
            scrubbed = GatewayKey.Replace(scrubbed, "${k} set");
            scrubbed = Password.Replace(scrubbed, "${k}${t} set");
            scrubbed = NumberedKey.Replace(scrubbed, "${k}${t} set");
            if (Regex.IsMatch(scrubbed, @"^(no )?(tacacs-server|radius-server|tacacs server|radius server|crypto isakmp|server-private)", Options, Limit))
                scrubbed = ServerKey.Replace(scrubbed, "${k}${t} set");
            return BareKey.Replace(scrubbed, "${k}${t} set");
        }
        catch (RegexMatchTimeoutException)
        {
            return "set";   // too odd to read safely: hidden whole
        }
    }

    private readonly record struct Statement(int Line, int Indent, string Text);

    /// <summary>
    /// style ios. mode lines: one row per command (text, command, negated, context, depth, line, file). mode blocks:
    /// one row per top-level command that has commands under it (header, name, body - its commands one per line, at
    /// any depth - line, file), so a rule can ask what a section lacks.
    /// </summary>
    public static List<JsonObject> Parse(string text, string file, string style, string mode)
    {
        if (style != "ios")
            throw new ArgumentException($"config style must be ios, not '{style}'.");
        if (mode is not ("lines" or "blocks"))
            throw new ArgumentException($"config mode must be lines or blocks, not '{mode}'.");
        var statements = Read(text);
        return mode == "lines" ? Lines(statements, file) : Blocks(statements, file);
    }

    private static List<Statement> Read(string text)
    {
        var statements = new List<Statement>();
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var raw = lines[i].TrimEnd('\r', ' ', '\t');
            var trimmed = raw.TrimStart(' ', '\t');
            if (trimmed.Length == 0 || trimmed[0] == '!' || trimmed == "end")
                continue;
            var indent = raw.Length - trimmed.Length;

            // banner motd ^C ... ^C: the text between the delimiters is a message, not commands.
            var banner = Regex.Match(trimmed, @"^(?<head>banner \S+) (?<d>\^C|\S)", RegexOptions.CultureInvariant, Limit);
            if (banner.Success)
            {
                var delimiter = banner.Groups["d"].Value;
                var rest = trimmed[banner.Length..];
                if (!rest.Contains(delimiter, StringComparison.Ordinal))
                {
                    while (++i < lines.Length && !lines[i].Contains(delimiter, StringComparison.Ordinal))
                    {
                    }
                }
                statements.Add(new Statement(i + 1, indent, $"{banner.Groups["head"].Value} {delimiter}"));
                continue;
            }
            statements.Add(new Statement(i + 1, indent, Scrub(trimmed)));
        }
        return statements;
    }

    private static List<JsonObject> Lines(List<Statement> statements, string file)
    {
        var rows = new List<JsonObject>();
        var stack = new List<Statement>();
        foreach (var statement in statements)
        {
            while (stack.Count > 0 && stack[^1].Indent >= statement.Indent)
                stack.RemoveAt(stack.Count - 1);
            var negated = statement.Text.StartsWith("no ", StringComparison.OrdinalIgnoreCase);
            rows.Add(new JsonObject
            {
                ["file"] = file,
                ["line"] = statement.Line,
                ["text"] = statement.Text,
                ["command"] = negated ? statement.Text[3..] : statement.Text,
                ["negated"] = negated,
                ["context"] = string.Join(" > ", stack.Select(s => s.Text)),
                ["depth"] = stack.Count,
            });
            stack.Add(statement);
        }
        return rows;
    }

    private static List<JsonObject> Blocks(List<Statement> statements, string file)
    {
        var rows = new List<JsonObject>();
        for (var i = 0; i < statements.Count; i++)
        {
            var head = statements[i];
            var body = new List<string>();
            var next = i + 1;
            while (next < statements.Count && statements[next].Indent > head.Indent)
                body.Add(statements[next++].Text);
            if (body.Count > 0)
            {
                rows.Add(new JsonObject
                {
                    ["file"] = file,
                    ["line"] = head.Line,
                    ["header"] = head.Text,
                    ["name"] = NameOf(head.Text),
                    ["body"] = string.Join('\n', body),
                });
            }
            i = next - 1;
        }
        return rows;
    }

    /// <summary>The kind of section: the header's first words, up to two, before the first one with a digit or a slash in it.</summary>
    private static string NameOf(string header)
    {
        var words = header.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var name = words.TakeWhile(w => !w.Any(char.IsDigit) && !w.Contains('/', StringComparison.Ordinal)).Take(2).ToList();
        return name.Count == 0 ? words[0] : string.Join(' ', name);
    }
}
