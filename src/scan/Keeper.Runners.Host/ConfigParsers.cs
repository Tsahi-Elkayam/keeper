using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Keeper.Runners.Host;

/// <summary>
/// Turns the configuration files of other software into rows a rule can ask questions of. Every row names its
/// file and line. Text that cannot be parsed throws FormatException: a file read wrongly is a failed read,
/// never an empty answer that would pass every rule.
/// </summary>
public static class ConfigParsers
{
    private static JsonObject Row(string file, int line) => new() { ["file"] = file, ["line"] = line };

    /// <summary>One row per line: n, line, file.</summary>
    public static List<JsonObject> Lines(string text, string file)
    {
        var rows = new List<JsonObject>();
        var number = 0;
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = raw.TrimEnd('\r');
            if (line.Length == 0)
                continue;
            var row = Row(file, number);
            row["text"] = CredentialText.Scrub(line);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>"Key value" or "key=value" settings (sshd_config, sysctl.conf, login.defs); # starts a comment. Rows after a Match line carry its text in "match"; before one there is no such field.</summary>
    public static List<JsonObject> Kv(string text, string file)
    {
        var rows = new List<JsonObject>();
        var number = 0;
        var match = "";
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = StripComment(raw.TrimEnd('\r'), "#").Trim();
            if (line.Length == 0)
                continue;
            var split = line.IndexOfAny([' ', '\t', '=']);
            var key = split < 0 ? line : line[..split];
            var value = split < 0 ? "" : line[(split + 1)..].Trim().TrimStart('=').Trim();
            var row = Setting(file, number, null, key, Unquote(value));
            // Everything after "Match ..." (sshd_config) holds only for what it matches, so it is not the global value.
            if (row["name"]!.ToString() == "match")
                match = value;
            if (match.Length > 0)
                row["match"] = match;
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>[section] headers with key=value lines (my.cnf, php.ini, systemd units); ; and # start comments.</summary>
    public static List<JsonObject> Ini(string text, string file)
    {
        var rows = new List<JsonObject>();
        var section = "";
        var number = 0;
        foreach (var raw in text.Split('\n'))
        {
            number++;
            var line = raw.TrimEnd('\r').Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;
            if (line[0] == '[' && line[^1] == ']')
            {
                section = line[1..^1].Trim();
                continue;
            }
            var split = line.IndexOfAny(['=', ':']);
            var key = split < 0 ? line : line[..split].Trim();
            var value = split < 0 ? "" : line[(split + 1)..].Trim();
            rows.Add(Setting(file, number, section, key, Unquote(value)));
        }
        return rows;
    }

    private static JsonObject Setting(string file, int line, string? section, string key, string value)
    {
        var row = Row(file, line);
        if (section is not null)
            row["section"] = section;
        row["key"] = key;
        row["name"] = key.ToLowerInvariant();
        row["value"] = value;
        SecretMask(row);
        return row;
    }

    private static readonly string[] SecretWords =
        ["password", "passwd", "passphrase", "secret", "apikey", "api_key", "api_token", "apitoken", "access_token", "accesstoken", "auth_token", "authtoken", "credential"];

    /// <summary>A setting whose name says its value is a credential keeps no value in the rows (a path to one is only a path).</summary>
    private static void SecretMask(JsonObject row)
    {
        var name = row["name"]!.ToString();
        var value = row["value"]!.ToString();
        var names = SecretProperties.IsSecret(name)
            || SecretWords.Any(w => name.Contains(w, StringComparison.Ordinal)) && !CredentialText.LocationWords.Any(w => name.Contains(w, StringComparison.Ordinal));
        if (names && value.Length > 0 && !CredentialText.IsPlainSetting(value))
            row["value"] = "set";
    }

    /// <summary>
    /// Directive files: nginx ("name args; name args { ... }") or Apache ("Name args", "&lt;Section args&gt; ... &lt;/Section&gt;").
    /// One row per directive: name (lower case), directive (as written), args, value (args joined), context
    /// (the enclosing blocks, "http &gt; server"), block, line, file. <paramref name="baseContext"/> is the context
    /// an included file starts in.
    /// </summary>
    public static List<JsonObject> Directives(string text, string file, string style, string baseContext = "") =>
        style switch
        {
            "nginx" => Nginx(text, file, baseContext),
            "apache" => Apache(text, file, baseContext),
            _ => throw new ArgumentException($"directive style must be nginx or apache, not '{style}'."),
        };

    private static JsonObject Directive(string file, int line, string name, IReadOnlyList<string> args, bool block, string context)
    {
        var row = Row(file, line);
        row["directive"] = name;
        row["name"] = name.ToLowerInvariant();
        row["args"] = new JsonArray(args.Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
        row["value"] = string.Join(' ', args);
        row["context"] = context;
        row["block"] = block;
        SecretMask(row);
        return row;
    }

    private static string Context(string baseContext, IEnumerable<string> stack)
    {
        var parts = stack.ToList();
        if (baseContext.Length > 0)
            parts.Insert(0, baseContext);
        return string.Join(" > ", parts);
    }

    private static string Describe(string name, IReadOnlyList<string> args) => args.Count == 0 ? name : $"{name} {string.Join(' ', args)}";

    private enum Kind { Word, Semicolon, Open, Close }

    private static List<JsonObject> Nginx(string text, string file, string baseContext)
    {
        var rows = new List<JsonObject>();
        var stack = new List<string>();
        var words = new List<string>();
        var start = 0;
        foreach (var (kind, word, line) in Lex(text))
        {
            switch (kind)
            {
                case Kind.Word:
                    if (words.Count == 0)
                        start = line;
                    words.Add(word);
                    break;
                case Kind.Semicolon:
                    if (words.Count > 0)
                        rows.Add(Directive(file, start, words[0], words.Skip(1).ToList(), false, Context(baseContext, stack)));
                    words.Clear();
                    break;
                case Kind.Open:
                    if (words.Count == 0)
                        throw new FormatException($"{file}:{line}: a block with no name.");
                    var args = words.Skip(1).ToList();
                    rows.Add(Directive(file, start, words[0], args, true, Context(baseContext, stack)));
                    stack.Add(Describe(words[0], args));
                    words.Clear();
                    break;
                default:
                    if (words.Count > 0)
                        throw new FormatException($"{file}:{line}: '{string.Join(' ', words)}' is missing its ';'.");
                    if (stack.Count == 0)
                        throw new FormatException($"{file}:{line}: a '}}' that closes nothing.");
                    stack.RemoveAt(stack.Count - 1);
                    break;
            }
        }
        if (words.Count > 0)
            throw new FormatException($"{file}: the file ends inside '{string.Join(' ', words)}'.");
        if (stack.Count > 0)
            throw new FormatException($"{file}: the block '{stack[^1]}' is never closed.");
        return rows;
    }

    private static IEnumerable<(Kind Kind, string Word, int Line)> Lex(string text)
    {
        var line = 1;
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '\n')
            {
                line++;
                i++;
            }
            else if (char.IsWhiteSpace(c))
            {
                i++;
            }
            else if (c == '#')
            {
                while (i < text.Length && text[i] != '\n')
                    i++;
            }
            else if (c == ';')
            {
                yield return (Kind.Semicolon, ";", line);
                i++;
            }
            else if (c == '{')
            {
                yield return (Kind.Open, "{", line);
                i++;
            }
            else if (c == '}')
            {
                yield return (Kind.Close, "}", line);
                i++;
            }
            else
            {
                var word = new StringBuilder();
                var wordLine = line;
                while (i < text.Length && !char.IsWhiteSpace(text[i]) && text[i] is not (';' or '{' or '}'))
                {
                    var ch = text[i];
                    if (ch is '"' or '\'')
                    {
                        i++;
                        while (i < text.Length && text[i] != ch)
                        {
                            if (text[i] == '\\' && i + 1 < text.Length)
                                i++;
                            if (text[i] == '\n')
                                line++;
                            word.Append(text[i++]);
                        }
                        i++;
                    }
                    else if (ch == '$' && i + 1 < text.Length && text[i + 1] == '{')
                    {
                        while (i < text.Length && text[i] != '}')
                            word.Append(text[i++]);
                        if (i < text.Length)
                            word.Append(text[i++]);
                    }
                    else
                    {
                        word.Append(ch);
                        i++;
                    }
                }
                yield return (Kind.Word, word.ToString(), wordLine);
            }
        }
    }

    private static List<JsonObject> Apache(string text, string file, string baseContext)
    {
        var rows = new List<JsonObject>();
        var stack = new List<(string Name, string Described)>();
        var lines = text.Split('\n');
        for (var n = 0; n < lines.Length; n++)
        {
            var start = n + 1;
            var line = lines[n].TrimEnd('\r').Trim();
            while (line.EndsWith('\\') && n + 1 < lines.Length)
                line = line[..^1].TrimEnd() + " " + lines[++n].TrimEnd('\r').Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;

            if (line.StartsWith("</", StringComparison.Ordinal) && line.EndsWith('>'))
            {
                var closing = line[2..^1].Trim();
                if (stack.Count == 0 || !stack[^1].Name.Equals(closing, StringComparison.OrdinalIgnoreCase))
                    throw new FormatException($"{file}:{start}: </{closing}> closes nothing that is open.");
                stack.RemoveAt(stack.Count - 1);
            }
            else if (line[0] == '<' && line.EndsWith('>'))
            {
                var inner = Split(line[1..^1]);
                if (inner.Count == 0)
                    throw new FormatException($"{file}:{start}: an empty <> section.");
                var args = inner.Skip(1).ToList();
                rows.Add(Directive(file, start, inner[0], args, true, Context(baseContext, stack.Select(s => s.Described))));
                stack.Add((inner[0], Describe(inner[0], args)));
            }
            else
            {
                var words = Split(line);
                rows.Add(Directive(file, start, words[0], words.Skip(1).ToList(), false, Context(baseContext, stack.Select(s => s.Described))));
            }
        }
        if (stack.Count > 0)
            throw new FormatException($"{file}: <{stack[^1].Name}> is never closed.");
        return rows;
    }

    /// <summary>Words separated by white space, with "double" and 'single' quotes keeping their spaces.</summary>
    private static List<string> Split(string line)
    {
        var words = new List<string>();
        var word = new StringBuilder();
        var inWord = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c is '"' or '\'')
            {
                inWord = true;
                for (i++; i < line.Length && line[i] != c; i++)
                {
                    if (line[i] == '\\' && i + 1 < line.Length)
                        i++;
                    word.Append(line[i]);
                }
            }
            else if (char.IsWhiteSpace(c))
            {
                if (inWord)
                    words.Add(word.ToString());
                word.Clear();
                inWord = false;
            }
            else
            {
                word.Append(c);
                inWord = true;
            }
        }
        if (inWord)
            words.Add(word.ToString());
        return words;
    }

    private static string StripComment(string line, string marker)
    {
        for (var i = 0; i < line.Length; i++)
        {
            if (string.CompareOrdinal(line, i, marker, 0, marker.Length) == 0 && (i == 0 || char.IsWhiteSpace(line[i - 1])))
                return line[..i];
        }
        return line;
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && (value[0] == '"' && value[^1] == '"' || value[0] == '\'' && value[^1] == '\'') ? value[1..^1] : value;

    internal static string Invariant(long value) => value.ToString(CultureInfo.InvariantCulture);
}
