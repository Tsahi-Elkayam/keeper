using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Rules;

namespace Keeper.Runners.Host;

/// <summary>
/// host: reads the machine Keeper runs on, read-only. read: facts (which system this is), file (a configuration
/// file parsed as lines, kv, ini, json or directives - nginx and Apache style, with their includes), stat (mode,
/// size, owner-writable bits of a path) or command (one from a fixed allowlist). Files that hold credentials or
/// keys are never opened; a setting whose name says it is a credential keeps no value in the rows.
/// </summary>
public sealed class HostRunner(Func<RunnerContext, IHostSession>? remote = null) : IRunner
{
    private static readonly string[] Reads = ["facts", "file", "stat", "command"];
    private static readonly string[] Formats = ["lines", "kv", "ini", "json", "directives"];

    public string Protocol => "host";

    public bool PerTarget => false;

    /// <summary>The local machine is one read; an ssh integration reads each of its target hosts.</summary>
    public bool IsPerTarget(IConnection connection) => IsRemote(connection);

    private static bool IsRemote(IConnection connection) => connection.Type == "ssh";

    public IEnumerable<string> Validate(QuerySpec query)
    {
        var read = query.Text("read");
        if (read is null || !Reads.Contains(read))
        {
            yield return $"read must be one of: {string.Join(", ", Reads)}";
            yield break;
        }

        if (read is "file" or "stat")
        {
            var path = query.Text("path");
            if (HostGuards.PathProblem(path ?? "") is { } problem)
                yield return problem;
        }
        if (read == "file")
        {
            var format = query.Text("format") ?? "lines";
            if (!Formats.Contains(format))
                yield return $"format must be one of: {string.Join(", ", Formats)}";
            if (format == "directives" && query.Text("style") is not ("nginx" or "apache"))
                yield return "directives need style: nginx or apache";
        }
        if (read == "command" && HostCommands.Problem(query.Text("name"), query.List("args")) is { } commandProblem)
            yield return commandProblem;
    }

    public async Task<RunnerResult> RunAsync(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var session = await Task.Run(() => Open(context), cancellationToken).ConfigureAwait(false);
            return await Task.Run(async () => query.Text("read") switch
            {
                "facts" => RunnerResult.Ok([Facts(session)]),
                "stat" => RunnerResult.Ok([Stat(session, query.Text("path")!)]),
                "file" => ReadFile(session, query, context),
                "command" => await Command(session, query, context, cancellationToken).ConfigureAwait(false),
                _ => RunnerResult.Failed("host: unknown read"),
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or JsonException or HostSessionException)
        {
            return RunnerResult.Failed($"host read failed: {ex.Message}");
        }
    }

    private IHostSession Open(RunnerContext context)
    {
        if (!IsRemote(context.Connection))
            return new LocalHostSession();
        if (context.Target is null)
            throw new HostSessionException("an ssh integration reads its target hosts: set the file's targets or the integration's targets option");
        return (remote ?? SshHostSession.Open)(context);
    }

    /// <summary>A true/false field of the query; rule files give it as a YAML boolean, tests as text.</summary>
    private static bool Flag(QuerySpec query, string field, bool otherwise) =>
        query.Fields[field] is JsonValue v ? v.TryGetValue<bool>(out var b) ? b : v.TryGetValue<string>(out var t) ? t.Equals("true", StringComparison.OrdinalIgnoreCase) : otherwise : otherwise;

    private static JsonObject Base(IHostSession session) => new() { ["host"] = session.HostName };

    private static JsonObject Facts(IHostSession session)
    {
        var row = Base(session);
        foreach (var (name, value) in session.Facts())
            row[name] = value?.DeepClone();
        return row;
    }

    private static JsonObject Stat(IHostSession session, string path)
    {
        path = session.Normalize(path);
        var stat = session.Stat(path);
        var row = Base(session);
        row["path"] = path;
        row["exists"] = stat.Exists;
        row["isLink"] = stat.IsLink;
        if (!stat.Exists)
            return row;
        row["isDirectory"] = stat.IsDirectory;
        row["size"] = stat.Size;
        row["modified"] = RowValues.Iso(stat.Modified);
        if (stat.Mode is { } mode)
        {
            var bits = (UnixFileMode)mode;
            row["mode"] = Convert.ToString(mode & 0xFFF, 8);
            row["worldWritable"] = (bits & UnixFileMode.OtherWrite) != 0;
            row["groupWritable"] = (bits & UnixFileMode.GroupWrite) != 0;
            row["worldReadable"] = (bits & UnixFileMode.OtherRead) != 0;
        }
        return row;
    }

    private static RunnerResult ReadFile(IHostSession session, QuerySpec query, RunnerContext context)
    {
        var path = session.Normalize(query.Text("path")!);
        var optional = Flag(query, "optional", false);
        if (!session.FileExists(path))
            return optional ? RunnerResult.Ok([]) : RunnerResult.Failed($"{path} does not exist");
        if (session.ReadProblem(path) is { } problem)
            return RunnerResult.Failed($"{path} was not read: {problem}");

        var format = query.Text("format") ?? "lines";
        var reasons = new List<string>();
        var follow = Flag(query, "follow", true);
        var rows = format switch
        {
            "directives" => WithIncludes(session, path, (text, file, context) => ConfigParsers.Directives(text, file, query.Text("style")!, context), follow, reasons),
            "json" => Json(session.ReadAllText(path), query.Text("items")),
            "kv" => WithOccurrences(WithIncludes(session, path, (text, file, _) => ConfigParsers.Kv(text, file), follow, reasons)),
            "ini" => ConfigParsers.Ini(session.ReadAllText(path), path),
            _ => ConfigParsers.Lines(session.ReadAllText(path), path),
        };
        foreach (var row in rows)
        {
            row["host"] = session.HostName;
            // The parsers keep credential values out of their own rows; arbitrary JSON gets the shared masker.
            if (format == "json")
                SecretProperties.Mask(row);
        }
        context.Log($"{path}: {rows.Count} rows");
        return reasons.Count == 0 ? RunnerResult.Ok(rows) : RunnerResult.Partial(rows, string.Join("; ", reasons));
    }

    private static List<JsonObject> WithOccurrences(List<JsonObject> rows)
    {
        NumberOccurrences(rows);
        return rows;
    }

    private static List<JsonObject> Json(string text, string? items)
    {
        var body = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { MaxDepth = 64, CommentHandling = JsonCommentHandling.Skip });
        return [.. RowValues.ItemsOf(body, items).Select(r => (JsonObject)RowValues.Detach(r))];
    }

    /// <summary>The rows of a file and of what it includes (a wildcard too), each row naming its own file.</summary>
    private static List<JsonObject> WithIncludes(IHostSession session, string path, Func<string, string, string, List<JsonObject>> parse, bool follow, List<string> reasons)
    {
        var rows = new List<JsonObject>();
        var files = 0;
        void Read(string file, string context, List<string> chain)
        {
            if (++files > HostGuards.MaxFiles)
            {
                if (files == HostGuards.MaxFiles + 1)
                    reasons.Add($"more than {HostGuards.MaxFiles} files are included; the rest were not read");
                return;
            }
            if (session.ReadProblem(file) is { } problem)
                throw new IOException($"{file} was not read: {problem}");
            foreach (var row in parse(session.ReadAllText(file), file, context))
            {
                rows.Add(row);
                if (!follow || row["block"] is JsonValue block && block.GetValue<bool>() || row["name"]!.ToString() is not ("include" or "includeoptional"))
                    continue;
                var arguments = row["args"] is JsonArray args ? args.Select(a => a!.ToString()) : [row["value"]!.ToString()];
                foreach (var pattern in arguments)
                {
                    foreach (var included in Expand(session, file, pattern))
                    {
                        if (chain.Contains(included, StringComparer.Ordinal))
                            reasons.Add($"include loop: {included} includes itself, directly or not");
                        else if (chain.Count >= HostGuards.MaxIncludeDepth)
                            reasons.Add($"includes nested deeper than {HostGuards.MaxIncludeDepth}; {included} was not read");
                        else
                            Read(included, row["context"]?.ToString() ?? "", [.. chain, included]);
                    }
                }
            }
        }
        Read(path, "", [path]);
        var distinct = reasons.Distinct(StringComparer.Ordinal).ToList();
        reasons.Clear();
        reasons.AddRange(distinct);
        return rows;
    }

    /// <summary>Which time a name has been seen, counting through the included files in reading order (sshd keeps the first).</summary>
    private static void NumberOccurrences(List<JsonObject> rows)
    {
        var seen = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var name = row["name"]!.ToString();
            row["occurrence"] = seen[name] = seen.GetValueOrDefault(name) + 1;
        }
    }

    /// <summary>The files an include names: relative to the including file's folder, a wildcard in the last part only.</summary>
    private static IEnumerable<string> Expand(IHostSession session, string from, string pattern)
    {
        var full = session.ResolveInclude(from, pattern);
        var cut = full.LastIndexOfAny(['/', '\\']);
        var folder = cut <= 0 ? full[..Math.Max(cut + 1, 1)] : full[..cut];
        var name = full[(cut + 1)..];
        if (name.Contains('*') || name.Contains('?'))
            return session.Glob(folder, name);
        return session.FileExists(full) ? [full] : [];
    }

    private static async Task<RunnerResult> Command(IHostSession session, QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var name = query.Text("name")!;
        var output = await session.RunAsync(name, query.List("args"), context.Timeout, cancellationToken).ConfigureAwait(false);
        if (!output.Found)
            return Flag(query, "optional", false) ? RunnerResult.Ok([]) : RunnerResult.Failed($"{name} is not installed on this machine");
        if (output.TimedOut)
            return RunnerResult.Failed($"{name} did not finish in {context.Timeout.TotalSeconds:0} s");

        var rows = new List<JsonObject>();
        var n = 0;
        foreach (var line in output.Lines.DefaultIfEmpty(""))
        {
            var row = Base(session);
            row["command"] = name;
            row["n"] = ++n;
            row["line"] = line;
            row["exitCode"] = output.ExitCode;
            rows.Add(row);
        }
        return output.Truncated ? RunnerResult.Partial(rows, $"{name} printed more than {HostCommands.MaxOutputBytes / 1024} KB; the rest was not read") : RunnerResult.Ok(rows);
    }
}

/// <summary>A machine could not be reached or read as asked (not a rule's fault, not a pass).</summary>
public sealed class HostSessionException(string message) : Exception(message);
