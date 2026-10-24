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
public sealed class HostRunner : IRunner
{
    private static readonly string[] Reads = ["facts", "file", "stat", "command"];
    private static readonly string[] Formats = ["lines", "kv", "ini", "json", "directives"];

    public string Protocol => "host";

    public bool PerTarget => false;

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
            return query.Text("read") switch
            {
                "facts" => RunnerResult.Ok([Facts()]),
                "stat" => RunnerResult.Ok([Stat(query.Text("path")!)]),
                "file" => ReadFile(query, context),
                "command" => await Command(query, context, cancellationToken).ConfigureAwait(false),
                _ => RunnerResult.Failed("host: unknown read"),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or JsonException)
        {
            return RunnerResult.Failed($"host read failed: {ex.Message}");
        }
    }

    /// <summary>A true/false field of the query; rule files give it as a YAML boolean, tests as text.</summary>
    private static bool Flag(QuerySpec query, string field, bool otherwise) =>
        query.Fields[field] is JsonValue v ? v.TryGetValue<bool>(out var b) ? b : v.TryGetValue<string>(out var t) ? t.Equals("true", StringComparison.OrdinalIgnoreCase) : otherwise : otherwise;

    private static JsonObject Base() => new() { ["host"] = Environment.MachineName };

    private static JsonObject Facts()
    {
        var row = Base();
        row["os"] = OperatingSystem.IsMacOS() ? "macos" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "other";
        row["kernel"] = Environment.OSVersion.VersionString;
        row["architecture"] = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        row["uptimeSeconds"] = Environment.TickCount64 / 1000;
        if (File.Exists("/etc/os-release"))
        {
            var release = ConfigParsers.Kv(File.ReadAllText("/etc/os-release"), "/etc/os-release").ToDictionary(r => r["name"]!.ToString(), r => r["value"]!.ToString(), StringComparer.Ordinal);
            row["osId"] = release.GetValueOrDefault("id");
            row["osVersion"] = release.GetValueOrDefault("version_id");
            row["osName"] = release.GetValueOrDefault("pretty_name");
        }
        else
        {
            row["osVersion"] = Environment.OSVersion.Version.ToString();
        }
        return row;
    }

    private static JsonObject Stat(string path)
    {
        var row = Base();
        row["path"] = path;
        var info = new FileInfo(path);
        var isLink = info.LinkTarget is not null;
        var exists = info.Exists || Directory.Exists(path) || isLink;
        row["exists"] = exists;
        row["isLink"] = isLink;
        if (!exists)
            return row;
        row["isDirectory"] = Directory.Exists(path);
        row["size"] = info.Exists ? info.Length : 0;
        row["modified"] = RowValues.Iso(File.GetLastWriteTimeUtc(path));
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(path);
            row["mode"] = Convert.ToString((int)mode, 8);
            row["worldWritable"] = (mode & UnixFileMode.OtherWrite) != 0;
            row["groupWritable"] = (mode & UnixFileMode.GroupWrite) != 0;
            row["worldReadable"] = (mode & UnixFileMode.OtherRead) != 0;
        }
        return row;
    }

    private static RunnerResult ReadFile(QuerySpec query, RunnerContext context)
    {
        var path = Path.GetFullPath(query.Text("path")!);
        var optional = Flag(query, "optional", false);
        if (!File.Exists(path))
            return optional ? RunnerResult.Ok([]) : RunnerResult.Failed($"{path} does not exist");
        if (HostGuards.ReadProblem(path) is { } problem)
            return RunnerResult.Failed($"{path} was not read: {problem}");

        var format = query.Text("format") ?? "lines";
        var reasons = new List<string>();
        var rows = format switch
        {
            "directives" => WithIncludes(path, (text, file, context) => ConfigParsers.Directives(text, file, query.Text("style")!, context), Flag(query, "follow", true), reasons),
            "json" => Json(path, query.Text("items")),
            "kv" => WithOccurrences(WithIncludes(path, (text, file, _) => ConfigParsers.Kv(text, file), Flag(query, "follow", true), reasons)),
            "ini" => ConfigParsers.Ini(File.ReadAllText(path), path),
            _ => ConfigParsers.Lines(File.ReadAllText(path), path),
        };
        foreach (var row in rows)
        {
            row["host"] = Environment.MachineName;
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

    private static List<JsonObject> Json(string path, string? items)
    {
        var body = JsonNode.Parse(File.ReadAllText(path), documentOptions: new JsonDocumentOptions { MaxDepth = 64, CommentHandling = JsonCommentHandling.Skip });
        return [.. RowValues.ItemsOf(body, items).Select(r => (JsonObject)RowValues.Detach(r))];
    }

    /// <summary>The rows of a file and of what it includes (a wildcard too), each row naming its own file.</summary>
    private static List<JsonObject> WithIncludes(string path, Func<string, string, string, List<JsonObject>> parse, bool follow, List<string> reasons)
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
            if (HostGuards.ReadProblem(file) is { } problem)
                throw new IOException($"{file} was not read: {problem}");
            foreach (var row in parse(File.ReadAllText(file), file, context))
            {
                rows.Add(row);
                if (!follow || row["block"] is JsonValue block && block.GetValue<bool>() || row["name"]!.ToString() is not ("include" or "includeoptional"))
                    continue;
                var arguments = row["args"] is JsonArray args ? args.Select(a => a!.ToString()) : [row["value"]!.ToString()];
                foreach (var pattern in arguments)
                {
                    foreach (var included in Expand(file, pattern))
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
    private static IEnumerable<string> Expand(string from, string pattern)
    {
        var full = Path.IsPathRooted(pattern) ? pattern : Path.Combine(Path.GetDirectoryName(from)!, pattern);
        full = Path.GetFullPath(full);
        var folder = Path.GetDirectoryName(full)!;
        var name = Path.GetFileName(full);
        if (name.Contains('*') || name.Contains('?'))
            return Directory.Exists(folder) ? Directory.GetFiles(folder, name).Order(StringComparer.Ordinal) : [];
        return File.Exists(full) ? [full] : [];
    }

    private static async Task<RunnerResult> Command(QuerySpec query, RunnerContext context, CancellationToken cancellationToken)
    {
        var name = query.Text("name")!;
        var args = query.List("args");
        var output = await HostCommands.RunAsync(name, args, context.Timeout, cancellationToken).ConfigureAwait(false);
        if (!output.Found)
            return Flag(query, "optional", false) ? RunnerResult.Ok([]) : RunnerResult.Failed($"{name} is not installed on this machine");
        if (output.TimedOut)
            return RunnerResult.Failed($"{name} did not finish in {context.Timeout.TotalSeconds:0} s");

        var rows = new List<JsonObject>();
        var n = 0;
        foreach (var line in output.Lines.DefaultIfEmpty(""))
        {
            var row = Base();
            row["command"] = name;
            row["n"] = ++n;
            row["line"] = line;
            row["exitCode"] = output.ExitCode;
            rows.Add(row);
        }
        return output.Truncated ? RunnerResult.Partial(rows, $"{name} printed more than {HostCommands.MaxOutputBytes / 1024} KB; the rest was not read") : RunnerResult.Ok(rows);
    }
}
