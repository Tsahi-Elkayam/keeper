using System.Text.Json;
using Keeper.Common;

namespace Keeper.Contracts;

/// <summary>
/// Writes one run folder. Files go into &lt;runs&gt;\&lt;id&gt;.tmp; <see cref="Complete"/> hashes them,
/// writes run.json and renames the folder, so a reader never sees half a run.
/// </summary>
public sealed class RunWriter : IDisposable
{
    private readonly string _tmp;
    private readonly string _final;
    private readonly Dictionary<string, JsonLinesWriter> _writers = [];
    private bool _completed;

    public RunWriter(string runsDir, string instance, string system, DateTimeOffset startedAt)
    {
        Instance = instance;
        System = system;
        StartedAt = startedAt;
        // Instance and system both: Keeper's own systems all read through the one implicit instance, and
        // scans started in the same second must not collide. A rerun within the second gets -2, -3, ...
        var name = Slug(instance) == Slug(system) ? Slug(instance) : $"{Slug(instance)}-{Slug(system)}";
        var id = $"{Iso.Stamp(startedAt)}-{name}";
        for (var n = 2; Directory.Exists(Path.Combine(runsDir, id)) || Directory.Exists(Path.Combine(runsDir, id + ".tmp")); n++)
            id = $"{Iso.Stamp(startedAt)}-{name}-{n}";
        RunId = id;
        _final = Path.Combine(runsDir, RunId);
        _tmp = _final + ".tmp";
        Directory.CreateDirectory(_tmp);
    }

    public string RunId { get; }
    public string Instance { get; }
    public string System { get; }
    public DateTimeOffset StartedAt { get; }
    public string Folder => _completed ? _final : _tmp;

    public void Row(RowRecord row) => Writer(RunFolder.Rows).Write(row);
    public void Result(ResultRecord result) => Writer(RunFolder.Results).Write(result);
    public void Finding(FindingRecord finding) => Writer(RunFolder.Findings).Write(finding);
    public void Coverage(CoverageRecord coverage) => Writer(RunFolder.Coverage).Write(coverage);

    public int CountOf(string fileName) => _writers.TryGetValue(fileName, out var w) ? w.Count : 0;

    public RunManifest Complete(string status, DateTimeOffset finishedAt, string? identity, IReadOnlyList<string> notes)
    {
        foreach (var writer in _writers.Values)
            writer.Dispose();

        var files = _writers.Keys
            .Order(StringComparer.Ordinal)
            .Select(name =>
            {
                var path = Path.Combine(_tmp, name);
                return new RunFile(name, Hashing.Sha256File(path), new FileInfo(path).Length);
            })
            .ToList();

        var manifest = new RunManifest
        {
            RunId = RunId,
            Instance = Instance,
            System = System,
            Identity = identity,
            Host = Environment.MachineName,
            StartedAt = Iso.Utc(StartedAt),
            FinishedAt = Iso.Utc(finishedAt),
            Status = status,
            Files = files,
            Counts = _writers.ToDictionary(w => w.Key, w => w.Value.Count),
            Notes = notes.Select(Redactor.Clean).ToList(),
        };
        File.WriteAllText(Path.Combine(_tmp, RunFolder.Manifest), JsonSerializer.Serialize(manifest, JsonLines.Options));
        MoveWhenFree(_tmp, _final);
        _completed = true;
        return manifest;
    }

    /// <summary>
    /// Renames the finished folder. An antivirus or EDR that is still reading the files it just saw written
    /// holds them for a moment; the rename waits for it rather than losing the run.
    /// </summary>
    private static void MoveWhenFree(string from, string to)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                Directory.Move(from, to);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException && attempt < 10 && Directory.Exists(from) && !Directory.Exists(to))
            {
                Thread.Sleep(100 * attempt);
            }
        }
    }

    public void Dispose()
    {
        foreach (var writer in _writers.Values)
            writer.Dispose();
    }

    private JsonLinesWriter Writer(string name)
    {
        if (_completed)
            throw new InvalidOperationException("The run is complete.");
        if (!_writers.TryGetValue(name, out var writer))
        {
            writer = new JsonLinesWriter(Path.Combine(_tmp, name));
            _writers[name] = writer;
        }
        return writer;
    }

    private static string Slug(string text) =>
        new(text.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-').ToArray());
}
