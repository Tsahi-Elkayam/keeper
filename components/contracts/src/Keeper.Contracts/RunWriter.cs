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
        RunId = $"{Iso.Stamp(startedAt)}-{Slug(instance)}";
        _final = Path.Combine(runsDir, RunId);
        _tmp = _final + ".tmp";
        if (Directory.Exists(_final) || Directory.Exists(_tmp))
            throw new IOException($"Run folder {RunId} already exists.");
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
        Directory.Move(_tmp, _final);
        _completed = true;
        return manifest;
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
