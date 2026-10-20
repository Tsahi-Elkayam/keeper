using System.Text.Json;
using System.Text.Json.Nodes;
using Keeper.Common;

namespace Keeper.Contracts;

public sealed class ContractException(string message) : Exception(message);

/// <summary>
/// A run folder: run.json plus rows/results/findings/coverage .jsonl. Written as &lt;id&gt;.tmp and
/// renamed when complete; every file's SHA-256 is in run.json, and every record is checked against
/// its contract before anything trusts it.
/// </summary>
public static class RunFolder
{
    public const string Manifest = "run.json";
    public const string Rows = "rows.jsonl";
    public const string Results = "results.jsonl";
    public const string Findings = "findings.jsonl";
    public const string Coverage = "coverage.jsonl";

    public static readonly IReadOnlyDictionary<string, string> FileSchemas = new Dictionary<string, string>
    {
        [Rows] = Schemas.Row,
        [Results] = Schemas.Result,
        [Findings] = Schemas.Finding,
        [Coverage] = Schemas.Coverage,
    };

    public static bool IsComplete(string folder) =>
        !folder.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) && File.Exists(Path.Combine(folder, Manifest));

    public static RunManifest ReadManifest(string folder)
    {
        var file = Path.Combine(folder, Manifest);
        if (!File.Exists(file))
            throw new ContractException($"{folder}: no {Manifest}.");

        RunManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<RunManifest>(File.ReadAllText(file), JsonLines.Options);
        }
        catch (JsonException ex)
        {
            throw new ContractException($"{file}: {ex.Message}");
        }
        if (manifest is null || manifest.Schema != Schemas.Run)
            throw new ContractException($"{file}: not a {Schemas.Run} manifest.");
        if (manifest.Status is not ("ok" or "partial" or "failed"))
            throw new ContractException($"{file}: status must be ok, partial or failed.");
        return manifest;
    }

    /// <summary>Checks the manifest, every file's hash and every record. Returns the manifest.</summary>
    public static RunManifest Verify(string folder)
    {
        var manifest = ReadManifest(folder);
        foreach (var expected in manifest.Files)
        {
            if (!FileSchemas.ContainsKey(expected.Name))
                throw new ContractException($"{folder}: unexpected file {expected.Name} in {Manifest}.");

            var file = Path.Combine(folder, expected.Name);
            if (!File.Exists(file))
                throw new ContractException($"{folder}: {expected.Name} is listed but missing.");
            if (!string.Equals(Hashing.Sha256File(file), expected.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new ContractException($"{folder}: {expected.Name} does not match its hash in {Manifest}.");

            VerifyRecords(file, FileSchemas[expected.Name]);
        }
        return manifest;
    }

    public static int VerifyRecords(string file, string schema)
    {
        var count = 0;
        foreach (var record in JsonLines.Read(file))
        {
            count++;
            var where = $"{Path.GetFileName(file)} record {count}";
            try
            {
                if (record["schema"] is not JsonValue value || !value.TryGetValue<string>(out var recordSchema) || recordSchema != schema)
                    throw new ContractException($"schema must be {schema}.");

                switch (schema)
                {
                    case Schemas.Row: Check(record.Deserialize<RowRecord>(JsonLines.Options)); break;
                    case Schemas.Result: Check(record.Deserialize<ResultRecord>(JsonLines.Options)); break;
                    case Schemas.Finding: Check(record.Deserialize<FindingRecord>(JsonLines.Options)); break;
                    case Schemas.Coverage: Check(record.Deserialize<CoverageRecord>(JsonLines.Options)); break;
                    default: throw new ContractException($"unknown schema {schema}");
                }
            }
            catch (Exception ex) when (ex is JsonException or ContractException or InvalidOperationException)
            {
                throw new ContractException($"{where}: {ex.Message}");
            }
        }
        return count;
    }

    private static void Check(RowRecord? row)
    {
        if (row is null || string.IsNullOrWhiteSpace(row.EntityKey))
            throw new ContractException("a row needs an entityKey.");
    }

    private static void Check(ResultRecord? result)
    {
        if (result is null || !Vocabulary.ResultStates.Contains(result.State))
            throw new ContractException($"state must be one of {string.Join(", ", Vocabulary.ResultStates)}.");
    }

    private static void Check(FindingRecord? finding)
    {
        if (finding is null)
            throw new ContractException("empty finding.");
        Require(Vocabulary.Kinds, finding.Kind, "kind");
        Require(Vocabulary.Lenses, finding.Lens, "lens");
        Require(Vocabulary.Categories, finding.Category, "category");
        Require(Vocabulary.Severities, finding.Severity, "severity");
        if (finding.FindingKey != FindingKey.For(finding.Instance, finding.CheckId, finding.Target))
            throw new ContractException("findingKey does not match instance|checkId|target.");
        if (finding.Deadline is not null && !DateOnly.TryParseExact(finding.Deadline, "yyyy-MM-dd", out _))
            throw new ContractException("deadline must be yyyy-MM-dd.");
    }

    private static void Check(CoverageRecord? coverage)
    {
        if (coverage is null)
            throw new ContractException("empty coverage record.");
        Require(Vocabulary.CoverageStates, coverage.State, "state");
        Require(Vocabulary.CoverageScopes, coverage.Scope, "scope");
    }

    private static void Require(IReadOnlySet<string> allowed, string value, string field)
    {
        if (!allowed.Contains(value))
            throw new ContractException($"{field} '{value}' must be one of {string.Join(", ", allowed)}.");
    }

    /// <summary>Records as raw JSON objects, for stages that only pass them on.</summary>
    public static IEnumerable<JsonObject> ReadRaw(string folder, string fileName)
    {
        var file = Path.Combine(folder, fileName);
        return File.Exists(file) ? JsonLines.Read(file) : [];
    }
}
