using Keeper.Common;
using Keeper.Contracts;
using Keeper.Queue;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Review.Load;

public sealed record LoadCandidate(string RunId, string Folder, string RelativeFolder, string? Problem);

/// <summary>
/// Finds complete run folders the store has not loaded, verifies each (hashes and records), and submits
/// the good ones as review.load-run requests. A folder that fails verification is reported, never loaded.
/// </summary>
public static class RunLoader
{
    public static IReadOnlyList<LoadCandidate> Pending(SqliteConnection readOnly, string runsDir, string dataDir)
    {
        if (!Directory.Exists(runsDir))
            return [];

        var loaded = Sql.Rows(readOnly, "SELECT run_id FROM run;").Select(r => (string)r["run_id"]!).ToHashSet(StringComparer.Ordinal);
        var candidates = new List<LoadCandidate>();
        foreach (var folder in Directory.GetDirectories(runsDir).Order(StringComparer.Ordinal))
        {
            if (!RunFolder.IsComplete(folder))
                continue;
            var runId = Path.GetFileName(folder);
            if (loaded.Contains(runId))
                continue;

            var relative = Path.GetRelativePath(dataDir, folder).Replace('\\', '/');
            string? problem = null;
            try
            {
                var manifest = RunFolder.Verify(folder);
                if (manifest.RunId != runId)
                    problem = $"run.json says {manifest.RunId}, the folder is {runId}";
            }
            catch (ContractException ex)
            {
                problem = ex.Message;
            }
            candidates.Add(new LoadCandidate(runId, folder, relative, problem));
        }
        return candidates;
    }

    public static string Submit(RequestWriter writer, LoadCandidate candidate) =>
        writer.Submit("review.load-run", $"Load scan {candidate.RunId}", new
        {
            folder = candidate.RelativeFolder,
            manifestSha256 = Hashing.Sha256File(Path.Combine(candidate.Folder, RunFolder.Manifest)),
        });
}
