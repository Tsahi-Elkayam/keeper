namespace Keeper.Queue;

/// <summary>
/// The spool folders. Producers write tmp\ then rename into queue\; keeper-qm moves each file
/// through work\ to done\ or failed\.
/// </summary>
public static class Spool
{
    public const string Tmp = "tmp";
    public const string Queue = "queue";
    public const string Work = "work";
    public const string Done = "done";
    public const string Failed = "failed";

    private static readonly string[] Folders = [Tmp, Queue, Work, Done, Failed];

    public static void EnsureFolders(string spoolDir)
    {
        foreach (var folder in Folders)
            Directory.CreateDirectory(Path.Combine(spoolDir, folder));
    }

    public static IReadOnlyList<(string Folder, int Count)> Counts(string spoolDir) =>
        [.. Folders.Select(f =>
        {
            var path = Path.Combine(spoolDir, f);
            return (f, Directory.Exists(path) ? Directory.GetFiles(path, "*.json").Length : 0);
        })];
}
