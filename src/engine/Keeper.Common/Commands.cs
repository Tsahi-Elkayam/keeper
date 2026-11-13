namespace Keeper.Common;

/// <summary>
/// The verbs of the one keeper binary. keeper's entry point adds them; a verb that runs another (run ->
/// scan, load, track ...; --now -> qm) calls it here, in the same process - no child process is started.
/// </summary>
public static class Commands
{
    private static readonly Dictionary<string, Func<string[], int>> Table = new(StringComparer.Ordinal);

    public static void Add(string verb, Func<string[], int> run) => Table[verb] = run;

    public static bool Exists(string verb) => Table.ContainsKey(verb);

    /// <summary>
    /// Runs the verb and returns its exit code. A verb that throws past its own handlers fails alone, as a
    /// separate process did: the caller (keeper run) gets an exit code and decides whether to go on.
    /// </summary>
    public static int Run(string verb, IEnumerable<string> args)
    {
        if (!Table.TryGetValue(verb, out var run))
            throw new ArgumentException($"'{verb}' is not a keeper verb. 'keeper help' lists them.");
        try
        {
            return run([.. args]);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"keeper {verb}: {Redactor.Clean(ex.Message)}");
            return ExitCodes.Failed;
        }
    }
}
