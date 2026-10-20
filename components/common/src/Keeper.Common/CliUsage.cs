namespace Keeper.Common;

/// <summary>How every keeper binary prints its usage.</summary>
public static class CliUsage
{
    /// <summary>
    /// Asked for (--help): to standard output, exit 0. Shown because the arguments were wrong: to
    /// standard error, exit <see cref="ExitCodes.Usage"/>.
    /// </summary>
    public static int Print(string text, bool asked)
    {
        (asked ? Console.Out : Console.Error).WriteLine(text.TrimEnd());
        return asked ? ExitCodes.Ok : ExitCodes.Usage;
    }
}
