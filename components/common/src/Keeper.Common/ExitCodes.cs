namespace Keeper.Common;

/// <summary>Exit codes every keeper binary uses.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int Failed = 1;
    public const int Usage = 2;

    /// <summary>Ran, but could not see everything it should have: partial data, or none.</summary>
    public const int NoData = 3;
}
