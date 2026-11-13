using System.Text.RegularExpressions;

namespace Keeper.Review;

public static partial class Identifiers
{
    /// <summary>Lower-case letters, digits, dots and dashes; starts with a letter; at most 100 characters.</summary>
    public static bool IsValid(string? id) => id is { Length: > 0 and <= 100 } && Pattern().IsMatch(id);

    /// <summary>System and record ids people choose: letters, digits, dots, dashes, underscores; at most 100.</summary>
    public static bool IsRecordId(string? id) => id is { Length: > 0 and <= 100 } && RecordPattern().IsMatch(id);

    [GeneratedRegex("^[a-z][a-z0-9.-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex RecordPattern();
}
