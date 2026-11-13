using System.Collections.Frozen;

namespace Keeper.Contracts;

/// <summary>The words every component agrees on. Lower-case, compared exactly.</summary>
public static class Vocabulary
{
    /// <summary>What is wrong: broken (does not work, or stops by its deadline), misconfigured (against a
    /// standard or best practice), missing (should exist or should have been done, and isn't).</summary>
    public static readonly FrozenSet<string> Kinds = Set("broken", "misconfigured", "missing");

    public static readonly FrozenSet<string> Lenses = Set("maintenance", "security", "both");

    public static readonly FrozenSet<string> Severities = Set("critical", "high", "medium", "low", "info");

    public static readonly FrozenSet<string> Categories = Set("HLT", "LCM", "LOG", "AVL", "CFG", "IAM", "AUT", "PKI", "BCK", "MON", "HYG", "CST");

    /// <summary>Categories that are always part of the security tier.</summary>
    public static readonly FrozenSet<string> SecurityCategories = Set("IAM", "AUT", "PKI");

    public static readonly FrozenSet<string> ResultStates = Set("pass", "fail", "n-a", "unknown");

    public static readonly FrozenSet<string> CoverageStates = Set("ok", "partial", "failed", "not-applicable");

    public static readonly FrozenSet<string> CoverageScopes = Set("rule", "query", "target");

    /// <summary>0 = most severe.</summary>
    public static int SeverityRank(string severity) => severity switch
    {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };

    public static bool IsSecurity(string category, string lens) =>
        SecurityCategories.Contains(category) || lens == "security";

    private static FrozenSet<string> Set(params string[] values) => values.ToFrozenSet(StringComparer.Ordinal);
}
