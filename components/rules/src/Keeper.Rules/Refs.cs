using System.Text.RegularExpressions;

namespace Keeper.Rules;

/// <summary>
/// A rule's references as FRAMEWORK:CONTROL, with one spelling per framework, so control evidence rolls
/// up under one name whoever wrote the rule ("CIS-CSC-v8:5.3" and "CIS-CONTROLS-8:5.3" are one control).
/// A reference without a control (a document, an RFC) keeps its text.
/// </summary>
public static partial class Refs
{
    private static readonly Dictionary<string, string> Frameworks = new(StringComparer.OrdinalIgnoreCase)
    {
        ["NIST-800-53"] = "NIST-800-53",
        ["NIST-SP-800-53"] = "NIST-800-53",
        ["CIS-Controls-v8"] = "CIS-Controls-v8",
        ["CIS-CSC-v8"] = "CIS-Controls-v8",
        ["CIS-CSC-8"] = "CIS-Controls-v8",
        ["CIS-CONTROLS-8"] = "CIS-Controls-v8",
        ["CIS-Controls-8"] = "CIS-Controls-v8",
        ["CIS-M365"] = "CIS-M365",
        ["CIS-MSSQL"] = "CIS-MSSQL",
        ["MITRE-ATTACK"] = "MITRE-ATTACK",
        ["ATTACK"] = "MITRE-ATTACK",
        ["PINGCASTLE"] = "PingCastle",
        ["ADCS"] = "ADCS",
        ["MS-KB"] = "MS-KB",
        ["CABF-BR"] = "CABF-BR",
    };

    /// <summary>"CIS-M365-5.2.3.5" (a benchmark id run together with its control) -> CIS-M365:5.2.3.5.</summary>
    [GeneratedRegex(@"^(CIS-M365|CIS-MSSQL)-(\d[\d.]*)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RunTogether();

    public static string Normalize(string reference)
    {
        var text = reference.Trim();
        if (RunTogether().Match(text) is { Success: true } joined)
            text = $"{joined.Groups[1].Value}:{joined.Groups[2].Value}";

        var colon = text.IndexOf(':');
        if (colon <= 0)
            return text;
        var framework = text[..colon].Trim();
        var control = text[(colon + 1)..].Trim();
        return $"{(Frameworks.TryGetValue(framework, out var canonical) ? canonical : framework)}:{control}";
    }

    public static IReadOnlyList<string> Normalize(IEnumerable<string> references) =>
        references.Select(Normalize).Where(r => r.Length > 0).Distinct(StringComparer.Ordinal).ToList();
}
