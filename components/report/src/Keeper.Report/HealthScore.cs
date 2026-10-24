namespace Keeper.Report;

/// <summary>
/// One number, A to E, for how healthy the estate is - and the rules it comes from, so it can be argued with.
///
/// Every open check costs points by severity (critical 20, high 10, medium 4, low 1); a check counts once however
/// many objects it failed on. A category (or system) scores 100 minus its points, never below 0. The overall score is
/// the average of the categories that were judged. Bands: A 90+, B 75+, C 60+, D 40+, E below. One open critical
/// check keeps the grade from being better than C, whatever the average says. Built on fewer than 80% of the
/// checks being judged, the score is provisional: a score is only as good as what could be read.
/// </summary>
public static class HealthScore
{
    public sealed record OpenCheck(string Severity, string Category, string System);

    /// <summary>Checks that gave a verdict (correct, should-configure, broken), and checks that could not (unreadable data, did not run).</summary>
    public sealed record Coverage(long Judged, long NotJudged);

    public sealed record CategoryScore(string Category, int Health, int OpenChecks);

    public sealed record SystemScore(string System, int Health, int OpenChecks);

    public sealed record Result(
        int? Overall, string Grade, string? GradeNote, bool Provisional, string? ProvisionalReason, int JudgedPercent, long Judged,
        IReadOnlyList<CategoryScore> Categories, IReadOnlyList<SystemScore> Systems);

    public const int ProvisionalBelowPercent = 80;

    public static IReadOnlyDictionary<string, int> Weights { get; } = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["critical"] = 20, ["high"] = 10, ["medium"] = 4, ["low"] = 1, ["info"] = 0,
    };

    public static string GradeFor(int score) => score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 40 => "D",
        _ => "E",
    };

    public static Result Compute(IReadOnlyList<OpenCheck> open, IReadOnlyCollection<string> judgedCategories, Coverage coverage)
    {
        static int Cost(OpenCheck c) => Weights.TryGetValue(c.Severity, out var w) ? w : 4;

        var categories = open.Select(c => c.Category).Concat(judgedCategories).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)
            .Select(name =>
            {
                var mine = open.Where(c => c.Category == name).ToList();
                return new CategoryScore(name, Math.Max(0, 100 - mine.Sum(Cost)), mine.Count);
            }).ToList();
        var systems = open.Select(c => c.System).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)
            .Select(name =>
            {
                var mine = open.Where(c => c.System == name).ToList();
                return new SystemScore(name, Math.Max(0, 100 - mine.Sum(Cost)), mine.Count);
            }).ToList();

        var total = coverage.Judged + coverage.NotJudged;
        var judgedPercent = total == 0 ? 0 : (int)Math.Round(100.0 * coverage.Judged / total, MidpointRounding.AwayFromZero);
        if (categories.Count == 0 || coverage.Judged == 0)
            return new Result(null, "-", null, true, "Nothing has been judged yet, so there is no score.", judgedPercent, coverage.Judged, categories, systems);

        var overall = (int)Math.Round(categories.Average(c => c.Health), MidpointRounding.AwayFromZero);
        var grade = GradeFor(overall);
        string? note = null;
        if (open.Any(c => c.Severity == "critical") && string.CompareOrdinal(grade, "C") < 0)
        {
            grade = "C";
            note = "Capped at C: at least one critical check is open.";
        }
        var provisional = judgedPercent < ProvisionalBelowPercent;
        return new Result(overall, grade, note, provisional,
            provisional ? $"Provisional: {coverage.NotJudged} of {total} checks could not be judged or did not run, so {judgedPercent}% of the picture is in this score." : null,
            judgedPercent, coverage.Judged, categories, systems);
    }
}
