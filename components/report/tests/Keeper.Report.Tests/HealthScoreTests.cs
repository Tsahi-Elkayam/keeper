namespace Keeper.Report.Tests;

public sealed class HealthScoreTests
{
    private static HealthScore.OpenCheck Open(string severity, string category = "CFG", string system = "windows") => new(severity, category, system);

    private static HealthScore.Coverage Judged(long judged, long notJudged = 0) => new(judged, notJudged);

    [Fact]
    public void An_estate_with_nothing_open_that_was_fully_judged_scores_100_grade_A()
    {
        var score = HealthScore.Compute([], ["CFG"], Judged(50));

        Assert.Equal(100, score.Overall);
        Assert.Equal("A", score.Grade);
        Assert.False(score.Provisional);
    }

    [Fact]
    public void Each_open_check_costs_points_by_severity()
    {
        // critical 20, high 10, medium 4, low 1: 100 - 20 - 10 - 4 - 1 = 65
        var score = HealthScore.Compute([Open("critical"), Open("high"), Open("medium"), Open("low")], ["CFG"], Judged(50));

        Assert.Equal(65, score.Overall);
    }

    [Fact]
    public void A_check_counts_once_however_many_objects_it_failed_on()
    {
        // The input is one entry per check, so a thousand failing objects cannot flatten the score: that is the caller's contract.
        var score = HealthScore.Compute([Open("high")], ["CFG"], Judged(50));

        Assert.Equal(90, score.Overall);
    }

    [Fact]
    public void A_category_cannot_go_below_zero()
    {
        var many = Enumerable.Range(0, 30).Select(_ => Open("critical")).ToList();

        var score = HealthScore.Compute(many, ["CFG"], Judged(50));

        Assert.Equal(0, score.Categories.Single().Health);
        Assert.Equal(0, score.Overall);
    }

    [Fact]
    public void The_overall_score_is_the_average_of_the_categories_that_were_judged()
    {
        // CFG loses 40 (two criticals), ID is untouched, KEY loses 10: (60 + 100 + 90) / 3 = 83.3 -> 83
        var score = HealthScore.Compute([Open("critical", "CFG"), Open("critical", "CFG"), Open("high", "KEY")], ["CFG", "ID", "KEY"], Judged(50));

        Assert.Equal(83, score.Overall);
        Assert.Equal(["CFG", "ID", "KEY"], score.Categories.Select(c => c.Category).Order());
    }

    [Fact]
    public void A_category_with_findings_counts_even_when_no_check_was_recorded_as_run_in_it()
    {
        var score = HealthScore.Compute([Open("high", "KEY")], [], Judged(50));

        Assert.Equal(90, score.Overall);
    }

    [Fact]
    public void One_open_critical_finding_keeps_the_grade_from_being_better_than_C()
    {
        // 100 categories of 100 and one with a critical: the average is still above 90, the grade is not.
        var categories = Enumerable.Range(0, 20).Select(i => $"C{i}").ToList();

        var score = HealthScore.Compute([Open("critical", "C0")], categories, Judged(500));

        Assert.True(score.Overall >= 90);
        Assert.Equal("C", score.Grade);
        Assert.Contains("critical", score.GradeNote, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(90, "A")]
    [InlineData(89, "B")]
    [InlineData(75, "B")]
    [InlineData(74, "C")]
    [InlineData(60, "C")]
    [InlineData(59, "D")]
    [InlineData(40, "D")]
    [InlineData(39, "E")]
    [InlineData(0, "E")]
    public void Grades_follow_the_published_bands(int score, string grade)
    {
        Assert.Equal(grade, HealthScore.GradeFor(score));
    }

    [Fact]
    public void A_score_built_on_less_than_four_fifths_of_the_checks_is_provisional_and_says_why()
    {
        var score = HealthScore.Compute([], ["CFG"], Judged(judged: 60, notJudged: 40));

        Assert.True(score.Provisional);
        Assert.Equal(60, score.JudgedPercent);
        Assert.Contains("40", score.ProvisionalReason, StringComparison.Ordinal);
    }

    [Fact]
    public void The_score_says_how_many_checks_it_stands_on()
    {
        Assert.Equal(50, HealthScore.Compute([], ["CFG"], Judged(50)).Judged);
    }

    [Fact]
    public void Nothing_judged_at_all_is_not_a_perfect_score()
    {
        var score = HealthScore.Compute([], [], Judged(0, 0));

        Assert.Null(score.Overall);
        Assert.Equal("-", score.Grade);
    }

    [Fact]
    public void Each_system_gets_its_own_score_from_its_own_checks()
    {
        var score = HealthScore.Compute([Open("high", system: "windows"), Open("medium", system: "nginx")], ["CFG"], Judged(50));

        Assert.Equal(90, score.Systems.Single(s => s.System == "windows").Health);
        Assert.Equal(96, score.Systems.Single(s => s.System == "nginx").Health);
    }
}
