using Keeper.Query;
using Keeper.Queue;
using Keeper.Review.Handlers;
using Keeper.Store;

namespace Keeper.Review;

/// <summary>What the review component contributes to a composed binary.</summary>
public static class ReviewComponent
{
    public static MigrationSet Schema { get; } = MigrationSet.FromResources("review", typeof(ReviewComponent).Assembly, "review/");

    public static QueryPack Questions { get; } = new("review", typeof(ReviewComponent).Assembly, "review-questions/");

    public static IReadOnlyList<IRequestHandler> Handlers() =>
    [
        new LoadRunHandler(),
        new RegisterHandler(),
        new RulesLoadHandler(),
        new OverrideHandler(),
        new TriageHandler(),
        new AttestationHandler(),
        new SettingHandler(),
        new SystemHandler(),
        new SystemRuleHandler(),
        .. Registers.Handlers(),
    ];
}
