using Keeper.Common;
using Keeper.Home;
using Keeper.Integrations;
using Keeper.Push;
using Keeper.Query;
using Keeper.Queue;
using Keeper.Rank;
using Keeper.Review;
using Keeper.Store;

namespace Keeper.Composition;

/// <summary>
/// What Keeper is made of, composed at build time: every component's schema, request handlers and
/// questions. Nothing is discovered or loaded from a folder at runtime.
/// </summary>
public static class Composition
{
    public static IReadOnlyList<MigrationSet> Schemas { get; } =
    [
        QueueSchema.Migrations,
        Keeper.Vault.Vault.Schema,
        IntegrationStore.Schema,
        ReviewComponent.Schema,
        Ranker.Schema,
        PushComponent.Schema,
    ];

    public static IReadOnlyList<IRequestHandler> Handlers() =>
    [
        .. ReviewComponent.Handlers(),
        .. IntegrationHandlers.All(),
        new RankRegisterHandler(),
        .. PushComponent.Handlers(),
    ];

    public static QueryPack KeeperQuestions { get; } = new("keeper", typeof(Composition).Assembly, "keeper-questions/");

    public static IReadOnlyList<QueryPack> Questions { get; } = [ReviewComponent.Questions, Ranker.Questions, KeeperQuestions];

    public static (KeeperPaths Paths, Database Db) Locate(CliArgs cli)
    {
        var (_, paths) = KeeperContext.Load(cli);
        return (paths, new Database(paths.Database));
    }
}
