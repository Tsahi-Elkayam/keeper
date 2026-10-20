using Keeper.Store;

namespace Keeper.Queue;

public static class QueueSchema
{
    public static MigrationSet Migrations { get; } = MigrationSet.FromResources("queue", typeof(QueueSchema).Assembly, "queue/");
}
