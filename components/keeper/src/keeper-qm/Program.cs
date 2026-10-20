using Keeper.Composition;
using Keeper.Queue;

// keeper-qm: the queue manager, the only writer of the store, composed with every component's handlers.
return QueueHost.Run("keeper-qm", args,
    cli =>
    {
        var (paths, db) = Composition.Locate(cli);
        return new QueueLocation(db, paths.Spool, paths.DataDir);
    },
    Composition.Schemas,
    Composition.Handlers());
