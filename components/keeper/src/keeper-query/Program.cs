using Keeper.Composition;
using Keeper.Query;

// keeper-query: answers questions from the store, read-only, with every component's question pack.
return QueryHost.Run("keeper-query", args,
    cli =>
    {
        var (paths, db) = Composition.Locate(cli);
        return new QueryLocation(db, Composition.Schemas, paths.TenantQueries);
    },
    Composition.Questions);
