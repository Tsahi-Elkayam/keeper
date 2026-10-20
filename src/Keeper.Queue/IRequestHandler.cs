using Keeper.Core;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Queue;

/// <summary>Applies one kind of request. One handler per kind; adding a kind never changes the queue manager.</summary>
public interface IRequestHandler
{
    /// <summary>The request kind, e.g. "override".</summary>
    string Kind { get; }

    /// <summary>Validates the payload and applies it inside the given transaction. Throws RequestException when invalid.</summary>
    void Apply(RequestContext context);
}

public sealed record RequestContext(
    SqliteConnection Connection,
    SqliteTransaction Transaction,
    RequestEnvelope Request,
    DateTimeOffset Now)
{
    public string NowText => Iso.Utc(Now);

    public SqliteCommand Command(string sql, params (string Name, object? Value)[] parameters) =>
        Sql.Command(Connection, sql, Transaction, parameters);
}
