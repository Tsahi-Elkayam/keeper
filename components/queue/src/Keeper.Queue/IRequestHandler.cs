using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Queue;

/// <summary>
/// Applies one kind of request. Kinds are namespaced by the component that owns them
/// (review.override, integrations.set-secret); adding a kind never changes the queue manager.
/// </summary>
public interface IRequestHandler
{
    string Kind { get; }

    /// <summary>Validates the payload and applies it inside the given transaction. Throws RequestException when invalid.</summary>
    void Apply(RequestContext context);
}

public sealed record RequestContext(
    SqliteConnection Connection,
    SqliteTransaction Transaction,
    RequestEnvelope Request,
    DateTimeOffset Now,
    string DataDir)
{
    public string NowText => Iso.Utc(Now);

    public SqliteCommand Command(string sql, params (string Name, object? Value)[] parameters) =>
        Sql.Command(Connection, sql, Transaction, parameters);

    public int Execute(string sql, params (string Name, object? Value)[] parameters) =>
        Sql.Execute(Connection, sql, Transaction, parameters);

    public object? Scalar(string sql, params (string Name, object? Value)[] parameters) =>
        Sql.Scalar(Connection, sql, Transaction, parameters);
}
