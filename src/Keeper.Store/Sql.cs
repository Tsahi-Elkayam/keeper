using Microsoft.Data.Sqlite;

namespace Keeper.Store;

/// <summary>Small helpers over ADO.NET. Values are always bound as parameters, never spliced into SQL.</summary>
public static class Sql
{
    public static SqliteCommand Command(
        SqliteConnection connection,
        string text,
        SqliteTransaction? transaction = null,
        params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.CommandText = text;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters)
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    public static void Execute(SqliteConnection connection, string text, SqliteTransaction? transaction = null)
    {
        using var command = Command(connection, text, transaction);
        command.ExecuteNonQuery();
    }

    public static object? Scalar(SqliteConnection connection, string text)
    {
        using var command = Command(connection, text);
        return command.ExecuteScalar();
    }
}
