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

    public static int Execute(SqliteConnection connection, string text, SqliteTransaction? transaction = null,
        params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, text, transaction, parameters);
        return command.ExecuteNonQuery();
    }

    public static object? Scalar(SqliteConnection connection, string text, SqliteTransaction? transaction = null,
        params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, text, transaction, parameters);
        var value = command.ExecuteScalar();
        return value is DBNull ? null : value;
    }

    /// <summary>Every row as column name -> value (DBNull becomes null). For small result sets.</summary>
    public static List<Dictionary<string, object?>> Rows(SqliteConnection connection, string text,
        SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, text, transaction, parameters);
        using var reader = command.ExecuteReader();
        var rows = new List<Dictionary<string, object?>>();
        while (reader.Read())
        {
            var row = new Dictionary<string, object?>(reader.FieldCount, StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }
        return rows;
    }
}
