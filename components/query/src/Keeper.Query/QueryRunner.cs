using Microsoft.Data.Sqlite;

namespace Keeper.Query;

/// <summary>Receives a query's result, one row at a time.</summary>
public interface IRowWriter
{
    void Columns(IReadOnlyList<string> names);

    void Row(IReadOnlyList<object?> values);

    void Complete();
}

/// <summary>
/// Runs a named query on a read-only connection. Every argument is bound as a parameter, never
/// spliced into the SQL; an argument the query does not declare is refused.
/// </summary>
public static class QueryRunner
{
    /// <returns>The number of rows written.</returns>
    public static int Run(SqliteConnection readOnly, NamedQuery query, IReadOnlyDictionary<string, string?> arguments, IRowWriter writer)
    {
        foreach (var name in arguments.Keys)
        {
            if (!query.Parameters.Any(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                throw new QueryException($"'{query.Name}' has no parameter --{name}. It takes {Describe(query)}.");
        }

        using var command = readOnly.CreateCommand();
        command.CommandText = query.Sql;
        foreach (var parameter in query.Parameters)
        {
            var value = arguments.FirstOrDefault(a => a.Key.Equals(parameter.Name, StringComparison.OrdinalIgnoreCase)).Value;
            if (parameter.Required && string.IsNullOrEmpty(value))
                throw new QueryException($"'{query.Name}' needs --{parameter.Name}.");
            command.Parameters.AddWithValue(":" + parameter.Name, (object?)value ?? DBNull.Value);
        }

        using var reader = command.ExecuteReader();
        writer.Columns(Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList());

        var rows = 0;
        while (reader.Read())
        {
            var values = new object?[reader.FieldCount];
            for (var i = 0; i < values.Length; i++)
                values[i] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            writer.Row(values);
            rows++;
        }
        writer.Complete();
        return rows;
    }

    public static string Describe(NamedQuery query) =>
        query.Parameters.Count == 0
            ? "no parameters"
            : string.Join(", ", query.Parameters.Select(p => p.Required ? $"--{p.Name}" : $"--{p.Name} (optional)"));
}
