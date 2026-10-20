namespace Keeper.Query;

public sealed record QueryParameter(string Name, bool Required);

/// <summary>
/// A question the store can answer: a .sql file whose header names it, describes it and declares
/// its parameters. The header is the comment block before the first statement:
/// <code>
/// -- name: broken
/// -- description: What is broken: ...
/// -- param: system optional
/// </code>
/// </summary>
public sealed record NamedQuery(string Name, string Description, IReadOnlyList<QueryParameter> Parameters, string Sql, string Origin)
{
    public static NamedQuery Parse(string text, string origin)
    {
        string? name = null;
        string? description = null;
        var parameters = new List<QueryParameter>();

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0)
                continue;
            if (!line.StartsWith("--", StringComparison.Ordinal))
                break;

            var body = line[2..].Trim();
            var colon = body.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
                continue;

            var value = body[(colon + 1)..].Trim();
            switch (body[..colon].Trim())
            {
                case "name":
                    name = value;
                    break;
                case "description":
                    description = value;
                    break;
                case "param":
                    parameters.Add(ParseParameter(value, origin));
                    break;
            }
        }

        if (string.IsNullOrWhiteSpace(name))
            throw new QueryException($"{origin}: missing '-- name:' header.");
        if (string.IsNullOrWhiteSpace(description))
            throw new QueryException($"{origin}: missing '-- description:' header.");
        return new NamedQuery(name, description, parameters, text, origin);
    }

    private static QueryParameter ParseParameter(string value, string origin)
    {
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || parts[1] is not ("required" or "optional"))
            throw new QueryException($"{origin}: a param line must read '-- param: <name> required|optional'.");
        return new QueryParameter(parts[0], parts[1] == "required");
    }
}

public sealed class QueryException(string message) : Exception(message);
