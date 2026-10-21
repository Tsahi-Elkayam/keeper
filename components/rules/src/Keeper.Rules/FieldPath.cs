using System.Text.Json.Nodes;

namespace Keeper.Rules;

/// <summary>
/// Row field paths: "a.b.c", and "a[].b" to take b from every element of the array a. A name with dots in it
/// is quoted: ["@odata.type"], value[].["user.company"]. A path that is missing anywhere gives no values.
/// Property names match case-insensitively.
/// </summary>
public static class FieldPath
{
    /// <summary>The path's names, each with whether to take every element of its array ("[]").</summary>
    public static IEnumerable<(string Name, bool Flatten)> Parts(string path)
    {
        if (!path.Contains("[\"", StringComparison.Ordinal))
        {
            foreach (var part in path.Split('.'))
                yield return part.EndsWith("[]", StringComparison.Ordinal) ? (part[..^2], true) : (part, false);
            yield break;
        }
        for (var i = 0; i < path.Length;)
        {
            string name;
            if (string.CompareOrdinal(path, i, "[\"", 0, 2) == 0 && path.IndexOf("\"]", i + 2, StringComparison.Ordinal) is var close and >= 0)
            {
                name = path[(i + 2)..close];
                i = close + 2;
            }
            else
            {
                var end = path.IndexOf('.', i);
                var stop = end < 0 ? path.Length : end;
                name = path[i..stop];
                i = stop;
            }
            var flatten = false;
            if (string.CompareOrdinal(path, i, "[]", 0, 2) == 0)
            {
                flatten = true;
                i += 2;
            }
            else if (name.EndsWith("[]", StringComparison.Ordinal))
            {
                flatten = true;
                name = name[..^2];
            }
            yield return (name, flatten);
            if (i < path.Length && path[i] == '.')
                i++;
        }
    }

    public static IReadOnlyList<JsonNode?> Resolve(JsonNode? root, string path)
    {
        IEnumerable<JsonNode?> current = [root];
        foreach (var (name, flatten) in Parts(path))
        {
            current = current.SelectMany(node =>
            {
                var next = Child(node, name);
                if (!flatten)
                    return next is null ? [] : new[] { next };
                return next is JsonArray array ? array : (IEnumerable<JsonNode?>)[];
            });
        }
        return current.ToList();
    }

    public static JsonNode? First(JsonNode? root, string path) => Resolve(root, path).FirstOrDefault(n => n is not null);

    private static JsonNode? Child(JsonNode? node, string name)
    {
        if (node is not JsonObject obj)
            return null;
        if (obj.TryGetPropertyValue(name, out var exact))
            return exact;
        foreach (var (key, value) in obj)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
                return value;
        }
        return null;
    }
}

/// <summary>"{field}" placeholders filled from a row; "{{" is a literal brace.</summary>
public static class Templates
{
    public static string Render(string template, JsonNode? row)
    {
        var output = new System.Text.StringBuilder(template.Length + 32);
        for (var i = 0; i < template.Length; i++)
        {
            var c = template[i];
            if (c == '{' && i + 1 < template.Length && template[i + 1] == '{')
            {
                output.Append('{');
                i++;
                continue;
            }
            if (c == '}' && i + 1 < template.Length && template[i + 1] == '}')
            {
                output.Append('}');
                i++;
                continue;
            }
            if (c != '{')
            {
                output.Append(c);
                continue;
            }
            var end = template.IndexOf('}', i + 1);
            if (end < 0)
            {
                output.Append(template, i, template.Length - i);
                break;
            }
            var path = template[(i + 1)..end].Trim();
            var values = FieldPath.Resolve(row, path)
                .SelectMany(n => n is JsonArray array ? array.ToList() : [n])
                .Select(Values.Text)
                .Where(t => t is not null);
            output.Append(string.Join(", ", values));
            i = end;
        }
        return output.ToString();
    }

    public static IEnumerable<string> Placeholders(string template)
    {
        for (var i = 0; i < template.Length; i++)
        {
            if (template[i] != '{' || (i + 1 < template.Length && template[i + 1] == '{'))
            {
                if (template[i] == '{')
                    i++;
                continue;
            }
            var end = template.IndexOf('}', i + 1);
            if (end < 0)
                yield break;
            yield return template[(i + 1)..end].Trim();
            i = end;
        }
    }
}
