using System.Text.Json.Nodes;

namespace Keeper.Rules;

/// <summary>
/// Row field paths: "a.b.c", and "a[].b" to take b from every element of the array a. A path that is
/// missing anywhere gives no values. Property names match case-insensitively.
/// </summary>
public static class FieldPath
{
    public static IReadOnlyList<JsonNode?> Resolve(JsonNode? root, string path)
    {
        IEnumerable<JsonNode?> current = [root];
        foreach (var part in path.Split('.'))
        {
            var flatten = part.EndsWith("[]", StringComparison.Ordinal);
            var name = flatten ? part[..^2] : part;
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
