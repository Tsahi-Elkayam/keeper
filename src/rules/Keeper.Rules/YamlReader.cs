using System.Text.Json.Nodes;
using YamlDotNet.RepresentationModel;

namespace Keeper.Rules;

/// <summary>
/// Reads YAML nodes strictly: every error carries file:line:column, unknown fields are refused, and
/// anchors/aliases are refused (no expansion tricks in a file that directs queries).
/// </summary>
internal sealed class YamlReader(string file, List<string> errors)
{
    public void Error(YamlNode node, string message) =>
        errors.Add($"{file}:{node.Start.Line}:{node.Start.Column}: {message}");

    public void Error(string message) => errors.Add($"{file}: {message}");

    public int Line(YamlNode node) => (int)node.Start.Line;

    public void RefuseAnchors(YamlNode node)
    {
        if (!node.Anchor.IsEmpty)
        {
            Error(node, "anchors and aliases are not allowed in rule files.");
            return;
        }
        switch (node)
        {
            case YamlMappingNode map:
                foreach (var (key, value) in map.Children)
                {
                    RefuseAnchors(key);
                    RefuseAnchors(value);
                }
                break;
            case YamlSequenceNode sequence:
                foreach (var item in sequence.Children)
                    RefuseAnchors(item);
                break;
        }
    }

    public Dictionary<string, YamlNode>? Fields(YamlNode? node, string what, IReadOnlyCollection<string>? allowed)
    {
        if (node is not YamlMappingNode map)
        {
            if (node is not null)
                Error(node, $"{what} must be a mapping.");
            return null;
        }
        var fields = new Dictionary<string, YamlNode>(StringComparer.Ordinal);
        foreach (var (key, value) in map.Children)
        {
            if (key is not YamlScalarNode { Value: { } name })
            {
                Error(key, $"{what}: keys must be plain words.");
                continue;
            }
            if (allowed is not null && !allowed.Contains(name))
            {
                Error(key, $"{what}: unknown field '{name}'. Allowed: {string.Join(", ", allowed)}.");
                continue;
            }
            if (!fields.TryAdd(name, value))
                Error(key, $"{what}: '{name}' appears twice.");
        }
        return fields;
    }

    public string? Text(Dictionary<string, YamlNode> fields, string name, string what, bool required = false)
    {
        if (!fields.TryGetValue(name, out var node))
        {
            if (required)
                Error($"{what}: '{name}' is required.");
            return null;
        }
        if (node is YamlScalarNode { Value: { } value })
            return value;
        Error(node, $"{what}: '{name}' must be a single value.");
        return null;
    }

    public List<string> Strings(Dictionary<string, YamlNode> fields, string name, string what)
    {
        if (!fields.TryGetValue(name, out var node))
            return [];
        if (node is YamlScalarNode { Value: { } single })
            return [single];
        if (node is YamlSequenceNode sequence)
        {
            var list = new List<string>();
            foreach (var item in sequence.Children)
            {
                if (item is YamlScalarNode { Value: { } value })
                    list.Add(value);
                else
                    Error(item, $"{what}: '{name}' must be a list of values.");
            }
            return list;
        }
        Error(node, $"{what}: '{name}' must be a list of values.");
        return [];
    }

    /// <summary>Converts a node to JSON. Scalars stay text; conditions and runners parse numbers themselves.</summary>
    public static JsonNode? ToJson(YamlNode node) => node switch
    {
        YamlScalarNode scalar => scalar.Value is null ? null : JsonValue.Create(scalar.Value),
        YamlSequenceNode sequence => new JsonArray(sequence.Children.Select(ToJson).ToArray()),
        YamlMappingNode map => new JsonObject(map.Children
            .Where(c => c.Key is YamlScalarNode { Value: not null })
            .Select(c => KeyValuePair.Create(((YamlScalarNode)c.Key).Value!, ToJson(c.Value)))),
        _ => null,
    };
}
