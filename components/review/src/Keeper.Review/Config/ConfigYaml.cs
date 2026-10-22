using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Keeper.Review.Config;

/// <summary>
/// The YAML reading and writing primitives the config files share - the same rules SystemsConfig established:
/// deterministic single-quoted scalars, parse through YamlDotNet, anchors and unknown fields refused, every
/// problem reported as file:line:column. SystemsConfig keeps its own copy (unchanged); the settings, overrides
/// and registers files are built on these.
/// </summary>
internal static partial class ConfigYaml
{
    public const string Schema = "keeper.config/1";

    /// <summary>Parses <paramref name="text"/> and returns its single document's root node, or throws.</summary>
    public static YamlNode Load(string text, string source)
    {
        var yaml = new YamlStream();
        try
        {
            yaml.Load(new StringReader(text));
        }
        catch (YamlException ex)
        {
            throw new ConfigException([$"{source}:{ex.Start.Line}:{ex.Start.Column}: {ex.Message}"]);
        }
        catch (ArgumentException ex)
        {
            throw new ConfigException([$"{source}: {ex.Message}"]);
        }
        if (yaml.Documents.Count != 1)
            throw new ConfigException([$"{source}: must hold exactly one YAML document."]);

        var errors = new List<string>();
        RefuseAnchors(yaml.Documents[0].RootNode, source, errors);
        if (errors.Count > 0)
            throw new ConfigException(errors);
        return yaml.Documents[0].RootNode;
    }

    /// <summary>The schema and optional client the top mapping declares; adds an error if the schema is wrong.</summary>
    public static void SchemaAndClient(Dictionary<string, YamlNode> top, string source, List<string> errors, out string? client)
    {
        var schema = Text(top, "schema", "file", required: true, source, errors);
        if (schema is not null && schema != Schema)
            Error(top["schema"], source, errors, $"schema must be {Schema}.");
        client = Text(top, "client", "file", required: false, source, errors);
    }

    public static Dictionary<string, YamlNode>? Fields(
        YamlNode? node, string what, IReadOnlyCollection<string> allowed, string source, List<string> errors)
    {
        if (node is not YamlMappingNode map)
        {
            if (node is not null)
                Error(node, source, errors, $"{what} must be a mapping.");
            return null;
        }
        var fields = new Dictionary<string, YamlNode>(StringComparer.Ordinal);
        foreach (var (key, value) in map.Children)
        {
            if (key is not YamlScalarNode { Value: { } name })
            {
                Error(key, source, errors, $"{what}: keys must be plain words.");
                continue;
            }
            if (!allowed.Contains(name))
            {
                Error(key, source, errors, $"{what}: unknown field '{name}'. Allowed: {string.Join(", ", allowed)}.");
                continue;
            }
            if (!fields.TryAdd(name, value))
                Error(key, source, errors, $"{what}: '{name}' appears twice.");
        }
        return fields;
    }

    public static string? Text(
        Dictionary<string, YamlNode> fields, string name, string what, bool required, string source, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
        {
            if (required)
                errors.Add($"{source}: {what} is missing '{name}'.");
            return null;
        }
        if (node is YamlScalarNode { Value: { } value })
            return value;
        Error(node, source, errors, $"{what}: '{name}' must be a single value.");
        return null;
    }

    /// <summary>A long from a scalar field; adds an error and returns null if it is not a whole number.</summary>
    public static long? Integer(Dictionary<string, YamlNode> fields, string name, string what, string source, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return null;
        if (node is YamlScalarNode { Value: { } value }
            && long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number))
            return number;
        Error(node, source, errors, $"{what}: '{name}' must be a whole number.");
        return null;
    }

    /// <summary>A double from a scalar field; adds an error and returns null if it is not a number.</summary>
    public static double? Real(Dictionary<string, YamlNode> fields, string name, string what, string source, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return null;
        if (node is YamlScalarNode { Value: { } value }
            && double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number))
            return number;
        Error(node, source, errors, $"{what}: '{name}' must be a number.");
        return null;
    }

    /// <summary>A bool from a scalar field; adds an error and returns null if it is not true or false.</summary>
    public static bool? Boolean(Dictionary<string, YamlNode> fields, string name, string what, string source, List<string> errors)
    {
        if (!fields.TryGetValue(name, out var node))
            return null;
        if (node is YamlScalarNode { Value: "true" or "false" } boolean)
            return boolean.Value == "true";
        Error(node, source, errors, $"{what}: '{name}' must be true or false.");
        return null;
    }

    private static void RefuseAnchors(YamlNode node, string source, List<string> errors)
    {
        if (!node.Anchor.IsEmpty)
        {
            Error(node, source, errors, "anchors and aliases are not allowed in config files.");
            return;
        }
        switch (node)
        {
            case YamlMappingNode map:
                foreach (var (key, value) in map.Children)
                {
                    RefuseAnchors(key, source, errors);
                    RefuseAnchors(value, source, errors);
                }
                break;
            case YamlSequenceNode sequence:
                foreach (var item in sequence.Children)
                    RefuseAnchors(item, source, errors);
                break;
        }
    }

    public static void Error(YamlNode node, string source, List<string> errors, string message) =>
        errors.Add($"{source}:{node.Start.Line}:{node.Start.Column}: {message}");

    /// <summary>A value safe to write without quotes - a plain lower-case word.</summary>
    public static bool Bareable(string value) => BareWord().IsMatch(value);

    /// <summary>A number formatted so it round-trips: no culture separators, no exponent surprises.</summary>
    public static string Number(double value) => value.ToString("R", CultureInfo.InvariantCulture);

    /// <summary>
    /// Single-quoted (<c>''</c> escapes a quote) for the common one-line value, matching SystemsConfig;
    /// double-quoted with escapes when the value holds a newline or tab, so every value round-trips.
    /// </summary>
    public static string Quote(string value)
    {
        if (value.IndexOfAny(['\n', '\r', '\t']) < 0)
            return "'" + value.Replace("'", "''") + "'";
        var sb = new StringBuilder("\"");
        foreach (var c in value)
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ => c.ToString(),
            });
        return sb.Append('"').ToString();
    }

    [GeneratedRegex("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex BareWord();
}
