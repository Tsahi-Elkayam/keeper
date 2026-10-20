using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Keeper.Common;
using Keeper.Contracts;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Keeper.Rules;

/// <summary>Checks a query's protocol-specific fields; returns the problems (none = valid).</summary>
public delegate IEnumerable<string> QueryValidator(QuerySpec query);

/// <summary>
/// Loads and validates rule files. Everything is checked before anything runs: vocabulary, ids,
/// conditions, regular expressions, templates, and each query against its protocol's runner.
/// </summary>
public static partial class RuleLoader
{
    public const string Schema = "keeper.rules/1";
    public const long MaxFileBytes = 1024 * 1024;

    private static readonly string[] FileFields = ["schema", "system", "name", "integration", "defaults", "targets", "rules"];
    private static readonly string[] DefaultFields = ["kind", "lens", "category", "severity", "refresh", "entity"];
    private static readonly string[] TargetFields = ["entity", "where", "field", "list"];
    private static readonly string[] RuleFields =
        ["id", "title", "kind", "lens", "category", "severity", "entity", "why", "fix", "refs", "refresh", "query", "each", "count", "evidence", "deadline", "emit"];
    private static readonly string[] EmitFields = ["check", "title", "kind", "category", "severity"];
    private static readonly string[] SeverityMapFields = ["field", "daysLeft", "ranges", "map", "default"];
    private static readonly string[] RangeFields = ["min", "max", "value"];

    public static RuleSet LoadAll(IEnumerable<(string Directory, string Origin)> folders, IReadOnlyDictionary<string, QueryValidator>? protocols)
    {
        var errors = new List<string>();
        var files = new List<RuleFile>();
        foreach (var (directory, origin) in folders)
        {
            if (!Directory.Exists(directory))
                continue;
            foreach (var path in Directory.GetFiles(directory, "*.yaml").Concat(Directory.GetFiles(directory, "*.yml")).Order(StringComparer.OrdinalIgnoreCase))
            {
                var file = Parse(path, origin, protocols, errors);
                if (file is not null)
                    files.Add(file);
            }
        }

        var seen = new Dictionary<string, Rule>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in files.SelectMany(f => f.Rules))
        {
            if (!seen.TryAdd(rule.Id, rule))
                errors.Add($"{rule.Source}:{rule.Line}: rule id {rule.Id} is already defined at {seen[rule.Id].Source}:{seen[rule.Id].Line}.");
        }
        if (errors.Count > 0)
            throw new RuleException(errors);
        return new RuleSet(files);
    }

    public static RuleFile LoadFile(string path, string origin, IReadOnlyDictionary<string, QueryValidator>? protocols)
    {
        var errors = new List<string>();
        var file = Parse(path, origin, protocols, errors);
        if (errors.Count > 0 || file is null)
            throw new RuleException(errors.Count > 0 ? errors : [$"{path}: could not be read."]);
        return file;
    }

    private static RuleFile? Parse(string path, string origin, IReadOnlyDictionary<string, QueryValidator>? protocols, List<string> errors)
    {
        var source = $"{origin}:{Path.GetFileName(path)}";
        var info = new FileInfo(path);
        if (info.Length > MaxFileBytes)
        {
            errors.Add($"{source}: larger than {MaxFileBytes / 1024} KB.");
            return null;
        }

        var yaml = new YamlStream();
        try
        {
            yaml.Load(new StringReader(File.ReadAllText(path)));
        }
        catch (YamlException ex)
        {
            errors.Add($"{source}:{ex.Start.Line}:{ex.Start.Column}: {ex.Message}");
            return null;
        }
        catch (ArgumentException ex)
        {
            errors.Add($"{source}: {ex.Message}");
            return null;
        }
        if (yaml.Documents.Count != 1)
        {
            errors.Add($"{source}: must hold exactly one YAML document.");
            return null;
        }

        var reader = new YamlReader(source, errors);
        var root = yaml.Documents[0].RootNode;
        var before = errors.Count;
        reader.RefuseAnchors(root);
        if (errors.Count > before)
            return null;

        var top = reader.Fields(root, "file", FileFields);
        if (top is null)
            return null;

        var schema = reader.Text(top, "schema", "file", required: true);
        if (schema is not null && schema != Schema)
            reader.Error(top["schema"], $"schema must be {Schema}.");

        var system = reader.Text(top, "system", "file", required: true) ?? "";
        if (!SystemId().IsMatch(system))
            reader.Error($"system '{system}' must be lower-case letters, digits and dashes.");
        var name = reader.Text(top, "name", "file") ?? system;
        var integration = reader.Text(top, "integration", "file", required: true) ?? "";
        if (!SystemId().IsMatch(integration))
            reader.Error($"integration '{integration}' must be lower-case letters, digits and dashes.");

        var defaults = top.TryGetValue("defaults", out var defaultsNode) ? reader.Fields(defaultsNode, "defaults", DefaultFields) : null;
        TargetSpec? targets = null;
        if (top.TryGetValue("targets", out var targetsNode) && reader.Fields(targetsNode, "targets", TargetFields) is { } t)
        {
            targets = new TargetSpec(
                reader.Text(t, "entity", "targets"),
                t.TryGetValue("where", out var where) ? ReadCondition(reader, where, "targets.where") : null,
                reader.Text(t, "field", "targets"),
                reader.Strings(t, "list", "targets"));
            if (targets.List.Count == 0 && (targets.Entity is null || targets.Field is null))
                reader.Error(targetsNode, "targets needs either list, or entity and field.");
        }

        var rules = new List<Rule>();
        if (!top.TryGetValue("rules", out var rulesNode) || rulesNode is not YamlSequenceNode sequence || sequence.Children.Count == 0)
        {
            reader.Error("rules must be a non-empty list.");
        }
        else
        {
            foreach (var node in sequence.Children)
            {
                var rule = ReadRule(reader, node, system, defaults, source, protocols);
                if (rule is not null)
                    rules.Add(rule);
            }
        }

        return errors.Count > before ? null : new RuleFile(system, name, integration, targets, rules, path, origin, Hashing.Sha256File(path));
    }

    private static Rule? ReadRule(YamlReader reader, YamlNode node, string system, Dictionary<string, YamlNode>? defaults,
        string source, IReadOnlyDictionary<string, QueryValidator>? protocols)
    {
        var fields = reader.Fields(node, "rule", RuleFields);
        if (fields is null)
            return null;

        var id = reader.Text(fields, "id", "rule", required: true) ?? "";
        var what = $"rule {id}";
        if (!RuleId().IsMatch(id))
            reader.Error(node, $"{what}: id must be letters, digits, dots, dashes or underscores (at most 100).");

        string Pick(string field, string? fallback)
        {
            var value = reader.Text(fields, field, what) ?? (defaults is not null ? reader.Text(defaults, field, "defaults") : null) ?? fallback;
            if (value is null)
                reader.Error(node, $"{what}: '{field}' is required (here or in defaults).");
            return value ?? "";
        }

        var kind = Pick("kind", null);
        var lens = Pick("lens", "both");
        var category = Pick("category", null);
        var entity = Pick("entity", null);
        var refreshText = Pick("refresh", "1d");
        RequireIn(reader, node, what, "kind", kind, Vocabulary.Kinds);
        RequireIn(reader, node, what, "lens", lens, Vocabulary.Lenses);
        RequireIn(reader, node, what, "category", category, Vocabulary.Categories);
        if (!Durations.TryParse(refreshText, out var refresh))
            reader.Error(node, $"{what}: refresh '{refreshText}' must be a duration such as 30m, 6h, 1d or 7d.");

        // severity: a word, or a map (by days left, by a numeric field, by a text field)
        string severity = "medium";
        SeverityMap? severityBy = null;
        if (fields.TryGetValue("severity", out var severityNode))
        {
            if (severityNode is YamlScalarNode { Value: { } word })
            {
                severity = word;
                RequireIn(reader, severityNode, what, "severity", word, Vocabulary.Severities);
            }
            else
            {
                severityBy = ReadSeverityMap(reader, severityNode, what);
                severity = severityBy?.Default ?? "medium";
            }
        }
        else if (defaults is not null && reader.Text(defaults, "severity", "defaults") is { } fromDefaults)
        {
            severity = fromDefaults;
            RequireIn(reader, node, what, "severity", severity, Vocabulary.Severities);
        }
        else
        {
            reader.Error(node, $"{what}: 'severity' is required (here or in defaults).");
        }

        var query = ReadQuery(reader, fields, what, protocols);

        Condition? each = null;
        CountCondition? count = null;
        var hasEach = fields.TryGetValue("each", out var eachNode);
        var hasCount = fields.TryGetValue("count", out var countNode);
        if (hasEach == hasCount)
            reader.Error(node, $"{what}: needs exactly one of 'each' or 'count'.");
        if (hasEach)
            each = eachNode is YamlScalarNode { Value: "any" } ? AlwaysCondition.Instance : ReadCondition(reader, eachNode!, $"{what}.each");
        if (hasCount)
            count = ReadCount(reader, countNode!, what);

        var evidence = reader.Text(fields, "evidence", what);
        var deadline = reader.Text(fields, "deadline", what);
        Emit? emit = null;
        if (fields.TryGetValue("emit", out var emitNode) && reader.Fields(emitNode, $"{what}.emit", EmitFields) is { } e)
        {
            var emitKind = reader.Text(e, "kind", what);
            var emitCategory = reader.Text(e, "category", what);
            if (emitKind is not null)
                RequireIn(reader, emitNode, what, "emit.kind", emitKind, Vocabulary.Kinds);
            if (emitCategory is not null)
                RequireIn(reader, emitNode, what, "emit.category", emitCategory, Vocabulary.Categories);
            emit = new Emit(reader.Text(e, "check", what), reader.Text(e, "title", what), emitKind, emitCategory,
                e.TryGetValue("severity", out var emitSeverity) ? ReadSeverityMap(reader, emitSeverity, $"{what}.emit") : null);
        }

        var title = reader.Text(fields, "title", what, required: true) ?? "";
        return new Rule
        {
            Id = id,
            System = system,
            Title = title,
            Kind = kind,
            Lens = lens,
            Category = category,
            Severity = severity,
            EntityType = entity,
            Why = reader.Text(fields, "why", what),
            Fix = reader.Text(fields, "fix", what),
            Refs = Refs.Normalize(reader.Strings(fields, "refs", what)),
            Refresh = refresh,
            Query = query ?? new QuerySpec("invalid", new JsonObject(), "-", null),
            Each = each,
            Count = count,
            Evidence = evidence,
            Deadline = deadline,
            SeverityBy = severityBy,
            Emit = emit,
            Source = source,
            Line = reader.Line(node),
        };
    }

    private static QuerySpec? ReadQuery(YamlReader reader, Dictionary<string, YamlNode> fields, string what,
        IReadOnlyDictionary<string, QueryValidator>? protocols)
    {
        if (!fields.TryGetValue("query", out var node))
        {
            reader.Error($"{what}: 'query' is required.");
            return null;
        }
        var map = reader.Fields(node, $"{what}.query", null);
        if (map is null)
            return null;

        var protocol = reader.Text(map, "protocol", $"{what}.query", required: true) ?? "";
        var key = reader.Text(map, "key", $"{what}.query", required: true) ?? "";
        var name = reader.Text(map, "name", $"{what}.query");
        var json = new JsonObject();
        foreach (var (field, value) in map.Where(f => f.Key is not ("protocol" or "key" or "name")))
            json[field] = YamlReader.ToJson(value);

        var query = new QuerySpec(protocol, json, key, name);
        if (protocols is not null)
        {
            if (!protocols.TryGetValue(protocol, out var validate))
                reader.Error(node, $"{what}: unknown protocol '{protocol}'. Known: {string.Join(", ", protocols.Keys.Order())}.");
            else
                foreach (var problem in validate(query))
                    reader.Error(node, $"{what}.query: {problem}");
        }
        return query;
    }

    private static Condition? ReadCondition(YamlReader reader, YamlNode node, string what)
    {
        if (node is YamlMappingNode map && map.Children.Count == 1 && map.Children.First().Key is YamlScalarNode { Value: "all" or "any" or "not" } combinator)
        {
            var inner = map.Children.First().Value;
            if (combinator.Value == "not")
                return ReadCondition(reader, inner, $"{what}.not") is { } negated ? new NotCondition(negated) : null;
            if (inner is not YamlSequenceNode list || list.Children.Count == 0)
            {
                reader.Error(inner, $"{what}.{combinator.Value} must be a non-empty list of conditions.");
                return null;
            }
            var items = list.Children.Select((c, i) => ReadCondition(reader, c, $"{what}.{combinator.Value}[{i}]")).ToList();
            if (items.Any(i => i is null))
                return null;
            return combinator.Value == "all" ? new AllCondition(items!) : new AnyCondition(items!);
        }

        var fields = reader.Fields(node, what, ["field", "op", "value", "threshold"]);
        if (fields is null)
            return null;
        var field = reader.Text(fields, "field", what, required: true);
        var op = reader.Text(fields, "op", what, required: true);
        if (field is null || op is null)
            return null;
        if (!Evaluator.Ops.Contains(op))
        {
            reader.Error(node, $"{what}: unknown op '{op}'. Known: {string.Join(", ", Evaluator.Ops.Order())}.");
            return null;
        }

        var value = fields.TryGetValue("value", out var valueNode) ? YamlReader.ToJson(valueNode) : null;
        if (value is null && !Evaluator.OpsWithoutValue.Contains(op))
            reader.Error(node, $"{what}: op '{op}' needs a value.");

        // value: { field: other } compares two fields of the same row; times / plus scale it (90% of the total).
        if (value is JsonObject reference)
        {
            foreach (var key in reference.Select(p => p.Key).Where(k => k is not ("field" or "times" or "plus")))
                reader.Error(node, $"{what}: value: {{ {key}: ... }} - a field reference takes field, times and plus only.");
            if (Values.Text(reference["field"]) is not { Length: > 0 })
                reader.Error(node, $"{what}: value: {{ field: <name> }} needs the field to compare with.");
            foreach (var key in new[] { "times", "plus" })
            {
                if (reference[key] is { } n && !Values.TryNumber(Values.Text(n), out _))
                    reader.Error(node, $"{what}: value.{key} must be a number.");
            }
            return new LeafCondition(field, op, value, reader.Text(fields, "threshold", what));
        }
        if (op is "match" or "notmatch" && Values.Text(value) is { } pattern)
        {
            try
            {
                _ = Evaluator.RegexFor(pattern);
            }
            catch (ArgumentException ex)
            {
                reader.Error(node, $"{what}: not a valid regular expression: {ex.Message}");
            }
        }
        if (op is "gt" or "ge" or "lt" or "le" or "age-gt" or "age-lt" or "until-lt" or "flag" or "noflag" or "size-gt" or "size-lt" or "size-eq"
            && !Values.TryNumber(Values.Text(value), out _))
            reader.Error(node, $"{what}: op '{op}' needs a number.");

        var threshold = reader.Text(fields, "threshold", what);
        if (threshold is not null && !ThresholdName().IsMatch(threshold))
            reader.Error(node, $"{what}: threshold '{threshold}' must be lower-case letters, digits, dots and dashes.");
        return new LeafCondition(field, op, value, threshold);
    }

    private static CountCondition? ReadCount(YamlReader reader, YamlNode node, string what)
    {
        if (node is YamlScalarNode { Value: "none" or "some" } mode)
            return new CountCondition(mode.Value!, null, 0, null);

        var fields = reader.Fields(node, $"{what}.count", ["op", "value", "threshold", "where"]);
        if (fields is null)
            return null;
        var where = fields.TryGetValue("where", out var whereNode) ? ReadCondition(reader, whereNode, $"{what}.count.where") : null;
        var op = reader.Text(fields, "op", $"{what}.count", required: true) ?? "";
        if (op is not ("gt" or "ge" or "lt" or "le" or "eq" or "ne"))
            reader.Error(node, $"{what}.count: op must be gt, ge, lt, le, eq or ne.");
        var valueText = reader.Text(fields, "value", $"{what}.count", required: true);
        if (!double.TryParse(valueText, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            reader.Error(node, $"{what}.count: value must be a number.");
        var threshold = reader.Text(fields, "threshold", $"{what}.count");
        if (threshold is not null && !ThresholdName().IsMatch(threshold))
            reader.Error(node, $"{what}.count: threshold '{threshold}' must be lower-case letters, digits, dots and dashes.");
        return new CountCondition("compare", op, value, threshold, where);
    }

    private static SeverityMap? ReadSeverityMap(YamlReader reader, YamlNode node, string what)
    {
        var fields = reader.Fields(node, $"{what}.severity", SeverityMapFields);
        if (fields is null)
            return null;

        var field = reader.Text(fields, "field", what);
        var daysLeft = reader.Text(fields, "daysLeft", what);
        if ((field is null) == (daysLeft is null))
            reader.Error(node, $"{what}.severity: needs exactly one of 'field' or 'daysLeft'.");

        var ranges = new List<SeverityRange>();
        if (fields.TryGetValue("ranges", out var rangesNode))
        {
            if (rangesNode is not YamlSequenceNode list)
            {
                reader.Error(rangesNode, $"{what}.severity.ranges must be a list.");
            }
            else
            {
                foreach (var item in list.Children)
                {
                    if (reader.Fields(item, $"{what}.severity.ranges", RangeFields) is not { } r)
                        continue;
                    double? Number(string name) =>
                        reader.Text(r, name, what) is { } t && double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : null;
                    var value = reader.Text(r, "value", what, required: true) ?? "";
                    RequireIn(reader, item, what, "severity.ranges.value", value, Vocabulary.Severities);
                    ranges.Add(new SeverityRange(Number("min"), Number("max"), value));
                }
            }
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (fields.TryGetValue("map", out var mapNode) && reader.Fields(mapNode, $"{what}.severity.map", null) is { } m)
        {
            foreach (var (text, valueNode) in m)
            {
                if (valueNode is YamlScalarNode { Value: { } severity })
                {
                    RequireIn(reader, valueNode, what, "severity.map", severity, Vocabulary.Severities);
                    values[text] = severity;
                }
            }
        }
        if (ranges.Count == 0 && values.Count == 0)
            reader.Error(node, $"{what}.severity: needs 'ranges' or 'map'.");
        if (daysLeft is not null && ranges.Any(r => r.Max is null))
            reader.Error(node, $"{what}.severity: ranges over daysLeft use 'max' (days left at most).");

        var @default = reader.Text(fields, "default", what, required: true) ?? "medium";
        RequireIn(reader, node, what, "severity.default", @default, Vocabulary.Severities);
        return new SeverityMap(field, daysLeft, ranges, values, @default);
    }

    private static void RequireIn(YamlReader reader, YamlNode node, string what, string field, string value, IReadOnlySet<string> allowed)
    {
        if (value.Length > 0 && !allowed.Contains(value))
            reader.Error(node, $"{what}: {field} '{value}' must be one of {string.Join(", ", allowed)}.");
    }

    [GeneratedRegex("^[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SystemId();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex RuleId();

    [GeneratedRegex("^[a-z][a-z0-9.-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex ThresholdName();
}
