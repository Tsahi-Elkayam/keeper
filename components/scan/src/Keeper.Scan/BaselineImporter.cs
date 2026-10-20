using System.Globalization;
using System.Text;

namespace Keeper.Scan;

/// <summary>One setting of a hardening baseline, as the baseline lists (CIS via HardeningKitty, Microsoft SCT) export them.</summary>
public sealed record BaselineSetting(string BaselineId, string Scope, string SettingType, string Path, string Name, string Expected,
    string Operator, string Severity, string Title, string Reference);

public sealed record BaselineImport(string Yaml, int Rules, int Queries, IReadOnlyList<(BaselineSetting Setting, string Reason)> Skipped);

/// <summary>
/// Turns a baseline list into a rule file: every registry setting becomes a registry rule on every target
/// host, the settings of one key share one read. The generated file belongs to the tenant (the baseline's
/// titles are the publisher's text), so it is written to the Keeper home's settings\rules, never the repo.
/// A setting that is not configured is a finding: a baseline counts "not set" as not compliant.
/// </summary>
public static class BaselineImporter
{
    public static readonly IReadOnlyList<string> Targets = ["workstations", "servers", "members", "dcs"];

    public static IReadOnlyList<BaselineSetting> ReadCsv(string file)
    {
        var lines = Csv(File.ReadAllText(file)).ToList();
        if (lines.Count == 0)
            return [];
        var header = lines[0].Select((h, i) => (h.Trim(), i)).ToDictionary(x => x.Item1, x => x.i, StringComparer.OrdinalIgnoreCase);
        string Get(IReadOnlyList<string> row, string column) =>
            header.TryGetValue(column, out var i) && i < row.Count ? row[i].Trim() : "";
        foreach (var required in new[] { "SettingType", "Path", "Name", "Expected", "Operator" })
        {
            if (!header.ContainsKey(required))
                throw new ArgumentException($"{file}: the baseline has no {required} column.");
        }
        return lines.Skip(1).Where(r => r.Count > 1)
            .Select(r => new BaselineSetting(Get(r, "BaselineId"), Get(r, "Scope"), Get(r, "SettingType"), Get(r, "Path"), Get(r, "Name"),
                Get(r, "Expected"), Get(r, "Operator"), Get(r, "Severity"), Get(r, "Title"), Get(r, "Reference")))
            .ToList();
    }

    public static string TargetFor(string baselineId)
    {
        var id = baselineId.ToLowerInvariant();
        if (!id.Contains("server", StringComparison.Ordinal))
            return "workstations";
        if (id.Contains("_dc", StringComparison.Ordinal) || id.Contains("-dc", StringComparison.Ordinal))
            return "dcs";
        return id.Contains("member", StringComparison.Ordinal) ? "members" : "servers";
    }

    public static BaselineImport Convert(IReadOnlyList<BaselineSetting> settings, string name, string target, string framework)
    {
        if (!Targets.Contains(target))
            throw new ArgumentException($"--targets must be one of {string.Join(", ", Targets)}.");
        var prefix = "BL-" + string.Concat(name.ToUpperInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-'));

        var skipped = new List<(BaselineSetting, string)>();
        var usable = new List<(BaselineSetting Setting, string Hive, string Key)>();
        foreach (var s in settings)
        {
            if (!s.SettingType.Equals("Registry", StringComparison.OrdinalIgnoreCase))
                skipped.Add((s, $"{(s.SettingType.Length == 0 ? "no setting type" : s.SettingType)}: not a registry setting"));
            else if (s.Scope.Equals("User", StringComparison.OrdinalIgnoreCase))
                skipped.Add((s, "a per-user setting (HKCU) - read per machine only"));
            else if (Split(s.Path) is not { } where)
                skipped.Add((s, "not under HKLM"));
            else if (s.Name.Length == 0 || s.Name.IndexOfAny(['.', '[', ']', '{', '}', '\'', '"', '\\']) >= 0)
                skipped.Add((s, "a value name rules cannot address"));
            else if (where.Key.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is ' ' or '_' or '.' or '(' or ')' or '-' or '{' or '}' or '\\')))
                skipped.Add((s, "a key path the registry runner refuses"));
            else if (Condition(s) is null)
                skipped.Add((s, $"operator '{s.Operator}' is not one this import understands"));
            else
                usable.Add((s, where.Hive, where.Key));
        }

        // One read per key: every rule on a key asks for the same values, so they share the fetch.
        var valuesByKey = usable.GroupBy(u => (u.Hive, u.Key.ToLowerInvariant()))
            .ToDictionary(g => g.Key, g => g.Select(u => u.Setting.Name).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList());

        var yaml = new StringBuilder();
        yaml.AppendLine("schema: keeper.rules/1");
        yaml.AppendLine($"system: baseline-{Slug(name)}");
        yaml.AppendLine($"name: {Q($"Baseline {name} (imported from {settings.FirstOrDefault()?.BaselineId ?? name})")}");
        yaml.AppendLine("integration: cim");
        yaml.AppendLine($"# Generated by 'keeper rules import-baseline' on {DateTime.UtcNow:yyyy-MM-dd}. Re-import to change it; edits here are overwritten.");
        yaml.AppendLine("targets:");
        yaml.AppendLine("  entity: computer");
        yaml.AppendLine("  field: dNSHostName");
        yaml.AppendLine("  where:");
        yaml.AppendLine("    all:");
        foreach (var line in TargetConditions(target))
            yaml.AppendLine($"      - {line}");
        yaml.AppendLine("defaults:");
        yaml.AppendLine("  lens: security");
        yaml.AppendLine("  refresh: 7d");
        yaml.AppendLine("  entity: computer");
        yaml.AppendLine("rules:");

        var number = 0;
        foreach (var (s, hive, key) in usable)
        {
            var values = valuesByKey[(hive, key.ToLowerInvariant())];
            var reference = s.Reference.Length == 0 ? null : $"{framework}:{StripPrefix(s.Reference)}";
            yaml.AppendLine($"  - id: {prefix}-{++number:D4}");
            yaml.AppendLine($"    title: {Q(s.Title.Length > 0 ? s.Title : $"{s.Path}\\{s.Name}")}");
            yaml.AppendLine("    kind: misconfigured");
            yaml.AppendLine("    category: CFG");
            yaml.AppendLine($"    severity: {Severity(s.Severity)}");
            yaml.AppendLine($"    why: {Q($"Baseline {s.BaselineId} expects {s.Path}\\{s.Name} {Describe(s)}. Not set counts as not compliant.")}");
            yaml.AppendLine($"    fix: {Q($"Set {s.Path}\\{s.Name} to {s.Expected} through the group policy (or MDM profile) that applies the baseline, then let policy refresh.")}");
            if (reference is not null)
                yaml.AppendLine($"    refs: [{Q(reference)}]");
            yaml.AppendLine($"    query: {{ protocol: registry, hive: {hive}, path: {Q(key)}, values: [{string.Join(", ", values.Select(Q))}], key: host }}");
            yaml.AppendLine($"    each: {Condition(s)}");
            yaml.AppendLine($"    evidence: {Q($"{{host}}: {s.Name} is {{{s.Name}}} (expected {Describe(s)})")}");
        }
        return new BaselineImport(yaml.ToString(), number, valuesByKey.Count, skipped);
    }

    private static IEnumerable<string> TargetConditions(string target) => target switch
    {
        "workstations" => ["{ field: operatingSystem, op: notmatch, value: Server }", "{ field: lastLogonTimestamp, op: age-lt, value: 30 }"],
        "servers" => ["{ field: operatingSystem, op: match, value: Server }", "{ field: lastLogonTimestamp, op: age-lt, value: 30 }"],
        "members" => ["{ field: operatingSystem, op: match, value: Server }", "{ field: userAccountControl, op: noflag, value: 8192 }",
                      "{ field: lastLogonTimestamp, op: age-lt, value: 30 }"],
        _ => ["{ field: userAccountControl, op: flag, value: 8192 }", "{ field: lastLogonTimestamp, op: age-lt, value: 30 }"],
    };

    /// <summary>The fail-when condition for one setting, or null for an operator this import does not understand.</summary>
    public static string? Condition(BaselineSetting s)
    {
        var field = Q(s.Name);
        var expected = Q(s.Expected);
        string Absent() => $"{{ field: {field}, op: absent }}";
        return s.Operator.Trim() switch
        {
            "=" or "==" => $"{{ any: [ {Absent()}, {{ field: {field}, op: ne, value: {expected} }} ] }}",
            "!=" => $"{{ field: {field}, op: eq, value: {expected} }}",
            ">=" => $"{{ any: [ {Absent()}, {{ field: {field}, op: lt, value: {expected} }} ] }}",
            "<=" => $"{{ any: [ {Absent()}, {{ field: {field}, op: gt, value: {expected} }} ] }}",
            "=|0" => $"{{ any: [ {Absent()}, {{ field: {field}, op: notin, value: [{expected}, '0'] }} ] }}",
            "<=!0" => $"{{ any: [ {Absent()}, {{ field: {field}, op: gt, value: {expected} }}, {{ field: {field}, op: eq, value: '0' }} ] }}",
            "contains" => $"{{ any: [ {Absent()}, {{ field: {field}, op: notcontains, value: {expected} }} ] }}",
            "absent" => $"{{ field: {field}, op: exists }}",
            "set" => Absent(),
            _ => null,
        };
    }

    private static string Describe(BaselineSetting s) => s.Operator.Trim() switch
    {
        "=" or "==" => $"= {s.Expected}",
        "!=" => $"not {s.Expected}",
        ">=" => $">= {s.Expected}",
        "<=" => $"<= {s.Expected}",
        "=|0" => $"{s.Expected} or 0",
        "<=!0" => $"<= {s.Expected} and not 0",
        "contains" => $"to contain {s.Expected}",
        "absent" => "not to be set",
        "set" => "to be set",
        _ => $"{s.Operator} {s.Expected}",
    };

    private static (string Hive, string Key)? Split(string path)
    {
        foreach (var prefix in new[] { @"HKLM\", @"HKEY_LOCAL_MACHINE\", @"HKLM:\" })
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && path.Length > prefix.Length)
            {
                // Published lists carry typos such as HKLM\\SOFTWARE: empty segments are dropped.
                var key = string.Join('\\', path[prefix.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries));
                return key.Length == 0 ? null : ("HKLM", key);
            }
        }
        return null;
    }

    private static string Severity(string severity) => severity.Trim().ToLowerInvariant() switch
    {
        "critical" => "critical",
        "high" => "high",
        "low" => "low",
        "info" or "informational" => "info",
        _ => "medium",
    };

    /// <summary>"CIS.1.1.6" -> "1.1.6": the list's own prefix repeats the framework the ref is filed under.</summary>
    private static string StripPrefix(string reference)
    {
        var dot = reference.IndexOf('.', StringComparison.Ordinal);
        return dot > 0 && reference[..dot].All(char.IsAsciiLetter) && dot + 1 < reference.Length ? reference[(dot + 1)..] : reference;
    }

    private static string Slug(string text) =>
        string.Concat(text.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-')).Trim('-');

    /// <summary>A YAML single-quoted scalar: nothing inside is interpreted.</summary>
    private static string Q(string text) => "'" + text.Replace("'", "''", StringComparison.Ordinal).ReplaceLineEndings(" ") + "'";

    /// <summary>RFC 4180 CSV: quoted fields, doubled quotes, line breaks inside quotes.</summary>
    private static IEnumerable<List<string>> Csv(string text)
    {
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else field.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { row.Add(field.ToString()); field.Clear(); }
            else if (c is '\r') { }
            else if (c == '\n') { row.Add(field.ToString()); field.Clear(); yield return row; row = []; }
            else field.Append(c);
        }
        if (field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            yield return row;
        }
    }
}
