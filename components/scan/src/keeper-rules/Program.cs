using System.Text.Json;
using Keeper.Common;
using Keeper.Home;
using Keeper.Queue;
using Keeper.Review.Handlers;
using Keeper.Rules;
using Keeper.Scan;

// keeper-rules: validate, list and explain rule files, and load the catalogue into the store.
try
{
    var cli = new CliArgs(args, flags: ["no-tenant", "apply"]);
    if (cli.Help)
        return Usage(asked: true);
    var command = cli.At(0) ?? "list";

    if (command == "import-baseline")
        return ImportBaseline(cli);

    if (command == "validate" && cli.Positional.Count > 1)
    {
        // Explicit files or folders: no Keeper home needed - this is what rule authors run.
        var validators = Runners.Registry().Validators;
        var files = new List<RuleFile>();
        foreach (var path in cli.Positional.Skip(1).Select(Path.GetFullPath))
        {
            if (File.Exists(path))
                files.Add(RuleLoader.LoadFile(path, "file", validators));
            else
                files.AddRange(RuleLoader.LoadAll([(path, "file")], validators).Files);
        }
        var duplicates = files.SelectMany(f => f.Rules).GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).ToList();
        if (duplicates.Count > 0)
            throw new RuleException(duplicates.Select(d => $"rule id {d.Key} is defined {d.Count()} times").ToList());
        Summary(new RuleSet(files));
        return ExitCodes.Ok;
    }

    var tenant = cli.Has("no-tenant") ? null : KeeperContext.Load(cli).Paths.TenantRules;
    var rules = RuleSources.Load(tenant);
    return command switch
    {
        "validate" => Validated(rules),
        "list" => List(rules, cli.Get("system")),
        "explain" => Explain(rules, cli.At(1) ?? throw new ArgumentException("explain needs a rule id.")),
        "load" => Load(rules, cli),
        _ => Usage(),
    };
}
catch (RuleException ex)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Failed;
}
catch (Exception ex) when (ex is ArgumentException or SettingsException or IOException)
{
    Console.Error.WriteLine(ex.Message);
    return ExitCodes.Usage;
}

static void Summary(RuleSet set)
{
    foreach (var file in set.Files)
        Console.WriteLine($"{file.System,-22} {file.Rules.Count,4} rules  {Path.GetFileName(file.Path)}");
    Console.WriteLine($"OK: {set.Rules.Count()} rules in {set.Files.Count} files.");
}

static int Validated(RuleSet set)
{
    Summary(set);
    return ExitCodes.Ok;
}

static int List(RuleSet set, string? system)
{
    foreach (var rule in set.Rules.Where(r => system is null || r.System.Equals(system, StringComparison.OrdinalIgnoreCase)).OrderBy(r => r.System).ThenBy(r => r.Id))
        Console.WriteLine($"{rule.Id,-34} {rule.Severity,-8} {rule.Kind,-13} {rule.Title}");
    return ExitCodes.Ok;
}

static int Explain(RuleSet set, string id)
{
    var rule = set.Rules.FirstOrDefault(r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException($"No rule {id}.");
    Console.WriteLine($"""
        {rule.Id}  ({rule.Source}:{rule.Line})
        {rule.Title}
          system    {rule.System}
          kind      {rule.Kind}, lens {rule.Lens}, category {rule.Category}, severity {rule.Severity}{(rule.SeverityBy is null ? "" : " (varies)")}
          entity    {rule.EntityType}, refreshed every {rule.Refresh}, stale after {rule.TtlMinutes / 60} h
          query     {rule.Query.Protocol} {rule.Query.Fields.ToJsonString()} key={rule.Query.Key}
          fails     {(rule.Count is { } c ? $"count {c.Mode} {c.Op} {c.Value}{(c.Threshold is null ? "" : $" (threshold {c.Threshold})")}" : Describe(rule.Each!))}
          why       {rule.Why}
          fix       {rule.Fix}
          refs      {string.Join(", ", rule.Refs)}
        """);
    return ExitCodes.Ok;
}

static string Describe(Condition condition) => condition switch
{
    AlwaysCondition => "every row",
    LeafCondition leaf => $"{leaf.Field} {leaf.Op} {Values.Text(leaf.Value)}{(leaf.Threshold is null ? "" : $" (threshold {leaf.Threshold})")}",
    AllCondition all => "all of: " + string.Join("; ", all.Items.Select(Describe)),
    AnyCondition any => "any of: " + string.Join("; ", any.Items.Select(Describe)),
    NotCondition not => "not (" + Describe(not.Item) + ")",
    _ => condition.ToString() ?? "",
};

static int Load(RuleSet set, CliArgs cli)
{
    var (_, paths) = KeeperContext.Load(cli);
    var buildId = Iso.Stamp(DateTimeOffset.UtcNow);
    var file = Path.Combine(paths.Builds, buildId, "rules.json");
    Directory.CreateDirectory(Path.GetDirectoryName(file)!);
    var rows = set.Rules.Select(r => new RulesLoadHandler.RuleRow(r.Id, r.System, r.Title, r.Kind, r.Lens, r.Category, r.Severity,
        r.EntityType, r.Query.Protocol, (int)r.Refresh.TotalMinutes, r.Why, r.Fix, r.Refs, r.Source) { QueryId = r.Query.Id }).ToList();
    File.WriteAllText(file, JsonSerializer.Serialize(rows, JsonLines.Options));

    new RequestWriter(paths.Spool).Submit("review.rules-load", $"Rule catalogue: {rows.Count} rules", new
    {
        file = Path.GetRelativePath(paths.DataDir, file).Replace('\\', '/'),
        sha256 = Hashing.Sha256File(file),
    });
    Console.WriteLine($"Queued the catalogue of {rows.Count} rules. 'keeper qm run' applies it.");
    return ExitCodes.Ok;
}

// A baseline list (CIS via HardeningKitty, Microsoft SCT) -> a tenant rule file of registry rules.
// Dry run unless --apply; the file goes to the Keeper home's settings\rules, never the repo.
static int ImportBaseline(CliArgs cli)
{
    var csv = cli.At(1) ?? throw new ArgumentException("import-baseline needs the baseline CSV.");
    var settings = BaselineImporter.ReadCsv(csv);
    if (settings.Count == 0)
        throw new ArgumentException($"{csv} has no settings.");
    var baselineId = settings[0].BaselineId.Length > 0 ? settings[0].BaselineId : Path.GetFileNameWithoutExtension(csv);
    var name = cli.Get("name") ?? baselineId;
    var target = cli.Get("targets") ?? BaselineImporter.TargetFor(baselineId);
    var framework = cli.Get("framework") ?? (baselineId.Contains("cis", StringComparison.OrdinalIgnoreCase) ? "CIS" : "MS-Baseline");
    var import = BaselineImporter.Convert(settings, name, target, framework);

    Console.WriteLine($"{csv}: {settings.Count} settings -> {import.Rules} registry rules on {target}, {import.Queries} reads per host.");
    foreach (var group in import.Skipped.GroupBy(s => s.Reason).OrderByDescending(g => g.Count()))
        Console.WriteLine($"  skipped {group.Count(),5}: {group.Key}");

    if (import.Rules == 0)
    {
        Console.WriteLine("Nothing to import: no setting here is one the registry runner can read.");
        return ExitCodes.NoData;
    }
    var (_, paths) = KeeperContext.Load(cli);
    var file = cli.Get("out") ?? Path.Combine(paths.TenantRules, $"baseline-{string.Concat(name.ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-')).Trim('-')}.yaml");
    KeeperHome.EnsureOutsideCode(file, "The generated baseline");

    // The generated file must load like any rule file before it is kept.
    var tmp = file + ".tmp";
    Directory.CreateDirectory(Path.GetDirectoryName(file)!);
    File.WriteAllText(tmp, import.Yaml);
    try
    {
        var loaded = RuleLoader.LoadFile(tmp, "tenant", Runners.Registry().Validators);
        if (!cli.Has("apply"))
        {
            Console.WriteLine($"Dry run: {loaded.Rules.Count} rules load cleanly. Re-run with --apply to write {file}.");
            return ExitCodes.Ok;
        }
        File.Move(tmp, file, overwrite: true);
        Console.WriteLine($"Wrote {file}. 'keeper scan {loaded.System}' (or keeper run) checks it on every target host.");
        return ExitCodes.Ok;
    }
    finally
    {
        if (File.Exists(tmp))
            File.Delete(tmp);
    }
}

static int Usage(bool asked = false) =>
    CliUsage.Print("""
        keeper-rules - rule files

          keeper-rules validate [<folder>...]   check rule files (with folders: no Keeper home needed)
          keeper-rules list [--system <s>]      every rule, one line each
          keeper-rules explain <rule-id>        what a rule reads and when it fails
          keeper-rules load                     queue the catalogue for the store
          keeper-rules import-baseline <csv> [--name n] [--targets workstations|servers|members|dcs]
                                        [--framework CIS] [--out file] [--apply]
                                                a baseline list -> registry rules in the Keeper home

          --no-tenant                           built-in rules only
        """, asked);
