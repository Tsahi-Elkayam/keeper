using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Keeper.Common;
using Keeper.Review.Cli;
using Keeper.Review.Handlers;
using Keeper.Store;

// keeper-register: the registers people keep - vendors, contracts, licences, key dates, initiatives.
// Rules read them (registers.yaml), so an end date or a notice period becomes a finding before it bites.
return RequestCli.Run("keeper-register", args, [], Command, Usage);

static int Command(RequestCli r)
{
    var cli = r.Cli;
    if (cli.At(0) == "list" && cli.At(1) is null)
        return Overview(r);

    var spec = Spec(cli.At(0) == "list" ? cli.At(1)! : cli.At(0)!);
    if (cli.At(0) == "list")
        return List(r, spec);

    switch (cli.At(1))
    {
        case "fields":
            foreach (var field in spec.Fields)
                Console.WriteLine($"  --{Kebab(field.Name),-20} {Describe(field)}");
            return ExitCodes.Ok;
        case "set":
        {
            var id = r.Positional(2, $"the {spec.Table} id");
            var current = Current(r, spec, id);
            var payload = new JsonObject { ["op"] = "upsert", [spec.IdField] = id };
            foreach (var field in spec.Fields)
            {
                var given = cli.Get(Kebab(field.Name)) ?? cli.Get(field.Name);
                payload[field.Name] = given is not null ? Parse(field, given) : FromRow(field, current);
            }
            var unknown = cli.Options.Keys.Where(k => k is not ("reason" or "settings" or "now")
                && !spec.Fields.Any(f => k.Equals(Kebab(f.Name), StringComparison.OrdinalIgnoreCase) || k.Equals(f.Name, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (unknown.Count > 0)
                throw new ArgumentException($"Unknown field(s) for {Name(spec)}: {string.Join(", ", unknown)}. 'keeper register {Name(spec)} fields' lists them.");
            return r.Submit(spec.Kind, payload, current is null ? $"{Name(spec)} {id} added." : $"{Name(spec)} {id} updated (fields not given are kept).");
        }
        case "remove":
        {
            var id = r.Positional(2, $"the {spec.Table} id");
            return r.Submit(spec.Kind, new JsonObject { ["op"] = "remove", [spec.IdField] = id }, $"{Name(spec)} {id} removed.");
        }
        default:
            return Usage();
    }
}

static RegisterSpec Spec(string name) =>
    Registers.All.FirstOrDefault(s => Name(s).Equals(name, StringComparison.OrdinalIgnoreCase))
    ?? throw new ArgumentException($"No register '{name}'. Registers: {string.Join(", ", Registers.All.Select(Name))}.");

static string Name(RegisterSpec spec) => spec.Kind["review.".Length..];

static string Kebab(string camel)
{
    var text = new StringBuilder();
    foreach (var c in camel)
    {
        if (char.IsAsciiLetterUpper(c))
            text.Append('-').Append(char.ToLowerInvariant(c));
        else
            text.Append(c);
    }
    return text.ToString();
}

static string Describe(RegisterField field) =>
    (field.Type switch
    {
        FieldType.Date => "date (yyyy-MM-dd, or 30d / 12w from today)",
        FieldType.Int => "whole number",
        FieldType.Real => "number",
        FieldType.Bool => "true | false",
        FieldType.Choice => string.Join(" | ", field.Choices!),
        _ => "text",
    }) + (field.Required ? ", required" : "") + (field.Default is { } d ? $", default {d}" : "");

static JsonNode? Parse(RegisterField field, string value)
{
    if (value.Length == 0)
        return field.Required ? throw new ArgumentException($"--{Kebab(field.Name)} cannot be empty.") : null;
    return field.Type switch
    {
        FieldType.Date => RequestCli.Date(value, "--" + Kebab(field.Name)),
        FieldType.Int => long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n)
            ? n : throw new ArgumentException($"--{Kebab(field.Name)} must be a whole number."),
        FieldType.Real => double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var x)
            ? x : throw new ArgumentException($"--{Kebab(field.Name)} must be a number."),
        FieldType.Bool => value.ToLowerInvariant() switch
        {
            "true" or "yes" => true,
            "false" or "no" => false,
            _ => throw new ArgumentException($"--{Kebab(field.Name)} must be true or false."),
        },
        _ => value,
    };
}

static JsonNode? FromRow(RegisterField field, Dictionary<string, object?>? row) =>
    row?[field.Column] switch
    {
        null => null,
        long n when field.Type == FieldType.Bool => n == 1,
        long n => n,
        double x => x,
        string s => s,
        var other => Convert.ToString(other, CultureInfo.InvariantCulture),
    };

static Dictionary<string, object?>? Current(RequestCli r, RegisterSpec spec, string id)
{
    using var connection = r.Read();
    // Table and column names come from the register's spec in code, never from input.
    return Sql.Rows(connection, $"SELECT * FROM {spec.Table} WHERE {spec.IdColumn} = :id;", null, (":id", id)).FirstOrDefault();
}

static int Overview(RequestCli r)
{
    using var connection = r.Read();
    foreach (var spec in Registers.All)
        Console.WriteLine($"{Name(spec),-12} {Sql.Scalar(connection, $"SELECT COUNT(*) FROM {spec.Table};")} rows");
    return ExitCodes.Ok;
}

static int List(RequestCli r, RegisterSpec spec)
{
    using var connection = r.Read();
    var shown = spec.Fields.Take(5).ToList();
    foreach (var row in Sql.Rows(connection, $"SELECT * FROM {spec.Table} ORDER BY {spec.IdColumn};"))
        Console.WriteLine($"{row[spec.IdColumn],-16} " + string.Join("  ", shown.Select(f => $"{f.Name}={row[f.Column] ?? "-"}")));
    return ExitCodes.Ok;
}

static int Usage()
{
    Console.Error.WriteLine($"""
        keeper-register - the registers rules read; changes need --reason

          keeper register list                          every register and its size
          keeper register list <register>               its rows
          keeper register <register> fields             the fields it takes
          keeper register <register> set <id> --<field> <value> ...   add, or change only the fields given
          keeper register <register> remove <id>

          registers: {string.Join(", ", Registers.All.Select(Name))}
          e.g. keeper register licence set backup-suite --product "Backup suite" --expires-on 2027-03-31 --seats 50 --reason "PO 2026"
        """);
    return ExitCodes.Usage;
}
