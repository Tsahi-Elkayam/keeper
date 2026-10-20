using System.Globalization;
using Keeper.Common;
using Keeper.Review.Cli;
using Keeper.Store;

// keeper-system: the systems the organisation runs, and which scanned entities belong to each.
// Findings are grouped, routed and ranked by system.
return RequestCli.Run("keeper-system", args, ["inactive"], Command, Usage);

static int Command(RequestCli r)
{
    var cli = r.Cli;
    switch (cli.At(0))
    {
        case "list":
            return List(r);
        case "add" or "set":
        {
            var id = r.Positional(1, "the system id, e.g. ERP");
            var current = Current(r, id);
            string? Pick(string option, string column) => cli.Get(option) ?? current?[column] as string;
            var criticality = cli.Get("criticality") is { } c
                ? int.Parse(c, NumberStyles.None, CultureInfo.InvariantCulture)
                : current?["criticality"] is long l ? (int)l : (int?)null;
            var payload = new
            {
                op = "upsert",
                systemId = id,
                name = Pick("name", "name") ?? throw new ArgumentException("--name is required for a new system."),
                team = Pick("team", "team"),
                purpose = Pick("purpose", "purpose"),
                owner = Pick("owner", "owner"),
                ownerPerson = Pick("owner-person", "owner_person"),
                route = Pick("route", "route"),
                criticality,
                active = !cli.Has("inactive") && (cli.Get("active") is not { } a ? current?["active"] is not 0L : a != "false"),
                notes = Pick("notes", "notes"),
            };
            return r.Submit("review.system", payload, current is null ? $"system {id} added." : $"system {id} updated.");
        }
        case "remove":
        {
            var id = r.Positional(1, "the system id");
            return r.Submit("review.system", new { op = "remove", systemId = id }, $"system {id} removed.");
        }
        case "map":
        {
            // keeper system map <rule-id> <system-id> --pattern <regex> [--field key|name|<attr>] [--type <entity type>]
            var ruleId = r.Positional(1, "the mapping id, e.g. erp-servers");
            var systemId = r.Positional(2, "the system id");
            var payload = new
            {
                op = "upsert",
                ruleId,
                systemId,
                pattern = cli.Require("pattern"),
                field = cli.Get("field") ?? "key",
                entityType = cli.Get("type") ?? "*",
                instance = cli.Get("integration") ?? "*",
                ord = cli.Get("order") is { } o ? int.Parse(o, NumberStyles.None, CultureInfo.InvariantCulture) : 100,
            };
            return r.Submit("review.system-rule", payload, $"{ruleId}: {payload.field} ~ /{payload.pattern}/ -> {systemId}. keeper track applies it to what is already seen.");
        }
        case "unmap":
        {
            var ruleId = r.Positional(1, "the mapping id");
            return r.Submit("review.system-rule", new { op = "remove", ruleId }, $"mapping {ruleId} removed.");
        }
        default:
            return Usage();
    }
}

static Dictionary<string, object?>? Current(RequestCli r, string id)
{
    using var connection = r.Read();
    return Sql.Rows(connection, "SELECT * FROM system WHERE system_id = :id;", null, (":id", id)).FirstOrDefault();
}

static int List(RequestCli r)
{
    using var connection = r.Read();
    foreach (var s in Sql.Rows(connection,
                 """
                 SELECT s.system_id, s.name, s.team, s.criticality, s.route, s.active,
                        (SELECT COUNT(*) FROM entity e WHERE e.system_id = s.system_id AND e.gone_since IS NULL) AS entities,
                        (SELECT COUNT(*) FROM finding f WHERE f.system_id = s.system_id AND f.status = 'open') AS open
                 FROM system s ORDER BY s.system_id;
                 """))
    {
        Console.WriteLine($"{s["system_id"],-16} {s["name"],-30} crit {s["criticality"] ?? "-"}  team {s["team"] ?? "-"}  " +
                          $"route {s["route"] ?? "-"}  {s["entities"]} entities, {s["open"]} open{(s["active"] is 0L ? "  (inactive)" : "")}");
    }
    Console.WriteLine();
    foreach (var m in Sql.Rows(connection, "SELECT rule_id, ord, instance, entity_type, field, pattern, system_id FROM system_rule ORDER BY ord, rule_id;"))
        Console.WriteLine($"  map {m["rule_id"],-20} #{m["ord"]} {m["instance"]}/{m["entity_type"]} {m["field"]} ~ /{m["pattern"]}/ -> {m["system_id"]}");
    return ExitCodes.Ok;
}

static int Usage()
{
    Console.Error.WriteLine("""
        keeper-system - the systems Keeper groups findings by; changes need --reason

          keeper system list
          keeper system add <ID> --name "<name>" [--team t] [--owner dept] [--owner-person p] [--purpose text]
                                 [--route servicenow|monday|triage] [--criticality 1|2|3] [--notes text]
          keeper system set <ID> [any of the above] [--inactive | --active true]   (unchanged fields are kept)
          keeper system remove <ID>                    only when it has no open findings
          keeper system map <map-id> <ID> --pattern <regex> [--field key|name|<attribute>] [--type <entity type>]
                                 [--integration <id>] [--order 100]       first matching map wins
          keeper system unmap <map-id>

          --now applies the change straight away.
        """);
    return ExitCodes.Usage;
}
