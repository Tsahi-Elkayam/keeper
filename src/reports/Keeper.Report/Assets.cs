using System.Text;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// The asset inventory, as a person who runs IT wants it: every machine and device the scans have seen - what it is,
/// what runs on it, where it is, when it was last seen, how many findings are open on it - counted, listed, and
/// exportable as CSV. Built from what the scans stored; nothing is read from a system for it.
/// </summary>
public static class Assets
{
    /// <summary>The entity types that are machines or devices. Accounts, groups, policies and settings are not assets.</summary>
    public static readonly IReadOnlyList<string> Types =
        ["computer", "managed-device", "device", "host", "vm", "endpoint", "appliance", "printer", "queue", "sql-instance", "backup-server", "sync-server"];

    private static readonly IReadOnlySet<string> Machines = new HashSet<string> { "computer", "managed-device", "device", "host", "vm", "endpoint" };

    /// <summary>An asset not seen for this many days is stale.</summary>
    public const int StaleDays = 30;

    private const int ListLimit = 300;
    private const int StaleListLimit = 100;

    private sealed record Asset(string Type, string Key, string Name, string Kind, string Os, string Address, string Model, string Serial,
        string System, string Integration, string FirstSeen, string LastSeen, string Status, long Open);

    private static List<Asset> Load(SqliteConnection connection, DateTimeOffset now)
    {
        var cutoff = Iso.Utc(now.AddDays(-StaleDays));
        var typeList = string.Join(", ", Types.Select(t => $"'{t}'"));
        var rows = Sql.Rows(connection,
            $$"""
            WITH seen AS (
                SELECT r.instance AS inst, rs.entity_type, rs.entity_key, rs.attrs,
                       ROW_NUMBER() OVER (PARTITION BY r.instance, rs.entity_type, rs.entity_key ORDER BY rs.observed_at DESC) AS rn
                FROM row_seen rs JOIN run r ON r.run_id = rs.run_id
                WHERE rs.entity_type IN ({{typeList}})
            )
            SELECT e.entity_type AS type, e.entity_key AS key, COALESCE(e.entity_name, e.entity_key) AS name, e.system_id AS system, e.instance,
                   e.first_seen, e.last_seen,
                   CASE WHEN e.gone_since IS NOT NULL THEN 'gone' WHEN e.last_seen < :cutoff THEN 'stale' ELSE 'current' END AS status,
                   COALESCE(json_extract(s.attrs, '$.kind'), '') AS kind,
                   COALESCE(json_extract(s.attrs, '$.operatingSystem'), json_extract(s.attrs, '$.osName'), json_extract(s.attrs, '$.os'), '') AS os,
                   COALESCE(json_extract(s.attrs, '$.addresses[0]'), json_extract(s.attrs, '$.ipAddress'), json_extract(s.attrs, '$.address'), '') AS address,
                   COALESCE(json_extract(s.attrs, '$.model'), json_extract(s.attrs, '$."printer-make-and-model"'), json_extract(s.attrs, '$.snmp.sysDescr'), '') AS model,
                   COALESCE(json_extract(s.attrs, '$.serialNumber'), json_extract(s.attrs, '$.serial'), '') AS serial,
                   (SELECT COUNT(*) FROM finding f WHERE f.instance = e.instance AND f.target = e.entity_key AND f.status = 'open') AS open
            FROM entity e
            LEFT JOIN seen s ON s.inst = e.instance AND s.entity_type = e.entity_type AND s.entity_key = e.entity_key AND s.rn = 1
            WHERE e.entity_type IN ({{typeList}})
            ORDER BY e.entity_type, e.entity_key;
            """, null, (":cutoff", cutoff));

        static string S(object? value) => value as string ?? "";
        return rows.Select(r => new Asset(S(r["type"]), S(r["key"]), S(r["name"]), S(r["kind"]), S(r["os"]), S(r["address"]), S(r["model"]),
            S(r["serial"]), S(r["system"]), S(r["instance"]), S(r["first_seen"]), S(r["last_seen"]), S(r["status"]), r["open"] is long n ? n : 0)).ToList();
    }

    public static Document Build(SqliteConnection connection, DateTimeOffset now)
    {
        var assets = Load(connection, now);
        if (assets.Count == 0)
            return new Document("Asset inventory", $"Generated {Iso.Utc(now)}.",
                [new Section("Assets", [], "No assets yet: the inventory is built from scans; run 'keeper run' (and 'keeper discover') first.")]);

        long Count(string status) => assets.Count(a => a.Status == status);
        var machines = assets.Where(a => Machines.Contains(a.Type)).ToList();
        static string Date(string iso) => iso.Length >= 10 ? iso[..10] : iso;

        string Line(Asset a) =>
            $"{a.Type} {a.Name}{(a.Name == a.Key ? "" : $" ({a.Key})")} - {Describe(a)} - last seen {Date(a.LastSeen)} - {a.Status} - {a.Open} open";

        return new Document("Asset inventory", $"Every machine and device the scans have seen. Generated {Iso.Utc(now)}.",
        [
            new Section("Summary",
                [.. assets.GroupBy(a => a.Type).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Select(g => $"{g.Key}: {g.Count()}")])
            {
                Intro = $"{assets.Count} asset{(assets.Count == 1 ? "" : "s")}: {Count("current")} current, {Count("stale")} not seen for {StaleDays} days, {Count("gone")} gone (no longer returned by their scan). " +
                        $"{assets.Count(a => a.Open > 0)} have open findings.",
            },
            new Section("Operating systems",
                [.. machines.GroupBy(a => a.Os.Length == 0 ? "unknown" : a.Os).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Select(g => $"{g.Key}: {g.Count()}")],
                "No machines yet.")
            {
                Intro = "Machines by the operating system their scan reported. 'unknown' is a machine whose scan did not report one - a gap in the inventory, not an absence.",
            },
            new Section("Not seen recently",
                [.. assets.Where(a => a.Status != "current").OrderBy(a => a.LastSeen, StringComparer.Ordinal).Take(StaleListLimit).Select(Line)],
                $"Everything was seen within {StaleDays} days."),
            new Section("All assets", [.. assets.Take(ListLimit).Select(Line), .. assets.Count > ListLimit ? [$"... and {assets.Count - ListLimit} more: 'keeper report assets --format csv' lists every one."] : Array.Empty<string>()]),
        ]);
    }

    private static string Describe(Asset a) =>
        string.Join(", ", new[] { a.Os, a.Model, a.Serial.Length == 0 ? "" : $"serial {a.Serial}", a.Kind, a.Address }.Where(s => s.Length > 0)) is { Length: > 0 } text ? text : "no details";

    /// <summary>One row per asset, for a spreadsheet. Names come from scanned systems, so a cell a spreadsheet would run as a formula is defused.</summary>
    public static string Csv(SqliteConnection connection, DateTimeOffset now)
    {
        var output = new StringBuilder();
        output.Append("type,key,name,kind,operating_system,address,model,serial,system,integration,first_seen,last_seen,status,open_findings\r\n");
        foreach (var a in Load(connection, now))
        {
            output.Append(string.Join(',', new[]
            {
                a.Type, a.Key, a.Name, a.Kind, a.Os, a.Address, a.Model, a.Serial, a.System, a.Integration, a.FirstSeen, a.LastSeen, a.Status,
            }.Select(Cell)));
            output.Append(',').Append(a.Open).Append("\r\n");
        }
        return output.ToString();
    }

    private static string Cell(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : value;
    }
}
