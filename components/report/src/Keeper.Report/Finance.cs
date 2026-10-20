using System.Globalization;
using Keeper.Common;
using Keeper.Store;
using Microsoft.Data.Sqlite;

namespace Keeper.Report;

/// <summary>
/// Money: what falls due and what needs a decision, what is paid for and not used, what was saved - from
/// the registers people keep and the cost findings scans raise. Amounts stay in their own currency; nothing
/// is converted or guessed.
/// </summary>
public static class Finance
{
    public static Document Build(SqliteConnection connection, DateTimeOffset now, int days)
    {
        string Money(object? amount, object? currency) =>
            amount is null ? "no amount recorded" : $"{Convert.ToDouble(amount, CultureInfo.InvariantCulture):#,0} {currency ?? ""}".TrimEnd();
        List<string> Lines(string sql, Func<Dictionary<string, object?>, string> line) =>
            Sql.Rows(connection, sql, null, (":days", days)).Select(line).ToList();

        var sections = new List<Section>
        {
            new($"Falls due in the next {days} days",
            [
                .. Lines("""
                    SELECT title, end_on, value, currency, COALESCE(decision, 'undecided') AS decision, owner,
                           CAST(julianday(end_on) - julianday(date('now')) AS INTEGER) AS left
                    FROM contract WHERE end_on IS NOT NULL AND julianday(end_on) - julianday(date('now')) <= :days ORDER BY end_on;
                    """, r => $"Contract {r["title"]}: ends {r["end_on"]} ({r["left"]} days), {Money(r["value"], r["currency"])}, decision {r["decision"]}{Owner(r)}"),
                .. Lines("""
                    SELECT product, expires_on, cost, currency, auto_renews, owner,
                           CAST(julianday(expires_on) - julianday(date('now')) AS INTEGER) AS left
                    FROM licence WHERE expires_on IS NOT NULL AND julianday(expires_on) - julianday(date('now')) <= :days ORDER BY expires_on;
                    """, r => $"Licence {r["product"]}: expires {r["expires_on"]} ({r["left"]} days), {Money(r["cost"], r["currency"])}" +
                              $"{(r["auto_renews"] is 1L ? ", renews by itself" : "")}{Owner(r)}"),
                .. Lines("""
                    SELECT kind, title, due_on, owner FROM key_date
                    WHERE kind IN ('renewal', 'price-change', 'contract', 'licence', 'other') AND julianday(due_on) - julianday(date('now')) <= :days
                    ORDER BY due_on;
                    """, r => $"{Cap((string)r["kind"]!)}: {r["title"]} - {r["due_on"]}{Owner(r)}"),
            ], "Nothing recorded falls due in this period."),

            new("Decisions overdue (inside the notice period, no decision)", Lines("""
                SELECT title, end_on, value, currency, notice_days, owner FROM contract
                WHERE end_on IS NOT NULL AND COALESCE(decision, 'undecided') = 'undecided'
                  AND julianday(end_on) - julianday(date('now')) <= notice_days
                ORDER BY end_on;
                """, r => $"{r["title"]}: ends {r["end_on"]}, notice is {r["notice_days"]} days, {Money(r["value"], r["currency"])}{Owner(r)}"),
                "Every contract inside its notice period has a decision."),

            new("Paid for, not used", Lines("""
                SELECT product, seats, seats_used, cost, currency, owner,
                       CASE WHEN cost IS NOT NULL AND seats > 0 THEN cost * (seats - seats_used) / seats END AS idle_cost
                FROM licence WHERE seats > 0 AND seats_used IS NOT NULL AND seats_used < seats * 0.8
                ORDER BY idle_cost DESC NULLS LAST;
                """, r => $"{r["product"]}: {r["seats_used"]} of {r["seats"]} seats used" +
                          $"{(r["idle_cost"] is null ? "" : $" - about {Money(r["idle_cost"], r["currency"])} of its cost is idle")}{Owner(r)}"),
                "No licence below 80% use (or seat use is not recorded)."),

            new("Over the cap (a true-up or a block is coming)", Lines("""
                SELECT product, seats, seats_used, owner FROM licence WHERE seats > 0 AND seats_used > seats ORDER BY seats_used - seats DESC;
                """, r => $"{r["product"]}: {r["seats_used"]} used of {r["seats"]}{Owner(r)}"),
                "No licence over its seats."),

            new("Cost findings from the scans", Lines("""
                SELECT check_id, MAX(title) AS title, COUNT(*) AS n, COUNT(DISTINCT system_id) AS systems
                FROM active_finding WHERE category = 'CST' GROUP BY check_id ORDER BY n DESC LIMIT 20;
                """, r => $"{r["n"]} x {r["title"]} ({r["check_id"]}){((long)r["systems"]! > 1 ? $" on {r["systems"]} systems" : "")}"),
                "No open cost findings (or no system that reports cost has been scanned)."),

            new("Savings initiatives", Lines("""
                SELECT status, currency, COUNT(*) AS n, SUM(saving_monthly) AS monthly,
                       SUM(CASE WHEN measured = 'bill' THEN saving_monthly END) AS on_bill
                FROM initiative WHERE status <> 'dropped' GROUP BY status, currency
                ORDER BY CASE status WHEN 'done' THEN 0 WHEN 'in-progress' THEN 1 WHEN 'approved' THEN 2 ELSE 3 END;
                """, r => $"{r["status"]}: {r["n"]} initiative(s), {Money(r["monthly"], r["currency"])} a month" +
                          $"{(r["on_bill"] is null ? " (estimated)" : $" ({Money(r["on_bill"], r["currency"])} seen on the bill)")}"),
                "No savings initiatives recorded."),

            new("Recorded totals", Lines("""
                SELECT 'licences' AS what, currency, COUNT(*) AS n, SUM(cost) AS total FROM licence WHERE cost IS NOT NULL GROUP BY currency
                UNION ALL
                SELECT 'contracts', currency, COUNT(*), SUM(value) FROM contract WHERE value IS NOT NULL
                    AND (end_on IS NULL OR julianday(end_on) >= julianday(date('now'))) GROUP BY currency;
                """, r => $"{Cap((string)r["what"]!)}: {r["n"]} with an amount, {Money(r["total"], r["currency"])}"),
                "No amounts recorded yet: 'keeper register licence set <id> --cost ... --currency ...'."),

            new("How to read this",
            [
                "Everything here comes from the registers (keeper register) and from scan findings in the cost category.",
                "Amounts are as recorded, per currency; Keeper converts nothing.",
                "Idle cost is the share of a licence's recorded cost that matches its unused seats - an estimate, not an invoice.",
                "Cloud spend itself (AWS, Azure bills) is not read yet; record it as initiatives or key dates until it is.",
            ]),
        };
        return new Document("Finance", $"The next {days} days, generated {Iso.Utc(now)}.", sections);
    }

    private static string Owner(Dictionary<string, object?> row) => row["owner"] is string { Length: > 0 } owner ? $" (owner {owner})" : "";

    private static string Cap(string text) => text.Length == 0 ? text : char.ToUpperInvariant(text[0]) + text[1..];
}
