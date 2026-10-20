using Keeper.Queue;

namespace Keeper.Review.Track;

/// <summary>
/// Today's standing of every system, kept per day in system_trend so a trend shows what was true then.
/// Written inside the register's transaction: a snapshot never disagrees with the register it follows.
/// </summary>
public static class TrendSnapshot
{
    public static void Write(RequestContext context)
    {
        var day = context.NowText[..10];
        const string perSystem = """
            WITH systems AS (SELECT system_id FROM system UNION SELECT DISTINCT system_id FROM finding),
            open_f AS (
                SELECT system_id, COUNT(*) AS open,
                       SUM(severity = 'critical') AS critical, SUM(severity = 'high') AS high, SUM(severity = 'medium') AS medium,
                       SUM(severity = 'low') AS low, SUM(severity = 'info') AS info, SUM(security = 1) AS security,
                       SUM(deadline IS NOT NULL AND deadline < :day) AS overdue
                FROM finding WHERE status = 'open' GROUP BY system_id
            ),
            accepted AS (SELECT system_id, COUNT(*) AS n FROM finding WHERE status = 'exception' GROUP BY system_id),
            moved AS (
                SELECT f.system_id,
                       SUM(e.event IN ('new', 'reopened')) AS opened, SUM(e.event = 'resolved') AS resolved
                FROM finding_event e JOIN finding f ON f.finding_key = e.finding_key
                WHERE substr(e.at, 1, 10) = :day GROUP BY f.system_id
            ),
            checks AS (
                SELECT en.system_id, SUM(r.state = 'pass') AS passing, SUM(r.state IN ('pass', 'fail')) AS judged
                FROM result r JOIN entity en ON en.instance = r.instance AND en.entity_type = r.entity_type AND en.entity_key = r.entity_key
                GROUP BY en.system_id
            ),
            per_system AS (
                SELECT s.system_id,
                       COALESCE(o.open, 0) AS open, COALESCE(o.critical, 0) AS critical, COALESCE(o.high, 0) AS high,
                       COALESCE(o.medium, 0) AS medium, COALESCE(o.low, 0) AS low, COALESCE(o.info, 0) AS info,
                       COALESCE(o.security, 0) AS security, COALESCE(o.overdue, 0) AS overdue, COALESCE(a.n, 0) AS accepted,
                       COALESCE(m.opened, 0) AS opened, COALESCE(m.resolved, 0) AS resolved,
                       COALESCE(c.passing, 0) AS checks_passing, COALESCE(c.judged, 0) AS checks_judged
                FROM systems s
                LEFT JOIN open_f o ON o.system_id = s.system_id
                LEFT JOIN accepted a ON a.system_id = s.system_id
                LEFT JOIN moved m ON m.system_id = s.system_id
                LEFT JOIN checks c ON c.system_id = s.system_id
            )
            """;

        // The day's last run wins: its rows replace the day's earlier ones.
        context.Execute("DELETE FROM system_trend WHERE day = :day;", (":day", day));
        context.Execute(
            $"""
            {perSystem}
            INSERT INTO system_trend (day, system_id, open, critical, high, medium, low, info, security, overdue, accepted,
                                      opened, resolved, checks_passing, checks_judged, at)
            SELECT :day, system_id, open, critical, high, medium, low, info, security, overdue, accepted,
                   opened, resolved, checks_passing, checks_judged, :at
            FROM per_system
            UNION ALL
            SELECT :day, '*', COALESCE(SUM(open), 0), COALESCE(SUM(critical), 0), COALESCE(SUM(high), 0), COALESCE(SUM(medium), 0),
                   COALESCE(SUM(low), 0), COALESCE(SUM(info), 0), COALESCE(SUM(security), 0), COALESCE(SUM(overdue), 0),
                   COALESCE(SUM(accepted), 0), COALESCE(SUM(opened), 0), COALESCE(SUM(resolved), 0),
                   COALESCE(SUM(checks_passing), 0), COALESCE(SUM(checks_judged), 0), :at
            FROM per_system;
            """,
            (":day", day), (":at", context.NowText));
    }
}
