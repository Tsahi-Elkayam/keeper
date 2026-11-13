-- Review, version 4: one row per system per day, written each time the register is applied (the day's
-- last run wins), so progress can be shown as it was - not rebuilt later from today's state.
-- system_id '*' is the whole estate.

CREATE TABLE system_trend (
    day            TEXT NOT NULL,                       -- yyyy-MM-dd, UTC
    system_id      TEXT NOT NULL,
    open           INTEGER NOT NULL,
    critical       INTEGER NOT NULL,
    high           INTEGER NOT NULL,
    medium         INTEGER NOT NULL,
    low            INTEGER NOT NULL,
    info           INTEGER NOT NULL,
    security       INTEGER NOT NULL,                    -- open findings in the security tier
    overdue        INTEGER NOT NULL,                    -- open findings past their deadline
    accepted       INTEGER NOT NULL,                    -- exceptions in force
    opened         INTEGER NOT NULL,                    -- new or reopened that day
    resolved       INTEGER NOT NULL,                    -- resolved that day
    checks_passing INTEGER NOT NULL,                    -- results that passed, on this system's entities
    checks_judged  INTEGER NOT NULL,                    -- results that passed or failed
    at             TEXT NOT NULL,
    PRIMARY KEY (day, system_id)
) STRICT;
