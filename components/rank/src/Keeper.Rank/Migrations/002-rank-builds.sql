-- Rank, version 2: every ranking is recorded, an empty one too. Before, a day with nothing to rank
-- left latest_ranking pointing at the previous day's list.

CREATE TABLE rank_build (
    build_id       TEXT PRIMARY KEY,
    at             TEXT NOT NULL,
    items          INTEGER NOT NULL,
    budget_minutes INTEGER NOT NULL
) STRICT;

INSERT INTO rank_build (build_id, at, items, budget_minutes)
SELECT build_id, MAX(at), COUNT(*), 0 FROM ranking GROUP BY build_id;

DROP VIEW latest_ranking;
CREATE VIEW latest_ranking AS
SELECT r.* FROM ranking r WHERE r.build_id = (SELECT MAX(build_id) FROM rank_build);
