-- Review, version 7: the catalogue remembers which query each rule reads (the query id the scanner writes
-- into coverage and row_seen). A finding about one host can then be judged against that query's own read of
-- the host - not against whatever other query of the system happened to read it. Filled by the next
-- 'keeper rules load'.

ALTER TABLE rule ADD COLUMN query_id TEXT;
