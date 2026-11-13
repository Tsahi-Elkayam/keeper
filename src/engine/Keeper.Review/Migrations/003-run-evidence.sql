-- Review, version 3: each run keeps the SHA-256 of the run.json it was loaded from. run.json lists the
-- hash of every file in the run folder, so this one value proves what a scan saw - the chain of custody
-- an evidence pack hands to an auditor, kept even after the run folder itself is pruned.

ALTER TABLE run ADD COLUMN manifest_sha256 TEXT;
