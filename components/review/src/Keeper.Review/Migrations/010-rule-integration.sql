-- Review, version 10: the integration type each rule reads through, as its rule file names it, and, for a file that
-- finds its hosts among what other scans saw, the entity type of those hosts. Keeper's own checks use them to tell a
-- system type nobody has set up (no integration of its type: not a finding, a coverage line) and one that waits for
-- another scan to list its hosts (said by keeper run) from one that has an integration and was still never scanned.

ALTER TABLE rule ADD COLUMN integration TEXT;
ALTER TABLE rule ADD COLUMN targets_entity TEXT;
