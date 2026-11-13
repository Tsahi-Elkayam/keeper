-- Review, version 8: an override can end. An exception accepted "until the server is replaced" lapses on its
-- own date (yyyy-MM-dd, the last day it holds) and the finding comes back; no end date stays as before.

ALTER TABLE override ADD COLUMN until TEXT;
