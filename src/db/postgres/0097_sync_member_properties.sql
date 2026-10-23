-- Offline sync purges (#1633): the property names each member was read
-- with, so a later read without one of them purges it. Empty when unknown.
ALTER TABLE sekai_sync_members ADD COLUMN IF NOT EXISTS properties TEXT NOT NULL DEFAULT '';
