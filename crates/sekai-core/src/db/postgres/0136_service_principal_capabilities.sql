-- Service-principal capabilities beyond Actions (#2006, ADR 0142):
-- `agent_turn_worker` lets a registered principal work agent turns in its
-- namespaces. Additive: older binaries neither read nor write the column,
-- so their updates keep a registration's capabilities.
ALTER TABLE sekai_service_principals
    ADD COLUMN IF NOT EXISTS capabilities_json TEXT NOT NULL DEFAULT '[]';
