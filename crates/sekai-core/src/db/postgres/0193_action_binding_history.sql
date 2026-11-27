-- Binding identity on Action instances and skip records for binding
-- history (#3551). Nullable so rows written before this migration, and
-- an older plane in a mixed deploy, keep no binding. Additive; rollback
-- leaves the column and table unread.
ALTER TABLE sekai_action_instances ADD COLUMN IF NOT EXISTS binding_id TEXT;

CREATE INDEX IF NOT EXISTS idx_action_instances_binding
    ON sekai_action_instances (namespace, binding_id, created_at_ms DESC, instance_id DESC)
    WHERE binding_id IS NOT NULL AND binding_id <> '';

CREATE TABLE IF NOT EXISTS sekai_action_binding_skips (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    op TEXT NOT NULL,
    skipped_reason TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    dataset_id TEXT NOT NULL DEFAULT '',
    version_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (namespace, binding_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_action_binding_skips_binding
    ON sekai_action_binding_skips (namespace, binding_id, created_at_ms DESC, event_id DESC);
