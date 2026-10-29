-- The object-set rows a stored governed-transform run read, kept so a
-- replay reads them again (#1979, ADR 0140). Keyed by the set's row digest:
-- unchanged sets across runs are stored once, and a write is idempotent.
-- The head row keeps the descriptor and columns, so an empty set is not an
-- unknown digest and a replay can check the set is the one it asks for.
-- `object_id` lets the rows of a deleted object be found. Additive.
CREATE TABLE IF NOT EXISTS sekai_transform_object_set_pin (
    namespace TEXT NOT NULL,
    digest TEXT NOT NULL,
    descriptor TEXT NOT NULL,
    columns_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, digest)
);
CREATE TABLE IF NOT EXISTS sekai_transform_object_set_pin_row (
    namespace TEXT NOT NULL,
    digest TEXT NOT NULL,
    row_id BIGINT NOT NULL,
    object_id TEXT NOT NULL,
    values_json TEXT NOT NULL,
    marking TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (namespace, digest, row_id)
);
CREATE INDEX IF NOT EXISTS sekai_transform_object_set_pin_row_object
    ON sekai_transform_object_set_pin_row (namespace, object_id);
