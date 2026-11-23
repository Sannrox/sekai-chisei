CREATE TABLE IF NOT EXISTS sekai_action_binding_dataset_cursors (
    namespace TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    PRIMARY KEY (namespace, binding_id, dataset_id)
);
