-- The principal a stored governed transform's object-set inputs are read as
-- (#1977, ADR 0140): the one that put the definition, and that definition's
-- digest; a run of another definition finds no reader. Additive.
CREATE TABLE IF NOT EXISTS sekai_transform_reader (
    namespace TEXT NOT NULL,
    transform_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    definition_digest TEXT NOT NULL,
    PRIMARY KEY (namespace, transform_id)
);
