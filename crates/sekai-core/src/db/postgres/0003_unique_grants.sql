WITH ranked_grants AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY object_id, principal
               ORDER BY created DESC, id DESC
           ) AS duplicate_rank
    FROM sekai_grants
)
DELETE FROM sekai_grants
WHERE id IN (
    SELECT id FROM ranked_grants WHERE duplicate_rank > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_object_principal
    ON sekai_grants(object_id, principal);
