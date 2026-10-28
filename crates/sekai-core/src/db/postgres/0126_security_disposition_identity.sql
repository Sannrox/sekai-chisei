-- Security dispositions (#1924): an exposure's first disposition and each
-- disposition's successor are unique at commit, so a disposition history is
-- one chain. A separate index, so the finding, occurrence and exposure index
-- from 0124 stays as it is. Dispositions are new, so no existing row can
-- conflict.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_objects_security_disposition_identity
    ON sekai_objects(namespace, external_id)
    WHERE kind = 'security_disposition' AND external_id <> '';
