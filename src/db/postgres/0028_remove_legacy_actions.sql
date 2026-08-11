-- Pre-1.0 removal of the legacy graph ActionTypeDef registry.
DROP TABLE IF EXISTS sekai_action_types;
DROP TABLE IF EXISTS sekai_action_approvals;
DELETE FROM sekai_grants
WHERE object_id IN (SELECT id FROM sekai_objects WHERE kind='action_approval');
DELETE FROM sekai_links
WHERE from_id IN (SELECT id FROM sekai_objects WHERE kind='action_approval')
   OR to_id IN (SELECT id FROM sekai_objects WHERE kind='action_approval');
DELETE FROM sekai_objects WHERE kind='action_approval';
