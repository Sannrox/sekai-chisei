-- Optional weights digest a registered hosted route declares (#1499).
ALTER TABLE chisei_routing_profiles ADD COLUMN IF NOT EXISTS artifact_digest TEXT;
