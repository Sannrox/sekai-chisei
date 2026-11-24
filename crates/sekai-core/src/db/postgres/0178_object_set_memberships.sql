-- Per-subscription ObjectSet membership (#3038): the member ids one reader
-- saw at the subscription's last committed page. Delivery state, written in
-- the same transaction as the cursor; a revoke deletes it.
CREATE TABLE IF NOT EXISTS sekai_object_set_memberships (
    namespace TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    epoch TEXT NOT NULL,
    member_ids_json TEXT NOT NULL,
    pending_ids_json TEXT NOT NULL,
    PRIMARY KEY(namespace, subscription_id)
);
