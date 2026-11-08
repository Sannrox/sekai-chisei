-- The in-plane fence bindings and geo feed are removed (ADR 0121, 0132 and
-- 0133 superseded). An adapter outside the plane replaces them when a
-- deployment first needs one; it keeps its own cursor state.
DROP TABLE IF EXISTS sekai_fence_binding_receipts;
DROP TABLE IF EXISTS sekai_fence_bindings;
DROP TABLE IF EXISTS sekai_ezu_geo_feeds;
