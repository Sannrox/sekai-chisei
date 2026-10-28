-- Change-feed cursors of package consumers (#1954): where a consumer such as
-- the security disposition reopener resumes in a namespace. Advanced by
-- compare-and-set, so instances running the same consumer never move it
-- backwards. Additive.
CREATE TABLE IF NOT EXISTS sekai_package_feed_cursors (
    namespace TEXT NOT NULL,
    consumer TEXT NOT NULL,
    next_seq BIGINT NOT NULL,
    PRIMARY KEY (namespace, consumer)
);
