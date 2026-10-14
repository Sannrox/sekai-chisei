CREATE TABLE IF NOT EXISTS sekai_governed_images (
    namespace TEXT NOT NULL,
    image_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, image_id)
);
CREATE TABLE IF NOT EXISTS sekai_governed_image_renditions (
    namespace TEXT NOT NULL,
    image_id TEXT NOT NULL,
    rendition_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, image_id, rendition_id),
    FOREIGN KEY (namespace, image_id)
        REFERENCES sekai_governed_images(namespace, image_id)
);
CREATE TABLE IF NOT EXISTS sekai_governed_image_annotations (
    namespace TEXT NOT NULL,
    image_id TEXT NOT NULL,
    annotation_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, image_id, annotation_id),
    FOREIGN KEY (namespace, image_id)
        REFERENCES sekai_governed_images(namespace, image_id)
);
CREATE TABLE IF NOT EXISTS sekai_open_table_sources (
    source_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_open_table_snapshots (
    source_id TEXT PRIMARY KEY,
    snapshot_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY (source_id) REFERENCES sekai_open_table_sources(source_id)
);
