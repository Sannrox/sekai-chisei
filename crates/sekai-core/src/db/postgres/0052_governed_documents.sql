CREATE TABLE IF NOT EXISTS sekai_governed_documents (
    namespace TEXT NOT NULL,
    document_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, document_id)
);

CREATE TABLE IF NOT EXISTS sekai_governed_renditions (
    namespace TEXT NOT NULL,
    document_id TEXT NOT NULL,
    rendition_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, document_id, rendition_id),
    FOREIGN KEY (namespace, document_id)
        REFERENCES sekai_governed_documents (namespace, document_id)
);
