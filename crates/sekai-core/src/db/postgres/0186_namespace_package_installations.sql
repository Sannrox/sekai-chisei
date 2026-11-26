CREATE TABLE IF NOT EXISTS sekai_namespace_package_installations (
    namespace TEXT NOT NULL,
    package_name TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, package_name)
);
