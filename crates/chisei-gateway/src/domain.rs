#[cfg(test)]
pub use sekai_chisei::domain::*;

#[cfg(not(test))]
pub fn is_valid_property_key(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(not(test))]
#[derive(Debug, Clone)]
pub struct Object {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub external_id: String,
    pub properties: std::collections::HashMap<String, String>,
    pub created: i64,
    pub updated: i64,
}
