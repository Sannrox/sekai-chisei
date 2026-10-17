//! Role and grant records shared by the store and Chisei principal mapping.

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub id: String,
    pub object_id: String,
    pub principal: String,
    pub role: Role,
    pub created: i64,
}
