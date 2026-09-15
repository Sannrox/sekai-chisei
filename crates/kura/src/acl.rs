use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    Denied { kind: String, property: String },
}

#[derive(Clone, Debug, Default)]
pub struct PropertyAcl {
    denied: HashSet<(String, String)>,
}

impl PropertyAcl {
    pub fn allow_all() -> Self {
        Self {
            denied: HashSet::new(),
        }
    }

    pub fn deny_property(kind: &str, property: &str) -> Self {
        let mut acl = Self::allow_all();
        acl.denied.insert((kind.into(), property.into()));
        acl
    }

    pub fn check(&self, kind: &str, property: &str) -> Result<(), AclError> {
        if self.denied.contains(&(kind.into(), property.into())) {
            return Err(AclError::Denied {
                kind: kind.into(),
                property: property.into(),
            });
        }
        Ok(())
    }
}
