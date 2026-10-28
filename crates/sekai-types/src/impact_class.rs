//! Impact class of a governed Action type (#1910).
//!
//! A closed set: routing (#1861) maps each class to the models it may use,
//! so an unknown value must be rejected at registration rather than match
//! nothing at call time. An unset class means unclassified. A stored value
//! this build does not know also reads as unclassified, so adding a class
//! never raises a call's class on an older plane.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImpactClass {
    Routine,
    HighImpact,
}

impl ImpactClass {
    pub const ALL: [Self; 2] = [Self::Routine, Self::HighImpact];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::HighImpact => "high_impact",
        }
    }

    /// Exact canonical spelling only; stored values are never normalized.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_canonical_spellings() {
        for class in ImpactClass::ALL {
            assert_eq!(ImpactClass::parse(class.as_str()), Some(class));
        }
        assert_eq!(ImpactClass::parse("High_Impact"), None);
        assert_eq!(ImpactClass::parse(" routine"), None);
        assert_eq!(ImpactClass::parse(""), None);
    }
}
