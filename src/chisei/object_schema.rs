//! Object schema vocabulary lives in Sekai (ADR 0096 rule 5).

pub use crate::sekai::object_schema::{
    InterfaceDef, ObjectType, PropertyDef, PropertyType, StructFieldDef,
    default_property_classification, is_restricted_property_classification,
    is_valid_property_classification, normalize_property_classification,
};
