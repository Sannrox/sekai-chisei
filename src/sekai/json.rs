use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{collections::HashSet, fmt};

struct DuplicateObjectKeyDetector;

struct DuplicateObjectValueSeed;

impl<'de> DeserializeSeed<'de> for DuplicateObjectValueSeed {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateObjectKeyDetector)
    }
}

impl<'de> Visitor<'de> for DuplicateObjectKeyDetector {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut duplicate = false;
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key) {
                duplicate = true;
            }
            duplicate |= access.next_value_seed(DuplicateObjectValueSeed)?;
        }
        Ok(duplicate)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut duplicate = false;
        while let Some(value) = access.next_element_seed(DuplicateObjectValueSeed)? {
            duplicate |= value;
        }
        Ok(duplicate)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(false)
    }
}

pub(crate) fn contains_duplicate_object_keys(input: &str) -> Result<bool, String> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let duplicate = deserializer
        .deserialize_any(DuplicateObjectKeyDetector)
        .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(duplicate)
}
