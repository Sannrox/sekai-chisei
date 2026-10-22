use std::collections::HashMap;

use crate::provider_profile::provider_registry_snapshot;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModelPricing {
    pub input_usd_micros_per_million: i64,
    pub output_usd_micros_per_million: i64,
    /// Discounted rate for prompt tokens served from the provider's cache.
    /// Defaults to `input_usd_micros_per_million` when the pricing entry omits
    /// the optional third field, so uncached traffic is priced unchanged.
    pub cached_input_usd_micros_per_million: i64,
    /// Anthropic-style five-minute cache creation rate. `None` means the
    /// pricing snapshot does not define this price class.
    pub cache_write_5m_usd_micros_per_million: Option<i64>,
    /// Anthropic-style one-hour cache creation rate. `None` means the pricing
    /// snapshot does not define this price class.
    pub cache_write_1h_usd_micros_per_million: Option<i64>,
}

pub fn parse_pricing_table(
    spec: &str,
) -> Result<HashMap<String, ModelPricing>, Box<dyn std::error::Error>> {
    let mut pricing = HashMap::new();
    for entry in spec
        .split([',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (model, rates) = entry.split_once('=').ok_or_else(|| {
            format!(
                "invalid gateway pricing entry {entry:?}; expected model=input_usd_per_1m:output_usd_per_1m"
            )
        })?;
        let model = model.trim();
        if model.is_empty() {
            return Err("invalid gateway pricing entry with empty model".into());
        }
        let rate_parts = rates.split(':').map(str::trim).collect::<Vec<_>>();
        if rate_parts.len() < 2 || rate_parts.len() > 5 {
            return Err(format!(
                "invalid gateway pricing rates for {model:?}; expected input_usd_per_1m:output_usd_per_1m[:cached_input_usd_per_1m[:cache_write_5m_usd_per_1m[:cache_write_1h_usd_per_1m]]]"
            )
            .into());
        }
        let input_usd_micros_per_million = parse_usd_micros(rate_parts[0])?;
        let output_usd_micros_per_million = parse_usd_micros(rate_parts[1])?;
        let cached_input_usd_micros_per_million = match rate_parts.get(2) {
            Some(cached) => parse_usd_micros(cached)?,
            None => input_usd_micros_per_million,
        };
        let cache_write_5m_usd_micros_per_million = rate_parts
            .get(3)
            .map(|rate| parse_usd_micros(rate))
            .transpose()?;
        let cache_write_1h_usd_micros_per_million = rate_parts
            .get(4)
            .map(|rate| parse_usd_micros(rate))
            .transpose()?;
        pricing.insert(
            model.to_string(),
            ModelPricing {
                input_usd_micros_per_million,
                output_usd_micros_per_million,
                cached_input_usd_micros_per_million,
                cache_write_5m_usd_micros_per_million,
                cache_write_1h_usd_micros_per_million,
            },
        );
    }
    Ok(pricing)
}

fn parse_usd_micros(value: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return Err(format!("invalid non-negative USD value {value:?}").into());
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 6 || !fraction.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid USD value {value:?}; use at most 6 decimal places").into());
    }
    let whole_micros = whole
        .parse::<i64>()
        .map_err(|_| format!("invalid USD value {value:?}"))?
        .checked_mul(1_000_000)
        .ok_or("USD value is too large")?;
    let mut padded_fraction = fraction.to_string();
    while padded_fraction.len() < 6 {
        padded_fraction.push('0');
    }
    let fraction_micros = if padded_fraction.is_empty() {
        0
    } else {
        padded_fraction
            .parse::<i64>()
            .map_err(|_| format!("invalid USD value {value:?}"))?
    };
    whole_micros
        .checked_add(fraction_micros)
        .ok_or_else(|| "USD value is too large".into())
}

pub fn lookup_pricing_entry<'a>(
    pricing: &'a HashMap<String, ModelPricing>,
    model: &str,
) -> Option<(&'a str, &'a ModelPricing)> {
    pricing
        .get_key_value(model)
        .or_else(|| {
            let registry = provider_registry_snapshot();
            registry.resolve_model(model).ok().and_then(|resolved| {
                let alias_matches = registry
                    .resolve_model(&resolved.upstream_model)
                    .map(|alias| alias.canonical_model == resolved.canonical_model)
                    .unwrap_or_else(|_| {
                        resolved.provider == "ollama" && resolved.upstream_model.contains('/')
                    });
                alias_matches
                    .then(|| pricing.get_key_value(&resolved.upstream_model))
                    .flatten()
            })
        })
        .map(|(model, pricing)| (model.as_str(), pricing))
}
