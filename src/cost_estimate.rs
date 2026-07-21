use std::collections::HashMap;

use crate::gateway::{ModelPricing, parse_pricing_table};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimateConfig {
    pub model: String,
    pub context_tokens: i64,
    pub turns: i64,
    pub output_tokens_per_turn: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimate {
    pub low_usd_micros: i64,
    pub high_usd_micros: i64,
    pub low_output_tokens: i64,
    pub high_output_tokens: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CacheCreationUsage {
    pub total_tokens: i64,
    pub five_minute_tokens: Option<i64>,
    pub one_hour_tokens: Option<i64>,
}

impl CostEstimateConfig {
    pub fn from_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut model = None;
        let mut context_tokens = None;
        let mut turns = 1;
        let mut output_tokens_per_turn = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--model" => model = Some(next_arg(&mut args, &arg)?),
                "--context-tokens" | "--prompt-tokens" => {
                    context_tokens = Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--turns" => turns = parse_positive(&next_arg(&mut args, &arg)?, &arg)?,
                "--output-tokens" => {
                    output_tokens_per_turn =
                        Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument {other:?}\n\n{}", usage())),
            }
        }
        Ok(Self {
            model: model.ok_or_else(|| format!("missing --model\n\n{}", usage()))?,
            context_tokens: context_tokens
                .ok_or_else(|| format!("missing --context-tokens\n\n{}", usage()))?,
            turns,
            output_tokens_per_turn,
        })
    }
}

pub fn pricing_from_env() -> Result<HashMap<String, ModelPricing>, String> {
    let spec = std::env::var("CHISEI_GATEWAY_PRICING")
        .or_else(|_| std::env::var("GATEWAY_PRICING"))
        .unwrap_or_default();
    parse_pricing_table(&spec).map_err(|error| error.to_string())
}

pub fn estimate_cost(
    config: &CostEstimateConfig,
    pricing: &HashMap<String, ModelPricing>,
) -> Result<CostEstimate, String> {
    let rates = pricing.get(&config.model).ok_or_else(|| {
        format!(
            "no pricing configured for {:?}; add it to CHISEI_GATEWAY_PRICING",
            config.model
        )
    })?;
    if config.context_tokens <= 0 || config.turns <= 0 {
        return Err("context tokens and turns must be positive".to_string());
    }
    let (low_output_per_turn, high_output_per_turn) = match config.output_tokens_per_turn {
        Some(output) if output > 0 => (
            output.saturating_mul(80) / 100,
            output.saturating_mul(120) / 100,
        ),
        Some(_) => return Err("output tokens must be positive".to_string()),
        None => (
            (config.context_tokens / 10).max(1),
            (config.context_tokens / 2).max(1),
        ),
    };
    let input_tokens = config
        .context_tokens
        .checked_mul(config.turns)
        .ok_or_else(|| "input token estimate is too large".to_string())?;
    let low_output_tokens = low_output_per_turn
        .checked_mul(config.turns)
        .ok_or_else(|| "output token estimate is too large".to_string())?;
    let high_output_tokens = high_output_per_turn
        .checked_mul(config.turns)
        .ok_or_else(|| "output token estimate is too large".to_string())?;
    Ok(CostEstimate {
        low_usd_micros: projected_cost(input_tokens, low_output_tokens, rates)?,
        high_usd_micros: projected_cost(input_tokens, high_output_tokens, rates)?,
        low_output_tokens,
        high_output_tokens,
    })
}

pub fn render_estimate(config: &CostEstimateConfig, estimate: &CostEstimate) -> String {
    format!(
        "estimated cost for {}: ${}–${} ({} context tokens × {} turns; {}–{} output tokens total)",
        config.model,
        format_usd(estimate.low_usd_micros),
        format_usd(estimate.high_usd_micros),
        config.context_tokens,
        config.turns,
        estimate.low_output_tokens,
        estimate.high_output_tokens,
    )
}

pub fn usage() -> String {
    "Usage: sekaictl estimate --model <model> --context-tokens <tokens> [--turns <count>] [--output-tokens <per-turn>]".to_string()
}

fn projected_cost(input: i64, output: i64, pricing: &ModelPricing) -> Result<i64, String> {
    cost_usd_micros("", pricing, input, output, 0, 0)
        .ok_or_else(|| "cost estimate is too large".to_string())
}

/// Shared provider-usage pricing for gateway and native executions.
///
/// Anthropic reports cache reads separately from uncached input, while OpenAI
/// compatible providers report cached input as a subset of prompt tokens.
pub(crate) fn cost_usd_micros(
    model: &str,
    pricing: &ModelPricing,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_input_tokens: i64,
    cache_creation_input_tokens: i64,
) -> Option<i64> {
    cost_usd_micros_with_cache_classes(
        model,
        pricing,
        input_tokens,
        output_tokens,
        cache_read_input_tokens,
        CacheCreationUsage {
            total_tokens: cache_creation_input_tokens,
            ..Default::default()
        },
    )
}

pub(crate) fn cost_usd_micros_with_cache_classes(
    model: &str,
    pricing: &ModelPricing,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_input_tokens: i64,
    cache_creation: CacheCreationUsage,
) -> Option<i64> {
    let cache_read = cache_read_input_tokens.max(0) as i128;
    let cache_creation_total = cache_creation.total_tokens.max(0) as i128;
    let input_tokens = input_tokens.max(0) as i128;
    let uncached_input = if crate::llm::provider_name(model) == "anthropic" {
        input_tokens
    } else {
        (input_tokens - cache_read).max(0)
    };
    let input_rate = pricing.input_usd_micros_per_million as i128;
    let output_rate = pricing.output_usd_micros_per_million as i128;
    let cached_rate = pricing.cached_input_usd_micros_per_million as i128;
    let classified_5m = cache_creation.five_minute_tokens.unwrap_or(0).max(0) as i128;
    let classified_1h = cache_creation.one_hour_tokens.unwrap_or(0).max(0) as i128;
    let classified = classified_5m.checked_add(classified_1h)?;
    if classified > cache_creation_total {
        return None;
    }
    let unclassified_creation = cache_creation_total.checked_sub(classified)?;
    let write_5m_rate = match (classified_5m, pricing.cache_write_5m_usd_micros_per_million) {
        (0, _) => 0,
        (_, Some(rate)) => rate as i128,
        (_, None) => return None,
    };
    let write_1h_rate = match (classified_1h, pricing.cache_write_1h_usd_micros_per_million) {
        (0, _) => 0,
        (_, Some(rate)) => rate as i128,
        (_, None) => return None,
    };
    // Legacy providers may report only an aggregate cache-creation count. It
    // can use the ordinary rate only when this pricing snapshot defines no
    // premium write classes; otherwise the cost is deliberately unknown.
    if unclassified_creation > 0
        && (pricing.cache_write_5m_usd_micros_per_million.is_some()
            || pricing.cache_write_1h_usd_micros_per_million.is_some())
    {
        return None;
    }
    let total = uncached_input
        .checked_mul(input_rate)?
        .checked_add(cache_read.checked_mul(cached_rate)?)?
        .checked_add(unclassified_creation.checked_mul(input_rate)?)?
        .checked_add(classified_5m.checked_mul(write_5m_rate)?)?
        .checked_add(classified_1h.checked_mul(write_1h_rate)?)?
        .checked_add((output_tokens.max(0) as i128).checked_mul(output_rate)?)?
        .checked_div(1_000_000)?;
    i64::try_from(total).ok()
}

fn format_usd(micros: i64) -> String {
    format!("{}.{:06}", micros / 1_000_000, (micros % 1_000_000).abs())
}

fn parse_positive(value: &str, flag: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{flag} must be a positive integer"))
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_a_range_when_output_is_unknown() {
        let pricing = parse_pricing_table("model-x=2:10").unwrap();
        let config = CostEstimateConfig {
            model: "model-x".to_string(),
            context_tokens: 10_000,
            turns: 2,
            output_tokens_per_turn: None,
        };
        let estimate = estimate_cost(&config, &pricing).unwrap();
        assert_eq!(estimate.low_usd_micros, 60_000);
        assert_eq!(estimate.high_usd_micros, 140_000);
        assert!(render_estimate(&config, &estimate).contains("$0.060000–$0.140000"));
    }

    #[test]
    fn parses_required_estimate_inputs() {
        let config = CostEstimateConfig::from_args([
            "--model".to_string(),
            "model-x".to_string(),
            "--context-tokens".to_string(),
            "12000".to_string(),
            "--turns".to_string(),
            "3".to_string(),
        ])
        .unwrap();
        assert_eq!(config.context_tokens, 12_000);
        assert_eq!(config.turns, 3);
    }

    #[test]
    fn shared_actual_cost_preserves_provider_cache_semantics() {
        let pricing = ModelPricing {
            input_usd_micros_per_million: 3_000_000,
            output_usd_micros_per_million: 15_000_000,
            cached_input_usd_micros_per_million: 300_000,
            ..Default::default()
        };
        assert_eq!(
            cost_usd_micros("gpt-5.5", &pricing, 100, 10, 80, 20),
            Some(294)
        );
        assert_eq!(
            cost_usd_micros("claude-sonnet-4-6", &pricing, 100, 10, 80, 20),
            Some(534)
        );
    }
}
