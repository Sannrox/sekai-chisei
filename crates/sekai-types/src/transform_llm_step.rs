//! A row-wise model step of an isolated-process transform (#3025).
//!
//! The definition's `code` is a prompt template. A runtime that holds a
//! gateway route renders it once per input row, sends one model call per row
//! through the gateway (ADR 0152), and writes each row back with the reply
//! in `output_column`, parsed as `output_type`. The plane checks the written
//! rows against the same type, so a runtime cannot commit a reply that does
//! not match: such a run is quarantined with an [`LLM_OUTPUT_TYPE_REASON`]
//! reason naming the row.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Engine of an isolated-process definition whose work is an [`LlmRowStep`].
pub const LLM_ROWS_ENGINE: &str = "llm-rows";
/// Placement label a runtime registers once it holds a gateway route, so
/// only such a runtime is offered model-step work.
pub const LLM_STEP_LABEL: &str = "sekai.step.llm";
/// The model step format a labelled runtime understands.
pub const LLM_STEP_LABEL_VALUE: &str = "v1";
/// First word of the reason a run whose reply did not parse is quarantined with.
pub const LLM_OUTPUT_TYPE_REASON: &str = "llm_output_type";

/// The type a model reply must parse as. Parsing is strict: the reply,
/// trimmed of surrounding whitespace, must be exactly a value of the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LlmOutputType {
    /// Any text.
    String,
    /// A JSON integer that fits in 64 bits.
    Integer,
    /// A JSON number.
    Number,
    /// `true` or `false`.
    Boolean,
}

impl LlmOutputType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Boolean => "boolean",
        }
    }

    /// The type named `name`, as written on the wire.
    pub fn parse_name(name: &str) -> Option<Self> {
        match name.trim() {
            "string" => Some(Self::String),
            "integer" => Some(Self::Integer),
            "number" => Some(Self::Number),
            "boolean" => Some(Self::Boolean),
            _ => None,
        }
    }

    /// The canonical value of `reply`, or `None` when it is not a value of
    /// this type.
    pub fn parse(self, reply: &str) -> Option<String> {
        let reply = reply.trim();
        match self {
            Self::String => Some(reply.to_string()),
            Self::Boolean => matches!(reply, "true" | "false").then(|| reply.to_string()),
            Self::Integer => serde_json::from_str::<serde_json::Number>(reply)
                .ok()
                .filter(|number| number.is_i64() || number.is_u64())
                .map(|number| number.to_string()),
            Self::Number => serde_json::from_str::<serde_json::Number>(reply)
                .ok()
                .map(|number| number.to_string()),
        }
    }
}

/// One model call per input row. The prompt template is the definition's
/// `code`; `{column}` takes the row's value, `{{` and `}}` are literal braces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmRowStep {
    /// The model the gateway routes, as its compatible surface names it.
    pub model: String,
    /// The column each output row carries the parsed reply in. It replaces
    /// an input column of the same name.
    pub output_column: String,
    pub output_type: LlmOutputType,
}

impl LlmRowStep {
    /// Refuses a blank model or output column.
    pub fn validate(&self) -> Result<(), String> {
        if self.model.trim().is_empty() {
            return Err("llm_step.model required".into());
        }
        if self.output_column.trim().is_empty() {
            return Err("llm_step.output_column required".into());
        }
        Ok(())
    }

    /// The output row for `row` and the model's `reply`, or the reason the
    /// reply does not parse, naming the row by `row_label`.
    pub fn output_row(
        &self,
        row: &HashMap<String, String>,
        reply: &str,
        row_label: &str,
    ) -> Result<HashMap<String, String>, String> {
        let value = self
            .output_type
            .parse(reply)
            .ok_or_else(|| self.type_reason(row_label))?;
        let mut out = row.clone();
        out.insert(self.output_column.clone(), value);
        Ok(out)
    }

    /// Checks rows a runtime wrote: each must carry `output_column` in the
    /// canonical form of `output_type`. Names the first bad row by position.
    pub fn check_written(&self, rows: &[HashMap<String, String>]) -> Result<(), String> {
        for (index, row) in rows.iter().enumerate() {
            let canonical = row.get(&self.output_column).and_then(|value| {
                self.output_type
                    .parse(value)
                    .filter(|parsed| parsed == value)
            });
            if canonical.is_none() {
                return Err(self.type_reason(&format!("output row {index}")));
            }
        }
        Ok(())
    }

    fn type_reason(&self, row_label: &str) -> String {
        format!(
            "{LLM_OUTPUT_TYPE_REASON}: {row_label}: {} is not {}",
            self.output_column,
            self.output_type.as_str()
        )
    }
}

/// Renders `template` over `row`. Refuses an unclosed or empty placeholder,
/// a lone `}`, and a column the row does not have.
pub fn render_prompt(template: &str, row: &HashMap<String, String>) -> Result<String, String> {
    render(template, |column| {
        row.get(column)
            .map(String::as_str)
            .ok_or_else(|| format!("prompt names column {column}, which the row does not have"))
    })
}

/// Checks the template's syntax without a row.
pub fn validate_prompt(template: &str) -> Result<(), String> {
    if template.trim().is_empty() {
        return Err("an llm-rows transform requires a prompt template as its code".into());
    }
    render(template, |_| Ok("")).map(drop)
}

fn render<'a>(
    template: &str,
    mut value: impl FnMut(&str) -> Result<&'a str, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find(['{', '}']) {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix("{{") {
            out.push('{');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("}}") {
            out.push('}');
            rest = after;
        } else if tail.starts_with('}') {
            return Err("prompt has a lone }; write }} for a literal brace".into());
        } else {
            let close = tail
                .find('}')
                .ok_or("prompt has an unclosed {; write {{ for a literal brace")?;
            let column = tail[1..close].trim();
            if column.is_empty() || column.contains('{') {
                return Err("prompt has an empty or nested placeholder".into());
            }
            out.push_str(value(column)?);
            rest = &tail[close + 1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(output_type: LlmOutputType) -> LlmRowStep {
        LlmRowStep {
            model: "gpt-5.5".into(),
            output_column: "score".into(),
            output_type,
        }
    }

    #[test]
    fn replies_parse_strictly_by_type() {
        let cases = [
            (LlmOutputType::Integer, " 42\n", Some("42")),
            (LlmOutputType::Integer, "4.2", None),
            (LlmOutputType::Integer, "forty-two", None),
            (LlmOutputType::Number, "4.5", Some("4.5")),
            (LlmOutputType::Number, "NaN", None),
            (LlmOutputType::Boolean, "true", Some("true")),
            (LlmOutputType::Boolean, "True", None),
            (LlmOutputType::String, "  hi ", Some("hi")),
        ];
        for (output_type, reply, expected) in cases {
            assert_eq!(
                output_type.parse(reply).as_deref(),
                expected,
                "{output_type:?} {reply:?}"
            );
        }
    }

    #[test]
    fn a_reply_that_does_not_parse_names_the_row() {
        let row = HashMap::from([("text".to_string(), "x".to_string())]);
        let step = step(LlmOutputType::Integer);
        assert_eq!(step.output_row(&row, "7", "row 3").unwrap()["score"], "7");
        assert_eq!(
            step.output_row(&row, "seven", "row 3").unwrap_err(),
            "llm_output_type: row 3: score is not integer"
        );
    }

    #[test]
    fn written_rows_must_carry_the_canonical_value() {
        let step = step(LlmOutputType::Integer);
        let row = |score: &str| HashMap::from([("score".to_string(), score.to_string())]);
        assert!(step.check_written(&[row("1"), row("2")]).is_ok());
        assert_eq!(
            step.check_written(&[row("1"), row(" 2")]).unwrap_err(),
            "llm_output_type: output row 1: score is not integer"
        );
        assert!(step.check_written(&[HashMap::new()]).is_err());
    }

    #[test]
    fn prompts_render_columns_and_escaped_braces() {
        let row = HashMap::from([("name".to_string(), "Ada".to_string())]);
        assert_eq!(
            render_prompt("Rate {name} as {{json}}", &row).unwrap(),
            "Rate Ada as {json}"
        );
        assert!(render_prompt("Rate {missing}", &row).is_err());
        for bad in ["Rate {name", "Rate }", "Rate {}", ""] {
            assert!(validate_prompt(bad).is_err(), "{bad:?}");
        }
    }
}
