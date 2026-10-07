//! Transform JobSpec and run-receipt view for the operator console (#1287).

use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{is_safe_namespace, principal_can_access_namespace};
use crate::sekai::governed_transform::{GovernedTransform, TransformRun};

pub const RUN_LIST_LIMIT: i64 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformViewError {
    InvalidNamespace,
    NamespaceDenied,
    NotFound,
    Internal,
}

impl TransformViewError {
    pub fn status(self) -> axum::http::StatusCode {
        match self {
            Self::InvalidNamespace => axum::http::StatusCode::BAD_REQUEST,
            Self::NamespaceDenied => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::Internal => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidNamespace => "Invalid namespace identifier.",
            Self::NamespaceDenied => "Namespace access denied.",
            Self::NotFound => "Transform run not found.",
            Self::Internal => "Failed to load transforms.",
        }
    }
}

pub struct TransformHome {
    pub namespace: String,
    pub transforms: Vec<GovernedTransform>,
    pub runs: Vec<TransformRun>,
}

fn authorize(db: &RuntimeDb, principal: &str, namespace: &str) -> Result<(), TransformViewError> {
    if !is_safe_namespace(namespace) {
        return Err(TransformViewError::InvalidNamespace);
    }
    let allowed = principal_can_access_namespace(db, principal, namespace)
        .map_err(|_| TransformViewError::Internal)?;
    if !allowed {
        return Err(TransformViewError::NamespaceDenied);
    }
    Ok(())
}

pub fn load_home(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<TransformHome, TransformViewError> {
    authorize(db, principal, namespace)?;
    let transforms = db
        .list_governed_transforms(namespace)
        .map_err(|_| TransformViewError::Internal)?;
    let runs = db
        .list_governed_transform_runs(namespace, RUN_LIST_LIMIT)
        .map_err(|_| TransformViewError::Internal)?;
    Ok(TransformHome {
        namespace: namespace.into(),
        transforms,
        runs,
    })
}

pub fn load_run(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    run_id: &str,
) -> Result<TransformRun, TransformViewError> {
    authorize(db, principal, namespace)?;
    let run = db
        .get_governed_transform_run(run_id)
        .map_err(|_| TransformViewError::Internal)?
        .ok_or(TransformViewError::NotFound)?;
    if run.namespace != namespace {
        return Err(TransformViewError::NotFound);
    }
    Ok(run)
}

pub fn render_home(home: &TransformHome) -> String {
    let mut defs = String::new();
    if home.transforms.is_empty() {
        defs.push_str("<p>No transform definitions in this namespace.</p>");
    } else {
        defs.push_str("<table class=\"ops-table\"><thead><tr><th>Id</th><th>Input</th><th>Output</th><th>Digest</th></tr></thead><tbody>");
        for transform in &home.transforms {
            defs.push_str(&format!(
                "<tr><td>{id}</td><td>{input}</td><td>{output}</td><td><code>{digest}</code></td></tr>",
                id = escape_html(&transform.transform_id),
                input = escape_html(&transform.input_dataset_id),
                output = escape_html(&transform.output_dataset_id),
                digest = escape_html(&transform.definition_digest),
            ));
        }
        defs.push_str("</tbody></table>");
    }

    let mut runs = String::new();
    if home.runs.is_empty() {
        runs.push_str("<p>No transform run receipts in this namespace.</p>");
    } else {
        runs.push_str("<table class=\"ops-table\"><thead><tr><th>Run</th><th>Transform</th><th>Rows in</th><th>Rows out</th><th>Quarantine</th></tr></thead><tbody>");
        for run in &home.runs {
            runs.push_str(&format!(
                r#"<tr><td><a href="/console/n/{ns}/transforms/{id}">{id}</a></td><td>{tid}</td><td>{inn}</td><td>{out}</td><td>{q}</td></tr>"#,
                ns = escape_html(&home.namespace),
                id = escape_html(&run.run_id),
                tid = escape_html(&run.transform_id),
                inn = run.rows_in,
                out = run.rows_out,
                q = if run.quarantined { "yes" } else { "no" },
            ));
        }
        runs.push_str("</tbody></table>");
    }

    format!(
        r#"
<section aria-labelledby="transform-heading">
  <h1 id="transform-heading">Transforms</h1>
  <p>Plane-owned in-process dataset jobs in <strong>{ns}</strong>. Mutate with <code>sekaictl admin transform</code>. Run rows are receipts.</p>
  <h2>Definitions</h2>
  {defs}
  <h2>Run receipts</h2>
  {runs}
</section>"#,
        ns = escape_html(&home.namespace),
        defs = defs,
        runs = runs,
    )
}

pub fn render_run(namespace: &str, run: &TransformRun) -> String {
    format!(
        r#"
<section aria-labelledby="transform-run-heading">
  <h1 id="transform-run-heading">Transform run</h1>
  <p><a href="/console/n/{ns}/transforms">All transforms</a></p>
  <table class="ops-table">
    <tbody>
      <tr><th>run_id</th><td><code>{run_id}</code></td></tr>
      <tr><th>transform_id</th><td>{tid}</td></tr>
      <tr><th>incremental</th><td>{inc}</td></tr>
      <tr><th>quarantined</th><td>{q}</td></tr>
      <tr><th>rows_in</th><td>{inn}</td></tr>
      <tr><th>rows_out</th><td>{out}</td></tr>
      <tr><th>definition_digest</th><td><code>{def}</code></td></tr>
      <tr><th>input_digest</th><td><code>{input}</code></td></tr>
      <tr><th>output_digest</th><td><code>{output}</code></td></tr>
      <tr><th>lineage_parent</th><td><code>{parent}</code></td></tr>
      <tr><th>quality_rule</th><td>{quality}</td></tr>
      <tr><th>created_at_ms</th><td>{created}</td></tr>
    </tbody>
  </table>
</section>"#,
        ns = escape_html(namespace),
        run_id = escape_html(&run.run_id),
        tid = escape_html(&run.transform_id),
        inc = run.incremental,
        q = run.quarantined,
        inn = run.rows_in,
        out = run.rows_out,
        def = escape_html(&run.definition_digest),
        input = escape_html(&run.input_digest),
        output = escape_html(&run.output_digest),
        parent = escape_html(&run.lineage_parent),
        quality = escape_html(&run.quality_rule),
        created = run.created_at_ms,
    )
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_home_names_the_namespace() {
        let html = render_home(&TransformHome {
            namespace: "ops".into(),
            transforms: Vec::new(),
            runs: Vec::new(),
        });
        assert!(html.contains("ops"));
        assert!(html.contains("No transform definitions"));
        assert!(html.contains("No transform run receipts"));
    }
}
