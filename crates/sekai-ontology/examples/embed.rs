use sekai_ontology::{Ontology, SqliteOntology};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "knowledge.db".into());
    let definitions = std::env::args().nth(2).unwrap_or_else(|| {
        format!(
            "{}/tests/fixtures/codebase.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let mut ontology = SqliteOntology::initialize(path)?;
    ontology.import_json(&std::fs::read_to_string(definitions)?)?;
    let exported = ontology.export()?;
    println!("{}", serde_json::to_string_pretty(&exported)?);
    let explanation = ontology.explain("Api")?;
    println!("{}", serde_json::to_string_pretty(&explanation)?);
    Ok(())
}
