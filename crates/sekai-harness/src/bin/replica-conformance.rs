fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = sekai_chisei::db::replica_conformance::run();
    println!("{}", serde_json::to_string(&report)?);
    report
        .passed
        .then_some(())
        .ok_or_else(|| "replica conformance failed".into())
}
