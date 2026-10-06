//! `deploy/tenkai.toml` must match the documented Combined dest-pair contract (#1268).

const TENKAI: &str = include_str!("../deploy/tenkai.toml");
const CARGO: &str = include_str!("../Cargo.toml");
const COMPOSE: &str = include_str!("../docker-compose.yml");

fn quoted_assignment<'a>(src: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key} = \"");
    let rest = src.split_once(&needle)?.1;
    rest.split_once('"').map(|(value, _)| value)
}

fn crate_version() -> &'static str {
    let package = CARGO
        .split("[workspace]")
        .next()
        .expect("[package] before [workspace]");
    quoted_assignment(package, "version").expect("Cargo.toml package version")
}

fn product_version() -> &'static str {
    let product = TENKAI
        .split("[deploy]")
        .next()
        .expect("[product] before [deploy]");
    quoted_assignment(product, "version").expect("tenkai product.version")
}

fn install_script() -> &'static str {
    let deploy = TENKAI.split("[deploy]").nth(1).expect("[deploy] table");
    let after = deploy
        .split_once("install = \"\"\"")
        .expect("install heredoc")
        .1;
    after.split_once("\"\"\"").expect("install terminator").0
}

#[test]
fn tenkai_install_sets_compose_dest_pair_and_matches_crate_version() {
    let version = crate_version();
    assert_eq!(product_version(), version);
    let install = install_script();
    assert!(
        install.contains(&format!("ghcr.io/sannrox/sekai-chisei:{version}")),
        "image tag must match crate version {version}"
    );
    assert!(
        COMPOSE.contains("SEKAI_DB_PATH=/data/sekai.db"),
        "compose dest-pair is the documented contract"
    );
    assert!(
        COMPOSE.contains("CHISEI_DB_PATH=/data/chisei.db"),
        "compose dest-pair is the documented contract"
    );
    assert!(
        install.contains("-e SEKAI_DB_PATH=/data/sekai.db"),
        "bare-image install must set the Sekai dest matching compose"
    );
    assert!(
        install.contains("-e CHISEI_DB_PATH=/data/chisei.db"),
        "bare-image install must set the Chisei dest"
    );
    assert!(
        !install.contains("SEKAI_SHARED_STORE=1"),
        "dest-pair is the compose default; retired single-store variables must stay unset"
    );
}
