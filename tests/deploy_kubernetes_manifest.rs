//! Kubernetes packaging (#1313): TLS StatefulSet, dest-pair, in-process Tenkai.
//! Probe, pod security, and Service port checks run on the parsed YAML in
//! scripts/tests/test_kubernetes_manifests.py.

const TENKAI: &str = include_str!("../deploy/kubernetes/tenkai.toml");
const STATEFULSET: &str = include_str!("../deploy/kubernetes/manifests/10-statefulset.yaml");
const EZU_ADAPTER: &str = include_str!("../deploy/kubernetes/manifests/30-ezu-adapter.yaml");
const CARGO: &str = include_str!("../Cargo.toml");

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
    quoted_assignment(product, "version").expect("kubernetes tenkai product.version")
}

#[test]
fn kubernetes_product_uses_inprocess_executor_and_matches_crate_version() {
    let version = crate_version();
    assert_eq!(product_version(), version);
    let product = TENKAI
        .split("[deploy]")
        .next()
        .expect("[product] before [deploy]");
    assert!(
        product.contains("kind = \"software\""),
        "kubernetes packaging is a software product"
    );
    assert!(
        TENKAI.contains("inputs = [\"manifests\"]"),
        "in-process executor applies manifests/"
    );
    assert!(
        TENKAI.contains("TENKAI_SOFTWARE_EXECUTOR=kubernetes-inprocess"),
        "install must name kubernetes-inprocess"
    );
    assert!(
        TENKAI.contains("exit 1"),
        "shell install must fail closed without the in-process executor"
    );
    // Tenkai runs a set `health` after the in-process workload checks, so a
    // fail-closed reminder there fails every apply.
    assert!(
        !TENKAI
            .lines()
            .any(|line| line.trim_start().starts_with("health")),
        "deploy.health must stay unset; workload conditions are the health check"
    );
}

#[test]
fn statefulset_is_single_replica_sqlite_tls() {
    let version = crate_version();
    let image = format!("ghcr.io/sannrox/sekai-chisei:v{version}");
    assert!(
        STATEFULSET.contains(&format!("image: {image}")),
        "image must use the published v-prefixed tag for crate version {version}"
    );
    assert!(
        STATEFULSET.contains("kind: StatefulSet"),
        "workload is a StatefulSet"
    );
    assert!(
        STATEFULSET.contains("replicas: 1"),
        "single replica; HA is out of scope"
    );
    assert!(
        STATEFULSET.contains("volumeClaimTemplates:"),
        "SQLite lives on a PVC"
    );
    assert!(
        STATEFULSET.contains("secretName: sekai-chisei-tls"),
        "TLS comes from Secret sekai-chisei-tls"
    );
    assert!(
        STATEFULSET.contains("value: /tls/tls.crt"),
        "SEKAI_TLS_CERT must point at the mounted certificate"
    );
    assert!(
        STATEFULSET.contains("value: /tls/tls.key"),
        "SEKAI_TLS_KEY must point at the mounted key"
    );
    assert!(
        STATEFULSET.contains("value: /data/sekai.db"),
        "bare-image dest-pair must set the Sekai dest matching compose"
    );
    assert!(
        STATEFULSET.contains("value: /data/chisei.db"),
        "bare-image dest-pair must set the Chisei dest"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_BIND"),
        "leave SEKAI_BIND unset so first boot is UDS-only until a credential exists"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_INSECURE"),
        "cluster binds must not enable insecure mode"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_ALLOW_PLAINTEXT"),
        "cluster binds must not allow plaintext gRPC"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_SOCKET"),
        "leave the image Unix socket on the PVC so first-run credential bootstrap works"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_SHARED_STORE"),
        "retired single-store variables must stay unset"
    );
}

#[test]
fn ezu_adapter_is_two_replicas_of_the_published_image() {
    let version = crate_version();
    let image = format!("ghcr.io/sannrox/sekai-chisei:v{version}");
    assert!(
        EZU_ADAPTER.contains(&format!("image: {image}")),
        "adapter image must use the published v-prefixed tag for crate version {version}"
    );
    assert!(
        EZU_ADAPTER.contains("kind: Deployment"),
        "adapter is a Deployment; nothing on disk is authoritative"
    );
    assert!(
        EZU_ADAPTER.contains("replicas: 2"),
        "two replicas, no leader"
    );
    assert!(
        EZU_ADAPTER.contains("command: [\"ezu-adapter\"]"),
        "the image runs the adapter process"
    );
    assert!(
        !EZU_ADAPTER.contains("volumeClaimTemplates:"),
        "adapter replicas share no PVC"
    );
}

#[test]
fn ezu_url_and_bearer_come_only_from_the_sealed_secret() {
    assert!(
        EZU_ADAPTER.contains("secretKeyRef:\n                  name: sekai-chisei-ezu"),
        "EZU_URL and EZU_TOKEN come from Secret sekai-chisei-ezu"
    );
    for needle in ["EZU_URL: ", "EZU_TOKEN: "] {
        assert!(
            !EZU_ADAPTER.contains(needle),
            "{needle:?} must not be a literal in the adapter manifest"
        );
    }
    assert!(
        EZU_ADAPTER.contains("value: https://sekai-chisei:50051"),
        "the adapter reaches the plane at the in-cluster Service"
    );
    assert!(
        !EZU_ADAPTER.contains("tls.key"),
        "the adapter mounts only the plane CA, not the server private key"
    );
    let config_map = EZU_ADAPTER
        .split("kind: Deployment")
        .next()
        .expect("ConfigMap document");
    assert!(
        !config_map.contains("EZU_URL") && !config_map.contains("EZU_TOKEN"),
        "the adapter ConfigMap must not hold the Ezu URL or bearer"
    );
}

#[test]
fn kubernetes_product_optionally_requires_ezu() {
    assert!(
        TENKAI.contains("[compatibility.components.sekai-chisei.requires]"),
        "kubernetes product declares optional Ezu requires so Tenkai writes a dependency document"
    );
    assert!(TENKAI.contains("\"ezu.query\""));
    assert!(TENKAI.contains("\"ezu.events\""));
    assert!(TENKAI.contains("optional = true"));
}
