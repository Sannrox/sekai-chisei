//! Kubernetes packaging (#1313): TLS StatefulSet, dest-pair, in-process Tenkai.

const TENKAI: &str = include_str!("../deploy/kubernetes/tenkai.toml");
const STATEFULSET: &str = include_str!("../deploy/kubernetes/manifests/10-statefulset.yaml");
const SERVICE: &str = include_str!("../deploy/kubernetes/manifests/20-service.yaml");
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
        "install/health must name kubernetes-inprocess"
    );
    assert!(
        TENKAI.contains("exit 1"),
        "shell install must fail closed without the in-process executor"
    );
}

#[test]
fn statefulset_is_single_replica_sqlite_tls_with_ops_probes() {
    let version = crate_version();
    let image = format!("ghcr.io/sannrox/sekai-chisei:{version}");
    assert!(
        STATEFULSET.contains(&format!("image: {image}")),
        "image tag must match crate version {version}"
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
        STATEFULSET.contains("OPS_BIND") && STATEFULSET.contains("value: \"0.0.0.0\""),
        "kubelet probes require OPS_BIND on a non-loopback address"
    );
    assert!(
        !STATEFULSET.contains("SEKAI_BIND"),
        "leave SEKAI_BIND unset so first boot is UDS-only until a credential exists"
    );
    assert!(
        STATEFULSET.contains("path: /healthz") && STATEFULSET.contains("port: ops"),
        "liveness uses the ops /healthz port"
    );
    assert!(
        STATEFULSET.contains("path: /readyz"),
        "readiness uses the ops /readyz port"
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
fn service_exposes_grpc_and_ops() {
    assert!(SERVICE.contains("kind: Service"));
    assert!(SERVICE.contains("name: grpc") && SERVICE.contains("port: 50051"));
    assert!(SERVICE.contains("name: ops") && SERVICE.contains("port: 9464"));
    assert!(SERVICE.contains("app: sekai-chisei"));
}
