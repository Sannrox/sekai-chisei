//! Contract compatibility matrix projection (#873).
//!
//! The matrix is derived from shipped Cargo, proto, and SDK metadata. It does
//! not invent compatibility. A consumer pin check is on-matrix only when it
//! names the exact versions and proto revision in the matrix.

use crate::sekai::client_package;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const MATRIX_CONTRACT: &str = "sekai.compatibility-matrix/v1";
pub const MATRIX_UNSUPPORTED: &str = "compatibility matrix protocol is unsupported";
pub const TYPESCRIPT_PACKAGE: &str = "@sannrox/sekai-chisei-sdk";
pub const PYTHON_PACKAGE: &str = "sekai-chisei-sdk";

const PROTO_FILES: &[&str] = &["sekai.proto", "chisei.proto"];
const TRACKED_CRATES: &[&str] = &["sekai-client", "sekai-proto", "sekai-chisei"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMatrix {
    pub contract_version: String,
    pub server_version: String,
    pub proto_revision: String,
    pub minimum_compatible_server: String,
    #[serde(default)]
    pub identity_assertion_contract: String,
    pub packages: CompatibilityPackages,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityPackages {
    #[serde(rename = "sekai-chisei")]
    pub sekai_chisei: String,
    #[serde(rename = "sekai-proto")]
    pub sekai_proto: String,
    #[serde(rename = "sekai-client")]
    pub sekai_client: String,
    pub typescript: String,
    pub python: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    OnMatrix,
    OffMatrix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinCheck {
    pub status: PinStatus,
    pub consumer: PathBuf,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CratePin {
    name: String,
    version: Option<String>,
    git: Option<String>,
    rev: Option<String>,
    path: Option<String>,
    workspace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
}

impl LockPackage {
    fn source_is_git(&self) -> bool {
        self.source
            .as_deref()
            .is_some_and(|source| source.starts_with("git+") || source.contains("?rev="))
    }

    fn label(&self) -> String {
        match &self.source {
            Some(source) if self.source_is_git() => {
                format!("lock {} source={source}", self.version)
            }
            _ => format!("lock {}", self.version),
        }
    }
}

impl CompatibilityMatrix {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .map_err(|error| format!("compatibility matrix {}: {error}", path.display()))?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        let matrix: Self = serde_json::from_str(raw)
            .map_err(|error| format!("compatibility matrix is invalid: {error}"))?;
        matrix.validate()?;
        Ok(matrix)
    }

    pub fn from_workspace(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref();
        let server_version = cargo_package_version(&root.join("Cargo.toml"))?;
        let sekai_proto = cargo_package_version(&root.join("crates/sekai-proto/Cargo.toml"))?;
        let sekai_client = cargo_package_version(&root.join("crates/sekai-client/Cargo.toml"))?;
        let typescript = json_package_version(&root.join("sdk/typescript/package.json"))?;
        let python = pyproject_project_version(&root.join("sdk/python/pyproject.toml"))?;
        let proto_revision = protocol_revision(root)?;
        let matrix = Self {
            contract_version: MATRIX_CONTRACT.to_string(),
            server_version: server_version.clone(),
            proto_revision,
            minimum_compatible_server: server_version.clone(),
            identity_assertion_contract: crate::identity_assertion::IDENTITY_ASSERTION_VERSION
                .into(),
            packages: CompatibilityPackages {
                sekai_chisei: server_version,
                sekai_proto,
                sekai_client,
                typescript,
                python,
            },
        };
        matrix.validate()?;
        require_in_tree_package_pins(root, &matrix)?;
        Ok(matrix)
    }

    pub fn to_pretty_json(&self) -> Result<String, String> {
        let mut body = serde_json::to_string_pretty(self)
            .map_err(|error| format!("compatibility matrix encode failed: {error}"))?;
        body.push('\n');
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != MATRIX_CONTRACT {
            return Err(MATRIX_UNSUPPORTED.into());
        }
        require_token("server_version", &self.server_version)?;
        require_token("minimum_compatible_server", &self.minimum_compatible_server)?;
        require_token("sekai-chisei", &self.packages.sekai_chisei)?;
        require_token("sekai-proto", &self.packages.sekai_proto)?;
        require_token("sekai-client", &self.packages.sekai_client)?;
        require_token("typescript", &self.packages.typescript)?;
        require_token("python", &self.packages.python)?;
        if !self.proto_revision.starts_with("sha256:") || self.proto_revision.len() <= 7 {
            return Err("compatibility matrix proto_revision is missing".into());
        }
        if !self.identity_assertion_contract.is_empty()
            && self.identity_assertion_contract
                != crate::identity_assertion::IDENTITY_ASSERTION_VERSION
        {
            return Err("compatibility matrix identity assertion contract is unsupported".into());
        }
        if self.packages.sekai_chisei != self.server_version {
            return Err(
                "compatibility matrix sekai-chisei version must match server_version".into(),
            );
        }
        Ok(())
    }

    pub fn expected_revision_label(&self) -> String {
        format!(
            "sekai-client {} / sekai-proto {} / proto_revision {}",
            self.packages.sekai_client, self.packages.sekai_proto, self.proto_revision
        )
    }

    pub fn expected_crate_version(&self, name: &str) -> Option<&str> {
        match name {
            "sekai-client" => Some(&self.packages.sekai_client),
            "sekai-proto" => Some(&self.packages.sekai_proto),
            "sekai-chisei" => Some(&self.packages.sekai_chisei),
            _ => None,
        }
    }
}

impl PinCheck {
    pub fn is_on_matrix(&self) -> bool {
        self.status == PinStatus::OnMatrix
    }

    pub fn report(&self) -> String {
        match self.status {
            PinStatus::OnMatrix => format!(
                "on-matrix\n  consumer: {}\n  {}",
                self.consumer.display(),
                self.summary
            ),
            PinStatus::OffMatrix => {
                format!(
                    "off-matrix\n  consumer: {}\n  {}",
                    self.consumer.display(),
                    self.summary
                )
            }
        }
    }
}

pub fn write_matrix(path: impl AsRef<Path>, matrix: &CompatibilityMatrix) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("compatibility matrix {}: {error}", parent.display()))?;
    }
    fs::write(path, matrix.to_pretty_json()?)
        .map_err(|error| format!("compatibility matrix {}: {error}", path.display()))
}

pub fn check_consumer(
    matrix: &CompatibilityMatrix,
    consumer: impl AsRef<Path>,
) -> Result<PinCheck, String> {
    matrix.validate()?;
    let consumer = consumer.as_ref();
    if !consumer.exists() {
        return Err(format!("consumer {} does not exist", consumer.display()));
    }
    let cargo = consumer.join("Cargo.toml");
    let package_json = consumer.join("package.json");
    let pyproject = consumer.join("pyproject.toml");
    let mut checks = Vec::new();
    if cargo.is_file() {
        checks.push(check_rust_consumer(matrix, consumer, &cargo)?);
    }
    if package_json.is_file() {
        checks.push(check_typescript_consumer(matrix, consumer, &package_json)?);
    }
    if pyproject.is_file() {
        checks.push(check_python_consumer(matrix, consumer, &pyproject)?);
    }
    if checks.is_empty() {
        return Err(format!(
            "consumer {} has no Cargo.toml, package.json, or pyproject.toml",
            consumer.display()
        ));
    }
    if let Some(off) = checks.iter().find(|check| !check.is_on_matrix()) {
        return Ok(off.clone());
    }
    Ok(on_matrix(
        consumer,
        format!("pins match {}", matrix.expected_revision_label()),
    ))
}

fn check_rust_consumer(
    matrix: &CompatibilityMatrix,
    consumer: &Path,
    manifest: &Path,
) -> Result<PinCheck, String> {
    let body = read_text(manifest)?;
    let pins = parse_manifest_pins(&body);
    let locks = match cargo_lock_path(consumer) {
        Some(lock) => pins_from_cargo_lock(&read_text(&lock)?),
        None => Vec::new(),
    };
    if pins.is_empty() && !locks.iter().any(|lock| is_tracked_crate(&lock.name)) {
        return Ok(off_matrix(
            consumer,
            format!(
                "no sekai-client, sekai-proto, or sekai-chisei pin; expected {}",
                matrix.expected_revision_label()
            ),
        ));
    }
    for pin in &pins {
        let pin = resolve_workspace_pin(consumer, pin)?;
        if let Some(reason) = rust_pin_mismatch(matrix, consumer, &pin, &locks)? {
            return Ok(off_matrix(consumer, reason));
        }
    }
    for lock in &locks {
        if !is_tracked_crate(&lock.name) || pins.iter().any(|pin| pin.name == lock.name) {
            continue;
        }
        if let Some(reason) = lock_only_mismatch(matrix, lock) {
            return Ok(off_matrix(consumer, reason));
        }
    }
    Ok(on_matrix(
        consumer,
        format!("rust pins match {}", matrix.expected_revision_label()),
    ))
}

fn rust_pin_mismatch(
    matrix: &CompatibilityMatrix,
    consumer: &Path,
    pin: &CratePin,
    locks: &[LockPackage],
) -> Result<Option<String>, String> {
    let expected = matrix
        .expected_crate_version(&pin.name)
        .expect("tracked crate");
    if pin.git.is_some() || pin.rev.is_some() {
        return Ok(Some(off_matrix_pin(
            &pin.name,
            &displayed_pin(pin),
            expected,
            matrix,
        )));
    }
    if let Some(reason) = lock_instances_mismatch(matrix, &pin.name, expected, locks) {
        return Ok(Some(reason));
    }
    if let Some(relative) = pin.path.as_deref() {
        let crate_dir = consumer.join(relative);
        let path_version = cargo_package_version(&crate_dir.join("Cargo.toml"))?;
        if path_version != expected {
            return Ok(Some(off_matrix_pin(
                &pin.name,
                &format!("path {} version {path_version}", crate_dir.display()),
                expected,
                matrix,
            )));
        }
        if let Some(req) = pin.version.as_deref()
            && let Some(exact) = exact_cargo_version(req)
            && exact != expected
        {
            return Ok(Some(off_matrix_pin(&pin.name, exact, expected, matrix)));
        }
        return Ok(None);
    }
    let Some(req) = pin.version.as_deref() else {
        return Ok(Some(off_matrix_pin(
            &pin.name,
            &displayed_pin(pin),
            expected,
            matrix,
        )));
    };
    if let Some(exact) = exact_cargo_version(req) {
        if exact != expected {
            return Ok(Some(off_matrix_pin(&pin.name, exact, expected, matrix)));
        }
        return Ok(None);
    }
    if is_plain_semver(req) {
        if req != expected {
            return Ok(Some(off_matrix_pin(&pin.name, req, expected, matrix)));
        }
        if locks.iter().any(|package| package.name == pin.name) {
            return Ok(None);
        }
        return Ok(Some(format!(
            "{} pin {req} is a Cargo caret range, not an exact pin; expected {} ={expected} ({})",
            pin.name,
            pin.name,
            matrix.expected_revision_label()
        )));
    }
    Ok(Some(format!(
        "{} pin {req} is not an exact version; expected {} ={expected} ({})",
        pin.name,
        pin.name,
        matrix.expected_revision_label()
    )))
}

fn lock_only_mismatch(matrix: &CompatibilityMatrix, lock: &LockPackage) -> Option<String> {
    let expected = matrix.expected_crate_version(&lock.name)?;
    lock_instances_mismatch(matrix, &lock.name, expected, std::slice::from_ref(lock))
}

fn lock_instances_mismatch(
    matrix: &CompatibilityMatrix,
    name: &str,
    expected: &str,
    locks: &[LockPackage],
) -> Option<String> {
    locks
        .iter()
        .filter(|package| package.name == name)
        .find_map(|lock| {
            (lock.source_is_git() || lock.version != expected)
                .then(|| off_matrix_pin(name, &lock.label(), expected, matrix))
        })
}

fn check_typescript_consumer(
    matrix: &CompatibilityMatrix,
    consumer: &Path,
    package_json: &Path,
) -> Result<PinCheck, String> {
    let value: serde_json::Value = serde_json::from_str(&read_text(package_json)?)
        .map_err(|error| format!("{}: {error}", package_json.display()))?;
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if name == TYPESCRIPT_PACKAGE || contains_vendored_proto(consumer) {
        return Ok(off_matrix(
            consumer,
            format!(
                "vendored TypeScript copy is off-matrix until replaced by a pin of {TYPESCRIPT_PACKAGE} {}; expected {}",
                matrix.packages.typescript,
                matrix.expected_revision_label()
            ),
        ));
    }
    if let Some(found) = json_dependency_version(&value, TYPESCRIPT_PACKAGE) {
        if found == matrix.packages.typescript {
            return Ok(on_matrix(
                consumer,
                format!(
                    "{TYPESCRIPT_PACKAGE} {} matches {}",
                    found,
                    matrix.expected_revision_label()
                ),
            ));
        }
        return Ok(off_matrix(
            consumer,
            off_matrix_pin(
                TYPESCRIPT_PACKAGE,
                &found,
                &matrix.packages.typescript,
                matrix,
            ),
        ));
    }
    Ok(off_matrix(
        consumer,
        format!(
            "no {TYPESCRIPT_PACKAGE} pin; expected {}",
            matrix.expected_revision_label()
        ),
    ))
}

fn check_python_consumer(
    matrix: &CompatibilityMatrix,
    consumer: &Path,
    pyproject: &Path,
) -> Result<PinCheck, String> {
    let body = read_text(pyproject)?;
    if pyproject_project_name(&body).as_deref() == Some(PYTHON_PACKAGE)
        || contains_vendored_proto(consumer)
    {
        return Ok(off_matrix(
            consumer,
            format!(
                "vendored Python copy is off-matrix until replaced by a pin of {PYTHON_PACKAGE} {}; expected {}",
                matrix.packages.python,
                matrix.expected_revision_label()
            ),
        ));
    }
    if let Some(found) = python_dependency_version(&body, PYTHON_PACKAGE) {
        if found == matrix.packages.python {
            return Ok(on_matrix(
                consumer,
                format!(
                    "{PYTHON_PACKAGE} {} matches {}",
                    found,
                    matrix.expected_revision_label()
                ),
            ));
        }
        return Ok(off_matrix(
            consumer,
            off_matrix_pin(PYTHON_PACKAGE, &found, &matrix.packages.python, matrix),
        ));
    }
    Ok(off_matrix(
        consumer,
        format!(
            "no {PYTHON_PACKAGE} pin; expected {}",
            matrix.expected_revision_label()
        ),
    ))
}

fn require_in_tree_package_pins(root: &Path, matrix: &CompatibilityMatrix) -> Result<(), String> {
    let client = parse_crate_pin(
        &read_text(&root.join("crates/sekai-client/Cargo.toml"))?,
        "sekai-proto",
    )
    .ok_or_else(|| "crates/sekai-client does not pin sekai-proto".to_string())?;
    match client.version.as_deref() {
        Some(version) if version == matrix.packages.sekai_proto => Ok(()),
        Some(version) => Err(format!(
            "crates/sekai-client pins sekai-proto {version}; expected {}",
            matrix.expected_revision_label()
        )),
        None => Err(format!(
            "crates/sekai-client sekai-proto pin has no version; expected {}",
            matrix.expected_revision_label()
        )),
    }
}

pub fn protocol_revision(root: impl AsRef<Path>) -> Result<String, String> {
    client_package::digest_bytes("protocol", &protocol_body(root.as_ref())?)
}

fn protocol_body(root: &Path) -> Result<String, String> {
    let mut body = String::new();
    for name in PROTO_FILES {
        let canonical = read_text(&root.join("proto").join(name))?;
        let crate_copy = read_text(&root.join("crates/sekai-proto/proto").join(name))?;
        if canonical != crate_copy {
            return Err(format!(
                "{name} in proto/ and crates/sekai-proto/proto/ diverge"
            ));
        }
        body.push_str(&canonical);
        body.push('\n');
    }
    Ok(body)
}

fn cargo_package_version(path: &Path) -> Result<String, String> {
    let body = read_text(path)?;
    table_assignment(&body, "package", "version")
        .ok_or_else(|| format!("{} is missing [package].version", path.display()))
}

fn json_package_version(path: &Path) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(&read_text(path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{} is missing version", path.display()))
}

fn pyproject_project_version(path: &Path) -> Result<String, String> {
    table_assignment(&read_text(path)?, "project", "version")
        .ok_or_else(|| format!("{} is missing [project].version", path.display()))
}

fn pyproject_project_name(body: &str) -> Option<String> {
    table_assignment(body, "project", "name")
}

fn json_dependency_version(value: &serde_json::Value, name: &str) -> Option<String> {
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(version) = value
            .get(key)
            .and_then(serde_json::Value::as_object)
            .and_then(|deps| deps.get(name))
            .and_then(serde_json::Value::as_str)
        {
            return Some(version.trim_start_matches('=').to_string());
        }
    }
    None
}

fn python_dependency_version(body: &str, name: &str) -> Option<String> {
    let project = uncomment(table_body(body, "project")?);
    let after = assignment_after(&project, "dependencies")?;
    for item in toml_string_array(after)? {
        let Some(rest) = item.trim().strip_prefix(name) else {
            continue;
        };
        if let Some(version) = rest.trim_start().strip_prefix("==") {
            let version = version.trim().to_string();
            if !version.is_empty() {
                return Some(version);
            }
        }
    }
    None
}

fn toml_string_array(src: &str) -> Option<Vec<String>> {
    let body = inline_table_like(src, '[', ']')?;
    let mut values = Vec::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        rest = rest.trim_start_matches([',', ' ', '\n', '\t']);
        if rest.is_empty() {
            break;
        }
        let value = quoted_value(rest)?;
        let consumed = 1 + value.len() + 1;
        values.push(value);
        rest = rest.get(consumed..)?.trim_start();
    }
    Some(values)
}

fn inline_table_like(src: &str, open: char, close: char) -> Option<&str> {
    let src = src.trim_start();
    if !src.starts_with(open) {
        return None;
    }
    let mut depth = 0;
    for (index, ch) in src.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(&src[1..index]);
            }
        }
    }
    None
}

fn parse_crate_pin(body: &str, name: &str) -> Option<CratePin> {
    parse_manifest_pins(body)
        .into_iter()
        .find(|pin| pin.name == name)
}

fn parse_manifest_pins(body: &str) -> Vec<CratePin> {
    let mut pins = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = table_body(body, section) {
            pins.extend(parse_inline_dep_assignments(table));
        }
        pins.extend(parse_dotted_dep_tables(body, section));
    }
    pins.extend(parse_target_dep_tables(body));
    pins.into_iter()
        .filter(|pin| is_tracked_crate(&pin.name))
        .collect()
}

fn parse_target_dep_tables(body: &str) -> Vec<CratePin> {
    let mut pins = Vec::new();
    let mut from = 0;
    while let Some(rel) = body[from..].find("[target.") {
        let start = from + rel;
        let after = &body[start + 1..];
        let Some(end) = after.find(']') else {
            break;
        };
        let header = &after[..end];
        let table = rest_table_body(&after[end + 1..]);
        if header.ends_with(".dependencies")
            || header.ends_with(".dev-dependencies")
            || header.ends_with(".build-dependencies")
        {
            pins.extend(parse_inline_dep_assignments(table));
        } else if let Some(name) = target_package_name(header)
            && let Some(pin) = pin_from_keys(name, table)
        {
            pins.push(pin);
        }
        from = start + 8;
    }
    pins
}

fn target_package_name(header: &str) -> Option<&str> {
    for marker in [
        ".dependencies.",
        ".dev-dependencies.",
        ".build-dependencies.",
    ] {
        if let Some((_, name)) = header.rsplit_once(marker)
            && !name.is_empty()
            && !name.contains('.')
        {
            return Some(name);
        }
    }
    None
}

fn parse_inline_dep_assignments(table: &str) -> Vec<CratePin> {
    let mut pins = Vec::new();
    let haystack = uncomment(table);
    let mut lines = haystack.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let Some(name) = parse_dep_key(trimmed[..eq].trim()) else {
            continue;
        };
        let name = name.as_str();
        let mut after = trimmed[eq + 1..].trim().to_string();
        if after.starts_with('{') && !after.contains('}') {
            for next in lines.by_ref() {
                after.push(' ');
                after.push_str(next.trim());
                if after.contains('}') {
                    break;
                }
            }
        }
        if let Some(pin) = pin_from_assignment(name, &after) {
            pins.push(pin);
        }
    }
    pins
}

fn parse_dotted_dep_tables(body: &str, section: &str) -> Vec<CratePin> {
    let mut pins = Vec::new();
    let needle = format!("[{section}.");
    let mut from = 0;
    while let Some(rel) = body[from..].find(&needle) {
        let start = from + rel;
        let after = &body[start + needle.len()..];
        let Some(end) = after.find(']') else {
            break;
        };
        let key = after[..end].trim();
        let table = rest_table_body(&after[end + 1..]);
        if let Some(pin) = pin_from_keys(key, table) {
            pins.push(pin);
        }
        from = start + needle.len();
    }
    pins
}

fn pin_from_assignment(name: &str, after: &str) -> Option<CratePin> {
    if after.starts_with('{') {
        return pin_from_keys(name, inline_table(after)?);
    }
    Some(CratePin {
        name: name.to_string(),
        version: quoted_value(after),
        git: None,
        rev: None,
        path: None,
        workspace: false,
    })
}

fn pin_from_keys(name: &str, table: &str) -> Option<CratePin> {
    Some(CratePin {
        name: quoted_key(table, "package").unwrap_or_else(|| name.to_string()),
        version: quoted_key(table, "version"),
        git: quoted_key(table, "git"),
        rev: quoted_key(table, "rev"),
        path: quoted_key(table, "path"),
        workspace: bool_key(table, "workspace"),
    })
}

fn resolve_workspace_pin(consumer: &Path, pin: &CratePin) -> Result<CratePin, String> {
    if !pin.workspace {
        return Ok(pin.clone());
    }
    let Some(root) = workspace_root(consumer) else {
        return Ok(pin.clone());
    };
    let body = read_text(&root.join("Cargo.toml"))?;
    let Some(table) = table_body(&body, "workspace.dependencies") else {
        return Ok(pin.clone());
    };
    let mut inherited = parse_inline_dep_assignments(table)
        .into_iter()
        .chain(parse_dotted_dep_tables(&body, "workspace.dependencies"))
        .find(|inherited| inherited.name == pin.name)
        .ok_or_else(|| {
            format!(
                "workspace pin {} is not declared in [workspace.dependencies]",
                pin.name
            )
        })?;
    inherited.name = pin.name.clone();
    Ok(inherited)
}

fn workspace_root(consumer: &Path) -> Option<PathBuf> {
    for dir in consumer.ancestors().skip(1) {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() && is_workspace_root(&manifest) {
            return Some(dir.to_path_buf());
        }
    }
    None
}

fn bool_key(src: &str, key: &str) -> bool {
    assignment_after(&uncomment(src), key)
        .is_some_and(|value| value.trim_start().starts_with("true"))
}

fn parse_dep_key(name: &str) -> Option<String> {
    if is_ident(name) {
        return Some(name.to_string());
    }
    quoted_value(name)
}

fn pins_from_cargo_lock(body: &str) -> Vec<LockPackage> {
    let mut pins = Vec::new();
    for package in body.split("[[package]]").skip(1) {
        let wrapped = format!("[package]\n{package}");
        let Some(name) = table_assignment(&wrapped, "package", "name") else {
            continue;
        };
        if !is_tracked_crate(&name) {
            continue;
        }
        if let Some(version) = table_assignment(&wrapped, "package", "version") {
            pins.push(LockPackage {
                name,
                version,
                source: table_assignment(&wrapped, "package", "source"),
            });
        }
    }
    pins
}

fn cargo_lock_path(consumer: &Path) -> Option<PathBuf> {
    let local = consumer.join("Cargo.lock");
    if local.is_file() {
        return Some(local);
    }
    for dir in consumer.ancestors().skip(1) {
        let manifest = dir.join("Cargo.toml");
        let lock = dir.join("Cargo.lock");
        if lock.is_file() && manifest.is_file() && is_workspace_root(&manifest) {
            return Some(lock);
        }
    }
    None
}

fn is_workspace_root(manifest: &Path) -> bool {
    read_text(manifest)
        .ok()
        .and_then(|body| table_body(&body, "workspace").map(|_| ()))
        .is_some()
}

fn is_tracked_crate(name: &str) -> bool {
    TRACKED_CRATES.contains(&name)
}

fn exact_cargo_version(req: &str) -> Option<&str> {
    let exact = req.trim().strip_prefix('=')?.trim();
    is_plain_semver(exact).then_some(exact)
}

fn is_plain_semver(req: &str) -> bool {
    let mut parts = req.split('.');
    let count = parts.clone().count();
    (2..=3).contains(&count)
        && parts.all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn uncomment(src: &str) -> String {
    src.lines()
        .map(strip_comment)
        .collect::<Vec<_>>()
        .join("\n")
}

fn rest_table_body(after: &str) -> &str {
    let end = after.find("\n[").unwrap_or(after.len());
    &after[..end]
}

fn table_assignment(src: &str, table: &str, key: &str) -> Option<String> {
    quoted_key(table_body(src, table)?, key)
}

fn table_body<'a>(src: &'a str, table: &str) -> Option<&'a str> {
    let header = format!("[{table}]");
    let start = src.find(&header)?;
    let after = &src[start + header.len()..];
    let end = after
        .find("\n[")
        .or_else(|| after.find("\r\n["))
        .unwrap_or(after.len());
    Some(&after[..end])
}

fn quoted_key(src: &str, key: &str) -> Option<String> {
    quoted_value(assignment_after(&uncomment(src), key)?)
}

fn assignment_after<'a>(src: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(rel) = src[from..].find(key) {
        let index = from + rel;
        let bounded = index == 0
            || src[..index]
                .chars()
                .last()
                .is_some_and(|ch| ch.is_whitespace() || ch == ',' || ch == '{');
        if bounded && let Some(after) = src[index + key.len()..].trim_start().strip_prefix('=') {
            return Some(after.trim_start());
        }
        from = index + key.len();
    }
    None
}

fn quoted_value(src: &str) -> Option<String> {
    let src = src.trim();
    let bytes = src.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &src[1..];
    let end = rest.find(quote as char)?;
    Some(rest[..end].to_string())
}

fn inline_table(src: &str) -> Option<&str> {
    inline_table_like(src, '{', '}')
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut quote = '\0';
    for (index, ch) in line.char_indices() {
        if !in_quotes && (ch == '"' || ch == '\'') {
            in_quotes = true;
            quote = ch;
        } else if in_quotes && ch == quote {
            in_quotes = false;
        } else if ch == '#' && !in_quotes {
            return &line[..index];
        }
    }
    line
}

fn contains_vendored_proto(consumer: &Path) -> bool {
    [
        "sekai.proto",
        "chisei.proto",
        "proto/sekai.proto",
        "proto/chisei.proto",
    ]
    .iter()
    .any(|name| consumer.join(name).is_file())
}

fn displayed_pin(pin: &CratePin) -> String {
    if let Some(rev) = &pin.rev {
        return format!("rev={rev}");
    }
    if let Some(git) = &pin.git {
        return format!("git={git}");
    }
    if let Some(path) = &pin.path {
        return format!("path={path}");
    }
    pin.version
        .clone()
        .unwrap_or_else(|| "unversioned".to_string())
}

fn off_matrix_pin(name: &str, found: &str, expected: &str, matrix: &CompatibilityMatrix) -> String {
    format!(
        "{name} pin {found} is off-matrix; expected {name} {expected} ({})",
        matrix.expected_revision_label()
    )
}

fn on_matrix(consumer: &Path, summary: String) -> PinCheck {
    PinCheck {
        status: PinStatus::OnMatrix,
        consumer: consumer.to_path_buf(),
        summary,
    }
}

fn off_matrix(consumer: &Path, summary: String) -> PinCheck {
    PinCheck {
        status: PinStatus::OffMatrix,
        consumer: consumer.to_path_buf(),
        summary,
    }
}

fn require_token(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("compatibility matrix {field} is missing"));
    }
    Ok(())
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_matrix() -> CompatibilityMatrix {
        CompatibilityMatrix {
            contract_version: MATRIX_CONTRACT.to_string(),
            server_version: "1.0.1".into(),
            proto_revision: "sha256:proto".into(),
            minimum_compatible_server: "1.0.1".into(),
            identity_assertion_contract: crate::identity_assertion::IDENTITY_ASSERTION_VERSION
                .into(),
            packages: CompatibilityPackages {
                sekai_chisei: "1.0.1".into(),
                sekai_proto: "1.0.1".into(),
                sekai_client: "0.1.2".into(),
                typescript: "0.1.0".into(),
                python: "0.1.0".into(),
            },
        }
    }

    fn write_consumer(body: &str) -> (TempDir, PathBuf) {
        let root = TempDir::new().unwrap();
        let consumer = root.path().join("consumer");
        fs::create_dir_all(&consumer).unwrap();
        fs::write(consumer.join("Cargo.toml"), body).unwrap();
        (root, consumer)
    }

    #[test]
    fn rust_version_pin_is_on_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"delivery-plane\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn rust_git_rev_pin_names_the_expected_revision() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"agent-harness\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = { git = \"https://example.invalid/sekai-chisei\", rev = \"deadbeef\" }\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("rev=deadbeef"), "{}", check.summary);
        assert!(
            check.summary.contains("sekai-client 0.1.2"),
            "{}",
            check.summary
        );
        assert!(check.summary.contains("sha256:proto"), "{}", check.summary);
    }

    #[test]
    fn rust_mismatched_version_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"stale\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"0.1.1\"\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("0.1.1"));
        assert!(
            check.summary.contains("sekai-client 0.1.2"),
            "{}",
            check.summary
        );
    }

    #[test]
    fn rust_lockfile_mismatch_fails_closed() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"locked\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n",
        );
        fs::write(
            consumer.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("0.1.0"), "{}", check.summary);
    }

    #[test]
    fn typescript_dependency_pin_is_on_matrix() {
        let matrix = sample_matrix();
        let root = TempDir::new().unwrap();
        let consumer = root.path().join("ts");
        fs::create_dir_all(&consumer).unwrap();
        fs::write(
            consumer.join("package.json"),
            r#"{"name":"delivery-ui","version":"1.0.0","dependencies":{"@sannrox/sekai-chisei-sdk":"0.1.0"}}"#,
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn vendored_typescript_copy_is_off_matrix() {
        let matrix = sample_matrix();
        let root = TempDir::new().unwrap();
        let consumer = root.path().join("vendored");
        fs::create_dir_all(consumer.join("proto")).unwrap();
        fs::write(
            consumer.join("package.json"),
            r#"{"name":"@sannrox/sekai-chisei-sdk","version":"0.1.0"}"#,
        )
        .unwrap();
        fs::write(consumer.join("proto/sekai.proto"), "syntax = \"proto3\";\n").unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(
            check.summary.contains("vendored TypeScript copy"),
            "{}",
            check.summary
        );
        assert!(check.summary.contains("sha256:proto"), "{}", check.summary);
    }

    #[test]
    fn rust_caret_pin_without_lockfile_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"caret\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"0.1.2\"\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("caret range"), "{}", check.summary);
        assert!(check.summary.contains("=0.1.2"), "{}", check.summary);
    }

    #[test]
    fn rust_caret_pin_with_resolved_registry_lock_is_on_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"caret-locked\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"0.1.2\"\n",
        );
        fs::write(
            consumer.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn rust_lockfile_git_source_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"git-lock\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n",
        );
        fs::write(
            consumer.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"git+https://github.com/Sannrox/sekai-chisei?rev=deadbeef#deadbeef\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("git+"), "{}", check.summary);
        assert!(check.summary.contains("0.1.2"), "{}", check.summary);
    }

    #[test]
    fn rust_renamed_package_pin_is_on_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"renamed\"\nversion = \"0.0.1\"\n\n[dependencies]\nclient = { package = \"sekai-client\", version = \"=0.1.2\" }\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn python_inline_project_dependency_is_on_matrix() {
        let matrix = sample_matrix();
        let root = TempDir::new().unwrap();
        let consumer = root.path().join("py");
        fs::create_dir_all(&consumer).unwrap();
        fs::write(
            consumer.join("pyproject.toml"),
            "[project]\nname = \"delivery-jobs\"\nversion = \"0.0.1\"\ndependencies = [\"requests==2.32.0\", \"sekai-chisei-sdk==0.1.0\"]\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn rust_second_lock_instance_cannot_hide_a_git_source() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"dual-lock\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n",
        );
        fs::write(
            consumer.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"git+https://github.com/Sannrox/sekai-chisei?rev=deadbeef#deadbeef\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("git+"), "{}", check.summary);
    }

    #[test]
    fn rust_caret_declaration_must_name_the_matrix_version() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"newer\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"0.2.0\"\n",
        );
        fs::write(
            consumer.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("0.2.0"), "{}", check.summary);
    }

    #[test]
    fn rust_target_dependency_git_pin_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"target-dep\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n\n[target.'cfg(unix)'.dependencies]\nsekai-proto = { git = \"https://example.invalid/repo\", rev = \"deadbeef\" }\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("sekai-proto"), "{}", check.summary);
    }

    #[test]
    fn rust_workspace_inherited_exact_pin_is_on_matrix() {
        let matrix = sample_matrix();
        let root = TempDir::new().unwrap();
        let workspace = root.path().join("workspace");
        let member = workspace.join("member");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n\n[workspace.dependencies]\nsekai-client = \"=0.1.2\"\n",
        )
        .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = { workspace = true }\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &member).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn rust_quoted_key_git_pin_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"quoted\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n\"sekai-proto\" = { git = \"https://example.invalid/repo\", rev = \"deadbeef\" }\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("sekai-proto"), "{}", check.summary);
    }

    #[test]
    fn rust_target_subtable_git_pin_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"subtable\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"=0.1.2\"\n\n[target.'cfg(unix)'.dependencies.sekai-proto]\ngit = \"https://example.invalid/repo\"\nrev = \"deadbeef\"\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(check.summary.contains("sekai-proto"), "{}", check.summary);
    }

    #[test]
    fn rust_workspace_lockfile_is_used_for_member_consumers() {
        let matrix = sample_matrix();
        let root = TempDir::new().unwrap();
        let workspace = root.path().join("workspace");
        let member = workspace.join("member");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .unwrap();
        fs::write(
            workspace.join("Cargo.lock"),
            "[[package]]\nname = \"sekai-client\"\nversion = \"0.1.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = \"0.1.2\"\n",
        )
        .unwrap();
        let check = check_consumer(&matrix, &member).unwrap();
        assert!(check.is_on_matrix(), "{}", check.report());
    }

    #[test]
    fn rust_compact_git_assignment_is_off_matrix() {
        let matrix = sample_matrix();
        let (_keep, consumer) = write_consumer(
            "[package]\nname = \"compact\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = { version=\"=0.1.2\", git=\"https://example.invalid/repo\", rev=\"deadbeef\" }\n",
        );
        let check = check_consumer(&matrix, &consumer).unwrap();
        assert!(!check.is_on_matrix());
        assert!(
            check.summary.contains("rev=deadbeef") || check.summary.contains("git="),
            "{}",
            check.summary
        );
    }

    #[test]
    fn unknown_matrix_contract_fails_closed() {
        let error = CompatibilityMatrix::from_json(
            r#"{"contract_version":"other","server_version":"1","proto_revision":"sha256:x","minimum_compatible_server":"1","packages":{"sekai-chisei":"1","sekai-proto":"1","sekai-client":"1","typescript":"1","python":"1"}}"#,
        )
        .unwrap_err();
        assert_eq!(error, MATRIX_UNSUPPORTED);
    }
}
