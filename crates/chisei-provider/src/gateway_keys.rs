/// Default virtual key the gateway issues for a named client.
pub fn default_virtual_key(name: &str) -> String {
    format!("sk-chisei-{name}")
}
