use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Action {
    pub kind: String,
    pub key: String,
    pub props: HashMap<String, String>,
}
