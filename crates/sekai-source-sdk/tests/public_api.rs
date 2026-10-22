//! Fail CI when the public API snapshot disagrees with the crate source.
//!
//! `public-api.txt` is the retained baseline. After the crate exists on
//! `origin/main`, removing or changing a recorded item without a major bump
//! fails even if the working-tree snapshot is updated.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::punctuated::Punctuated;
use syn::{
    Fields, FnArg, GenericArgument, GenericParam, ImplItem, Item, PathArguments, ReturnType,
    Signature, Type, TypeParamBound, Visibility, WherePredicate, visit::Visit,
};

fn snapshot_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("public-api.txt")
}

fn crate_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn major(version: &str) -> &str {
    version.split('.').next().expect("semver major")
}

#[test]
fn public_api_snapshot_matches_and_major_tracks_breaks() {
    let text = fs::read_to_string(snapshot_path()).expect("public-api.txt");
    let (snap_version, body) = parse_snapshot(&text);
    let actual = surface_from_source(&crate_src());
    if body != actual {
        eprintln!("expected snapshot:\n{}", actual.join("\n"));
        assert_ne!(
            major(crate_version()),
            major(&snap_version),
            "public-api.txt is stale against the crate source. Update it. Incompatible changes also require a major crate bump"
        );
        panic!(
            "public-api.txt is stale after a major bump; replace it with the surface printed above"
        );
    }
    assert_eq!(
        crate_version(),
        snap_version,
        "public-api.txt crate-version must match CARGO_PKG_VERSION"
    );
    if let Some((base_version, base_items)) = snapshot_on_origin_main() {
        let changed: Vec<&String> = base_items
            .iter()
            .filter(|item| !actual.contains(item))
            .collect();
        if !changed.is_empty() {
            assert_ne!(
                major(crate_version()),
                major(&base_version),
                "public API items changed from origin/main require a major crate bump: {changed:?}"
            );
        }
    }
}

fn parse_snapshot(text: &str) -> (String, Vec<String>) {
    let mut lines = text.lines();
    let header = lines.next().expect("version header");
    let prefix = "# crate-version: ";
    assert!(
        header.starts_with(prefix),
        "public-api.txt must start with `{prefix}<semver>`"
    );
    let version = header[prefix.len()..].trim().to_string();
    let body = lines
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    (version, body)
}

fn snapshot_on_origin_main() -> Option<(String, Vec<String>)> {
    let output = Command::new("git")
        .args(["show", "origin/main:crates/sekai-source-sdk/public-api.txt"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(parse_snapshot(&text))
}

fn surface_from_source(src_root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    scan_file(src_root.join("lib.rs"), None, &mut names);
    for module in [
        "change_capture",
        "conformance",
        "contract",
        "discover",
        "feed",
        "github",
        "lineage",
        "sdk",
        "snapshot",
    ] {
        scan_file(
            src_root.join(format!("{module}.rs")),
            Some(module),
            &mut names,
        );
    }
    names.sort();
    names.dedup();
    names
}

fn scan_file(path: PathBuf, module: Option<&str>, names: &mut Vec<String>) {
    let src = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    });
    let file = syn::parse_file(&src).unwrap_or_else(|error| {
        panic!("parse {}: {error}", path.display());
    });
    let mut pub_types = Vec::new();
    for item in &file.items {
        match item {
            Item::Struct(item) if is_pub(&item.vis) => pub_types.push(item.ident.to_string()),
            Item::Enum(item) if is_pub(&item.vis) => pub_types.push(item.ident.to_string()),
            Item::Trait(item) if is_pub(&item.vis) => pub_types.push(item.ident.to_string()),
            _ => {}
        }
    }
    let mut visitor = SurfaceVisitor {
        module: module.map(str::to_string),
        names,
        pub_types,
    };
    visitor.visit_file(&file);
}

struct SurfaceVisitor<'a> {
    module: Option<String>,
    names: &'a mut Vec<String>,
    pub_types: Vec<String>,
}

impl SurfaceVisitor<'_> {
    fn qualify(&self, name: &str) -> String {
        match &self.module {
            Some(module) => format!("{module}::{name}"),
            None => name.to_string(),
        }
    }

    fn push(&mut self, name: String) {
        self.names.push(self.qualify(&name));
    }
}

fn is_pub(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("cfg") && attr.to_token_stream_contains_test())
}

trait CfgTest {
    fn to_token_stream_contains_test(&self) -> bool;
}

impl CfgTest for syn::Attribute {
    fn to_token_stream_contains_test(&self) -> bool {
        self.meta
            .require_list()
            .map(|list| list.tokens.to_string().contains("test"))
            .unwrap_or(false)
    }
}

fn format_path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| {
            let ident = segment.ident.to_string();
            match &segment.arguments {
                PathArguments::None => ident,
                PathArguments::AngleBracketed(args) => {
                    let inner = args
                        .args
                        .iter()
                        .map(|arg| match arg {
                            GenericArgument::Type(ty) => format_type(ty),
                            GenericArgument::Lifetime(lifetime) => lifetime.to_string(),
                            GenericArgument::Const(expr) => quote_expr(expr),
                            GenericArgument::AssocType(assoc) => {
                                format!("{}={}", assoc.ident, format_type(&assoc.ty))
                            }
                            _ => "_".into(),
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{ident}<{inner}>")
                }
                PathArguments::Parenthesized(args) => {
                    let inputs = args
                        .inputs
                        .iter()
                        .map(format_type)
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{ident}({inputs}) -> {}", format_return(&args.output))
                }
            }
        })
        .collect::<Vec<_>>()
        .join("::")
}

fn quote_expr(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(value) => value.to_string(),
            syn::Lit::Str(value) => format!("{:?}", value.value()),
            syn::Lit::Bool(value) => value.value.to_string(),
            _ => "_".into(),
        },
        _ => "_".into(),
    }
}

fn format_type(ty: &Type) -> String {
    match ty {
        Type::Path(path) => format_path(&path.path),
        Type::Reference(reference) => {
            let mutability = if reference.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{mutability}{}", format_type(&reference.elem))
        }
        Type::Tuple(tuple) => {
            let inner = tuple
                .elems
                .iter()
                .map(format_type)
                .collect::<Vec<_>>()
                .join(",");
            format!("({inner})")
        }
        Type::Slice(slice) => format!("[{}]", format_type(&slice.elem)),
        Type::Array(array) => format!("[{};{}]", format_type(&array.elem), quote_expr(&array.len)),
        Type::Paren(paren) => format_type(&paren.elem),
        Type::Never(_) => "!".into(),
        Type::Ptr(ptr) => {
            let kind = if ptr.mutability.is_some() {
                "*mut"
            } else {
                "*const"
            };
            format!("{kind} {}", format_type(&ptr.elem))
        }
        Type::BareFn(_) => "fn".into(),
        Type::ImplTrait(impl_trait) => {
            let bounds = impl_trait
                .bounds
                .iter()
                .map(format_bound)
                .collect::<Vec<_>>()
                .join("+");
            format!("impl {bounds}")
        }
        Type::TraitObject(trait_object) => {
            let bounds = trait_object
                .bounds
                .iter()
                .map(format_bound)
                .collect::<Vec<_>>()
                .join("+");
            format!("dyn {bounds}")
        }
        _ => "_".into(),
    }
}

fn format_inputs(inputs: &Punctuated<FnArg, syn::token::Comma>) -> String {
    inputs
        .iter()
        .map(|input| match input {
            FnArg::Receiver(receiver) => {
                let mutability = if receiver.mutability.is_some() {
                    "mut "
                } else {
                    ""
                };
                if receiver.reference.is_some() {
                    format!("&{mutability}self")
                } else {
                    format!("{mutability}self")
                }
            }
            FnArg::Typed(pat) => format_type(&pat.ty),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_return(ty: &ReturnType) -> String {
    match ty {
        ReturnType::Default => "()".into(),
        ReturnType::Type(_, ty) => format_type(ty),
    }
}

fn format_bound(bound: &TypeParamBound) -> String {
    match bound {
        TypeParamBound::Trait(trait_bound) => format_path(&trait_bound.path),
        TypeParamBound::Lifetime(lifetime) => lifetime.to_string(),
        _ => "_".into(),
    }
}

fn format_generic_params(generics: &syn::Generics) -> String {
    let params = generics
        .params
        .iter()
        .map(|param| match param {
            GenericParam::Type(ty) => {
                let ident = ty.ident.to_string();
                let bounds = ty
                    .bounds
                    .iter()
                    .map(format_bound)
                    .collect::<Vec<_>>()
                    .join("+");
                if bounds.is_empty() {
                    ident
                } else {
                    format!("{ident}:{bounds}")
                }
            }
            GenericParam::Lifetime(lifetime) => lifetime.lifetime.to_string(),
            GenericParam::Const(constant) => {
                format!("const {}:{}", constant.ident, format_type(&constant.ty))
            }
        })
        .collect::<Vec<_>>();
    if params.is_empty() {
        String::new()
    } else {
        format!("<{}>", params.join(","))
    }
}

fn format_where_clause(generics: &syn::Generics) -> String {
    let Some(where_clause) = &generics.where_clause else {
        return String::new();
    };
    let predicates = where_clause
        .predicates
        .iter()
        .map(|predicate| match predicate {
            WherePredicate::Type(ty) => {
                let bounds = ty
                    .bounds
                    .iter()
                    .map(format_bound)
                    .collect::<Vec<_>>()
                    .join("+");
                format!("{}:{bounds}", format_type(&ty.bounded_ty))
            }
            WherePredicate::Lifetime(lifetime) => {
                let bounds = lifetime
                    .bounds
                    .iter()
                    .map(|bound| bound.to_string())
                    .collect::<Vec<_>>()
                    .join("+");
                format!("{}:{bounds}", lifetime.lifetime)
            }
            _ => "_".into(),
        })
        .collect::<Vec<_>>();
    if predicates.is_empty() {
        String::new()
    } else {
        format!(" where {}", predicates.join(","))
    }
}

fn format_generics(generics: &syn::Generics) -> String {
    format!(
        "{}{}",
        format_generic_params(generics),
        format_where_clause(generics)
    )
}

fn format_sig(sig: &Signature) -> String {
    format!(
        "{}{}({}) -> {}{}",
        sig.ident,
        format_generic_params(&sig.generics),
        format_inputs(&sig.inputs),
        format_return(&sig.output),
        format_where_clause(&sig.generics)
    )
}

impl Visit<'_> for SurfaceVisitor<'_> {
    fn visit_item(&mut self, item: &Item) {
        match item {
            Item::Const(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                self.push(format!("{}: {}", item.ident, format_type(&item.ty)));
            }
            Item::Fn(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                self.push(format_sig(&item.sig));
            }
            Item::Struct(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                let ident = item.ident.to_string();
                self.pub_types.push(ident.clone());
                self.push(ident.clone());
                if let Fields::Named(fields) = &item.fields {
                    for field in &fields.named {
                        if is_pub(&field.vis)
                            && let Some(name) = &field.ident
                        {
                            self.push(format!("{ident}.{name}: {}", format_type(&field.ty)));
                        }
                    }
                }
            }
            Item::Enum(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                let ident = item.ident.to_string();
                self.pub_types.push(ident.clone());
                self.push(ident.clone());
                for variant in &item.variants {
                    let payload = match &variant.fields {
                        Fields::Unit => String::new(),
                        Fields::Unnamed(fields) => {
                            let inner = fields
                                .unnamed
                                .iter()
                                .map(|field| format_type(&field.ty))
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("({inner})")
                        }
                        Fields::Named(fields) => {
                            let inner = fields
                                .named
                                .iter()
                                .filter_map(|field| {
                                    field
                                        .ident
                                        .as_ref()
                                        .map(|name| format!("{name}:{}", format_type(&field.ty)))
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("{{{inner}}}")
                        }
                    };
                    self.push(format!("{ident}::{}{payload}", variant.ident));
                }
            }
            Item::Trait(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                let ident = item.ident.to_string();
                self.pub_types.push(ident.clone());
                let supertraits = item
                    .supertraits
                    .iter()
                    .map(format_bound)
                    .collect::<Vec<_>>()
                    .join("+");
                if supertraits.is_empty() {
                    self.push(format!("{ident}{}", format_generics(&item.generics)));
                } else {
                    self.push(format!(
                        "{ident}{}:{supertraits}",
                        format_generics(&item.generics)
                    ));
                }
                for trait_item in &item.items {
                    if let syn::TraitItem::Fn(method) = trait_item {
                        self.push(format!("{ident}::{}", format_sig(&method.sig)));
                    }
                }
            }
            Item::Type(item) if is_pub(&item.vis) && !is_test(&item.attrs) => {
                self.push(format!("{} = {}", item.ident, format_type(&item.ty)));
            }
            Item::Use(item)
                if is_pub(&item.vis) && !is_test(&item.attrs) && self.module.is_none() =>
            {
                collect_use_names(&item.tree, self.names);
            }
            Item::Impl(item) if !is_test(&item.attrs) && item.trait_.is_none() => {
                let Some(self_ty) = type_ident(&item.self_ty) else {
                    return;
                };
                if !self.pub_types.iter().any(|name| name == &self_ty) {
                    return;
                }
                for impl_item in &item.items {
                    if let ImplItem::Fn(method) = impl_item
                        && is_pub(&method.vis)
                    {
                        self.push(format!("{self_ty}::{}", format_sig(&method.sig)));
                    }
                }
            }
            Item::Mod(item) if is_test(&item.attrs) || item.ident == "tests" => {}
            other => syn::visit::visit_item(self, other),
        }
    }
}

fn type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|seg| seg.ident.to_string()),
        _ => None,
    }
}

fn collect_use_names(tree: &syn::UseTree, names: &mut Vec<String>) {
    match tree {
        syn::UseTree::Name(name) => names.push(name.ident.to_string()),
        syn::UseTree::Rename(rename) => names.push(rename.rename.to_string()),
        syn::UseTree::Path(path) => collect_use_names(&path.tree, names),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_names(tree, names);
            }
        }
        syn::UseTree::Glob(_) => names.push("*".into()),
    }
}
