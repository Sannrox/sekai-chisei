#[path = "../../build/emit_git_version.rs"]
mod emit_git_version;

fn main() {
    emit_git_version::emit();
}
