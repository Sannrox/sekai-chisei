fn main() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["sekai.proto", "chisei.proto"] {
        let workspace_contract = std::path::Path::new("../../proto").join(name);
        let packaged_contract = std::path::Path::new("proto").join(name);
        println!("cargo:rerun-if-changed={}", packaged_contract.display());
        if workspace_contract.exists() {
            println!("cargo:rerun-if-changed={}", workspace_contract.display());
            if std::fs::read(&workspace_contract)? != std::fs::read(&packaged_contract)? {
                return Err(format!(
                    "{} must match the workspace contract {}",
                    packaged_contract.display(),
                    workspace_contract.display()
                )
                .into());
            }
        }
    }
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/sekai.proto", "proto/chisei.proto"], &["proto/"])?;
    Ok(())
}
