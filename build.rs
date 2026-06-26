fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["proto/sekai.proto", "proto/chisei.proto", "proto/llm.proto"],
            &["proto/"],
        )?;
    Ok(())
}
