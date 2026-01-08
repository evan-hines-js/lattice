fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;

    // Re-run if proto files change
    println!("cargo:rerun-if-changed=proto/agent.proto");

    Ok(())
}
