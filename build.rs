use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");
    
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/proto")
        .compile(
            &[
                proto_dir.join("walletd.proto"),
            ],
            &[proto_dir],
        )?;

    println!("cargo:rerun-if-changed=proto/");
    
    Ok(())
}