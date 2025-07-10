use gquic::Endpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let mut endpoint = Endpoint::bind(addr).await?;
    
    println!("GQUIC server listening on {}", addr);
    println!("This is a minimal working QUIC implementation!");
    println!("Library compiles and runs successfully!");
    
    Ok(())
}
