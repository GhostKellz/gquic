use anyhow::Result;
use clap::{Parser, Subcommand};
use gquic::prelude::*;
use std::net::SocketAddr;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(name = "gquicd")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    #[arg(short, long)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start QUIC server daemon
    Server {
        #[arg(short, long, default_value = "0.0.0.0:443")]
        bind: SocketAddr,
        
        #[arg(short, long)]
        cert: Option<String>,
        
        #[arg(short, long)]
        key: Option<String>,
        
        #[arg(long)]
        alpn: Vec<String>,
    },
    
    /// Run QUIC client test
    Client {
        #[arg(short, long)]
        endpoint: String,
        
        #[arg(short, long)]
        message: Option<String>,
        
        #[arg(long)]
        alpn: Option<String>,
    },
    
    /// Show daemon status
    Status,
    
    /// Stop running daemon
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing
    let log_level = match cli.log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(log_level))
        .init();

    info!("🚀 gquicd v{} starting...", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Server { bind, cert, key, alpn } => {
            info!("Starting QUIC server on {}", bind);
            run_server(bind, cert, key, alpn).await?;
        }
        
        Commands::Client { endpoint, message, alpn } => {
            info!("Connecting to {}", endpoint);
            run_client(endpoint, message, alpn).await?;
        }
        
        Commands::Status => {
            info!("Checking daemon status...");
            // TODO: Implement status check via IPC/PID file
            println!("gquicd status: running");
        }
        
        Commands::Stop => {
            info!("Stopping daemon...");
            // TODO: Implement graceful shutdown via signal
            println!("gquicd stopped");
        }
    }

    Ok(())
}

async fn run_server(bind: SocketAddr, cert: Option<String>, key: Option<String>, alpn: Vec<String>) -> Result<()> {
    let mut config = QuicServerConfig::builder()
        .bind(bind);

    if let (Some(cert_path), Some(key_path)) = (cert, key) {
        config = config.with_tls_files(&cert_path, &key_path)?;
    } else {
        warn!("No TLS certificate provided, using self-signed (development only)");
        config = config.with_self_signed_cert()?;
    }

    for protocol in alpn {
        config = config.with_alpn(&protocol);
    }

    let server = config.build()?;
    
    info!("🔐 QUIC server listening on {}", bind);
    info!("📡 ALPN protocols: {:?}", server.config().alpn_protocols);
    
    server.run().await
}

async fn run_client(endpoint: String, message: Option<String>, alpn: Option<String>) -> Result<()> {
    let addr: SocketAddr = endpoint.parse()
        .map_err(|_| anyhow::anyhow!("Invalid endpoint address: {}", endpoint))?;

    let mut config = QuicClientConfig::builder()
        .server_name("localhost".to_string());

    if let Some(protocol) = alpn {
        config = config.with_alpn(&protocol);
    }

    let client = QuicClient::new(config.build())?;
    let conn = client.connect(addr).await?;
    
    let mut stream = client.open_bi_stream(&conn).await?;
    
    let msg = message.unwrap_or_else(|| "ping".to_string());
    stream.write_all(msg.as_bytes()).await?;
    
    let response = stream.read_to_end(1024).await?;
    info!("Received: {}", String::from_utf8_lossy(&response));
    
    Ok(())
}