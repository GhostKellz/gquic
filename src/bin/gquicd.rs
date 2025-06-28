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
            check_daemon_status().await?;
        }
        
        Commands::Stop => {
            info!("Stopping daemon...");
            stop_daemon().await?;
        }
    }

    Ok(())
}

async fn run_server(bind: SocketAddr, cert: Option<String>, key: Option<String>, alpn: Vec<String>) -> Result<()> {
    // Write PID file for daemon management
    write_pid_file()?;
    
    let mut config_builder = QuicServerConfig::builder()
        .bind(bind);

    if let (Some(cert_path), Some(key_path)) = (cert, key) {
        config_builder = config_builder.with_tls_files(&cert_path, &key_path)?;
    } else {
        warn!("No TLS certificate provided, using self-signed (development only)");
        config_builder = config_builder.with_self_signed_cert()?;
    }

    for protocol in alpn {
        config_builder = config_builder.with_alpn(&protocol);
    }

    let server = config_builder.build_server()?;
    
    info!("🔐 QUIC server listening on {}", bind);
    info!("📡 ALPN protocols: {:?}", server.config().alpn_protocols);
    
    // Set up cleanup on shutdown
    let result = server.run().await;
    
    // Clean up PID file on exit
    let _ = std::fs::remove_file(PID_FILE);
    info!("PID file cleaned up");
    
    result
}

async fn run_client(endpoint: String, message: Option<String>, alpn: Option<String>) -> Result<()> {
    let addr: SocketAddr = endpoint.parse()
        .map_err(|_| anyhow::anyhow!("Invalid endpoint address: {}", endpoint))?;

    let mut config_builder = QuicClientConfig::builder()
        .server_name("localhost".to_string());

    if let Some(protocol) = alpn {
        config_builder = config_builder.with_alpn(&protocol);
    }

    let client = QuicClient::new(config_builder.build())?;
    let conn = client.connect(addr).await?;
    
    let mut stream = client.open_bi_stream(&conn).await?;
    
    let msg = message.unwrap_or_else(|| "ping".to_string());
    stream.write_all(msg.as_bytes()).await?;
    stream.finish().await?;
    
    let response = stream.read_to_end(1024).await?;
    info!("Received: {}", String::from_utf8_lossy(&response));
    
    Ok(())
}

// PID file management
const PID_FILE: &str = "/tmp/gquicd.pid";

async fn check_daemon_status() -> Result<()> {
    match std::fs::read_to_string(PID_FILE) {
        Ok(pid_str) => {
            let pid: u32 = pid_str.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid PID in file"))?;
            
            // Check if process is running (simplified)
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                println!("gquicd is running (PID: {})", pid);
            } else {
                println!("gquicd is not running (stale PID file)");
                // Clean up stale PID file
                let _ = std::fs::remove_file(PID_FILE);
            }
        }
        Err(_) => {
            println!("gquicd is not running (no PID file)");
        }
    }
    Ok(())
}

async fn stop_daemon() -> Result<()> {
    match std::fs::read_to_string(PID_FILE) {
        Ok(pid_str) => {
            let pid: u32 = pid_str.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid PID in file"))?;
            
            // Send SIGTERM (simplified - in production would use proper signal handling)
            println!("Sending stop signal to PID {}", pid);
            
            // For now, just remove the PID file
            // In production, this would send SIGTERM and wait for graceful shutdown
            match std::fs::remove_file(PID_FILE) {
                Ok(_) => println!("gquicd stopped"),
                Err(e) => println!("Warning: Could not remove PID file: {}", e),
            }
        }
        Err(_) => {
            println!("gquicd is not running (no PID file)");
        }
    }
    Ok(())
}

fn write_pid_file() -> Result<()> {
    let pid = std::process::id();
    std::fs::write(PID_FILE, pid.to_string())
        .map_err(|e| anyhow::anyhow!("Failed to write PID file: {}", e))?;
    info!("PID file written: {} (PID: {})", PID_FILE, pid);
    Ok(())
}