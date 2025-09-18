//! GhostPanel GQUIC Integration Usage Examples
//!
//! This example demonstrates how to use the gaming-optimized QUIC implementation
//! for container management with ultra-low latency and gaming-aware optimizations.

use std::time::Duration;
use tokio;
use gquic::{
    QuicResult,
    gpanel_integration::{GpanelQuicIntegration, ContainerOperationType, GamingStatus},
    gpanel_optimizations::{GamingCongestionConfig, GamingTelemetry},
};

#[tokio::main]
async fn main() -> QuicResult<()> {
    // Initialize tracing for observability
    tracing_subscriber::init();

    // Example 1: Create a gaming-optimized QUIC server for container management
    println!("🚀 Starting GhostPanel QUIC Server...");

    let gaming_config = GamingCongestionConfig {
        max_gaming_cwnd: 32768,
        gaming_threshold_pps: 100,
        target_gaming_rtt: Duration::from_millis(5), // Sub-5ms target
        gaming_session_timeout: Duration::from_secs(30),
    };

    let mut integration = GpanelQuicIntegration::new(
        "0.0.0.0:4433", // QUIC server port
        Some(gaming_config)
    ).await?;

    // Enable container networking integration with Bolt
    integration.enable_container_networking("/var/run/bolt/bolt.sock").await?;

    println!("✅ GhostPanel QUIC server started on port 4433");

    // Example 2: Register a gaming container for optimized handling
    println!("\n🎮 Registering gaming container...");

    integration.register_gaming_container(
        "minecraft-server-1".to_string(),
        Some("gpu0".to_string()) // GPU device for gaming optimizations
    ).await?;

    let status = integration.get_gaming_status().await;
    println!("Gaming mode active: {}", status.gaming_mode_active);
    println!("Active gaming sessions: {}", status.active_gaming_sessions);

    // Example 3: Accept connections and handle container operations
    tokio::spawn(async move {
        loop {
            match integration.accept_connection().await {
                Ok(connection) => {
                    println!("📡 New gaming-optimized connection accepted");

                    // Handle different container operations with appropriate priorities
                    handle_container_operations(connection, &integration).await;
                }
                Err(e) => {
                    eprintln!("❌ Connection error: {}", e);
                    break;
                }
            }
        }
    });

    // Example 4: Simulate gaming telemetry updates
    println!("\n📊 Starting gaming telemetry simulation...");

    let integration_clone = integration.clone();
    tokio::spawn(async move {
        let mut frame_counter = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(16)).await; // 60 FPS
            frame_counter += 1;

            let telemetry = GamingTelemetry {
                gpu_utilization: 85.0 + (frame_counter as f32 * 0.1) % 10.0, // Simulated GPU load
                frame_time_ms: 16.7, // 60 FPS target
                input_lag_ms: 2.5 + (frame_counter as f32 * 0.01) % 2.0, // Simulated input lag
                network_latency_us: 2500, // 2.5ms network latency
                packet_loss_percent: 0.1,
            };

            if let Err(e) = integration_clone.update_gaming_telemetry("minecraft-server-1", telemetry).await {
                eprintln!("Failed to update gaming telemetry: {}", e);
            }

            // Print status every 5 seconds
            if frame_counter % 300 == 0 {
                let status = integration_clone.get_gaming_status().await;
                println!("🎮 Gaming Status - Sessions: {}, Buffer utilization: {:.1}%",
                         status.active_gaming_sessions, status.buffer_pool_utilization);
            }
        }
    });

    // Example 5: Maintenance cycle for cleanup and optimization
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            if let Err(e) = integration.maintenance_cycle().await {
                eprintln!("Maintenance cycle error: {}", e);
            } else {
                println!("🔧 Maintenance cycle completed");
            }
        }
    });

    // Keep the server running
    println!("\n🌟 GhostPanel QUIC server is running! Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await.unwrap();
    println!("\n🛑 Shutting down GhostPanel QUIC server...");

    Ok(())
}

async fn handle_container_operations(
    connection: std::sync::Arc<tokio::sync::Mutex<gquic::Connection>>,
    integration: &GpanelQuicIntegration,
) {
    // Example container operations with different priorities

    // 1. Critical operation: Start a gaming container
    if let Ok(stream) = integration.create_container_stream(
        connection.clone(),
        "minecraft-server-1".to_string(),
        ContainerOperationType::Start,
    ).await {
        println!("🚀 Created critical priority stream for container start");

        // Send container start command (highest priority)
        let start_command = bytes::Bytes::from(r#"{"action": "start", "image": "minecraft:latest"}"#);
        if let Err(e) = stream.send_data(start_command).await {
            eprintln!("Failed to send start command: {}", e);
        }
    }

    // 2. Gaming telemetry stream (high priority during gaming)
    if let Ok(stream) = integration.create_container_stream(
        connection.clone(),
        "minecraft-server-1".to_string(),
        ContainerOperationType::GamingTelemetry,
    ).await {
        println!("📊 Created gaming telemetry stream");

        // Send real-time gaming metrics
        let telemetry_data = bytes::Bytes::from(r#"{"gpu_util": 85.0, "input_lag": 2.5}"#);
        if let Err(e) = stream.send_data(telemetry_data).await {
            eprintln!("Failed to send telemetry: {}", e);
        }
    }

    // 3. Container logs (normal priority)
    if let Ok(stream) = integration.create_container_stream(
        connection.clone(),
        "minecraft-server-1".to_string(),
        ContainerOperationType::Logs,
    ).await {
        println!("📝 Created container logs stream");

        // Stream container logs
        let log_data = bytes::Bytes::from("[INFO] Minecraft server started successfully");
        if let Err(e) = stream.send_data(log_data).await {
            eprintln!("Failed to send logs: {}", e);
        }
    }

    // 4. Bulk operation: Image pull (lowest priority)
    if let Ok(stream) = integration.create_container_stream(
        connection,
        "minecraft-server-1".to_string(),
        ContainerOperationType::ImagePull,
    ).await {
        println!("📦 Created bulk priority stream for image pull");

        // Send image pull request (will be deprioritized during gaming)
        let pull_command = bytes::Bytes::from(r#"{"action": "pull", "image": "minecraft:1.19.2"}"#);
        if let Err(e) = stream.send_data(pull_command).await {
            eprintln!("Failed to send pull command: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gaming_optimization_integration() {
        let config = GamingCongestionConfig::default();
        let integration = GpanelQuicIntegration::new("127.0.0.1:0", Some(config)).await;

        assert!(integration.is_ok());
        let integration = integration.unwrap();

        // Test gaming container registration
        let result = integration.register_gaming_container(
            "test-gaming-container".to_string(),
            Some("gpu0".to_string())
        ).await;

        assert!(result.is_ok());

        let status = integration.get_gaming_status().await;
        assert!(status.gaming_mode_active);
        assert_eq!(status.active_gaming_sessions, 1);
    }

    #[tokio::test]
    async fn test_telemetry_updates() {
        let integration = GpanelQuicIntegration::new("127.0.0.1:0", None).await.unwrap();

        // Register gaming container first
        integration.register_gaming_container(
            "test-container".to_string(),
            None
        ).await.unwrap();

        // Update telemetry
        let telemetry = GamingTelemetry {
            gpu_utilization: 75.0,
            frame_time_ms: 16.7,
            input_lag_ms: 3.0,
            network_latency_us: 3000,
            packet_loss_percent: 0.05,
        };

        let result = integration.update_gaming_telemetry("test-container", telemetry).await;
        assert!(result.is_ok());
    }
}