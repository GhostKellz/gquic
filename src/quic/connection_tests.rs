#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    
    #[tokio::test]
    async fn test_connection_creation() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
        let conn_id = ConnectionId::new();
        
        let conn = Connection::new(conn_id.clone(), addr, socket, true);
        
        assert_eq!(conn.connection_id().await, conn_id);
        assert_eq!(conn.remote_address().await, addr);
        assert_eq!(conn.state().await, ConnectionState::Initial);
    }
    
    #[tokio::test]
    async fn test_flow_controller_basic() {
        let mut controller = FlowController::new(1000, 1000);
        
        // Test initial state
        assert_eq!(controller.send_window(), 1000);
        assert_eq!(controller.receive_window(), 1000);
        assert!(controller.can_send(500));
        assert!(controller.can_send(1000));
        assert!(!controller.can_send(1001));
        
        // Test data sent
        controller.on_data_sent(500).unwrap();
        assert_eq!(controller.send_window(), 500);
        assert!(controller.can_send(500));
        assert!(!controller.can_send(501));
        
        // Test data received
        controller.on_data_received(300).unwrap();
        assert_eq!(controller.receive_window(), 700);
        
        // Test window updates
        controller.update_max_data(1500);
        assert_eq!(controller.send_window(), 1000); // 1500 - 500 sent
        
        controller.update_max_receive_data(1200);
        assert_eq!(controller.receive_window(), 900); // 1200 - 300 received
    }
    
    #[tokio::test]
    async fn test_flow_controller_limits() {
        let mut controller = FlowController::new(100, 100);
        
        // Test send limit
        controller.on_data_sent(100).unwrap();
        assert!(controller.on_data_sent(1).is_err());
        
        // Test receive limit
        controller.on_data_received(100).unwrap();
        assert!(controller.on_data_received(1).is_err());
    }
    
    #[tokio::test]
    async fn test_connection_flow_control() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
        let conn_id = ConnectionId::new();
        
        let conn = Connection::new(conn_id, addr, socket, true);
        
        // Test initial flow control state
        assert!(conn.can_send(1000).await);
        assert!(!conn.can_send(100000).await);
        
        // Test data tracking
        conn.on_data_sent(500).await.unwrap();
        assert_eq!(conn.send_window().await, 65536 - 500);
        
        conn.on_data_received(300).await.unwrap();
        assert_eq!(conn.receive_window().await, 65536 - 300);
        
        // Test window updates
        conn.update_max_data(100000).await;
        assert_eq!(conn.send_window().await, 100000 - 500);
    }
    
    #[tokio::test]
    async fn test_connection_state_transitions() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
        let conn_id = ConnectionId::new();
        
        let conn = Connection::new(conn_id, addr, socket, true);
        
        // Initial state
        assert_eq!(conn.state().await, ConnectionState::Initial);
        
        // Cannot open streams in initial state
        assert!(conn.open_bi().await.is_err());
        assert!(conn.open_uni().await.is_err());
        
        // TODO: Test state transitions when handshake is implemented
    }
    
    #[tokio::test]
    async fn test_connection_id_generation() {
        let id1 = ConnectionId::new();
        let id2 = ConnectionId::new();
        
        // IDs should be different
        assert_ne!(id1, id2);
        
        // IDs should be proper length (16 bytes for UUID)
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        
        // Test serialization
        let bytes = id1.to_bytes();
        let id3 = ConnectionId::from_bytes(&bytes);
        assert_eq!(id1, id3);
    }
    
    #[tokio::test]
    async fn test_connection_stats() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
        let conn_id = ConnectionId::new();
        
        let conn = Connection::new(conn_id, addr, socket, true);
        
        let stats = conn.stats().await;
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.streams_opened, 0);
        assert_eq!(stats.streams_closed, 0);
        assert_eq!(stats.congestion_window, 1200);
        
        // Test stat updates through flow control
        conn.on_data_sent(500).await.unwrap();
        conn.on_data_received(300).await.unwrap();
        
        let updated_stats = conn.stats().await;
        assert_eq!(updated_stats.bytes_sent, 500);
        assert_eq!(updated_stats.bytes_received, 300);
    }
    
    #[test]
    fn test_connection_state_enum() {
        use ConnectionState::*;
        
        // Test all states exist
        let states = vec![Initial, Handshaking, Connected, Closing, Closed, Failed];
        
        for state in states {
            match state {
                Initial => assert_eq!(state, ConnectionState::Initial),
                Handshaking => assert_eq!(state, ConnectionState::Handshaking),
                Connected => assert_eq!(state, ConnectionState::Connected),
                Closing => assert_eq!(state, ConnectionState::Closing),
                Closed => assert_eq!(state, ConnectionState::Closed),
                Failed => assert_eq!(state, ConnectionState::Failed),
            }
        }
    }
}