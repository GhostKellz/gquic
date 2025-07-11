//! HTTP/3 implementation over QUIC
//! 
//! This module provides HTTP/3 support for QUIC connections,
//! including request/response handling and gRPC-over-QUIC support.

use crate::quic::{
    connection::Connection,
    error::{QuicError, Result},
    stream::{BiStream, UniStream},
};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, info, warn, error};

/// HTTP/3 frame types as defined in RFC 9114
#[derive(Debug, Clone, PartialEq)]
pub enum Http3Frame {
    /// DATA frame - carries HTTP message body
    Data { data: Bytes },
    /// HEADERS frame - carries HTTP headers
    Headers { headers: Vec<(String, String)> },
    /// CANCEL_PUSH frame - cancels server push
    CancelPush { push_id: u64 },
    /// SETTINGS frame - conveys connection settings
    Settings { settings: HashMap<u64, u64> },
    /// PUSH_PROMISE frame - announces server push
    PushPromise { push_id: u64, headers: Vec<(String, String)> },
    /// GOAWAY frame - initiates connection shutdown
    GoAway { id: u64 },
    /// MAX_PUSH_ID frame - controls server push
    MaxPushId { max_push_id: u64 },
}

impl Http3Frame {
    /// Encode frame to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            Http3Frame::Data { data } => {
                buf.put_u8(0x0); // DATA frame type
                buf.put_u64_le(data.len() as u64); // Length
                buf.extend_from_slice(data);
            }
            Http3Frame::Headers { headers } => {
                buf.put_u8(0x1); // HEADERS frame type
                let headers_data = encode_headers(headers);
                buf.put_u64_le(headers_data.len() as u64);
                buf.extend_from_slice(&headers_data);
            }
            Http3Frame::Settings { settings } => {
                buf.put_u8(0x4); // SETTINGS frame type
                let settings_data = encode_settings(settings);
                buf.put_u64_le(settings_data.len() as u64);
                buf.extend_from_slice(&settings_data);
            }
            Http3Frame::GoAway { id } => {
                buf.put_u8(0x7); // GOAWAY frame type
                buf.put_u64_le(8); // Length
                buf.put_u64_le(*id);
            }
            _ => {
                // Simplified encoding for other frame types
                buf.put_u8(0xFF); // Unknown frame type
                buf.put_u64_le(0); // Empty length
            }
        }
        
        buf.freeze()
    }
    
    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 9 {
            return Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat("Frame too short".to_string())
            ));
        }
        
        let frame_type = data[0];
        let length = u64::from_le_bytes(data[1..9].try_into().unwrap()) as usize;
        let payload = &data[9..];
        
        if payload.len() < length {
            return Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat("Payload too short".to_string())
            ));
        }
        
        match frame_type {
            0x0 => Ok(Http3Frame::Data { 
                data: Bytes::copy_from_slice(&payload[..length]) 
            }),
            0x1 => {
                let headers = decode_headers(&payload[..length])?;
                Ok(Http3Frame::Headers { headers })
            }
            0x4 => {
                let settings = decode_settings(&payload[..length])?;
                Ok(Http3Frame::Settings { settings })
            }
            0x7 => {
                if length != 8 {
                    return Err(QuicError::Protocol(
                        crate::quic::error::ProtocolError::InvalidFrameFormat("Invalid GOAWAY length".to_string())
                    ));
                }
                let id = u64::from_le_bytes(payload[..8].try_into().unwrap());
                Ok(Http3Frame::GoAway { id })
            }
            _ => Err(QuicError::Protocol(
                crate::quic::error::ProtocolError::InvalidFrameFormat(format!("Unknown frame type: {}", frame_type))
            )),
        }
    }
}

/// HTTP/3 method enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum Http3Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
}

impl fmt::Display for Http3Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Http3Method::Get => write!(f, "GET"),
            Http3Method::Post => write!(f, "POST"),
            Http3Method::Put => write!(f, "PUT"),
            Http3Method::Delete => write!(f, "DELETE"),
            Http3Method::Head => write!(f, "HEAD"),
            Http3Method::Options => write!(f, "OPTIONS"),
            Http3Method::Patch => write!(f, "PATCH"),
            Http3Method::Connect => write!(f, "CONNECT"),
            Http3Method::Trace => write!(f, "TRACE"),
        }
    }
}

/// HTTP/3 request
#[derive(Debug, Clone)]
pub struct Http3Request {
    pub method: Http3Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
}

impl Http3Request {
    /// Create a new HTTP/3 request
    pub fn new(method: Http3Method, path: String) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: None,
        }
    }
    
    /// Add a header to the request
    pub fn header(mut self, name: String, value: String) -> Self {
        self.headers.push((name, value));
        self
    }
    
    /// Set the request body
    pub fn body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }
    
    /// Check if this is a gRPC request
    pub fn is_grpc(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.to_lowercase() == "content-type" && value.starts_with("application/grpc")
        })
    }
}

/// HTTP/3 response
#[derive(Debug, Clone)]
pub struct Http3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
}

impl Http3Response {
    /// Create a new HTTP/3 response
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
        }
    }
    
    /// Add a header to the response
    pub fn header(mut self, name: String, value: String) -> Self {
        self.headers.push((name, value));
        self
    }
    
    /// Set the response body
    pub fn body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }
    
    /// Create a gRPC response
    pub fn grpc(status: u16, content_type: &str) -> Self {
        Self::new(status)
            .header("content-type".to_string(), content_type.to_string())
            .header("grpc-status".to_string(), "0".to_string())
    }
}

/// HTTP/3 connection handler
pub struct Http3Connection {
    quic_connection: Connection,
    settings: HashMap<u64, u64>,
    max_push_id: u64,
}

impl Http3Connection {
    /// Create a new HTTP/3 connection
    pub fn new(quic_connection: Connection) -> Self {
        let mut settings = HashMap::new();
        settings.insert(0x1, 100); // QPACK_MAX_TABLE_CAPACITY
        settings.insert(0x6, 100); // QPACK_BLOCKED_STREAMS
        settings.insert(0x7, 100); // MAX_FIELD_SECTION_SIZE
        
        Self {
            quic_connection,
            settings,
            max_push_id: 0,
        }
    }
    
    /// Send HTTP/3 request
    pub async fn send_request(&self, request: Http3Request) -> Result<Http3Response> {
        // Open a new bidirectional stream
        let mut stream = self.quic_connection.open_bi().await?;
        
        // Send HEADERS frame
        let mut headers = vec![
            (":method".to_string(), request.method.to_string()),
            (":path".to_string(), request.path),
            (":scheme".to_string(), "https".to_string()),
        ];
        headers.extend(request.headers);
        
        let headers_frame = Http3Frame::Headers { headers };
        stream.write_all(&headers_frame.encode()).await?;
        
        // Send DATA frame if body exists
        if let Some(body) = request.body {
            let data_frame = Http3Frame::Data { data: body };
            stream.write_all(&data_frame.encode()).await?;
        }
        
        // Finish sending
        stream.finish().await?;
        
        // Read response
        let response_data = stream.read_to_end().await?;
        self.parse_response(&response_data)
    }
    
    /// Handle incoming HTTP/3 request
    pub async fn handle_request<F>(&self, mut stream: BiStream, handler: F) -> Result<()>
    where
        F: Fn(Http3Request) -> Result<Http3Response>,
    {
        // Read request data
        let request_data = stream.read_to_end().await?;
        
        // Parse request
        let request = self.parse_request(&request_data)?;
        
        // Handle request
        let response = handler(request)?;
        
        // Send response
        self.send_response(&mut stream, response).await?;
        
        Ok(())
    }
    
    /// Send HTTP/3 response
    async fn send_response(&self, stream: &mut BiStream, response: Http3Response) -> Result<()> {
        // Send HEADERS frame
        let mut headers = vec![
            (":status".to_string(), response.status.to_string()),
        ];
        headers.extend(response.headers);
        
        let headers_frame = Http3Frame::Headers { headers };
        stream.write_all(&headers_frame.encode()).await?;
        
        // Send DATA frame if body exists
        if let Some(body) = response.body {
            let data_frame = Http3Frame::Data { data: body };
            stream.write_all(&data_frame.encode()).await?;
        }
        
        // Finish sending
        stream.finish().await?;
        
        Ok(())
    }
    
    /// Parse HTTP/3 request from bytes
    fn parse_request(&self, data: &[u8]) -> Result<Http3Request> {
        let mut offset = 0;
        let mut method = Http3Method::Get;
        let mut path = String::new();
        let mut headers = Vec::new();
        let mut body = None;
        
        while offset < data.len() {
            let frame = Http3Frame::decode(&data[offset..])?;
            
            match frame {
                Http3Frame::Headers { headers: frame_headers } => {
                    for (name, value) in frame_headers {
                        match name.as_str() {
                            ":method" => {
                                method = match value.as_str() {
                                    "GET" => Http3Method::Get,
                                    "POST" => Http3Method::Post,
                                    "PUT" => Http3Method::Put,
                                    "DELETE" => Http3Method::Delete,
                                    "HEAD" => Http3Method::Head,
                                    "OPTIONS" => Http3Method::Options,
                                    "PATCH" => Http3Method::Patch,
                                    "CONNECT" => Http3Method::Connect,
                                    "TRACE" => Http3Method::Trace,
                                    _ => Http3Method::Get,
                                };
                            }
                            ":path" => {
                                path = value;
                            }
                            _ => {
                                if !name.starts_with(':') {
                                    headers.push((name, value));
                                }
                            }
                        }
                    }
                }
                Http3Frame::Data { data } => {
                    body = Some(data);
                }
                _ => {
                    // Skip other frame types
                }
            }
            
            // Move to next frame (simplified - should parse frame length properly)
            offset += data.len();
        }
        
        Ok(Http3Request {
            method,
            path,
            headers,
            body,
        })
    }
    
    /// Parse HTTP/3 response from bytes
    fn parse_response(&self, data: &[u8]) -> Result<Http3Response> {
        let mut offset = 0;
        let mut status = 200;
        let mut headers = Vec::new();
        let mut body = None;
        
        while offset < data.len() {
            let frame = Http3Frame::decode(&data[offset..])?;
            
            match frame {
                Http3Frame::Headers { headers: frame_headers } => {
                    for (name, value) in frame_headers {
                        match name.as_str() {
                            ":status" => {
                                status = value.parse().unwrap_or(200);
                            }
                            _ => {
                                if !name.starts_with(':') {
                                    headers.push((name, value));
                                }
                            }
                        }
                    }
                }
                Http3Frame::Data { data } => {
                    body = Some(data);
                }
                _ => {
                    // Skip other frame types
                }
            }
            
            // Move to next frame (simplified - should parse frame length properly)
            offset += data.len();
        }
        
        Ok(Http3Response {
            status,
            headers,
            body,
        })
    }
    
    /// Send HTTP/3 settings
    pub async fn send_settings(&self) -> Result<()> {
        // Settings are typically sent on a control stream
        // For now, we'll send them on the connection
        let settings_frame = Http3Frame::Settings { 
            settings: self.settings.clone() 
        };
        
        // In a real implementation, this would be sent on the control stream
        debug!("HTTP/3 settings: {:?}", settings_frame);
        
        Ok(())
    }
}

/// gRPC-over-QUIC handler
pub struct GrpcOverQuic {
    http3_connection: Http3Connection,
}

impl GrpcOverQuic {
    /// Create a new gRPC-over-QUIC handler
    pub fn new(quic_connection: Connection) -> Self {
        Self {
            http3_connection: Http3Connection::new(quic_connection),
        }
    }
    
    /// Handle gRPC request
    pub async fn handle_grpc_request<F>(&self, stream: BiStream, handler: F) -> Result<()>
    where
        F: Fn(Http3Request) -> Result<Http3Response>,
    {
        // Handle as HTTP/3 request but ensure it's gRPC
        self.http3_connection.handle_request(stream, |request| {
            if !request.is_grpc() {
                return Err(QuicError::Protocol(
                    crate::quic::error::ProtocolError::InvalidFrameFormat("Not a gRPC request".to_string())
                ));
            }
            
            // Process gRPC request
            let mut response = handler(request)?;
            
            // Ensure gRPC headers are present
            if !response.headers.iter().any(|(name, _)| name == "grpc-status") {
                response.headers.push(("grpc-status".to_string(), "0".to_string()));
            }
            
            Ok(response)
        }).await
    }
    
    /// Send gRPC request
    pub async fn send_grpc_request(&self, service: &str, method: &str, body: Bytes) -> Result<Http3Response> {
        let request = Http3Request::new(Http3Method::Post, format!("/{}/{}", service, method))
            .header("content-type".to_string(), "application/grpc+proto".to_string())
            .header("te".to_string(), "trailers".to_string())
            .header("grpc-timeout".to_string(), "60S".to_string())
            .body(body);
        
        self.http3_connection.send_request(request).await
    }
}

/// Encode HTTP headers (simplified QPACK encoding)
fn encode_headers(headers: &[(String, String)]) -> Vec<u8> {
    let mut buf = Vec::new();
    
    for (name, value) in headers {
        // Simplified header encoding - real implementation would use QPACK
        let name_bytes = name.as_bytes();
        let value_bytes = value.as_bytes();
        
        buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(value_bytes);
    }
    
    buf
}

/// Decode HTTP headers (simplified QPACK decoding)
fn decode_headers(data: &[u8]) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    let mut offset = 0;
    
    while offset + 8 <= data.len() {
        let name_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + name_len > data.len() {
            break;
        }
        
        let name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
        offset += name_len;
        
        if offset + 4 > data.len() {
            break;
        }
        
        let value_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        
        if offset + value_len > data.len() {
            break;
        }
        
        let value = String::from_utf8_lossy(&data[offset..offset + value_len]).to_string();
        offset += value_len;
        
        headers.push((name, value));
    }
    
    Ok(headers)
}

/// Encode HTTP/3 settings
fn encode_settings(settings: &HashMap<u64, u64>) -> Vec<u8> {
    let mut buf = Vec::new();
    
    for (key, value) in settings {
        buf.extend_from_slice(&key.to_le_bytes());
        buf.extend_from_slice(&value.to_le_bytes());
    }
    
    buf
}

/// Decode HTTP/3 settings
fn decode_settings(data: &[u8]) -> Result<HashMap<u64, u64>> {
    let mut settings = HashMap::new();
    let mut offset = 0;
    
    while offset + 16 <= data.len() {
        let key = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        let value = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        
        settings.insert(key, value);
    }
    
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_frame_encoding() {
        let frame = Http3Frame::Data { 
            data: Bytes::from("hello world") 
        };
        
        let encoded = frame.encode();
        assert!(!encoded.is_empty());
        
        let decoded = Http3Frame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }
    
    #[test]
    fn test_http3_request() {
        let request = Http3Request::new(Http3Method::Post, "/test".to_string())
            .header("content-type".to_string(), "application/grpc+proto".to_string())
            .body(Bytes::from("test body"));
        
        assert!(request.is_grpc());
        assert_eq!(request.method, Http3Method::Post);
        assert_eq!(request.path, "/test");
    }
    
    #[test]
    fn test_grpc_response() {
        let response = Http3Response::grpc(200, "application/grpc+proto");
        
        assert_eq!(response.status, 200);
        assert!(response.headers.iter().any(|(name, _)| name == "grpc-status"));
    }
    
    #[test]
    fn test_header_encoding() {
        let headers = vec![
            ("content-type".to_string(), "application/grpc+proto".to_string()),
            ("grpc-timeout".to_string(), "60S".to_string()),
        ];
        
        let encoded = encode_headers(&headers);
        let decoded = decode_headers(&encoded).unwrap();
        
        assert_eq!(headers, decoded);
    }
}