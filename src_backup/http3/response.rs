// HTTP/3 response types

use bytes::Bytes;
use http::{StatusCode, HeaderMap, Version};

/// HTTP/3 response representation
#[derive(Debug, Clone)]
pub struct Http3Response {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

impl Http3Response {
    /// Create a new HTTP/3 response
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            version: Version::HTTP_3,
            headers: HeaderMap::new(),
            body: None,
        }
    }
    
    /// Create a 200 OK response
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }
    
    /// Create a 404 Not Found response
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
    }
    
    /// Create a 500 Internal Server Error response
    pub fn internal_server_error() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR)
    }
    
    /// Set the response body
    pub fn body<B: Into<Bytes>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }
    
    /// Check if the response has a body
    pub fn has_body(&self) -> bool {
        self.body.is_some()
    }
    
    /// Get the response body
    pub fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }
}
