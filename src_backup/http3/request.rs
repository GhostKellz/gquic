// HTTP/3 request types and handling

use bytes::Bytes;
use std::collections::HashMap;
use http::{Method, Uri, Version, HeaderMap, HeaderName, HeaderValue};

/// HTTP/3 request representation
#[derive(Debug, Clone)]
pub struct Http3Request {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

impl Http3Request {
    /// Create a new HTTP/3 request
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            version: Version::HTTP_3,
            headers: HeaderMap::new(),
            body: None,
        }
    }
    
    /// Create a GET request
    pub fn get(uri: Uri) -> Self {
        Self::new(Method::GET, uri)
    }
    
    /// Create a POST request  
    pub fn post(uri: Uri) -> Self {
        Self::new(Method::POST, uri)
    }
    
    /// Create a PUT request
    pub fn put(uri: Uri) -> Self {
        Self::new(Method::PUT, uri)
    }
    
    /// Create a DELETE request
    pub fn delete(uri: Uri) -> Self {
        Self::new(Method::DELETE, uri)
    }
    
    /// Add a header to the request
    pub fn header<K, V>(mut self, key: K, value: V) -> Self 
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        if let (Ok(name), Ok(val)) = (HeaderName::try_from(key), HeaderValue::try_from(value)) {
            self.headers.insert(name, val);
        }
        self
    }
    
    /// Set the request body
    pub fn body<B: Into<Bytes>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }
    
    /// Convert to pseudo-headers for HTTP/3 transmission
    pub fn to_pseudo_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        
        headers.insert(":method".to_string(), self.method.to_string());
        headers.insert(":path".to_string(), self.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string());
        headers.insert(":scheme".to_string(), self.uri.scheme_str().unwrap_or("https").to_string());
        
        if let Some(authority) = self.uri.authority() {
            headers.insert(":authority".to_string(), authority.to_string());
        }
        
        headers
    }
    
    /// Get regular headers (non-pseudo)
    pub fn regular_headers(&self) -> &HeaderMap {
        &self.headers
    }
    
    /// Check if the request has a body
    pub fn has_body(&self) -> bool {
        self.body.is_some()
    }
    
    /// Get the request body
    pub fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }
    
    /// Get the content length
    pub fn content_length(&self) -> Option<usize> {
        self.body.as_ref().map(|b| b.len())
    }
}

/// Builder for HTTP/3 requests
#[derive(Debug)]
pub struct Http3RequestBuilder {
    request: Http3Request,
}

impl Http3RequestBuilder {
    /// Create a new request builder
    pub fn new() -> Self {
        Self {
            request: Http3Request::new(Method::GET, Uri::default()),
        }
    }
    
    /// Set the HTTP method
    pub fn method(mut self, method: Method) -> Self {
        self.request.method = method;
        self
    }
    
    /// Set the URI
    pub fn uri<U>(mut self, uri: U) -> Result<Self, http::Error>
    where
        Uri: TryFrom<U>,
        <Uri as TryFrom<U>>::Error: Into<http::Error>,
    {
        self.request.uri = Uri::try_from(uri).map_err(Into::into)?;
        Ok(self)
    }
    
    /// Add a header
    pub fn header<K, V>(mut self, key: K, value: V) -> Result<Self, http::Error>
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let name = HeaderName::try_from(key).map_err(Into::into)?;
        let value = HeaderValue::try_from(value).map_err(Into::into)?;
        self.request.headers.insert(name, value);
        Ok(self)
    }
    
    /// Set the request body
    pub fn body<B: Into<Bytes>>(mut self, body: B) -> Self {
        self.request.body = Some(body.into());
        self
    }
    
    /// Build the request
    pub fn build(self) -> Http3Request {
        self.request
    }
}

impl Default for Http3RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_request_creation() {
        let request = Http3Request::get("https://example.com/path".parse().unwrap())
            .header("user-agent", "gquic/0.3.0")
            .body("test body");
            
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/path");
        assert!(request.has_body());
        assert_eq!(request.content_length(), Some(9));
    }
    
    #[test]
    fn test_pseudo_headers() {
        let request = Http3Request::post("https://api.example.com/users".parse().unwrap());
        let pseudo_headers = request.to_pseudo_headers();
        
        assert_eq!(pseudo_headers.get(":method"), Some(&"POST".to_string()));
        assert_eq!(pseudo_headers.get(":path"), Some(&"/users".to_string()));
        assert_eq!(pseudo_headers.get(":scheme"), Some(&"https".to_string()));
        assert_eq!(pseudo_headers.get(":authority"), Some(&"api.example.com".to_string()));
    }
    
    #[test]
    fn test_request_builder() {
        let request = Http3RequestBuilder::new()
            .method(Method::POST)
            .uri("https://api.example.com/submit").unwrap()
            .header("content-type", "application/json").unwrap()
            .body(r#"{"key": "value"}"#)
            .build();
            
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.headers.get("content-type").unwrap(), "application/json");
        assert!(request.has_body());
    }
}
