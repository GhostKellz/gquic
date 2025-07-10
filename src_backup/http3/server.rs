// HTTP/3 server implementation

use crate::quic::Endpoint;
use super::{Http3Connection, error::Http3Error};

pub struct Http3Server {
    quic_endpoint: Endpoint,
}

impl Http3Server {
    pub fn new(quic_endpoint: Endpoint) -> Self {
        Self { quic_endpoint }
    }
    
    pub async fn accept(&self) -> Result<Http3Connection, Http3Error> {
        todo!("Implement connection acceptance")
    }
}
