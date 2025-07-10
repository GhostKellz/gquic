// HTTP/3 client implementation

use crate::quic::Connection as QuicConnection;
use super::{Http3Connection, Http3Request, Http3Response, error::Http3Error};

pub struct Http3Client {
    connection: Http3Connection,
}

impl Http3Client {
    pub async fn connect(quic_connection: QuicConnection) -> Result<Self, Http3Error> {
        let connection = Http3Connection::new(quic_connection).await?;
        Ok(Self { connection })
    }
    
    pub async fn send_request(&self, _request: Http3Request) -> Result<Http3Response, Http3Error> {
        todo!("Implement request sending")
    }
}
