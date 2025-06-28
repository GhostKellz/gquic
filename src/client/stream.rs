use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::quic::{BiStream, UniStream};

/// Client-side bidirectional stream wrapper
pub struct ClientBiStream {
    inner: BiStream,
}

impl ClientBiStream {
    pub fn new(stream: BiStream) -> Self {
        Self { inner: stream }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.inner.write_all(data).await.map_err(|e| anyhow::anyhow!("Stream write error: {}", e))
    }

    pub async fn read_to_end(&mut self, max_size: usize) -> anyhow::Result<Vec<u8>> {
        self.inner.read_to_end(max_size).await.map_err(|e| anyhow::anyhow!("Stream read error: {}", e))
    }

    pub async fn finish(&mut self) -> anyhow::Result<()> {
        self.inner.finish().await.map_err(|e| anyhow::anyhow!("Stream finish error: {}", e))
    }
}

impl AsyncRead for ClientBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Client-side unidirectional stream wrapper
pub struct ClientUniStream {
    inner: UniStream,
}

impl ClientUniStream {
    pub fn new(stream: UniStream) -> Self {
        Self { inner: stream }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.inner.write_all(data).await.map_err(|e| anyhow::anyhow!("Stream write error: {}", e))
    }

    pub async fn finish(&mut self) -> anyhow::Result<()> {
        self.inner.finish().await.map_err(|e| anyhow::anyhow!("Stream finish error: {}", e))
    }
}

impl AsyncWrite for ClientUniStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}