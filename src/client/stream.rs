use anyhow::Result;
use bytes::Bytes;
use futures::stream::Stream;
use quinn::{RecvStream, SendStream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct BiStream {
    send: SendStream,
    recv: RecvStream,
}

impl BiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.send.write_all(data).await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().await?;
        Ok(())
    }

    pub async fn read_to_end(&mut self, max_size: usize) -> Result<Vec<u8>> {
        let data = self.recv.read_to_end(max_size).await?;
        Ok(data)
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>> {
        match self.recv.read_chunk(usize::MAX, true).await? {
            Some(chunk) => Ok(Some(chunk.bytes)),
            None => Ok(None),
        }
    }

    pub fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

impl AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

pub struct UniStream {
    send: SendStream,
}

impl UniStream {
    pub fn new(send: SendStream) -> Self {
        Self { send }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.send.write_all(data).await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().await?;
        Ok(())
    }
}

impl AsyncWrite for UniStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}