//! Generic bidirectional byte-pipe bridge.
//!
//! The core operation of frp2p is: take two streams that speak AsyncRead +
//! AsyncWrite (one is typically a `tokio::net::TcpStream`, the other is
//! typically a pair of Iroh `SendStream` / `RecvStream`) and copy bytes
//! in both directions until either side closes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

/// Bytes-per-direction summary returned by [`bridge`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BridgeStats {
    pub a_to_b: u64,
    pub b_to_a: u64,
}

/// Bridge two byte streams. Bytes written to `a` are forwarded to `b`
/// and vice versa. Returns when either direction hits EOF or an error.
///
/// Both `a` and `b` must be `(AsyncRead + AsyncWrite + Unpin)`. For Iroh
/// streams pass the `(RecvStream, SendStream)` tuple directly — Rust
/// resolves them as separate `&mut` references to the two halves.
pub async fn bridge<A, B>(a: A, b: B) -> io::Result<BridgeStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a = a;
    let mut b = b;
    let started = Instant::now();

    let a_to_b = copy_one_direction(&mut a, &mut b).await?;
    debug!(bytes = a_to_b, "a->b closed");
    let b_to_a = copy_one_direction(&mut b, &mut a).await?;
    debug!(bytes = b_to_a, "b->a closed");

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;

    let stats = BridgeStats { a_to_b, b_to_a };
    trace!(?stats, elapsed_ms = started.elapsed().as_millis() as u64, "bridge done");
    Ok(stats)
}

async fn copy_one_direction<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

/// Combined bi-directional stream from a separate recv/send pair.
///
/// `iroh::endpoint::{RecvStream, SendStream}` split read and write
/// halves; many helpers (including our own [`bridge`]) need a single
/// value that implements both `AsyncRead` and `AsyncWrite`. This wrapper
/// glues them together.
#[derive(Debug)]
pub struct BiStream<R, W> {
    pub reader: R,
    pub writer: W,
}

impl<R, W> BiStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for BiStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for BiStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bridges_bytes_in_both_directions() {
        let (mut a1, a2) = duplex(64);
        let (b1, mut b2) = duplex(64);

        let bridge_task = tokio::spawn(async move { bridge(a2, b1).await });

        a1.write_all(b"hello-from-a").await.unwrap();
        a1.shutdown().await.ok();
        b2.write_all(b"hello-from-b").await.unwrap();
        b2.shutdown().await.ok();

        let mut got_a = Vec::new();
        b2.read_to_end(&mut got_a).await.unwrap();
        let mut got_b = Vec::new();
        a1.read_to_end(&mut got_b).await.unwrap();

        let stats = bridge_task.await.unwrap().unwrap();
        assert!(stats.a_to_b >= 12, "a->b should carry at least 'hello-from-a'");
        assert!(stats.b_to_a >= 12, "b->a should carry at least 'hello-from-b'");
    }

    #[tokio::test]
    async fn bridge_handles_immediate_eof() {
        // One side closes immediately; bridge should still complete cleanly.
        let (a1, a2) = duplex(64);
        let (b1, b2) = duplex(64);
        drop(a1);
        drop(b2);

        let stats = bridge(a2, b1).await.unwrap();
        assert_eq!(stats.a_to_b, 0);
        let _ = stats;
    }
}