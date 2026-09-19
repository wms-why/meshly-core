//! Per-connection bandwidth cap for the relay's **reply** direction
//! (provider → consumer).
//!
//! The cap is implemented as a token bucket. Each relay task owns an
//! [`Arc<AtomicU64>`] holding the current bytes-per-second value; the
//! value starts at the server's configured default but can be swapped at
//! runtime by writing to the atomic. Each refill reads the atomic
//! fresh, so a dynamic update takes effect on the next write — no
//! coordination with the writer task is needed.
//!
//! `0` in the atomic means "unlimited": the writer passes through
//! without sleeping.
//!
//! The handle is registered in [`ServerState`](crate::registry::ServerState)
//! under a stable `stream_id` so a future control-plane message can
//! address an individual connection. See `ServerState::register_relay_rate`
//! and `ServerState::update_relay_rate`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Shared, atomically-updateable handle to one connection's bandwidth cap
/// in **bytes per second**. `0` disables throttling.
pub type RateLimitHandle = Arc<AtomicU64>;

/// Build a fresh rate handle wrapping `initial_bps`.
pub fn new_handle(initial_bps: u64) -> RateLimitHandle {
    Arc::new(AtomicU64::new(initial_bps))
}

/// Single-owner token bucket. Drives one writer task; the bucket's
/// `available` token count and `last_refill` timestamp are local state.
#[derive(Debug)]
struct Bucket {
    handle: RateLimitHandle,
    available: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(handle: RateLimitHandle) -> Self {
        // Start with one full second's worth of tokens so the first
        // burst of a new connection isn't artificially delayed.
        let initial = handle.load(Ordering::Relaxed) as f64;
        Self {
            handle,
            available: initial,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let bps = self.handle.load(Ordering::Relaxed);
        if bps == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let cap = bps as f64;
        // Capping at `cap` (1 second's worth) prevents a long pause
        // from dumping a huge token reservoir into the next burst.
        self.available = (self.available + elapsed * cap).min(cap);
        self.last_refill = now;
    }

    /// Block (asynchronously) until `n` tokens are available, then take them.
    async fn acquire(&mut self, n: usize) {
        let bps = self.handle.load(Ordering::Relaxed);
        if bps == 0 || n == 0 {
            return; // unlimited, or empty request
        }
        let needed = n as f64;
        loop {
            self.refill();
            if self.available >= needed {
                self.available -= needed;
                return;
            }
            let deficit = needed - self.available;
            let wait_secs = deficit / bps as f64;
            // Floor at 1ms so a large single write against a small cap
            // doesn't spin in a sub-millisecond loop while the bucket
            // catches up.
            let wait = Duration::from_secs_f64(wait_secs).max(Duration::from_millis(1));
            tokio::time::sleep(wait).await;
        }
    }
}

/// Read from `reader`, write to `writer`, throttling writes to the rate
/// held in `handle`. Returns the total bytes copied.
///
/// We use our own copy loop instead of wrapping `AsyncWrite` because
/// rate-limiting inside `poll_write` would need to allocate an internal
/// buffer and a custom waker — the loop version is much smaller and
/// easier to reason about, and `tokio::io::copy`'s 8 KiB buffer isn't a
/// fit for a connection that may pause for seconds between writes.
pub async fn copy_throttled<R, W>(
    reader: &mut R,
    writer: &mut W,
    handle: &RateLimitHandle,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 16 KiB read buffer — bigger than tokio::io::copy's default 8 KiB
    // to reduce per-read overhead when the consumer is on a fast link
    // but the reply direction is being throttled.
    let mut buf = vec![0u8; 16 * 1024];
    let mut bucket = Bucket::new(handle.clone());
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        bucket.acquire(n).await;
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    writer.flush().await?;
    Ok(total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Instant;

    /// Pumping 1 MiB through a 100 KiB/s limiter must take at least
    /// ~10s of wall time (we expect ~10.5s with overhead). We give
    /// the assertion generous slack so CI noise doesn't flake it, but
    /// cap the upper bound so a missing limiter trips the test.
    #[tokio::test(start_paused = true)]
    async fn copy_throttled_enforces_bandwidth_cap() {
        // 1 MiB payload.
        let payload = vec![0xABu8; 1024 * 1024];
        let mut reader = Cursor::new(payload.clone());

        // Sink that just discards.
        let mut sink = tokio::io::sink();

        let handle = new_handle(100 * 1024); // 100 KiB/s
        let start = Instant::now();
        let n = copy_throttled(&mut reader, &mut sink, &handle)
            .await
            .expect("copy");
        let elapsed = start.elapsed();

        assert_eq!(n as usize, payload.len());
        // 1 MiB at 100 KiB/s = 10.48576 s. Allow ±20% slack.
        let secs = elapsed.as_secs_f64();
        assert!(
            secs > 8.0,
            "throttled copy finished too fast ({secs:.2}s) — limiter not engaged?"
        );
        assert!(
            secs < 20.0,
            "throttled copy took too long ({secs:.2}s) — limiter too aggressive?"
        );
    }

    /// With `bytes_per_sec = 0` the limiter must short-circuit and let
    /// the full payload through immediately (well under 1 s even with
    /// the cost of a few tokio context switches).
    #[tokio::test(start_paused = true)]
    async fn copy_throttled_zero_means_unlimited() {
        let payload = vec![0xCDu8; 256 * 1024];
        let mut reader = Cursor::new(payload.clone());
        let mut sink = tokio::io::sink();

        let handle = new_handle(0);
        let start = Instant::now();
        let n = copy_throttled(&mut reader, &mut sink, &handle)
            .await
            .expect("copy");
        let elapsed = start.elapsed();

        assert_eq!(n as usize, payload.len());
        assert!(
            elapsed < Duration::from_secs(1),
            "unlimited copy took {elapsed:?} — limiter didn't honor 0?"
        );
    }

    /// Updating the rate mid-stream should let the next refill use the
    /// new value. We pump 100 KiB at 50 KiB/s (forcing at least one
    /// real wait because the bucket starts with one second's worth =
    /// 50 KiB), then flip the same handle to unlimited and verify a
    /// second 100 KiB chunk drains quickly.
    #[tokio::test(start_paused = true)]
    async fn dynamic_rate_update_takes_effect() {
        let mut sink = tokio::io::sink();
        let handle = new_handle(50 * 1024); // 50 KiB/s

        // First chunk: 100 KiB at 50 KiB/s. Bucket holds 50 KiB of
        // initial credit, so the second 50 KiB must wait ~1 s.
        let first = vec![0u8; 100 * 1024];
        let mut reader_first = Cursor::new(first.clone());
        let start = Instant::now();
        let n_first = copy_throttled(&mut reader_first, &mut sink, &handle)
            .await
            .expect("slow copy");
        let slow_elapsed = start.elapsed();
        assert_eq!(n_first as usize, first.len());
        assert!(
            slow_elapsed > Duration::from_millis(800),
            "100 KiB at 50 KiB/s should take ~1s, took {slow_elapsed:?}"
        );

        // Flip the same handle to unlimited. The next copy_throttled
        // call builds a fresh bucket from the same handle — which now
        // reads `0` — and short-circuits the throttle entirely.
        handle.store(0, Ordering::Relaxed);
        let second = vec![0u8; 100 * 1024];
        let mut reader_second = Cursor::new(second.clone());
        let start = Instant::now();
        let n_second = copy_throttled(&mut reader_second, &mut sink, &handle)
            .await
            .expect("fast copy");
        let fast_elapsed = start.elapsed();
        assert_eq!(n_second as usize, second.len());
        assert!(
            fast_elapsed < Duration::from_millis(500),
            "after update to unlimited, copy should be fast, took {fast_elapsed:?}"
        );
    }
}
