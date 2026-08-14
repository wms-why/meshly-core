//! Wire protocol frames and HMAC-based authentication.
//!
//! Two channels exist:
//!
//! 1. **Control plane** (`meshly-core/control`, Client → Server): registration,
//!    subscription, heartbeat. Frames here carry identifiers and metadata.
//!
//! 2. **Data plane** (`meshly-core/<svc>` direct or `meshly-core/data` relayed): per-stream
//!    authentication followed by a raw byte pipe. Only the first stream on a
//!    connection needs to prove possession of the shared secret; subsequent
//!    streams on the same connection are considered authenticated by
//!    association.
//!
//! ## Frame format
//!
//! All framed messages use: `[tag: u8][len: u16 LE][payload: len bytes]`.
//!
//! Tags in `0x01..=0x0F` are used by the data plane authentication handshake.
//! Tags in `0x10..=0x1F` are used by the control plane.

use std::io;

use bytes::{BufMut, BytesMut};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Tag constants
// ---------------------------------------------------------------------------

/// Data-plane tag: server-issued nonce.
pub const DATA_AUTH_NONCE: u8 = 0x01;
/// Data-plane tag: client-issued HMAC proof.
pub const DATA_AUTH_PROOF: u8 = 0x02;
/// Data-plane tag: authentication accepted.
pub const DATA_AUTH_OK: u8 = 0x03;
/// Data-plane tag: authentication rejected.
pub const DATA_AUTH_ERR: u8 = 0x04;

/// Data-plane tag: open a relayed tunnel with target metadata.
pub const DATA_OPEN: u8 = 0x05;

/// Control-plane tag: client hello with group token.
pub const CONTROL_HELLO: u8 = 0x10;
/// Control-plane tag: server hello-ok with session id.
pub const CONTROL_HELLO_OK: u8 = 0x11;
/// Control-plane tag: register a service.
pub const CONTROL_REGISTER: u8 = 0x12;
/// Control-plane tag: registration accepted.
pub const CONTROL_REGISTER_OK: u8 = 0x13;
/// Control-plane tag: subscribe to a remote service.
pub const CONTROL_SUBSCRIBE: u8 = 0x14;
/// Control-plane tag: subscription resolved.
pub const CONTROL_SUBSCRIBE_OK: u8 = 0x15;
/// Control-plane tag: heartbeat (both directions).
pub const CONTROL_HEARTBEAT: u8 = 0x16;
/// Control-plane tag: error.
pub const CONTROL_ERROR: u8 = 0x1F;

// ---------------------------------------------------------------------------
// Auth outcome codes
// ---------------------------------------------------------------------------

/// Authentication accepted.
pub const AUTH_ERR_OK: u8 = 0;
/// Generic bad HMAC proof.
pub const AUTH_ERR_BAD_PROOF: u8 = 1;
/// Nonce missing or already consumed.
pub const AUTH_ERR_NO_NONCE: u8 = 2;
/// Provider timed out waiting for the proof.
pub const AUTH_ERR_TIMEOUT: u8 = 3;
/// Provider is shutting down.
pub const AUTH_ERR_SHUTDOWN: u8 = 4;
/// Service name in the proof does not match the bound ALPN.
pub const AUTH_ERR_WRONG_SERVICE: u8 = 5;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors raised while reading or writing frames.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("unexpected EOF reading frame header")]
    ShortHeader,
    #[error("unexpected EOF reading frame payload (wanted {0} bytes, got {1})")]
    ShortPayload(usize, usize),
    #[error("frame length {0} exceeds maximum {1}")]
    TooLong(usize, usize),
    #[error("unknown frame tag: {0}")]
    UnknownTag(u8),
    #[error("invalid UTF-8 in frame: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("authentication failed: code={0}, reason={1}")]
    AuthFailed(u8, String),
}

/// Maximum single-frame payload size: 32 KiB. Plenty for our metadata;
/// data plane traffic after auth is raw bytes (no frames).
pub const MAX_FRAME_PAYLOAD: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Frame structs
// ---------------------------------------------------------------------------

/// AuthNonce (data plane): server → client. 32 random bytes.
#[derive(Debug, Clone)]
pub struct AuthNonce {
    pub nonce: [u8; 32],
}

/// AuthProof (data plane): client → server. 32-byte HMAC-SHA256.
#[derive(Debug, Clone)]
pub struct AuthProof {
    pub mac: [u8; 32],
}

/// AuthOk (data plane): server → client. No payload.
#[derive(Debug, Clone, Copy)]
pub struct AuthOk;

/// AuthErr (data plane): server → client. 1-byte code + UTF-8 reason.
#[derive(Debug, Clone)]
pub struct AuthErr {
    pub code: u8,
    pub reason: String,
}

/// Hello (control plane): client → server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub group_token: String,
    pub client_info: String,
}

/// HelloOk (control plane): server → client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloOk {
    pub session_id: u64,
}

/// Register (control plane): client → server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Register {
    pub service: String,
}

/// RegisterOk (control plane): server → client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterOk {
    pub service: String,
}

/// Subscribe (control plane): client → server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscribe {
    pub service: String,
}

/// SubscribeOk (control plane): server → client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeOk {
    pub service: String,
    pub provider_node_id: Option<String>,
    pub relay_required: bool,
}

/// Tagged enum of all frames that can be exchanged.
///
/// Reading from the wire produces a `Frame`; writing a `Frame` serializes
/// it back to the wire.
#[derive(Debug, Clone)]
pub enum Frame {
    AuthNonce(AuthNonce),
    AuthProof(AuthProof),
    AuthOk(AuthOk),
    AuthErr(AuthErr),

    /// Data-plane open: targets a remote service when traversing the relay.
    /// The proof is computed over (service_name || nonce) where the nonce is
    /// generated by the relay server upon receiving this frame.
    DataOpen {
        target_service: String,
        target_provider: String,
        proof: [u8; 32],
    },

    Hello(Hello),
    HelloOk(HelloOk),
    Register(Register),
    RegisterOk(RegisterOk),
    Subscribe(Subscribe),
    SubscribeOk(SubscribeOk),
    Heartbeat,
    ControlError { code: u16, reason: String },
}

impl Frame {
    /// Returns the tag byte for this frame.
    pub fn tag(&self) -> u8 {
        match self {
            Frame::AuthNonce(_) => DATA_AUTH_NONCE,
            Frame::AuthProof(_) => DATA_AUTH_PROOF,
            Frame::AuthOk(_) => DATA_AUTH_OK,
            Frame::AuthErr(_) => DATA_AUTH_ERR,
            Frame::DataOpen { .. } => DATA_OPEN,
            Frame::Hello(_) => CONTROL_HELLO,
            Frame::HelloOk(_) => CONTROL_HELLO_OK,
            Frame::Register(_) => CONTROL_REGISTER,
            Frame::RegisterOk(_) => CONTROL_REGISTER_OK,
            Frame::Subscribe(_) => CONTROL_SUBSCRIBE,
            Frame::SubscribeOk(_) => CONTROL_SUBSCRIBE_OK,
            Frame::Heartbeat => CONTROL_HEARTBEAT,
            Frame::ControlError { .. } => CONTROL_ERROR,
        }
    }

    /// Serialize this frame's payload (no tag/length prefix).
    pub fn encode_payload(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = BytesMut::new();
        match self {
            Frame::AuthNonce(a) => out.put_slice(&a.nonce),
            Frame::AuthProof(p) => out.put_slice(&p.mac),
            Frame::AuthOk(_) => {}
            Frame::AuthErr(e) => {
                out.put_u8(e.code);
                out.put_slice(e.reason.as_bytes());
            }
            Frame::DataOpen {
                target_service,
                target_provider,
                proof,
            } => {
                let svc = target_service.as_bytes();
                if svc.len() > u16::MAX as usize {
                    return Err(FrameError::TooLong(svc.len(), u16::MAX as usize));
                }
                out.put_u16_le(svc.len() as u16);
                out.put_slice(svc);
                let provider = target_provider.as_bytes();
                if provider.len() > u16::MAX as usize {
                    return Err(FrameError::TooLong(provider.len(), u16::MAX as usize));
                }
                out.put_u16_le(provider.len() as u16);
                out.put_slice(provider);
                out.put_slice(proof);
            }
            Frame::Hello(h) => write_json(h, &mut out)?,
            Frame::HelloOk(h) => write_json(h, &mut out)?,
            Frame::Register(r) => write_json(r, &mut out)?,
            Frame::RegisterOk(r) => write_json(r, &mut out)?,
            Frame::Subscribe(s) => write_json(s, &mut out)?,
            Frame::SubscribeOk(s) => write_json(s, &mut out)?,
            Frame::Heartbeat => {}
            Frame::ControlError { code, reason } => {
                out.put_u16_le(*code);
                out.put_slice(reason.as_bytes());
            }
        }
        Ok(out.to_vec())
    }

    /// Parse a frame from tag + payload bytes.
    pub fn decode(tag: u8, payload: &[u8]) -> Result<Frame, FrameError> {
        let cur = payload;
        let frame = match tag {
            DATA_AUTH_NONCE => {
                let n: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| FrameError::ShortPayload(32, payload.len()))?;
                Frame::AuthNonce(AuthNonce { nonce: n })
            }
            DATA_AUTH_PROOF => {
                let m: [u8; 32] = payload
                    .try_into()
                    .map_err(|_| FrameError::ShortPayload(32, payload.len()))?;
                Frame::AuthProof(AuthProof { mac: m })
            }
            DATA_AUTH_OK => Frame::AuthOk(AuthOk),
            DATA_AUTH_ERR => {
                if payload.is_empty() {
                    return Err(FrameError::ShortPayload(1, 0));
                }
                let code = payload[0];
                let reason = String::from_utf8(payload[1..].to_vec())?;
                Frame::AuthErr(AuthErr { code, reason })
            }
            DATA_OPEN => {
                if payload.len() < 4 {
                    return Err(FrameError::ShortPayload(4, payload.len()));
                }
                let svc_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                let need = 4 + svc_len + 2 + 32;
                if payload.len() < need {
                    return Err(FrameError::ShortPayload(need, payload.len()));
                }
                let svc = String::from_utf8(payload[4..4 + svc_len].to_vec())?;
                let prov_len = u16::from_le_bytes([
                    payload[4 + svc_len],
                    payload[4 + svc_len + 1],
                ]) as usize;
                let prov_start = 4 + svc_len + 2;
                let prov_end = prov_start + prov_len;
                let provider = String::from_utf8(payload[prov_start..prov_end].to_vec())?;
                let mut proof = [0u8; 32];
                proof.copy_from_slice(&payload[prov_end..prov_end + 32]);
                Frame::DataOpen {
                    target_service: svc,
                    target_provider: provider,
                    proof,
                }
            }
            CONTROL_HELLO => Frame::Hello(read_json(cur)?),
            CONTROL_HELLO_OK => Frame::HelloOk(read_json(cur)?),
            CONTROL_REGISTER => Frame::Register(read_json(cur)?),
            CONTROL_REGISTER_OK => Frame::RegisterOk(read_json(cur)?),
            CONTROL_SUBSCRIBE => Frame::Subscribe(read_json(cur)?),
            CONTROL_SUBSCRIBE_OK => Frame::SubscribeOk(read_json(cur)?),
            CONTROL_HEARTBEAT => Frame::Heartbeat,
            CONTROL_ERROR => {
                if payload.len() < 2 {
                    return Err(FrameError::ShortPayload(2, payload.len()));
                }
                let code = u16::from_le_bytes([payload[0], payload[1]]);
                let reason = String::from_utf8(payload[2..].to_vec())?;
                Frame::ControlError { code, reason }
            }
            other => return Err(FrameError::UnknownTag(other)),
        };
        Ok(frame)
    }

    /// Write a frame (tag + length + payload) to an async writer.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), FrameError> {
        let payload = self.encode_payload()?;
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::TooLong(payload.len(), MAX_FRAME_PAYLOAD));
        }
        let mut head = [0u8; 3];
        head[0] = self.tag();
        head[1] = (payload.len() & 0xff) as u8;
        head[2] = ((payload.len() >> 8) & 0xff) as u8;
        w.write_all(&head).await?;
        if !payload.is_empty() {
            w.write_all(&payload).await?;
        }
        Ok(())
    }

    /// Read a frame (tag + length + payload) from an async reader.
    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, FrameError> {
        let mut head = [0u8; 3];
        match r.read_exact(&mut head).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(FrameError::ShortHeader);
            }
            Err(e) => return Err(FrameError::Io(e)),
        }
        let tag = head[0];
        let len = u16::from_le_bytes([head[1], head[2]]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return Err(FrameError::TooLong(len, MAX_FRAME_PAYLOAD));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            match r.read_exact(&mut payload).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(FrameError::ShortPayload(len, 0));
                }
                Err(e) => return Err(FrameError::Io(e)),
            }
        }
        Self::decode(tag, &payload)
    }
}

// ---------------------------------------------------------------------------
// HMAC proof
// ---------------------------------------------------------------------------

/// Compute `HMAC_SHA256(shared_secret, service_name || nonce)`.
///
/// The shared_secret is the raw byte string configured by the user
/// (typically a UTF-8 passphrase). `service_name` is the ALPN suffix
/// (e.g. `"ssh"`), included so that a proof for one service cannot be
/// replayed against another.
pub fn compute_proof(shared_secret: &[u8], service_name: &str, nonce: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(shared_secret)
        .expect("HMAC accepts any key length");
    mac.update(service_name.as_bytes());
    mac.update(nonce);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Verify an HMAC proof in constant time. Returns true if the proof
/// matches the expected value for the given (secret, service, nonce).
pub fn verify_proof(
    shared_secret: &[u8],
    service_name: &str,
    nonce: &[u8; 32],
    proof: &[u8; 32],
) -> bool {
    let expected = compute_proof(shared_secret, service_name, nonce);
    bool::from(expected.ct_eq(proof))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_json<T: Serialize>(v: &T, out: &mut BytesMut) -> Result<(), FrameError> {
    let bytes = serde_json::to_vec(v).map_err(|e| {
        FrameError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("json encode: {e}")))
    })?;
    if bytes.len() > u16::MAX as usize {
        return Err(FrameError::TooLong(bytes.len(), u16::MAX as usize));
    }
    out.put_slice(&bytes);
    Ok(())
}

fn read_json<'a, T: Deserialize<'a>>(cur: &'a [u8]) -> Result<T, FrameError> {
    serde_json::from_slice(cur).map_err(|e| {
        FrameError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("json decode: {e}")))
    })
}

/// Convenience: read a single frame from an in-memory buffer (used in tests).
pub fn decode_from_bytes(buf: &[u8]) -> Result<Frame, FrameError> {
    if buf.len() < 3 {
        return Err(FrameError::ShortHeader);
    }
    let tag = buf[0];
    let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    if buf.len() < 3 + len {
        return Err(FrameError::ShortPayload(len, buf.len() - 3));
    }
    Frame::decode(tag, &buf[3..3 + len])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn hmac_proof_is_deterministic_and_service_bound() {
        let secret = b"correct horse battery staple";
        let nonce = [0xab; 32];
        let a = compute_proof(secret, "ssh", &nonce);
        let b = compute_proof(secret, "ssh", &nonce);
        assert_eq!(a, b);
        let c = compute_proof(secret, "web", &nonce);
        assert_ne!(a, c, "different service should yield different proof");
        assert!(verify_proof(secret, "ssh", &nonce, &a));
        assert!(!verify_proof(secret, "web", &nonce, &a));
    }

    #[test]
    fn proof_rejects_wrong_secret() {
        let nonce = [0u8; 32];
        let good = compute_proof(b"abc", "svc", &nonce);
        assert!(!verify_proof(b"abd", "svc", &nonce, &good));
    }

    #[tokio::test]
    async fn roundtrip_frame_over_async_buf() {
        let (mut a, mut b) = duplex(1024);
        let f = Frame::AuthNonce(AuthNonce { nonce: [7u8; 32] });
        let copy = f.clone();
        let writer = tokio::spawn(async move {
            f.write_to(&mut a).await.unwrap();
        });
        let got = Frame::read_from(&mut b).await.unwrap();
        writer.await.unwrap();
        match got {
            Frame::AuthNonce(n) => assert_eq!(n.nonce, [7u8; 32]),
            other => panic!("unexpected frame: {other:?}"),
        }
        // sanity: original frame matches
        assert_eq!(copy.tag(), DATA_AUTH_NONCE);
    }

    #[test]
    fn json_payload_roundtrips() {
        let f = Frame::Hello(Hello {
            group_token: "tkn".into(),
            client_info: "meshly-core-client/0.1".into(),
        });
        let payload = f.encode_payload().unwrap();
        let back = Frame::decode(CONTROL_HELLO, &payload).unwrap();
        match back {
            Frame::Hello(h) => {
                assert_eq!(h.group_token, "tkn");
                assert_eq!(h.client_info, "meshly-core-client/0.1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_oversize_payload() {
        // Manually craft a frame header that claims the maximum u16 length,
        // which exceeds MAX_FRAME_PAYLOAD (64 KiB). read_from should reject
        // it without consuming any body bytes.
        let len: u16 = u16::MAX;
        let mut buf = vec![DATA_AUTH_NONCE, (len & 0xff) as u8, (len >> 8) as u8];
        buf.extend_from_slice(&vec![0u8; 8]);
        let err = Frame::read_from(&mut buf.as_slice()).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLong(_, _)));
    }
}