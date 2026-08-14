//! ALPN byte string constants and helpers.
//!
//! Three ALPNs are reserved by meshly-core:
//!
//! | ALPN              | Direction        | Purpose                                    |
//! |-------------------|------------------|--------------------------------------------|
//! | `meshly-core/control`   | Client → Server  | Registration / subscription / heartbeat    |
//! | `meshly-core/data`      | Client → Server  | Relayed data tunnel (when P2P fails)       |
//! | `meshly-core/<svc>`     | Client ↔ Client  | Direct data tunnel for service `<svc>`     |
//!
//! Service names are constrained to `[a-z0-9-]{1,32}` to keep ALPN bytes
//! printable and to prevent collisions in future hierarchical namespaces.

use thiserror::Error;

/// ALPN used by clients to reach the server's control plane.
pub const ALPN_CONTROL: &[u8] = b"meshly-core/control";

/// ALPN used by clients to reach the server's data relay (P2P fallback).
pub const ALPN_DATA: &[u8] = b"meshly-core/data";

/// Returns the ALPN bytes for the control plane.
#[inline]
pub fn alpn_control() -> Vec<u8> {
    ALPN_CONTROL.to_vec()
}

/// Returns the ALPN bytes for the data relay plane.
#[inline]
pub fn alpn_data() -> Vec<u8> {
    ALPN_DATA.to_vec()
}

/// Returns the ALPN bytes for direct P2P data transfer of `service`.
///
/// Example: `alpn_for_service("ssh") == b"meshly-core/ssh"`.
pub fn alpn_for_service(service: &str) -> Result<Vec<u8>, AlpnError> {
    validate_service_name(service)?;
    Ok(format!("meshly-core/{service}").into_bytes())
}

/// Errors returned when a service name fails validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AlpnError {
    #[error("service name must be 1..=32 chars, got {0}")]
    BadLength(usize),
    #[error("service name has invalid chars (allowed: [a-z0-9-]): {0:?}")]
    InvalidChars(String),
    #[error("service name must not start or end with '-'")]
    BadEdge,
    #[error("service name must not contain consecutive '-'")]
    DoubleDash,
    #[error("service name is reserved: {0:?}")]
    Reserved(String),
}

/// Names reserved for future administrative ALPNs (control plane, status, reload).
const RESERVED: &[&str] = &[
    "control", "data", "status", "reload", "admin", "metrics", "ping",
];

/// Validate a service name. See module docs for the rule set.
pub fn validate_service_name(name: &str) -> Result<(), AlpnError> {
    let len = name.len();
    if !(1..=32).contains(&len) {
        return Err(AlpnError::BadLength(len));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(AlpnError::BadEdge);
    }
    if name.contains("--") {
        return Err(AlpnError::DoubleDash);
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(AlpnError::InvalidChars(name.to_string()));
    }
    if RESERVED.contains(&name) {
        return Err(AlpnError::Reserved(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_for_valid_service() {
        assert_eq!(alpn_for_service("ssh").unwrap(), b"meshly-core/ssh");
        assert_eq!(alpn_for_service("my-web-1").unwrap(), b"meshly-core/my-web-1");
    }

    #[test]
    fn rejects_invalid_names() {
        assert!(matches!(
            validate_service_name(""),
            Err(AlpnError::BadLength(0))
        ));
        assert!(matches!(
            validate_service_name(&"a".repeat(33)),
            Err(AlpnError::BadLength(33))
        ));
        assert!(matches!(validate_service_name("-ssh"), Err(AlpnError::BadEdge)));
        assert!(matches!(validate_service_name("ssh-"), Err(AlpnError::BadEdge)));
        assert!(matches!(validate_service_name("ss--h"), Err(AlpnError::DoubleDash)));
        assert!(matches!(
            validate_service_name("SSH"),
            Err(AlpnError::InvalidChars(_))
        ));
        assert!(matches!(
            validate_service_name("ssh_22"),
            Err(AlpnError::InvalidChars(_))
        ));
        assert!(matches!(validate_service_name("control"), Err(AlpnError::Reserved(_))));
    }

    #[test]
    fn accepts_boundary_lengths() {
        assert!(validate_service_name("a").is_ok());
        assert!(validate_service_name(&"a".repeat(32)).is_ok());
    }
}