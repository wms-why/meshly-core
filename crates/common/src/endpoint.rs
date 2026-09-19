//! EndpointID string parsing.
//!
//! Iroh `EndpointId`s (`PublicKey` aliases) are 32 bytes. Two
//! string forms are accepted across the project:
//!
//! - The canonical z-base32 encoding produced by `EndpointId::to_string()`.
//! - The 64-char lowercase hex encoding used in some log / config contexts.
//!
//! [`parse_endpoint_id`] accepts both forms and returns `None` on
//! anything else.

use iroh::EndpointId;

/// Parse an EndpointID from either its canonical z-base32 form or
/// its 64-char hex form. Returns `None` for any other shape.
pub fn parse_endpoint_id(s: &str) -> Option<EndpointId> {
    if let Ok(id) = s.parse::<EndpointId>() {
        return Some(id);
    }
    if let Ok(bytes) = hex::decode(s)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return iroh::PublicKey::from_bytes(&arr).ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zbase32_round_trip() {
        // 32 zero bytes → canonical z-base32 is all-zero chars; the
        // important thing is that the canonical form parses back.
        let arr = [0u8; 32];
        let id = iroh::PublicKey::from_bytes(&arr).unwrap();
        let s = id.to_string();
        assert_eq!(parse_endpoint_id(&s), Some(id));
    }

    #[test]
    fn parses_hex_form() {
        let arr = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let id = iroh::PublicKey::from_bytes(&arr).unwrap();
        let hex_str = hex::encode(arr);
        assert_eq!(parse_endpoint_id(&hex_str), Some(id));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_endpoint_id("not-a-node-id").is_none());
        // wrong length hex
        assert!(parse_endpoint_id(&"ab".repeat(32)).is_none()); // 64 chars but not valid hex bytes
        assert!(parse_endpoint_id("").is_none());
    }
}