//! Shared types and utilities for frp2p.
//!
//! Modules are intentionally small and focused; both server and client crates
//! depend on this library to avoid duplication of protocol definitions,
//! frame encoding, tunnel bridging logic, and configuration schema.

pub mod alpn;
pub mod config;
pub mod identity;
pub mod protocol;
pub mod tunnel;

pub use alpn::{alpn_control, alpn_data, alpn_for_service, validate_service_name, AlpnError};
pub use config::{
    ClientConfig, CommonConfig, ConsumeConfig, ExposeConfig, GroupConfig, LoggingConfig,
    ReconnectConfig, ServerConfig, RootConfig,
};
pub use identity::{load_or_generate, load_or_generate_at, IdentityPaths};
pub use protocol::{
    compute_proof, AuthErr, AuthNonce, AuthOk, AuthProof, Frame, FrameError, Hello, HelloOk,
    Register, RegisterOk, Subscribe, SubscribeOk, AUTH_ERR_BAD_PROOF, AUTH_ERR_NO_NONCE,
    AUTH_ERR_OK, AUTH_ERR_TIMEOUT, CONTROL_HELLO, CONTROL_HELLO_OK, CONTROL_REGISTER,
    CONTROL_REGISTER_OK, CONTROL_SUBSCRIBE, CONTROL_SUBSCRIBE_OK, DATA_OPEN,
};
pub use tunnel::{bridge, BiStream, BridgeStats};