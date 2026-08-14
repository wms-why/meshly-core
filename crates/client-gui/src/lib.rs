//! meshly-core-client-gui: stub library for the future GUI frontend.
//!
//! v1 does not implement any GUI; this crate exists so the workspace
//! builds and downstream projects can depend on a stable library name.
//!
//! ## Roadmap
//!
//! - v1.1: minimal `egui` or `iced` shell that wraps `meshly-core-client`:
//!   - read config files via the dialog
//!   - live status of exposed/consumed services
//!   - node id display
//! - v1.2: system tray icon + quick-toggle for individual services
//!
//! The GUI process will reuse the same library (`meshly_core_common`) as the
//! CLI client, so configuration parsing, ALPN derivation, and tunnel
//! bridging logic stay identical.

#![doc(html_root_url = "https://docs.rs/meshly-core-client-gui/0.1.0")]

/// Returns a constant string identifying this placeholder.
pub fn placeholder() -> &'static str {
    "meshly-core-client-gui: placeholder; GUI not implemented in v1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_non_empty() {
        assert!(!placeholder().is_empty());
    }
}