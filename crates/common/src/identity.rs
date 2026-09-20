//! Iroh `SecretKey` persistence and load/generate.
//!
//! The identity (a.k.a. the Iroh NodeID private key) is the long-lived secret
//! that gives a meshly-core node its stable public address. It must be persisted
//! between runs so that other peers can keep addressing the same node.
//!
//! Storage location:
//! - Linux:   `$XDG_CONFIG_HOME/meshly-core/identity.key` (default `~/.config/meshly-core/identity.key`)
// - macOS:   `$HOME/Library/Application Support/meshly-core/identity.key`
// - Windows: `%APPDATA%/meshly-core/identity.key`
//!
//! On Unix, the file is written with mode 0o600. On Windows, ACLs are not
//! modified; rely on the user's profile directory ACL instead.
//!
//! The on-disk format is the 32-byte raw secret key returned by
//! `iroh::SecretKey::to_bytes`. We write it directly (no JSON, no PEM) and
//! read it back identically. If you need to migrate, treat the file as
//! opaque and rotate by deleting it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::SecretKey;

/// Decode a `SecretKey` from the 32-byte on-disk representation.
fn decode_key(bytes: &[u8]) -> Result<SecretKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity key must be exactly 32 bytes, got {}", bytes.len()))?;
    Ok(SecretKey::from_bytes(&arr))
}

/// Paths used by identity persistence.
///
/// Returned from [`load_or_generate`] / [`load_or_generate_at`] so callers
/// can log where the file lives (useful for diagnostics and the
/// `meshly-core-client id` subcommand).
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    /// Directory containing the identity key file.
    pub dir: PathBuf,
    /// Full path to the identity key file.
    pub key_file: PathBuf,
}

/// Load an existing `SecretKey` from disk, or generate a fresh one and
/// persist it. Returns the key plus the resolved paths.
///
/// The default location is `<config_dir>/meshly-core/identity.key` where
/// `config_dir` comes from the `dirs` crate. On Unix we ensure the
/// directory has mode 0o700 and the file has mode 0o600.
pub fn load_or_generate() -> Result<(SecretKey, IdentityPaths)> {
    let dir = default_dir()?;
    let key_file = dir.join("identity.key");
    load_or_generate_at(&key_file)
}

/// Variant of [`load_or_generate`] that takes an explicit file path.
/// The parent directory is created if it does not exist.
pub fn load_or_generate_at(key_file: &Path) -> Result<(SecretKey, IdentityPaths)> {
    let dir = key_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity key path has no parent: {}", key_file.display()))?
        .to_path_buf();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create identity dir {}", dir.display()))?;
    restrict_dir(&dir);

    let paths = IdentityPaths {
        dir: dir.clone(),
        key_file: key_file.to_path_buf(),
    };

    if key_file.exists() {
        let mut f = std::fs::File::open(key_file)
            .with_context(|| format!("open identity key {}", key_file.display()))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .with_context(|| format!("read identity key {}", key_file.display()))?;
        let key = decode_key(&buf)?;
        Ok((key, paths))
    } else {
        let key = SecretKey::generate();
        let bytes = key.to_bytes();
        // Atomic-ish write: write to a tmp file in the same dir, then rename.
        let tmp = dir.join(".identity.key.tmp");
        {
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("create tmp identity key {}", tmp.display()))?;
            f.write_all(&bytes)
                .with_context(|| format!("write tmp identity key {}", tmp.display()))?;
            f.sync_all().ok();
        }
        std::fs::rename(&tmp, key_file)
            .with_context(|| format!("rename identity key to {}", key_file.display()))?;
        restrict_file(key_file);
        Ok((key, paths))
    }
}

fn default_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("could not determine user config directory"))?;
    Ok(base.join("meshly-core"))
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {
    // No-op on non-Unix; rely on OS-level profile ACLs.
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {
    // No-op on non-Unix.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_key_at_tmp_path() {
        let tmp = std::env::temp_dir().join(format!(
            "meshly-core-test-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let key_file = tmp.join("identity.key");
        let (k1, paths) = load_or_generate_at(&key_file).unwrap();
        assert!(paths.key_file.exists());

        let (k2, _) = load_or_generate_at(&key_file).unwrap();
        assert_eq!(k1.public(), k2.public(), "key should persist across reads");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn different_paths_yield_different_keys() {
        let tmp = std::env::temp_dir().join(format!(
            "meshly-core-test-{}-{:x}",
            std::process::id(),
            rand::random::<u64>() ^ 0xdeadbeef
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let (k1, _) = load_or_generate_at(&tmp.join("a.key")).unwrap();
        let (k2, _) = load_or_generate_at(&tmp.join("b.key")).unwrap();
        assert_ne!(k1.public(), k2.public());

        std::fs::remove_dir_all(&tmp).ok();
    }

    // -- Phase 0: targeted idempotency + permission tests -----------------

    /// `load_or_generate_at` must be idempotent: two calls on the same
    /// path return the *same* SecretKey (not just the same public key).
    /// The second call must not generate a new key over the existing one.
    #[test]
    fn load_or_generate_at_is_idempotent() {
        let tmp = std::env::temp_dir().join(format!(
            "meshly-core-idem-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let key_file = tmp.join("identity.key");
        let (k1, _) = load_or_generate_at(&key_file).unwrap();
        let bytes_after_first = std::fs::read(&key_file).unwrap();

        // Second call must reuse the on-disk key, not overwrite.
        let (k2, paths2) = load_or_generate_at(&key_file).unwrap();
        let bytes_after_second = std::fs::read(&key_file).unwrap();

        assert_eq!(
            k1.to_bytes(),
            k2.to_bytes(),
            "SecretKey bytes must be identical across calls"
        );
        assert_eq!(
            bytes_after_first, bytes_after_second,
            "file bytes must not be rewritten on second load"
        );
        assert_eq!(paths2.key_file, key_file);

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// When the identity file does not exist, a new key must be generated
    /// and persisted. Use a fresh subdirectory under tempdir so the test
    /// cannot collide with another test or the developer's real key.
    #[test]
    fn load_or_generate_at_creates_new_key_when_missing() {
        let tmp = std::env::temp_dir().join(format!(
            "meshly-core-newkey-{}-{:x}",
            std::process::id(),
            rand::random::<u64>() ^ 0xc0ffee
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let key_file = tmp.join("fresh.identity.key");
        assert!(!key_file.exists(), "precondition: file must not exist");

        let (key, paths) = load_or_generate_at(&key_file).unwrap();
        assert!(key_file.exists(), "file must be created");
        assert_eq!(paths.key_file, key_file);

        // The on-disk content must be 32 bytes (the raw SecretKey bytes).
        let bytes = std::fs::read(&key_file).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, key.to_bytes());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// On Unix, the freshly created identity file must be readable and
    /// writable by the owner only (mode 0o600). This is a security
    /// requirement — the private key must not be world-readable.
    #[cfg(unix)]
    #[test]
    fn load_or_generate_at_chmods_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join(format!(
            "meshly-core-perms-{}-{:x}",
            std::process::id(),
            rand::random::<u64>() ^ 0xface
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let key_file = tmp.join("perms.identity.key");
        let (_, _) = load_or_generate_at(&key_file).unwrap();

        let meta = std::fs::metadata(&key_file).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected mode 0o600, got {mode:o} ({mode})"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }
}