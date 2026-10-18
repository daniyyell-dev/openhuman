//! The credential fallback files a profile keeps beside `config.toml`.
//!
//! `auth-profiles.json` and `http-credentials.json` are the on-disk fallbacks
//! the credential stores use when no storage backend holds them. Under layout
//! v2 they live as encrypted secrets (`tsd.secrets`, `enc2:` ChaCha20-Poly1305,
//! a per-scope key derived from the process master key) in the profile's
//! `local` scope. Step 2 of the migration imports them there, verifies the
//! read-back, and lists them in the plan as deleted entries so the archive
//! holds them and the final step removes them. A file that is not imported
//! (no usable master key, not valid JSON) is never classified, so it is left
//! in place and the stores keep adopting it lazily.
//!
//! The process-level files stay where they are and are outside every profile's
//! plan: `keyring/master.key` and the shared `secrets.enc` keyring (one file
//! for all profiles, entries namespaced by user id, adopted per key on first
//! read by `secret_storage::get`). The master key is never written into
//! `storage.db`.

use std::path::Path;

use tinystoragedrivers::secrets::SecretStore as _;

use super::state::LayoutError;
use super::Target;
use crate::security::credentials::http_creds::{STORAGE_SECRET_NAME, STORE_FILENAME};
use crate::security::credentials::profiles::{PROFILES_FILENAME, PROFILES_SECRET_NAME};
use crate::storage;

/// The path prefix a profile-level plan entry carries (`@profile/<file>`),
/// to tell it from an entry below `workspace/`.
pub const PROFILE_PREFIX: &str = "@profile/";

/// (file name beside `config.toml`, secret name on the storage backend).
pub const FILES: [(&str, &str); 2] = [
    (PROFILES_FILENAME, PROFILES_SECRET_NAME),
    (STORE_FILENAME, STORAGE_SECRET_NAME),
];

/// Imports the credential files of `target` into the v1 database's `local`
/// scope and returns the file names that are now safe to archive and delete.
///
/// A record already on the backend is authoritative (a v1 core with the
/// backend installed adopts and then updates it there, so the file may be
/// stale); it is only checked to be readable with the current key.
///
/// # Errors
///
/// A write that does not read back identically, or a stored record that does
/// not decrypt with the current key. Nothing is deleted then.
pub async fn import(target: &Target) -> Result<Vec<String>, LayoutError> {
    let mut files = Vec::new();
    for (file, secret) in FILES {
        let path = target.profile_dir.join(file);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            tracing::warn!(target: "openhuman::storage", file, "[layout] credential entry is not a regular file; left in place");
            continue;
        }
        let bytes = read(&path)?;
        if serde_json::from_slice::<serde_json::Value>(&bytes).is_err() {
            tracing::warn!(target: "openhuman::storage", file, "[layout] credential file is not valid JSON; left in place");
            continue;
        }
        files.push((file, secret, bytes));
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    if !crate::security::secret_storage::encrypted_file_backend::storage_master_key_resolvable() {
        tracing::warn!(
            target: "openhuman::storage",
            "[layout] no master key to encrypt the credential files with; left in place"
        );
        return Ok(Vec::new());
    }
    let keys = storage::secrets::keys()
        .map_err(|e| LayoutError::Other(anyhow::anyhow!("master key for credentials: {e}")))?;
    let backend = super::legacy::open_v1(target).await?;
    let scoped = backend
        .for_scope(&storage::tenant_scope(None))
        .map_err(|e| LayoutError::Other(anyhow::anyhow!("open the local scope: {e}")))?;
    let secrets = storage::secrets::over(&scoped, keys);
    let mut imported = Vec::new();
    for (file, secret, bytes) in files {
        let stored = secrets.get(secret).await.map_err(|e| {
            LayoutError::Verify(format!("stored credential record for {file}: {e}"))
        })?;
        if stored.is_none() {
            secrets
                .set(secret, &bytes)
                .await
                .map_err(|e| LayoutError::Other(anyhow::anyhow!("store {file}: {e}")))?;
            let back = secrets
                .get(secret)
                .await
                .map_err(|e| LayoutError::Verify(format!("read back {file}: {e}")))?;
            if back.as_deref().map(|b| b.as_slice()) != Some(bytes.as_slice()) {
                return Err(LayoutError::Verify(format!(
                    "{file} did not read back identically; refusing to delete it"
                )));
            }
        }
        tracing::info!(target: "openhuman::storage", file, "[layout] credential file imported");
        imported.push(file.to_owned());
    }
    drop(backend);
    Ok(imported)
}

fn read(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, LayoutError> {
    Ok(zeroize::Zeroizing::new(std::fs::read(path)?))
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
