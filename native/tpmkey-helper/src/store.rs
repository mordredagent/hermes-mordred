//! Opaque key-blob file store.
//!
//! Each key persists as an opaque blob at `<store>/<tag_hex>.bin`. The store is
//! backend-agnostic: it neither parses nor validates blob contents (a TPM key
//! context in Phase 2b), so the whole module is exercisable on any host. The
//! directory layout mirrors the Swift SE helper, under a `tpm` leaf:
//!
//!   1. `MORDRED_TPMKEY_STORE`           — explicit absolute dir (authoritative)
//!   2. `$HERMES_HOME/mordred/keyvault/tpm`
//!   3. `~/.hermes/mordred/keyvault/tpm`

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A store I/O outcome that maps onto the neutral taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// `generate` refused to overwrite an existing blob (→ `EXISTS`).
    Exists,
    /// No blob for the tag (→ `NOT_FOUND`).
    NotFound,
    /// Any other filesystem failure.
    Io(String),
}

/// Reject a tag that is not a single safe path component.
///
/// Defense-in-depth: the dispatcher already constrains tags to hex
/// (`ops::require_tag`), but the blob store is a `pub` API that Phase 2b's TPM
/// backend will call, so it must not silently depend on the dispatcher to keep
/// `<tag_hex>.bin` inside `dir`. A separator, `.`/`..`, NUL, or empty tag is a
/// programming error, surfaced as [`StoreError::Io`].
fn ensure_safe_tag(tag_hex: &str) -> Result<(), StoreError> {
    let is_unsafe = tag_hex.is_empty()
        || tag_hex == "."
        || tag_hex == ".."
        || tag_hex.contains('/')
        || tag_hex.contains('\\')
        || tag_hex.contains('\0');
    if is_unsafe {
        Err(StoreError::Io(format!("unsafe tag component: {tag_hex:?}")))
    } else {
        Ok(())
    }
}

/// Expand a leading `~` in `path` against `home` (mirrors `expandingTildeInPath`).
fn expand_tilde(path: &str, home: &Path) -> PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// Resolve the store directory from explicit env values (pure; no I/O).
pub fn store_dir_from(
    env_store: Option<&str>,
    env_hermes_home: Option<&str>,
    home: &Path,
) -> PathBuf {
    if let Some(store) = env_store {
        if !store.is_empty() {
            return expand_tilde(store, home);
        }
    }
    let base = match env_hermes_home {
        Some(h) if !h.is_empty() => expand_tilde(h, home),
        _ => home.join(".hermes"),
    };
    base.join("mordred").join("keyvault").join("tpm")
}

/// Resolve the store directory from the live process environment.
pub fn store_dir() -> PathBuf {
    let store = std::env::var("MORDRED_TPMKEY_STORE").ok();
    let hermes_home = std::env::var("HERMES_HOME").ok();
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    store_dir_from(store.as_deref(), hermes_home.as_deref(), &home)
}

/// The blob path for `tag_hex` under `dir`.
pub fn blob_path(dir: &Path, tag_hex: &str) -> PathBuf {
    dir.join(format!("{tag_hex}.bin"))
}

/// Refuse a store directory that is itself a symlink (M4, security review
/// 2026-06-11; parity with the Python vault's lstat-based refusal): an
/// offline-planted link must not redirect the 0700 chmod or the blob writes
/// into an attacker-chosen directory. lstat-based — a link to a perfectly
/// real directory is still refused.
fn ensure_dir_not_symlink(dir: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(StoreError::Io(format!(
            "refusing symlinked store dir: {}",
            dir.display()
        ))),
        _ => Ok(()),
    }
}

/// Write `blob` for `tag_hex`, refusing to overwrite an existing key.
///
/// Creates `dir` (0700) if absent and opens the blob `O_CREAT | O_EXCL` (0600),
/// so a pre-existing key surfaces as [`StoreError::Exists`] race-free.
pub fn write_blob_excl(dir: &Path, tag_hex: &str, blob: &[u8]) -> Result<(), StoreError> {
    ensure_safe_tag(tag_hex)?;
    ensure_dir_not_symlink(dir)?;
    fs::create_dir_all(dir).map_err(|e| StoreError::Io(e.to_string()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| StoreError::Io(e.to_string()))?;
    let path = blob_path(dir, tag_hex);
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(StoreError::Exists),
        Err(e) => return Err(StoreError::Io(e.to_string())),
    };
    file.write_all(blob)
        .map_err(|e| StoreError::Io(e.to_string()))?;
    // Pin the mode exactly (independent of the process umask), matching the
    // Swift helper's explicit 0600 on the written blob. Handle-based (M4) so
    // a racing path swap cannot redirect the chmod.
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(())
}

/// Read the blob for `tag_hex` (→ [`StoreError::NotFound`] when absent).
///
/// Opens `O_NOFOLLOW` (M4): a planted symlink at the blob path must not be
/// followed out of the store — parity with the Python keyvault's
/// `os.open(O_NOFOLLOW)` contract documented in `_storage.py`. `O_NOFOLLOW`
/// only guards the final component, so the store dir itself gets the same
/// lstat refusal as the write path.
pub fn read_blob(dir: &Path, tag_hex: &str) -> Result<Vec<u8>, StoreError> {
    use std::io::Read;

    ensure_safe_tag(tag_hex)?;
    ensure_dir_not_symlink(dir)?;
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(blob_path(dir, tag_hex))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
        Err(e) => return Err(StoreError::Io(e.to_string())),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(bytes)
}

/// Delete the blob for `tag_hex`, idempotently (a missing blob is success).
/// Refuses a symlinked store dir like the read/write paths (M4).
pub fn delete_blob(dir: &Path, tag_hex: &str) -> Result<(), StoreError> {
    ensure_safe_tag(tag_hex)?;
    ensure_dir_not_symlink(dir)?;
    match fs::remove_file(blob_path(dir, tag_hex)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    /// A unique throwaway directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            p.push(format!("tpmkey-test-{}-{}-{}", std::process::id(), tag, n));
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn explicit_store_is_authoritative() {
        let home = Path::new("/home/u");
        let dir = store_dir_from(Some("/tmp/keys"), Some("/srv/hermes"), home);
        assert_eq!(dir, PathBuf::from("/tmp/keys"));
    }

    #[test]
    fn hermes_home_when_no_explicit_store() {
        let home = Path::new("/home/u");
        let dir = store_dir_from(None, Some("/srv/hermes"), home);
        assert_eq!(dir, PathBuf::from("/srv/hermes/mordred/keyvault/tpm"));
    }

    #[test]
    fn default_home_when_neither_set() {
        let home = Path::new("/home/u");
        let dir = store_dir_from(None, None, home);
        assert_eq!(dir, PathBuf::from("/home/u/.hermes/mordred/keyvault/tpm"));
    }

    #[test]
    fn empty_env_values_are_ignored() {
        let home = Path::new("/home/u");
        let dir = store_dir_from(Some(""), Some(""), home);
        assert_eq!(dir, PathBuf::from("/home/u/.hermes/mordred/keyvault/tpm"));
    }

    #[test]
    fn tilde_in_explicit_store_expands() {
        let home = Path::new("/home/u");
        let dir = store_dir_from(Some("~/keys"), None, home);
        assert_eq!(dir, PathBuf::from("/home/u/keys"));
    }

    #[test]
    fn write_then_read_round_trips_opaque_bytes() {
        let tmp = TempDir::new("rt");
        let blob = b"\x00\x01\xfe\xff opaque".to_vec();
        write_blob_excl(tmp.path(), "abcd", &blob).unwrap();
        assert_eq!(read_blob(tmp.path(), "abcd").unwrap(), blob);
    }

    #[test]
    fn write_refuses_to_overwrite() {
        let tmp = TempDir::new("excl");
        write_blob_excl(tmp.path(), "dup", b"one").unwrap();
        assert_eq!(
            write_blob_excl(tmp.path(), "dup", b"two"),
            Err(StoreError::Exists)
        );
        assert_eq!(read_blob(tmp.path(), "dup").unwrap(), b"one".to_vec());
    }

    #[test]
    fn read_missing_is_not_found() {
        let tmp = TempDir::new("miss");
        assert_eq!(read_blob(tmp.path(), "nope"), Err(StoreError::NotFound));
    }

    #[test]
    fn delete_is_idempotent() {
        let tmp = TempDir::new("del");
        assert_eq!(delete_blob(tmp.path(), "ghost"), Ok(()));
        write_blob_excl(tmp.path(), "real", b"x").unwrap();
        assert_eq!(delete_blob(tmp.path(), "real"), Ok(()));
        assert_eq!(read_blob(tmp.path(), "real"), Err(StoreError::NotFound));
    }

    #[test]
    fn rejects_unsafe_tag_components() {
        let tmp = TempDir::new("trav");
        for bad in ["", ".", "..", "../escape", "a/b", "a\\b"] {
            assert!(
                matches!(
                    write_blob_excl(tmp.path(), bad, b"x"),
                    Err(StoreError::Io(_))
                ),
                "write accepted unsafe tag {bad:?}"
            );
            assert!(
                matches!(read_blob(tmp.path(), bad), Err(StoreError::Io(_))),
                "read accepted unsafe tag {bad:?}"
            );
            assert!(
                matches!(delete_blob(tmp.path(), bad), Err(StoreError::Io(_))),
                "delete accepted unsafe tag {bad:?}"
            );
        }
    }

    #[test]
    fn read_refuses_symlinked_blob() {
        // Security review M4: a planted symlink at <store>/<tag>.bin must not
        // let the helper read (and hand to the parent process) an arbitrary
        // file from outside the store.
        let tmp = TempDir::new("lnkread");
        fs::create_dir_all(tmp.path()).unwrap();
        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, b"not-a-blob").unwrap();
        std::os::unix::fs::symlink(&outside, blob_path(tmp.path(), "lnk")).unwrap();
        assert!(
            matches!(read_blob(tmp.path(), "lnk"), Err(StoreError::Io(_))),
            "read followed a symlinked blob"
        );
    }

    #[test]
    fn write_refuses_symlinked_store_dir() {
        // Security review M4 (parity with the Python vault's lstat refusal):
        // an offline-planted symlink at the store dir must not redirect the
        // 0700 chmod and the blob write into an attacker-chosen directory.
        let real = TempDir::new("lnkdir-real");
        fs::create_dir_all(real.path()).unwrap();
        let holder = TempDir::new("lnkdir-holder");
        fs::create_dir_all(holder.path()).unwrap();
        let link = holder.path().join("store");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        assert!(
            matches!(write_blob_excl(&link, "ab", b"x"), Err(StoreError::Io(_))),
            "write accepted a symlinked store dir"
        );
    }

    #[test]
    fn read_and_delete_refuse_symlinked_store_dir() {
        // M4 review follow-up: O_NOFOLLOW only guards the final path
        // component, so read/delete need the same lstat dir refusal as write.
        let real = TempDir::new("lnkdir-rd-real");
        fs::create_dir_all(real.path()).unwrap();
        write_blob_excl(real.path(), "ab", b"x").unwrap();
        let holder = TempDir::new("lnkdir-rd-holder");
        fs::create_dir_all(holder.path()).unwrap();
        let link = holder.path().join("store");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        assert!(
            matches!(read_blob(&link, "ab"), Err(StoreError::Io(_))),
            "read accepted a symlinked store dir"
        );
        assert!(
            matches!(delete_blob(&link, "ab"), Err(StoreError::Io(_))),
            "delete accepted a symlinked store dir"
        );
        // The real dir still works untouched.
        assert_eq!(read_blob(real.path(), "ab").unwrap(), b"x".to_vec());
    }

    #[test]
    fn blob_is_0600_and_dir_is_0700() {
        let tmp = TempDir::new("perm");
        write_blob_excl(tmp.path(), "p", b"x").unwrap();
        let dir_mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(blob_path(tmp.path(), "p"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}
