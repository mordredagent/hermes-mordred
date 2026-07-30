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
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process nonce for staging-file names. The PID separates helper
/// processes; this counter separates concurrent writes within one process
/// (notably the store's unit tests).
static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(0);

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

/// Validate an existing store directory without following its final component.
///
/// Returns `false` when absent so the write path can create it. A symlink,
/// non-directory, or mode other than 0700 is rejected instead of followed or
/// silently repaired; read/delete use the same invariant as publication.
fn validate_store_dir(dir: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(StoreError::Io(format!(
            "refusing symlinked store dir: {}",
            dir.display()
        ))),
        Ok(meta) if !meta.file_type().is_dir() => Err(StoreError::Io(format!(
            "store path is not a directory: {}",
            dir.display()
        ))),
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o700 {
                Err(StoreError::Io(format!(
                    "store directory must be mode 0700, got {mode:04o}: {}",
                    dir.display()
                )))
            } else {
                Ok(true)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error.to_string())),
    }
}

/// A staging path that is removed on every normal error path. A process crash
/// may leave the dotfile behind, but never a partial `<tag>.bin` tombstone:
/// readers and future creates ignore staging names.
struct StagingPath {
    path: PathBuf,
    armed: bool,
}

impl StagingPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn remove(&mut self) -> io::Result<()> {
        fs::remove_file(&self.path)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for StagingPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create a private staging file in `dir`.
///
/// A stale staging file left by a killed helper is harmless. Skip over it and
/// choose another nonce so it cannot block generation for the real tag.
fn create_staging_file(dir: &Path, tag_hex: &str) -> Result<(fs::File, StagingPath), StoreError> {
    for _ in 0..1024 {
        let nonce = NEXT_STAGING_FILE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".{tag_hex}.tmp-{}-{nonce}", std::process::id());
        let path = dir.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((file, StagingPath::new(path))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(StoreError::Io(e.to_string())),
        }
    }
    Err(StoreError::Io(
        "could not allocate a unique key-blob staging file".to_string(),
    ))
}

/// Flush directory-entry changes for durable publication of a blob.
fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| StoreError::Io(e.to_string()))?;
    directory
        .sync_all()
        .map_err(|e| StoreError::Io(e.to_string()))
}

/// Core implementation, injectable only so the partial-write cleanup invariant
/// can be fault-tested without depending on disk exhaustion.
fn write_blob_excl_with_hooks<F, S, R>(
    dir: &Path,
    tag_hex: &str,
    write_blob: F,
    mut sync_directory: S,
    remove_staging: R,
) -> Result<(), StoreError>
where
    F: FnOnce(&mut fs::File) -> io::Result<()>,
    S: FnMut(&Path) -> Result<(), StoreError>,
    R: FnOnce(&mut StagingPath) -> io::Result<()>,
{
    ensure_safe_tag(tag_hex)?;
    if !validate_store_dir(dir)? {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(dir)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        if !validate_store_dir(dir)? {
            return Err(StoreError::Io(
                "store directory disappeared after creation".to_string(),
            ));
        }
    }

    let target = blob_path(dir, tag_hex);
    let (mut file, mut staging) = create_staging_file(dir, tag_hex)?;
    write_blob(&mut file).map_err(|e| StoreError::Io(e.to_string()))?;
    // Pin the mode exactly (independent of the process umask), matching the
    // Swift helper's explicit 0600 on the written blob. Handle-based (M4) so
    // a racing path swap cannot redirect the chmod.
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| StoreError::Io(e.to_string()))?;
    // Persist the complete contents and mode before the file becomes visible
    // at the authoritative name. Therefore every visible target is complete.
    file.sync_all().map_err(|e| StoreError::Io(e.to_string()))?;
    drop(file);

    // A hard link is an atomic no-replace publication primitive on the same
    // filesystem. Unlike `rename`, it cannot overwrite a concurrently-created
    // target; exactly one competing generate wins and all others get EXISTS.
    match fs::hard_link(&staging.path, &target) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(StoreError::Exists),
        Err(e) => return Err(StoreError::Io(e.to_string())),
    }

    // The target is visible but is not a durable commit until the parent
    // directory is synced. Propagate failure as an indeterminate generation:
    // Python must not persist metadata/ciphertext for a key name that can
    // disappear after power loss. The visible orphan is intentionally left
    // for explicit reset/remediation.
    sync_directory(dir)?;
    if let Err(error) = remove_staging(&mut staging) {
        eprintln!(
            "mordred-hermes-tpmkey: key blob was published, but its private staging \
             name could not be removed: {error}"
        );
    }
    // Explicitly run the RAII cleanup retry before the final directory sync.
    drop(staging);
    if let Err(error) = sync_directory(dir) {
        eprintln!(
            "mordred-hermes-tpmkey: key blob is available, but staging cleanup \
             could not be synced: {error:?}"
        );
    }
    Ok(())
}

/// Core implementation with the production publication/cleanup hooks.
fn write_blob_excl_with<F>(dir: &Path, tag_hex: &str, write_blob: F) -> Result<(), StoreError>
where
    F: FnOnce(&mut fs::File) -> io::Result<()>,
{
    write_blob_excl_with_hooks(dir, tag_hex, write_blob, sync_dir, StagingPath::remove)
}

/// Write `blob` for `tag_hex`, refusing to overwrite an existing key.
///
/// The complete blob is written and synced under a private staging name, then
/// atomically hard-linked into place. This preserves `O_EXCL`-equivalent
/// concurrency semantics while ensuring an interrupted write cannot leave a
/// partial authoritative blob that permanently blocks regeneration. The file
/// inode is synced before publication and the first parent-directory sync is
/// required before success. Private staging cleanup and its follow-up sync are
/// best-effort after that durable publication point.
pub fn write_blob_excl(dir: &Path, tag_hex: &str, blob: &[u8]) -> Result<(), StoreError> {
    write_blob_excl_with(dir, tag_hex, |file| file.write_all(blob))
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
    validate_store_dir(dir)?;
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(blob_path(dir, tag_hex))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
        Err(e) => return Err(StoreError::Io(e.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| StoreError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::Io("key blob is not a regular file".to_string()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(StoreError::Io(format!(
            "key blob must be mode 0600, got {mode:04o}"
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(bytes)
}

fn delete_blob_with_sync<S>(dir: &Path, tag_hex: &str, sync_directory: S) -> Result<(), StoreError>
where
    S: FnOnce(&Path) -> Result<(), StoreError>,
{
    ensure_safe_tag(tag_hex)?;
    validate_store_dir(dir)?;
    match fs::remove_file(blob_path(dir, tag_hex)) {
        Ok(()) => sync_directory(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::Io(e.to_string())),
    }
}

/// Delete the blob for `tag_hex`, idempotently (a missing blob is success).
/// Refuses a symlinked store dir like the read/write paths (M4), unlinks a
/// final symlink itself without following its target, and syncs the parent
/// directory before reporting durable success.
pub fn delete_blob(dir: &Path, tag_hex: &str) -> Result<(), StoreError> {
    delete_blob_with_sync(dir, tag_hex, sync_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

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
    fn concurrent_writers_publish_exactly_one_complete_blob() {
        let tmp = TempDir::new("race");
        let dir = tmp.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();

        for writer in 0_u8..8 {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let blob = vec![writer; 4096];
                barrier.wait();
                (writer, write_blob_excl(&dir, "same", &blob))
            }));
        }

        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("writer thread"))
            .collect();
        let winners: Vec<_> = results
            .iter()
            .filter_map(|(writer, result)| result.as_ref().ok().map(|()| *writer))
            .collect();
        assert_eq!(winners.len(), 1, "exactly one writer must publish");
        assert!(
            results
                .iter()
                .filter(|(_, result)| matches!(result, Err(StoreError::Exists)))
                .count()
                == 7,
            "every losing writer must receive EXISTS"
        );
        assert_eq!(
            read_blob(tmp.path(), "same").unwrap(),
            vec![winners[0]; 4096],
            "the published target must contain one complete writer payload"
        );

        let names: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("same.bin")],
            "normal success and contention must clean every staging file"
        );
    }

    #[test]
    fn failed_partial_staging_write_does_not_create_a_tombstone() {
        let tmp = TempDir::new("partial");
        let result = write_blob_excl_with(tmp.path(), "retryable", |file| {
            file.write_all(b"partial")?;
            Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected write failure",
            ))
        });
        assert!(matches!(result, Err(StoreError::Io(_))));
        assert_eq!(
            read_blob(tmp.path(), "retryable"),
            Err(StoreError::NotFound),
            "a failed write must not publish the authoritative target"
        );
        assert!(
            fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "the normal failure path must clean its private staging file"
        );

        write_blob_excl(tmp.path(), "retryable", b"complete").unwrap();
        assert_eq!(
            read_blob(tmp.path(), "retryable").unwrap(),
            b"complete".to_vec(),
            "the same tag must remain retryable after an interrupted write"
        );
    }

    #[test]
    fn post_publish_sync_failure_reports_indeterminate_generation() {
        let tmp = TempDir::new("publish-sync");
        let result = write_blob_excl_with_hooks(
            tmp.path(),
            "durable",
            |file| file.write_all(b"complete"),
            |_dir| {
                Err(StoreError::Io(
                    "injected directory sync failure".to_string(),
                ))
            },
            StagingPath::remove,
        );

        assert!(matches!(result, Err(StoreError::Io(_))));
        assert_eq!(
            read_blob(tmp.path(), "durable").unwrap(),
            b"complete".to_vec(),
            "the complete visible orphan remains for explicit reset/remediation"
        );
    }

    #[test]
    fn post_publish_cleanup_failure_does_not_report_a_false_generate_failure() {
        let tmp = TempDir::new("publish-cleanup");
        let result = write_blob_excl_with_hooks(
            tmp.path(),
            "complete",
            |file| file.write_all(b"complete"),
            sync_dir,
            |_staging| Err(io::Error::other("injected staging cleanup failure")),
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            read_blob(tmp.path(), "complete").unwrap(),
            b"complete".to_vec()
        );
        assert_eq!(
            fs::read_dir(tmp.path()).unwrap().count(),
            1,
            "the RAII retry should remove the failed-cleanup staging name"
        );
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
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
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
        fs::set_permissions(real.path(), fs::Permissions::from_mode(0o700)).unwrap();
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
    fn read_refuses_loose_mode_blob() {
        let tmp = TempDir::new("loose-blob");
        write_blob_excl(tmp.path(), "ab", b"x").unwrap();
        fs::set_permissions(
            blob_path(tmp.path(), "ab"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            matches!(read_blob(tmp.path(), "ab"), Err(StoreError::Io(_))),
            "read accepted a loose-mode key blob"
        );
    }

    #[test]
    fn read_refuses_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let tmp = TempDir::new("fifo");
        fs::create_dir_all(tmp.path()).unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let fifo = blob_path(tmp.path(), "ab");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(result, 0, "mkfifo failed: {}", io::Error::last_os_error());
        assert!(
            matches!(read_blob(tmp.path(), "ab"), Err(StoreError::Io(_))),
            "read accepted a FIFO key blob"
        );
    }

    #[test]
    fn read_write_delete_refuse_loose_store_dir() {
        let tmp = TempDir::new("loose-dir");
        fs::create_dir_all(tmp.path()).unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(blob_path(tmp.path(), "ab"), b"x").unwrap();
        fs::set_permissions(
            blob_path(tmp.path(), "ab"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            write_blob_excl(tmp.path(), "new", b"x"),
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            read_blob(tmp.path(), "ab"),
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            delete_blob(tmp.path(), "ab"),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn delete_unlinks_blob_symlink_without_touching_target() {
        let tmp = TempDir::new("delete-link");
        fs::create_dir_all(tmp.path()).unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, blob_path(tmp.path(), "ab")).unwrap();

        assert_eq!(delete_blob(tmp.path(), "ab"), Ok(()));
        assert_eq!(fs::read(outside).unwrap(), b"keep");
        assert!(!blob_path(tmp.path(), "ab").exists());
    }

    #[test]
    fn delete_directory_sync_failure_is_reported() {
        let tmp = TempDir::new("delete-sync");
        write_blob_excl(tmp.path(), "ab", b"x").unwrap();

        let result = delete_blob_with_sync(tmp.path(), "ab", |_dir| {
            Err(StoreError::Io(
                "injected delete directory sync failure".to_string(),
            ))
        });

        assert!(matches!(result, Err(StoreError::Io(_))));
        assert_eq!(read_blob(tmp.path(), "ab"), Err(StoreError::NotFound));
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
