"""mordred_hermes.keyvault.vault — the on-disk Mordred vault orchestration.

Composes the keyvault primitives into the artifact that actually encrypts
``.env`` / ``config.yaml`` / Hermes memory at rest:

- :mod:`mordred_hermes.keyvault.vault_master` seals ONE master (Secure-
  Enclave ``wmk`` hot path + Argon2id passphrase recovery cold path),
- :mod:`mordred_hermes.keyvault.file_container` (``MVLT``) encrypts each
  file's bytes under that master,
- :mod:`mordred_hermes.keyvault.manifest` (``MVMF``) is the authenticated
  registry of enrolled files + their ciphertext digests + a generation,
- :mod:`mordred_hermes.keyvault.anchor` pins ``SHA-256(wmk)`` + generation
  in a device-bound store an offline attacker can read but not write.

On-disk layout under ``root/``::

    manifest.<gen>.mvmf   one authenticated manifest per generation
    blobs/<sha256>.blob   content-addressed MVLT ciphertexts
    recovery.mrkv         Argon2id passphrase recovery sidecar (cold path)
    .lock                 fcntl.flock target for write transactions

**Commit model (crash safety + anti-rollback).** The device-bound anchor
names which generation is authoritative, so the anchor flip is the single
commit point of an :meth:`OpenVault.enroll_file` transaction:

1. write the new content-addressed ciphertext blob,
2. write ``manifest.<N+1>.mvmf``,
3. **flip the anchor to generation N+1** ← commit,
4. (best-effort) garbage-collect the superseded manifest + orphan blobs.

A crash before step 3 leaves the anchor pinning generation N: reopening
loads ``manifest.<N>``, the half-written generation is ignored, and the
vault is neither bricked nor rolled forward (Codex review P1-c). Because
the anchor pins the canonical wmk fingerprint and the authoritative
generation, an offline attacker can neither substitute a wmk they minted
against the (public) SE key (P1-a) nor roll the whole vault back to an
older validly-MAC'd snapshot (P1-b) — both move a value only the locked
device can write.

**Fail-closed.** An enrolled name MUST decrypt: a name absent from the
manifest, a missing blob, a blob that does not match its content address,
or an AEAD failure all raise :class:`VaultError`; the vault never falls
back to reading a file as plaintext.

**Threat ceiling (B2 / unattended SE).** This protects offline disk reads
and offline disk swaps (stolen / powered-off / imaged / backup). It does
NOT protect against a same-uid attacker on a running, unlocked machine —
an unattended wrapping key lets any same-uid process unwrap the master.
That tradeoff is accepted for hands-free operation.

Like its keyvault siblings it imports :mod:`cryptography` (through the
crypto modules) and is only importable where the ``[macos]`` extra is
installed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from types import TracebackType

from . import anchor, file_container, manifest, vault_master
from ._storage import atomic_write, keyvault_lock, safe_read
from .anchor import AnchorStore
from .kek import MasterKey, open_master_key
from .wrap import NativeBackend

_RECOVERY_NAME = "recovery.mrkv"
_LOCK_NAME = ".lock"
_BLOBS_DIR = "blobs"
_DIR_MODE = 0o700
_FILE_MODE = 0o600


class VaultError(Exception):
    """A vault operation failed closed.

    Raised for vault-level faults: an uninitialized / already-initialized
    root, a missing authoritative manifest, a name that is not enrolled, a
    ciphertext blob that is missing or does not match its content address,
    an AEAD failure, or use of a closed vault. Distinct from
    :class:`mordred_hermes.keyvault.anchor.AnchorError` (freshness-pin
    failures) and :class:`mordred_hermes.keyvault.manifest.ManifestError`
    (manifest authentication failures), which propagate as themselves so a
    caller can tell a tamper attempt from an operational error — but all
    three are hard failures that prevent the vault from opening or reading.
    """


def _manifest_path(root: Path, generation: int) -> Path:
    return root / f"manifest.{generation}.mvmf"


def _latest_manifest_generation(root: Path) -> int | None:
    """Highest ``manifest.<gen>.mvmf`` generation on disk, or ``None`` if none.

    Used only by :func:`recover_vault`, which has no device-bound anchor to
    name the authoritative generation and so falls back to the newest manifest
    present. (Normal :func:`open_vault` never guesses — the anchor names it.)
    """
    generations: list[int] = []
    for p in root.glob("manifest.*.mvmf"):
        middle = p.name[len("manifest.") : -len(".mvmf")]
        if middle.isdigit():
            generations.append(int(middle))
    return max(generations) if generations else None


def _blob_path(root: Path, digest: str) -> Path:
    return root / _BLOBS_DIR / f"{digest}.blob"


def _ensure_dir(path: Path) -> None:
    # lstat-based: a symlink (even one pointing at a real 0700 dir) is refused
    # so an offline-planted symlink cannot redirect the vault tree's chmod /
    # writes outside the 0700 root (codex impl-review P2). The residual
    # lstat->mkdir/chmod TOCTOU only matters to a live same-uid attacker, who
    # is out of scope.
    if path.is_symlink():
        raise VaultError(f"refusing to use a symlinked vault path: {path}")
    if not path.exists():
        path.mkdir(mode=_DIR_MODE, parents=True)
    elif not path.is_dir():
        raise VaultError(f"vault path exists but is not a directory: {path}")
    os.chmod(path, _DIR_MODE)


def _ensure_lock(root: Path) -> None:
    lock = root / _LOCK_NAME
    if not lock.exists():
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE)
        os.close(fd)


def init_vault(
    root: Path,
    *,
    key_id: str,
    passphrase: str,
    backend: NativeBackend,
    store: AnchorStore,
    anchor_label: str,
) -> OpenVault:
    """Create a fresh, empty vault at ``root`` and return it opened.

    Seals one master under the existing Secure-Enclave wrapping key
    ``key_id`` (SE ``wmk`` + passphrase recovery), writes the recovery
    sidecar and the generation-0 manifest, then flips the device-bound
    anchor to generation 0 — the same commit point an enroll uses, so a
    crashed init (no anchor) simply allows a clean re-init.

    Raises:
        VaultError: a vault is already initialized at ``root`` (its anchor
            exists in ``store``).
        ValueError: ``passphrase`` is empty.
        WrapKeyNotFound: no SE wrapping key exists for ``key_id``.
    """
    root = Path(root)
    _ensure_dir(root)
    _ensure_dir(root / _BLOBS_DIR)
    _ensure_lock(root)

    sealed, master = vault_master.seal(key_id=key_id, passphrase=passphrase, backend=backend)
    try:
        # The clobber-check and the writes are one critical section: checking
        # the anchor outside the lock would let two concurrent inits both pass
        # it and then race their writes, silently destroying the first vault.
        with keyvault_lock(root):
            if store.read(anchor_label) is not None:
                raise VaultError(f"a vault is already initialized for anchor label {anchor_label!r}")
            atomic_write(root / _RECOVERY_NAME, sealed.recovery)
            empty = manifest.VaultManifest(key_id=key_id, wmk=sealed.wmk, files={}, generation=0)
            atomic_write(_manifest_path(root, 0), manifest.encode(empty, master))
            anchor.write_anchor(store, anchor_label, wmk=sealed.wmk, generation=0)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=key_id,
        master=master,
        manifest_=empty,
        store=store,
        anchor_label=anchor_label,
        wmk=sealed.wmk,
    )


def open_vault(
    root: Path,
    *,
    key_id: str,
    backend: NativeBackend,
    store: AnchorStore,
    anchor_label: str,
) -> OpenVault:
    """Open an existing vault, verifying freshness before trusting anything.

    Sequence (the two-phase bootstrap):

    1. read the device-bound anchor → the authoritative generation N (and
       the pinned wmk fingerprint),
    2. load ``manifest.<N>`` and ``parse_unverified`` it to extract ``wmk``,
    3. :func:`anchor.verify_anchor` — reject unless ``SHA-256(wmk)`` and the
       manifest's generation match the pins (defeats P1-a + P1-b),
    4. SE-unwrap the now-trusted ``wmk`` to obtain the master,
    5. :func:`manifest.decode` to authenticate the full manifest under it.

    Raises:
        AnchorMissing / AnchorMismatch / AnchorCorrupt: freshness-pin
            failure (all subclasses of ``AnchorError``).
        ManifestError: the manifest failed authentication under the master.
        VaultError: the authoritative manifest file is missing.
        WrapKeyNotFound / WrapAuthCancelled / ...: SE unwrap failures.
    """
    root = Path(root)
    record = anchor.read_anchor(store, anchor_label)

    mpath = _manifest_path(root, record.generation)
    try:
        blob = safe_read(mpath)
    except FileNotFoundError as e:
        raise VaultError(
            f"authoritative manifest for generation {record.generation} is missing — "
            "vault is corrupt or was rolled back below its anchor"
        ) from e

    untrusted = manifest.parse_unverified(blob)
    # Pin-check BEFORE unwrapping: the wmk we are about to feed the Enclave
    # must match the fingerprint the (unwritable) anchor holds, and the
    # manifest's generation must match the authoritative generation.
    anchor.verify_anchor(store, anchor_label, wmk=untrusted.wmk, generation=untrusted.generation)

    master = open_master_key(untrusted.wmk, key_id, backend=backend)
    try:
        verified = manifest.decode(blob, master)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=key_id,
        master=master,
        manifest_=verified,
        store=store,
        anchor_label=anchor_label,
        wmk=untrusted.wmk,
    )


def recover_vault(root: Path, passphrase: str) -> OpenVault:
    """Open a vault from its passphrase recovery sidecar (cold path).

    For when the device — and therefore the Secure-Enclave wrapping key AND
    the device-bound anchor — is gone (new machine, lost key, non-macOS).
    Uses neither the SE backend nor the anchor store:

    1. pick the newest ``manifest.<gen>.mvmf`` on disk (no anchor to name it),
    2. ``parse_unverified`` to extract ``wmk``,
    3. read ``recovery.mrkv`` and :func:`vault_master.open_passphrase` —
       its baked-in ``SHA-256(wmk)`` verification digest still binds the
       sidecar to the real ``wmk``, so a substituted manifest ``wmk`` raises
       :class:`~mordred_hermes.keyvault.recovery.RecoveryDigestMismatch`
       before the Argon2 cost; a wrong passphrase raises ``InvalidTag``,
    4. :func:`manifest.decode` authenticates the manifest under the recovered
       master.

    Accepted weakening vs :func:`open_vault`: with no device-bound anchor,
    recovery cannot guarantee freshness — an offline attacker who rolled the
    on-disk snapshot back to an older (validly-MAC'd, same-wmk) generation is
    undetectable here. The returned vault is therefore READ-ONLY: enrolling
    requires re-keying onto a new device first (a separate operation).

    Raises:
        VaultError: no manifest on disk, or the recovery sidecar is missing.
        recovery.RecoveryDigestMismatch: the manifest's ``wmk`` was substituted.
        cryptography.exceptions.InvalidTag: wrong passphrase.
        ManifestError: the manifest failed authentication under the master.
    """
    root = Path(root)
    generation = _latest_manifest_generation(root)
    if generation is None:
        raise VaultError("no manifest found at this root — not a vault, or all manifests are missing")
    try:
        blob = safe_read(_manifest_path(root, generation))
    except FileNotFoundError as e:
        raise VaultError(f"manifest for generation {generation} vanished — cannot recover this vault") from e
    untrusted = manifest.parse_unverified(blob)

    try:
        recovery_blob = safe_read(root / _RECOVERY_NAME)
    except FileNotFoundError as e:
        raise VaultError("recovery sidecar (recovery.mrkv) is missing — cannot recover this vault") from e

    master = vault_master.open_passphrase(recovery_blob, passphrase, wmk=untrusted.wmk)
    try:
        verified = manifest.decode(blob, master)
    except BaseException:
        master.close()
        raise
    return OpenVault(
        root=root,
        key_id=verified.key_id,
        master=master,
        manifest_=verified,
        store=None,
        anchor_label="",
        wmk=untrusted.wmk,
    )


class OpenVault:
    """A live handle to an opened vault.

    Holds the in-RAM master (closed on :meth:`close`) and the currently
    committed manifest. Read/enroll go through this handle; nothing here
    persists plaintext to disk. Usable as a context manager.
    """

    __slots__ = ("_closed", "_key_id", "_label", "_manifest", "_master", "_root", "_store", "_wmk")

    def __init__(
        self,
        *,
        root: Path,
        key_id: str,
        master: MasterKey,
        manifest_: manifest.VaultManifest,
        store: AnchorStore | None,
        anchor_label: str,
        wmk: bytes,
    ) -> None:
        self._root = root
        self._key_id = key_id
        self._master = master
        self._manifest = manifest_
        self._store = store
        self._label = anchor_label
        self._wmk = wmk
        self._closed = False

    def _check(self) -> None:
        if self._closed:
            raise VaultError("vault is closed")

    @property
    def generation(self) -> int:
        """The currently committed generation."""
        self._check()
        return self._manifest.generation

    def list_files(self) -> list[str]:
        """The logical names enrolled in the current manifest."""
        self._check()
        return list(self._manifest.files.keys())

    def read_file(self, name: str) -> bytes:
        """Decrypt and return the bytes of enrolled file ``name``.

        Fail-closed: a name absent from the manifest, a missing blob, a
        blob whose content does not match the manifest's content-address,
        or an AEAD failure all raise :class:`VaultError`.
        """
        self._check()
        digest = self._manifest.files.get(name)
        if digest is None:
            raise VaultError(f"{name!r} is not enrolled in this vault")
        bpath = _blob_path(self._root, digest)
        # No exists() pre-check: it races a concurrent gc, and safe_read's
        # FileNotFoundError is the authoritative "blob is gone" signal. Catch it
        # so the fail-closed read path only ever raises VaultError.
        try:
            blob = safe_read(bpath)
        except FileNotFoundError as e:
            raise VaultError(f"ciphertext blob for {name!r} is missing (digest {digest})") from e
        if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), digest):
            raise VaultError(f"ciphertext blob for {name!r} does not match its content address — rejected")
        try:
            return file_container.decode(blob, self._master, name=name)
        except file_container.EncryptedFileError as e:
            raise VaultError(f"failed to authenticate / decrypt {name!r}") from e

    def enroll_file(self, name: str, plaintext: bytes) -> None:
        """Encrypt ``plaintext`` as enrolled file ``name`` and commit it.

        Bumps the generation, writes the content-addressed blob and the new
        manifest, then flips the anchor (the commit point). A crash before
        the flip leaves the previous generation committed.

        Raises:
            VaultError: the vault is closed, or was opened in recovery mode
                (no device anchor to commit against — re-key first).
        """
        self._check()
        if self._store is None:
            raise VaultError(
                "vault opened in recovery mode (no device-bound anchor) — re-key onto a device before enrolling"
            )
        store = self._store
        blob = file_container.encode(self._master, plaintext, key_id=self._key_id, wmk=self._wmk, name=name)
        digest = hashlib.sha256(blob).hexdigest()
        new_generation = self._manifest.generation + 1
        new_files = dict(self._manifest.files)
        new_files[name] = digest
        new_manifest = manifest.VaultManifest(
            key_id=self._key_id, wmk=self._wmk, files=new_files, generation=new_generation
        )

        _ensure_lock(self._root)
        with keyvault_lock(self._root):
            # Re-derive the authoritative state under the lock before writing.
            # If another process committed since this handle opened (or last
            # enrolled), our in-RAM generation lags the device anchor — writing
            # manifest.<N+1> over the newer state and flipping the anchor back
            # would roll the vault back and let _gc drop the newer writer's
            # blobs (codex impl-review P1: stale-writer rollback). The anchor is
            # the source of truth (an offline attacker cannot move it), so an
            # advance here is a legitimate concurrent writer: fail closed and
            # require a reopen.
            pinned = anchor.read_anchor(store, self._label)
            stale_generation = pinned.generation != self._manifest.generation
            wmk_changed = not hmac.compare_digest(pinned.wmk_sha256, anchor.wmk_fingerprint(self._wmk))
            if stale_generation or wmk_changed:
                raise VaultError(
                    f"stale vault handle: in-memory generation {self._manifest.generation} no longer matches the "
                    f"device anchor (generation {pinned.generation}) — another writer advanced the vault; reopen it"
                )
            atomic_write(_blob_path(self._root, digest), blob)
            atomic_write(_manifest_path(self._root, new_generation), manifest.encode(new_manifest, self._master))
            # ---- commit: the anchor flip makes generation N+1 authoritative ----
            anchor.write_anchor(store, self._label, wmk=self._wmk, generation=new_generation)
            self._manifest = new_manifest
            self._gc(superseded_generation=new_generation - 1)

    def _gc(self, *, superseded_generation: int) -> None:
        """Best-effort: drop the superseded manifest + any orphan blobs.

        Runs only AFTER the anchor commit, so a failure here cannot lose
        committed data — it only leaves recoverable clutter. Blobs still
        referenced by the current manifest are never removed.
        """
        try:
            old = _manifest_path(self._root, superseded_generation)
            if old.exists():
                old.unlink()
            kept = set(self._manifest.files.values())
            for b in (self._root / _BLOBS_DIR).glob("*.blob"):
                if b.stem not in kept:
                    b.unlink()
        except OSError:
            pass

    def close(self) -> None:
        """Zero the in-RAM master and block further use. Idempotent."""
        if not self._closed:
            self._master.close()
            self._closed = True

    def __enter__(self) -> OpenVault:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        self.close()
