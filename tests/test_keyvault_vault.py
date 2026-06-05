"""Tests for the vault orchestration layer (fail-closed, crash-safe, anti-rollback).

This is where the pieces compose into the actual on-disk vault:

- :mod:`mordred_hermes.keyvault.vault_master` seals ONE master (SE wmk +
  passphrase recovery),
- :mod:`mordred_hermes.keyvault.manifest` is the authenticated registry,
- :mod:`mordred_hermes.keyvault.anchor` is the device-bound freshness pin,
- :mod:`mordred_hermes.keyvault.file_container` encrypts each file's bytes.

On-disk layout under the vault ``root/``::

    manifest.<gen>.mvmf   one authenticated manifest per generation
    blobs/<sha256>.blob   content-addressed MVLT ciphertexts
    recovery.mrkv         passphrase recovery sidecar (cold path)
    .lock                 flock target for write transactions

The anchor (in the device-bound store, NOT on disk) names which generation
is authoritative, so the anchor flip is the single commit point: a crash
before it leaves the previous generation as the consistent committed state.

These run cross-platform — :class:`FakeBackend` does a real P-256 ECDH and
:class:`FakeAnchorStore` is an in-memory keychain stand-in, so the whole
open/enroll/read path runs on Linux CI; only the hardware Enclave +
real Keychain are stubbed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from mordred_hermes.keyvault import anchor, manifest, recovery, vault

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_KEY_ID = "vault-test-key"
_LABEL = "mordred.vault.test"
_PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def backend() -> FakeBackend:
    b = FakeBackend()
    b.generate_enclave_key(_KEY_ID)
    return b


@pytest.fixture
def store() -> FakeAnchorStore:
    return FakeAnchorStore()


def _init(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> vault.OpenVault:
    return vault.init_vault(
        root, key_id=_KEY_ID, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=_LABEL
    )


def _open(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> vault.OpenVault:
    return vault.open_vault(root, key_id=_KEY_ID, backend=backend, store=store, anchor_label=_LABEL)


# ---------------------------------------------------------------------------
# init + happy-path round-trips
# ---------------------------------------------------------------------------


def test_init_creates_empty_vault(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    assert v.list_files() == []
    assert v.generation == 0
    v.close()


def test_enroll_then_read_round_trips(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"ANTHROPIC_API_KEY=sk-secret\n")
    assert v.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
    v.close()


def test_enroll_bumps_generation(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"a")
    assert v.generation == 1
    v.enroll_file("config.yaml", b"b")
    assert v.generation == 2
    assert sorted(v.list_files()) == [".env", "config.yaml"]
    v.close()


def test_reopen_persists_enrolled_files(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"SECRET=1\n")
    v.enroll_file("notes/2026/foo.md", b"# memory\n")
    v.close()

    reopened = _open(tmp_path, backend, store)
    assert sorted(reopened.list_files()) == [".env", "notes/2026/foo.md"]
    assert reopened.read_file(".env") == b"SECRET=1\n"
    assert reopened.read_file("notes/2026/foo.md") == b"# memory\n"
    reopened.close()


def test_re_enroll_updates_content(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"v1")
    v.enroll_file(".env", b"v2")  # same name, new content
    assert v.read_file(".env") == b"v2"
    v.close()
    reopened = _open(tmp_path, backend, store)
    assert reopened.read_file(".env") == b"v2"
    reopened.close()


def test_no_plaintext_on_disk(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    secret = b"super-secret-token-value-12345"
    v.enroll_file(".env", secret)
    v.close()
    # Walk every file in the vault tree; none may contain the plaintext.
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert secret not in p.read_bytes(), f"plaintext leaked into {p}"


# ---------------------------------------------------------------------------
# fail-closed read path
# ---------------------------------------------------------------------------


def test_read_unenrolled_name_fails_closed(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    with pytest.raises(vault.VaultError):
        v.read_file(".env")  # never enrolled
    v.close()


def test_read_tampered_blob_fails_closed(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """A swapped/edited ciphertext blob no longer matches the content-address
    recorded in the manifest → reject (never decrypt mismatched bytes)."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    blobs = list((tmp_path / "blobs").glob("*.blob"))
    assert len(blobs) == 1
    raw = bytearray(blobs[0].read_bytes())
    raw[-1] ^= 0x01
    blobs[0].write_bytes(bytes(raw))

    reopened = _open(tmp_path, backend, store)
    with pytest.raises(vault.VaultError):
        reopened.read_file(".env")
    reopened.close()


def test_missing_blob_fails_closed(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    for b in (tmp_path / "blobs").glob("*.blob"):
        b.unlink()

    reopened = _open(tmp_path, backend, store)
    with pytest.raises(vault.VaultError):
        reopened.read_file(".env")
    reopened.close()


# ---------------------------------------------------------------------------
# anti-rollback / anti-substitution (the whole point of option B)
# ---------------------------------------------------------------------------


def test_whole_manifest_rollback_rejected(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Codex P1-b: attacker restores the gen-1 manifest after gen-2 committed.
    The anchor (which the attacker cannot write) still pins gen 2, and the
    gen-2 manifest file is what open loads — deleting it must fail closed,
    never silently fall back to the older manifest."""
    v = _init(tmp_path, backend, store)
    v.enroll_file("a", b"1")  # gen 1
    v.enroll_file("b", b"2")  # gen 2, anchor now pins gen 2
    v.close()

    # Simulate an offline attacker dropping the vault back to the gen-1 view
    # by removing the gen-2 manifest. They cannot touch the device-bound anchor.
    (tmp_path / "manifest.2.mvmf").unlink()

    with pytest.raises((vault.VaultError, manifest.ManifestError, anchor.AnchorError)):
        _open(tmp_path, backend, store)


def test_wmk_substitution_rejected(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Codex P1-a: attacker forges a whole manifest under a wmk THEY minted
    against the victim's SE public key (wrap_dek is offline). The anchor pins
    SHA-256(the real wmk); the forged wmk has a different fingerprint."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")  # gen 1
    v.close()

    # Attacker mints a second master under the SAME (public) SE key and writes
    # a validly-MAC'd manifest for it at the authoritative generation path.
    from mordred_hermes.keyvault import kek

    wmk_evil = kek.seal_master_key(_KEY_ID, backend=backend)
    master_evil = kek.open_master_key(wmk_evil, _KEY_ID, backend=backend)
    forged = manifest.encode(manifest.VaultManifest(key_id=_KEY_ID, wmk=wmk_evil, files={}, generation=1), master_evil)
    (tmp_path / "manifest.1.mvmf").write_bytes(forged)

    with pytest.raises((vault.VaultError, anchor.AnchorError)):
        _open(tmp_path, backend, store)


def test_missing_anchor_fails_closed(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Deleting the anchor (e.g. to force a fallback) must not open the vault."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    store.delete(_LABEL)
    with pytest.raises((vault.VaultError, anchor.AnchorError)):
        _open(tmp_path, backend, store)


# ---------------------------------------------------------------------------
# crash consistency (P1-c): anchor flip is the commit point
# ---------------------------------------------------------------------------


def test_crash_before_anchor_commit_keeps_old_state(
    tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore
) -> None:
    """If a new manifest+blob are written but the process crashes BEFORE the
    anchor flip, reopening must see the previous committed generation — the
    half-written generation is ignored, not bricked, not rolled forward."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"committed")  # gen 1, fully committed
    v.close()

    # Hand-simulate a crashed enroll to gen 2: drop a gen-2 manifest on disk
    # (as enroll would, mid-transaction) but leave the anchor pinning gen 1.
    record = anchor.read_anchor(store, _LABEL)
    assert record.generation == 1
    (tmp_path / "manifest.2.mvmf").write_bytes((tmp_path / "manifest.1.mvmf").read_bytes())

    reopened = _open(tmp_path, backend, store)
    assert reopened.generation == 1
    assert reopened.read_file(".env") == b"committed"
    reopened.close()


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------


def test_close_blocks_further_use(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"x")
    v.close()
    with pytest.raises(vault.VaultError):
        v.read_file(".env")


def test_context_manager_closes(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    with _init(tmp_path, backend, store) as v:
        v.enroll_file(".env", b"inside")
        assert v.read_file(".env") == b"inside"
    with pytest.raises(vault.VaultError):
        v.read_file(".env")


def test_recovery_sidecar_written(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """init must persist the passphrase recovery blob as a sidecar (NOT inside
    the manifest — keeping the Argon2id brute-force target out of the
    integrity-critical registry, per the design review)."""
    v = _init(tmp_path, backend, store)
    v.close()
    sidecar = tmp_path / "recovery.mrkv"
    assert sidecar.exists()
    assert sidecar.read_bytes()  # non-empty


def test_files_are_owner_only_mode(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"x")
    v.close()
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert (p.stat().st_mode & 0o077) == 0, f"{p} is group/other-accessible"


# ---------------------------------------------------------------------------
# cold-path recovery (device / Secure Enclave gone — passphrase + sidecar)
# ---------------------------------------------------------------------------
#
# When the device (and therefore the SE wrapping key AND the device-bound
# anchor) is gone, the vault is recovered from the recovery.mrkv sidecar with
# the passphrase. The recovery digest = SHA-256(wmk) baked into the sidecar
# still binds it to the real wmk, so a substituted wmk in the manifest is
# rejected (RecoveryDigestMismatch) even though there is no anchor to check.
# Accepted weakening: with no device-bound anchor, recovery cannot guarantee
# freshness (rollback to an older on-disk snapshot is undetectable), and a
# recovered vault is READ-ONLY until it is re-keyed onto a new device.


def test_recover_reads_enrolled_files(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"ANTHROPIC_API_KEY=sk-secret\n")
    v.close()

    # Recovery uses neither the SE backend nor the anchor store.
    rv = vault.recover_vault(tmp_path, _PASSPHRASE)
    assert rv.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
    rv.close()


def test_recover_reads_latest_generation(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"v1")
    v.enroll_file("config.yaml", b"cfg")  # gen 2 is the latest on disk
    v.close()

    rv = vault.recover_vault(tmp_path, _PASSPHRASE)
    assert rv.generation == 2
    assert sorted(rv.list_files()) == [".env", "config.yaml"]
    assert rv.read_file("config.yaml") == b"cfg"
    rv.close()


def test_recover_wrong_passphrase_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    with pytest.raises(InvalidTag):
        vault.recover_vault(tmp_path, "wrong passphrase")


def test_recover_wmk_substitution_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """No anchor in recovery, but the recovery digest = SHA-256(wmk) binds the
    sidecar to the real wmk: a manifest whose wmk was swapped is rejected."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")  # gen 1
    v.close()

    from mordred_hermes.keyvault import kek

    wmk_evil = kek.seal_master_key(_KEY_ID, backend=backend)
    master_evil = kek.open_master_key(wmk_evil, _KEY_ID, backend=backend)
    forged = manifest.encode(manifest.VaultManifest(key_id=_KEY_ID, wmk=wmk_evil, files={}, generation=1), master_evil)
    (tmp_path / "manifest.1.mvmf").write_bytes(forged)

    with pytest.raises(recovery.RecoveryDigestMismatch):
        vault.recover_vault(tmp_path, _PASSPHRASE)


def test_recover_tampered_manifest_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """A manifest body edit (attacker has no master) passes the recovery-digest
    check on the untouched wmk but fails the MAC under the recovered master."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    mpath = tmp_path / "manifest.1.mvmf"
    body_b, _, b64tag = mpath.read_bytes().partition(b"\n")
    import base64

    raw = bytearray(base64.b64decode(b64tag))
    raw[-1] ^= 0x01
    mpath.write_bytes(body_b + b"\n" + base64.b64encode(bytes(raw)))

    with pytest.raises(manifest.ManifestError):
        vault.recover_vault(tmp_path, _PASSPHRASE)


def test_recover_missing_manifest_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    for m in tmp_path.glob("manifest.*.mvmf"):
        m.unlink()
    with pytest.raises(vault.VaultError):
        vault.recover_vault(tmp_path, _PASSPHRASE)


def test_recover_missing_sidecar_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    (tmp_path / "recovery.mrkv").unlink()
    with pytest.raises(vault.VaultError):
        vault.recover_vault(tmp_path, _PASSPHRASE)


def test_recovered_vault_is_read_only(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """A recovered vault has no SE key / anchor to commit against, so enroll
    must refuse until the vault is re-keyed onto a new device."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")
    v.close()
    rv = vault.recover_vault(tmp_path, _PASSPHRASE)
    with pytest.raises(vault.VaultError):
        rv.enroll_file("config.yaml", b"nope")
    rv.close()


# ---------------------------------------------------------------------------
# concurrency: a stale handle must not roll the vault back (codex impl-review P1)
# ---------------------------------------------------------------------------


def test_enroll_on_stale_handle_is_rejected(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Two handles open at the same generation; one commits ahead, leaving the
    other behind. The stale handle's in-RAM generation now lags the device
    anchor (which only a live writer can move). A further enroll through the
    stale handle must NOT silently re-mint the newer manifest, flip the anchor
    backwards, and let GC drop the newer writer's blob — it must fail closed and
    leave the committed state untouched (codex impl-review P1: stale-writer
    rollback). This is a normal concurrent-process scenario, not the
    out-of-scope live attacker."""
    first = _init(tmp_path, backend, store)
    first.enroll_file("a", b"1")  # gen 1 — both handles will agree here

    stale = _open(tmp_path, backend, store)
    assert stale.generation == 1

    # The first handle advances the vault to gen 2; the anchor now pins gen 2.
    first.enroll_file("b", b"2")
    assert first.generation == 2

    # The stale handle (still in-RAM gen 1) must refuse: writing manifest.2 with
    # its divergent {a, c} file set would drop "b" and roll the anchor back.
    with pytest.raises(vault.VaultError):
        stale.enroll_file("c", b"3")

    first.close()
    stale.close()

    # The committed gen-2 state stands: a + b present, c never landed.
    reopened = _open(tmp_path, backend, store)
    assert sorted(reopened.list_files()) == ["a", "b"]
    assert reopened.read_file("a") == b"1"
    assert reopened.read_file("b") == b"2"
    reopened.close()


def test_read_file_blob_vanishes_after_check_is_vault_error(
    tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The blob can be unlinked (e.g. by a concurrent gc) between the presence
    check and the read, so safe_read raises FileNotFoundError. The fail-closed
    read contract permits no other exception type to escape, so it must surface
    as VaultError (codex impl-review P2)."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"value")

    def _vanished(_path: Path) -> bytes:
        raise FileNotFoundError(_path)

    monkeypatch.setattr(vault, "safe_read", _vanished)
    with pytest.raises(vault.VaultError):
        v.read_file(".env")
    v.close()


# ---------------------------------------------------------------------------
# offline-swap hardening: refuse symlinked vault paths (codex impl-review P2)
# ---------------------------------------------------------------------------


def test_init_rejects_symlinked_blobs_dir(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """An offline attacker who pre-plants ``blobs/`` as a symlink would redirect
    every ciphertext write outside the 0700 vault tree. init must refuse a
    symlinked path rather than chmod/write through it (codex impl-review P2)."""
    root = tmp_path / "vault"
    root.mkdir(mode=0o700)
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    (root / "blobs").symlink_to(target, target_is_directory=True)

    with pytest.raises(vault.VaultError):
        _init(root, backend, store)


def test_init_rejects_symlinked_root(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Same defence one level up: a symlinked vault root must be refused."""
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    root = tmp_path / "vault"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(vault.VaultError):
        _init(root, backend, store)


# ---------------------------------------------------------------------------
# unenroll_file — the purge primitive (mirror of enroll_file)
# ---------------------------------------------------------------------------


def test_unenroll_removes_name_and_bumps_generation(
    tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore
) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"SECRET=1\n")
    gen_before = v.generation
    v.unenroll_file(".env")
    assert ".env" not in v.list_files()
    assert v.generation == gen_before + 1
    with pytest.raises(vault.VaultError):
        v.read_file(".env")  # fail-closed: no longer enrolled
    v.close()


def test_unenroll_keeps_other_files_intact(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"SECRET=1\n")
    v.enroll_file("config.yaml", b"model: x\n")
    v.unenroll_file(".env")
    assert v.list_files() == ["config.yaml"]
    assert v.read_file("config.yaml") == b"model: x\n"
    v.close()


def test_unenroll_gcs_orphan_blob(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"SECRET=1\n")
    assert len(list((tmp_path / "blobs").glob("*.blob"))) == 1
    v.unenroll_file(".env")
    # the removed file's ciphertext blob is no longer referenced → GC'd
    assert list((tmp_path / "blobs").glob("*.blob")) == []
    v.close()


def test_unenroll_absent_name_is_noop(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file("config.yaml", b"x")
    gen_before = v.generation
    v.unenroll_file(".env")  # never enrolled → clean no-op, no generation churn
    assert v.generation == gen_before
    assert v.list_files() == ["config.yaml"]
    v.close()


def test_unenroll_persists_after_reopen(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"S=1\n")
    v.enroll_file("config.yaml", b"y")
    v.unenroll_file(".env")
    v.close()

    reopened = _open(tmp_path, backend, store)
    assert reopened.list_files() == ["config.yaml"]
    with pytest.raises(vault.VaultError):
        reopened.read_file(".env")
    reopened.close()


def test_unenroll_recovery_mode_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """A recovery-mode handle has no device anchor to commit against — refuse."""
    v = _init(tmp_path, backend, store)
    v.enroll_file(".env", b"S=1\n")
    v.close()

    rec = vault.recover_vault(tmp_path, _PASSPHRASE)
    with pytest.raises(vault.VaultError):
        rec.unenroll_file(".env")
    rec.close()


def test_unenroll_stale_handle_raises(tmp_path: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """A handle whose in-RAM generation lags the device anchor must fail closed."""
    a = _init(tmp_path, backend, store)
    a.enroll_file(".env", b"S=1\n")

    b = _open(tmp_path, backend, store)  # second writer advances the vault
    b.enroll_file("config.yaml", b"y")
    b.close()

    with pytest.raises(vault.VaultError):
        a.unenroll_file(".env")  # handle `a` is now stale
    a.close()
