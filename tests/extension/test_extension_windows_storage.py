"""Checked Windows extension storage, exercised through real ``_private_fs`` on each host.

Pairing, attestation, WebAuthn, history and the wallet snapshot fingerprint run
their Windows branch here. On POSIX the descriptor-relative private backend
stands in for NTFS admission (mode/owner/link checks instead of DACLs); the
real Windows backend runs the same module in the scoped Windows CI job.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import hashlib
import json
import os
import queue
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.extension import _windows_storage as storage
from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import crypto as xc
from mordred_hermes.extension import errors as extension_errors
from mordred_hermes.extension import history, pairing
from mordred_hermes.extension import wallet as extension_wallet
from tests._child_env import with_package_under_test
from tests.extension._windows_storage_support import REPO_ROOT, enable_checked_storage

ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
CODE = "MORT-AAAAAAAA-BBBBBBBB"
REPLAY_ID = "a" * 64


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    enable_checked_storage(monkeypatch)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(pairing, "se_available", lambda: False)
    pairing._invalidate_state_cache()
    yield tmp_path
    pairing._invalidate_state_cache()


def ext(home: Path) -> Path:
    return home / "extension"


def put(directory: Path, name: str, data: bytes) -> None:
    """Publish test state through the checked primitives (create or replace)."""
    with open_private_directory(directory, create=True) as checked, checked.transaction() as tx:
        try:
            tx.stat(name)
        except PrivateFSError:
            tx.create_bytes(name, data)
        else:
            tx.replace_bytes(name, data)


def checked_delete(directory: Path, name: str) -> None:
    with open_private_directory(directory) as checked, checked.transaction() as tx:
        tx.delete_file(name)


def broaden(path: Path) -> None:
    if os.name == "nt":
        subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    else:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def posture(path: Path) -> object:
    if os.name == "nt":
        return subprocess.check_output(["icacls.exe", str(path)])
    return stat.S_IMODE(os.lstat(path).st_mode)


def sha(data: bytes | str) -> str:
    """Compare secrets (PEM, aes_key, ext_token) only through digests in asserts."""
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def snapshot(directory: Path) -> dict[str, str]:
    return {entry.name: file_sha(entry) for entry in sorted(directory.iterdir()) if entry.is_file()}


def token_is_valid(token: str) -> bool:
    return pairing.validate_token(token)


def loaded_token_sha() -> str | None:
    loaded = pairing.load_pairing()
    return None if loaded is None else sha(loaded.ext_token)


def p256_public_key_b64() -> str:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return xc.b64u_encode(
        public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def handshake() -> dict[str, Any]:
    code, _expires = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    return pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x11" * 32))


@pytest.fixture
def paired(home: Path) -> dict[str, Any]:
    result = handshake()
    pairing.save_webauthn_credential("cred-1", p256_public_key_b64(), origin=ORIGIN)
    history.save_messages([{"role": "user", "content": "hello"}])
    return result


def operations(token: str) -> dict[str, Callable[[], object]]:
    return {
        "generate_code": pairing.generate_code,
        "consume": lambda: pairing._consume_code(CODE),
        "pair_outcome": lambda: pairing.pair_outcome(CODE),
        "code_consumed": lambda: pairing.code_consumed(CODE),
        "revoke": lambda: pairing.revoke_code(CODE),
        "load_pairing": pairing.load_pairing,
        "attest": pairing.attest_pubkey_spki_b64,
        "channel_key": lambda: pairing.save_channel_key("C1", b"\x01" * 32),
        "replay": lambda: pairing.claim_e2e_replay_identities(("b" * 64,)),
        "fingerprint": lambda: pairing.authentication_generation_fingerprint(token),
        "webauthn_has": pairing.has_webauthn_credential,
        "webauthn_save": lambda: pairing.save_webauthn_credential("cred-2", p256_public_key_b64(), origin=ORIGIN),
        "webauthn_clear": pairing.clear_webauthn_credential,
        "history_load": history.load_history,
        "history_save": lambda: history.save_messages([{"role": "user", "content": "again"}]),
        "history_clear": history.clear,
        "clear_pairing": pairing.clear_pairing,
    }


# --------------------------------------------------------------------------- #
# Checked round trips                                                         #
# --------------------------------------------------------------------------- #


def test_handshake_state_and_history_use_the_checked_directory(paired: dict[str, Any], home: Path) -> None:
    valid = token_is_valid(paired["ext_token"])
    assert valid is True
    assert pairing.has_webauthn_credential() is True
    assert history.load_history().status == history.STATUS_OK
    names = sorted(entry.name for entry in ext(home).iterdir())
    assert names == [
        ".mordred-fs.lock",
        "attest_key.pem",
        "history.enc",
        "pending.json",
        "state.json",
        "webauthn.json",
    ]
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(ext(home)).st_mode) == 0o700
        assert {stat.S_IMODE(os.lstat(ext(home) / name).st_mode) for name in names} == {0o600}

    pairing.save_channel_key("C1", b"\x01" * 32)
    assert pairing.load_channel_keys() == {"C1": b"\x01" * 32}
    assert pairing.claim_e2e_replay_identities((REPLAY_ID,)) is True
    assert pairing.claim_e2e_replay_identities((REPLAY_ID,)) is False
    pairing.clear_webauthn_credential()
    assert pairing.has_webauthn_credential() is False
    history.clear()
    assert history.load_history().status == history.STATUS_EMPTY
    pairing.clear_pairing()
    assert pairing.load_pairing() is None
    assert sorted(entry.name for entry in ext(home).iterdir()) == [".mordred-fs.lock", "attest_key.pem", "pending.json"]


def test_checked_absence_reads_create_nothing(home: Path) -> None:
    assert pairing.load_pairing() is None
    assert pairing.load_channel_keys() == {}
    assert pairing.code_consumed(CODE) is False
    assert pairing.has_webauthn_credential() is False
    assert pairing.authentication_generation_fingerprint() is None
    assert history.load_history().status == history.STATUS_UNAVAILABLE
    pairing.clear_pairing()
    pairing.clear_webauthn_credential()
    history.clear()
    assert not ext(home).exists()


def test_cancelled_code_round_trip(home: Path) -> None:
    code, _expires = pairing.generate_code()
    assert pairing.pair_outcome(code) == ("pending", None)
    assert pairing.revoke_code(code) is True
    assert pairing.code_consumed(code) is True
    assert pairing.pair_outcome(code) == ("failed", "cancelled")
    with pytest.raises(pairing.PairError, match="already_used"):
        pairing._consume_code(code)


_RAW_PATH_METHODS = (
    "chmod",
    "exists",
    "is_file",
    "lstat",
    "mkdir",
    "open",
    "read_bytes",
    "read_text",
    "rename",
    "replace",
    "stat",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
)


@contextlib.contextmanager
def forbid_raw_extension_paths(directory: Path) -> Iterator[None]:
    """Fail any raw ``pathlib``/``open()`` use on ``directory`` for the block's duration."""
    guarded = os.fspath(directory)
    owned = {name: name in vars(Path) for name in _RAW_PATH_METHODS}
    originals = {name: getattr(Path, name) for name in _RAW_PATH_METHODS}
    real_open = builtins.open

    def guard(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
        def method(self: Path, *args: Any, **kwargs: Any) -> Any:
            if os.fspath(self).startswith(guarded):
                pytest.fail(f"raw Path.{name} reached extension state from the Windows branch")
            return original(self, *args, **kwargs)

        return method

    def guarded_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and os.fspath(file).startswith(guarded):
            pytest.fail("raw open() reached extension state from the Windows branch")
        return real_open(file, *args, **kwargs)

    for name, original in originals.items():
        setattr(Path, name, guard(name, original))
    builtins.open = guarded_open
    try:
        yield
    finally:
        builtins.open = real_open
        for name, original in originals.items():
            if owned[name]:
                setattr(Path, name, original)
            else:
                delattr(Path, name)


def test_posix_tolerant_storage_is_unreachable_on_windows(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> Any:
        pytest.fail("POSIX extension storage helper reached from the Windows branch")

    class ForbiddenModule:
        def __getattr__(self, name: str) -> Any:
            pytest.fail(f"pairing.os.{name} reached from the Windows branch")

    for owner, name in [
        (pairing, "safe_read"),
        (pairing, "atomic_write"),
        (pairing, "private_flock"),
        (pairing, "_state_stat_key"),
        (history, "atomic_write"),
    ]:
        monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr(pairing, "os", ForbiddenModule())
    # A present wallet selection, so the checked wallet fingerprint stats it.
    put(ext(home), "wallet.json", b"{}")
    with forbid_raw_extension_paths(ext(home)):
        _exercise_every_storage_operation()


def _exercise_every_storage_operation() -> None:
    result = handshake()
    valid = token_is_valid(result["ext_token"])
    assert valid
    assert pairing.attest_pubkey_spki_b64()
    pairing.save_channel_key("C1", b"\x01" * 32)
    assert pairing.load_channel_keys() == {"C1": b"\x01" * 32}
    assert pairing.claim_e2e_replay_identities((REPLAY_ID,)) is True
    pairing.save_webauthn_credential("cred-1", p256_public_key_b64(), origin=ORIGIN)
    assert pairing.has_webauthn_credential()
    generation = pairing.authentication_generation_fingerprint(result["ext_token"])
    assert generation is not None
    pairing.clear_webauthn_credential()
    history.save_messages([{"role": "user", "content": "hello"}])
    assert history.projected_history().turns == [{"role": "user", "content": "hello"}]
    history.clear()
    code, _expires = pairing.generate_code()
    assert pairing.revoke_code(code) is True
    assert pairing.pair_outcome(code) == ("failed", "cancelled")
    assert pairing.code_consumed(code) is True
    wallet_fingerprint = extension_wallet._wallet_config_fingerprint()
    assert len(wallet_fingerprint) == 5 and str(wallet_fingerprint[0]).endswith("wallet.json")
    pairing.clear_pairing()
    assert pairing.load_pairing() is None


# --------------------------------------------------------------------------- #
# Unsafe, corrupt and oversized state refuses                                 #
# --------------------------------------------------------------------------- #


def test_unsafe_directory_refuses_every_operation_without_repair(paired: dict[str, Any], home: Path) -> None:
    before = snapshot(ext(home))
    broaden(ext(home))
    directory_posture = posture(ext(home))
    for name, operation in operations(paired["ext_token"]).items():
        with pytest.raises(storage.ExtensionStorageError) as error:
            operation()
        assert error.value.commit_state == "not_committed", name
        assert error.value.wire_reason == "storage_unavailable", name
    with pytest.raises(pairing.PairError) as pair_error:
        pairing.handle_pair_init(CODE, "x", "y")
    assert pair_error.value.reason == "storage_unavailable"
    assert posture(ext(home)) == directory_posture
    assert snapshot(ext(home)) == before


@pytest.mark.parametrize(
    ("name", "names"),
    [
        ("state.json", ["load_pairing", "channel_key", "replay", "fingerprint", "webauthn_has", "history_load"]),
        ("pending.json", ["generate_code", "consume", "pair_outcome", "code_consumed", "revoke"]),
        ("webauthn.json", ["webauthn_has", "webauthn_save", "webauthn_clear"]),
        ("attest_key.pem", ["attest"]),
        ("history.enc", ["history_load", "history_save", "history_clear"]),
    ],
)
def test_hardlinked_file_refuses_its_operations_unchanged(
    paired: dict[str, Any], home: Path, name: str, names: list[str]
) -> None:
    os.link(ext(home) / name, ext(home) / "alias")
    before = snapshot(ext(home))
    selected = operations(paired["ext_token"])
    for operation in names:
        with pytest.raises(storage.ExtensionStorageError):
            selected[operation]()
    assert snapshot(ext(home)) == before


@pytest.mark.parametrize("name", ["state.json", "pending.json", "attest_key.pem", "webauthn.json"])
def test_broadened_file_refuses_without_repair(paired: dict[str, Any], home: Path, name: str) -> None:
    broaden(ext(home) / name)
    before, file_posture = snapshot(ext(home)), posture(ext(home) / name)
    selected = operations(paired["ext_token"])
    relevant = {
        "state.json": "load_pairing",
        "pending.json": "generate_code",
        "attest_key.pem": "attest",
        "webauthn.json": "webauthn_has",
    }[name]
    with pytest.raises(storage.ExtensionStorageError):
        selected[relevant]()
    assert posture(ext(home) / name) == file_posture
    assert snapshot(ext(home)) == before


def test_unsafe_attestation_key_refuses_pairing_and_records_the_reason(paired: dict[str, Any], home: Path) -> None:
    os.link(ext(home) / "attest_key.pem", ext(home) / "alias")
    key_before = file_sha(ext(home) / "attest_key.pem")
    code, _expires = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as error:
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x11" * 32))
    assert error.value.reason == "storage_unavailable"
    assert pairing.pair_outcome(code) == ("failed", "storage_unavailable")
    key_after = file_sha(ext(home) / "attest_key.pem")
    assert key_after == key_before
    valid = token_is_valid(paired["ext_token"])
    assert valid is True


def test_oversized_state_refuses_without_replacement(paired: dict[str, Any], home: Path) -> None:
    huge = b"{" + b" " * storage.MAX_BYTES["state.json"] + b"}"
    put(ext(home), "state.json", huge)
    for operation in (pairing.load_pairing, lambda: pairing.save_channel_key("C1", b"\x01" * 32)):
        with pytest.raises(storage.ExtensionStorageError):
            operation()
    stored, expected = file_sha(ext(home) / "state.json"), sha(huge)
    assert stored == expected


def test_oversized_write_refuses_before_touching_storage(home: Path) -> None:
    with pytest.raises(storage.ExtensionStorageError) as error:
        pairing._write_private(ext(home) / "pending.json", b"x" * (storage.MAX_BYTES["pending.json"] + 1))
    assert error.value.commit_state == "not_committed"
    assert not ext(home).exists()


@pytest.mark.parametrize(
    ("name", "payload", "operation"),
    [
        ("pending.json", b'{"MORT-', "generate_code"),
        ("pending.json", b"[]", "consume"),
        ("state.json", b'{"aes_key": "', "load_pairing"),
        ("state.json", b"[]", "replay"),
        ("state.json", b"\xff", "channel_key"),
        ("webauthn.json", b'{"credential_id"', "webauthn_has"),
        ("attest_key.pem", b"-----BEGIN PRIVATE KEY-----\ntruncated", "attest"),
    ],
)
def test_corrupt_or_truncated_state_refuses_and_is_never_reset(
    paired: dict[str, Any], home: Path, name: str, payload: bytes, operation: str
) -> None:
    put(ext(home), name, payload)
    with pytest.raises(RuntimeError) as error:
        operations(paired["ext_token"])[operation]()
    assert not isinstance(error.value, storage.ExtensionStorageError)
    stored, expected = file_sha(ext(home) / name), sha(payload)
    assert stored == expected


def test_undecryptable_history_keeps_its_status_and_blob(paired: dict[str, Any], home: Path) -> None:
    put(ext(home), "history.enc", b"truncated")
    assert history.load_history().status == history.STATUS_UNDECRYPTABLE
    stored, expected = file_sha(ext(home) / "history.enc"), sha(b"truncated")
    assert stored == expected


# --------------------------------------------------------------------------- #
# Attestation identity                                                        #
# --------------------------------------------------------------------------- #


def test_lost_attestation_key_refuses_with_a_classified_reason(paired: dict[str, Any], home: Path) -> None:
    checked_delete(ext(home), "attest_key.pem")
    with pytest.raises(pairing.PairError) as direct:
        pairing.attest_pubkey_spki_b64()
    assert direct.value.reason == "attestation_key_missing"
    code, _expires = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as handshake_error:
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x11" * 32))
    assert handshake_error.value.reason == "attestation_key_missing"
    assert pairing.pair_outcome(code) == ("failed", "attestation_key_missing")
    assert not (ext(home) / "attest_key.pem").exists()
    still_paired = pairing.validate_token(paired["ext_token"])
    assert still_paired is True


def test_lost_attestation_key_is_reported_through_pair_fail(paired: dict[str, Any], home: Path) -> None:
    checked_delete(ext(home), "attest_key.pem")
    code, _expires = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    frame = {
        "id": "p1",
        "type": "pair_init",
        "code": code,
        "ext_pubkey": ext_pub,
        "challenge": xc.b64u_encode(b"\x11" * 32),
    }
    reply = _dispatch(_connection(), frame)
    assert reply == {"id": "p1", "type": "pair_fail", "reason": "attestation_key_missing"}


def test_lost_attestation_key_recovers_by_unpairing_then_pairing(paired: dict[str, Any], home: Path) -> None:
    checked_delete(ext(home), "attest_key.pem")
    pairing.clear_pairing()
    result = handshake()
    repaired = pairing.validate_token(result["ext_token"])
    old_rejected = pairing.validate_token(paired["ext_token"])
    assert repaired is True and old_rejected is False
    assert (ext(home) / "attest_key.pem").exists()


def test_attestation_key_is_created_once_by_concurrent_threads(home: Path) -> None:
    results: list[str] = []
    barrier = threading.Barrier(4)

    def worker() -> None:
        barrier.wait()
        results.append(pairing.attest_pubkey_spki_b64())

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(results) == 4 and len(set(results)) == 1
    pem_before = file_sha(ext(home) / "attest_key.pem")
    assert pairing.attest_pubkey_spki_b64() == results[0]
    pem_after = file_sha(ext(home) / "attest_key.pem")
    assert pem_after == pem_before


def test_attestation_key_after_unpair_is_a_fresh_identity(paired: dict[str, Any], home: Path) -> None:
    pairing.clear_pairing()
    checked_delete(ext(home), "attest_key.pem")
    assert pairing.attest_pubkey_spki_b64()
    assert (ext(home) / "attest_key.pem").exists()


# --------------------------------------------------------------------------- #
# state.json cache                                                            #
# --------------------------------------------------------------------------- #


def test_state_cache_is_reused_for_an_unchanged_checked_identity(
    paired: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    parses: list[str] = []
    real_read_json = pairing._read_json

    def counting(path: Path) -> dict[str, Any]:
        if path.name == "state.json":
            parses.append(path.name)
        return real_read_json(path)

    monkeypatch.setattr(pairing, "_read_json", counting)
    pairing._invalidate_state_cache()
    for _ in range(3):
        assert pairing.load_pairing() is not None
    assert parses == ["state.json"]


def test_state_cache_rereads_a_replaced_identity_with_same_size_and_mtime(paired: dict[str, Any], home: Path) -> None:
    state = ext(home) / "state.json"
    before_replacement, original_token = loaded_token_sha(), sha(paired["ext_token"])
    assert before_replacement == original_token
    raw = state.read_bytes()
    original = os.stat(state)
    data = json.loads(raw)
    data["ext_token"] = "Z" * len(data["ext_token"])
    replacement = json.dumps(data).encode()
    assert len(replacement) == len(raw)
    put(ext(home), "state.json", replacement)
    os.utime(state, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert (os.stat(state).st_size, os.stat(state).st_mtime_ns) == (original.st_size, original.st_mtime_ns)
    after_replacement, replacement_token = loaded_token_sha(), sha(data["ext_token"])
    assert after_replacement == replacement_token


def test_state_cache_never_serves_after_a_security_change(paired: dict[str, Any], home: Path) -> None:
    assert pairing.load_pairing() is not None
    broaden(ext(home) / "state.json")
    with pytest.raises(storage.ExtensionStorageError):
        pairing.load_pairing()
    with pytest.raises(storage.ExtensionStorageError):
        pairing.validate_token(paired["ext_token"])


# --------------------------------------------------------------------------- #
# Classified failure outcomes                                                 #
# --------------------------------------------------------------------------- #


class _FaultyTransaction:
    """Publish ``name`` for real, then report the outcome as uncertain."""

    def __init__(self, tx: Any, published: list[str], name: str) -> None:
        self._tx = tx
        self._published = published
        self._name = name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tx, name)

    def replace_bytes(self, name: str, data: bytes) -> None:
        self._published.append(name)
        self._tx.replace_bytes(name, data)
        if name == self._name:
            raise PrivateFSError("io", "flush", native_code=1117, commit_state="uncertain")


class _FaultyDirectory:
    def __init__(self, directory: Any, published: list[str], name: str) -> None:
        self._directory = directory
        self._published = published
        self._name = name

    def __getattr__(self, name: str) -> Any:
        return getattr(self._directory, name)

    @contextlib.contextmanager
    def transaction(self, *, blocking: bool = True) -> Iterator[Any]:
        with self._directory.transaction(blocking=blocking) as tx:
            yield _FaultyTransaction(tx, self._published, self._name)


def _fail_publication_of(monkeypatch: pytest.MonkeyPatch, name: str) -> list[str]:
    published: list[str] = []
    real = storage.open_private_directory

    @contextlib.contextmanager
    def faulty(path: Any, *, create: bool = False) -> Iterator[Any]:
        with real(path, create=create) as directory:
            yield _FaultyDirectory(directory, published, name)

    monkeypatch.setattr(storage, "open_private_directory", faulty)
    return published


def test_uncertain_publication_is_classified_and_never_retried(
    paired: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = storage.open_private_directory
    published = _fail_publication_of(monkeypatch, "state.json")
    with pytest.raises(storage.ExtensionStorageUncertain, match="inspect") as error:
        pairing.save_channel_key("C1", b"\x01" * 32)
    assert error.value.commit_state == "uncertain"
    assert error.value.wire_reason == "storage_uncertain"
    assert error.value.native_code == 1117
    assert published == ["state.json"]
    monkeypatch.setattr(storage, "open_private_directory", real)
    assert pairing.load_channel_keys() == {"C1": b"\x01" * 32}


def test_uncertain_pairing_commit_is_surfaced_without_further_writes(
    paired: dict[str, Any], home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, _expires = pairing.generate_code()
    published = _fail_publication_of(monkeypatch, "state.json")
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as error:
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x11" * 32))
    assert error.value.reason == "storage_uncertain"
    assert isinstance(error.value, pairing.PairingStorageError)
    assert error.value.commit_state == "uncertain"
    # The code was claimed, state.json was attempted exactly once, and no
    # outcome annotation followed the uncertain publication.
    assert published == ["pending.json", "state.json"]
    entry = json.loads((ext(home) / "pending.json").read_bytes())[code]
    assert entry["used"] is True and "result" not in entry


@pytest.mark.parametrize("reason", ["io", "missing"])
def test_directory_cleanup_after_a_save_is_uncertain(home: Path, monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    real = storage.open_private_directory

    @contextlib.contextmanager
    def fail_cleanup(path: Any, *, create: bool = False) -> Iterator[Any]:
        with real(path, create=create) as directory:
            yield directory
        raise PrivateFSError(reason, "close", native_code=6, commit_state="uncertain")

    monkeypatch.setattr(storage, "open_private_directory", fail_cleanup)
    with pytest.raises(storage.ExtensionStorageUncertain) as error:
        pairing.generate_code()
    assert error.value.reason == reason
    assert error.value.native_code == 6


def test_partial_publication_promotes_a_later_refusal_to_uncertain(paired: dict[str, Any], home: Path) -> None:
    os.link(ext(home) / "webauthn.json", ext(home) / "alias")
    with pytest.raises(storage.ExtensionStorageUncertain):
        pairing.clear_pairing()
    assert not (ext(home) / "state.json").exists()
    assert (ext(home) / "webauthn.json").exists()


@pytest.mark.parametrize("phase", ["lock", "cleanup"])
def test_missing_lock_or_cleanup_error_is_not_absence(
    paired: dict[str, Any], monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    real = storage.open_optional_private_directory

    class MissingLock:
        def __init__(self, directory: Any) -> None:
            self._directory = directory

        def __getattr__(self, name: str) -> Any:
            return getattr(self._directory, name)

        def transaction(self, *, blocking: bool = True) -> Any:
            raise PrivateFSError("missing", "lock")

    @contextlib.contextmanager
    def failing(path: Any) -> Iterator[Any]:
        with real(path) as directory:
            yield MissingLock(directory) if phase == "lock" else directory
        if phase == "cleanup":
            raise PrivateFSError("missing", "close")

    monkeypatch.setattr(storage, "open_optional_private_directory", failing)
    for operation in (pairing.load_pairing, lambda: pairing.code_consumed(CODE), history.load_history):
        with pytest.raises(storage.ExtensionStorageError) as error:
            operation()
        assert error.value.reason == "missing"


# --------------------------------------------------------------------------- #
# API surfaces the classified refusal                                         #
# --------------------------------------------------------------------------- #


class _FakeWS:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[dict[str, Any]] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


async def _chat_handler(_content: str, _context: dict[str, Any]) -> Any:
    yield history.load_messages()


def _connection() -> extension_api._Connection:
    return extension_api._Connection(_FakeWS(), _chat_handler, client_origin=ORIGIN)


def _dispatch(conn: extension_api._Connection, frame: dict[str, Any]) -> dict[str, Any]:
    asyncio.run(conn.dispatch(json.dumps(frame)))
    sent: list[dict[str, Any]] = conn.ws.sent  # type: ignore[attr-defined]
    return sent[-1]


def test_api_surfaces_unsafe_storage_instead_of_empty_state(paired: dict[str, Any], home: Path) -> None:
    pairing.clear_webauthn_credential()
    conn = _connection()
    authenticated = _dispatch(conn, {"type": "auth", "ext_token": paired["ext_token"]})
    assert authenticated["type"] == "auth_ok"

    os.link(ext(home) / "history.enc", ext(home) / "alias")
    assert _dispatch(conn, {"id": "h1", "type": "history_get"}) == {
        "id": "h1",
        "type": "error",
        "reason": "storage_unavailable",
    }
    assert _dispatch(conn, {"id": "h2", "type": "history_clear"})["reason"] == "storage_unavailable"
    os.unlink(ext(home) / "alias")

    broaden(ext(home))
    assert _dispatch(conn, {"id": "e1", "type": "encrypt", "plaintext": "x"}) == {
        "type": "auth_fail",
        "reason": "storage_unavailable",
    }
    assert conn.authed is False

    fresh = _connection()
    asyncio.run(fresh.send_challenge())
    challenge = fresh.ws.sent[-1]  # type: ignore[attr-defined]
    assert challenge["webauthn_required"] is True
    assert challenge["storage_error"] == "storage_unavailable"
    refused = _dispatch(fresh, {"type": "auth", "ext_token": paired["ext_token"]})
    assert refused == {"type": "auth_fail", "reason": "storage_unavailable"}
    assert _dispatch(fresh, {"id": "p1", "type": "pair_init", "code": CODE, "ext_pubkey": "x", "challenge": "y"}) == {
        "id": "p1",
        "type": "pair_fail",
        "reason": "storage_unavailable",
    }


def test_chat_and_wallet_wire_codes_classify_storage_refusals() -> None:
    unavailable = storage.ExtensionStorageError("unsafe", "validate_object")
    uncertain = storage.ExtensionStorageUncertain("io", "flush")
    for context in ("chat", "accounts_request", "sign_request"):
        assert extension_errors.wire_error_code(unavailable, fallback="x", context=context) == "storage_unavailable"
        assert extension_errors.wire_error_code(uncertain, fallback="x", context=context) == "storage_uncertain"
    assert "inspect" in str(uncertain)
    assert "unsafe" in str(unavailable) and "validate_object" not in str(unavailable)


# --------------------------------------------------------------------------- #
# Wallet snapshot cache revalidates checked wallet storage                    #
# --------------------------------------------------------------------------- #


def test_wallet_snapshot_cache_revalidates_checked_wallet_storage(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.keyvault import extension_sign

    monkeypatch.setattr(extension_sign, "_WINDOWS_WALLET_STORAGE", True, raising=False)
    extension_sign.set_wallet({"kind": "raw", "key_id": "synthetic", "envelope_id": "test-envelope", "chain_id": 1})
    calls: list[int] = []

    def resolve() -> tuple[str, str]:
        calls.append(1)
        return ("0xabc", "0x1")

    monkeypatch.setattr(extension_wallet, "_load_account_snapshot", resolve)
    extension_wallet.reset_account_snapshot_cache()
    assert extension_wallet._get_account_snapshot() == ("0xabc", "0x1")
    assert extension_wallet._get_account_snapshot() == ("0xabc", "0x1")
    assert calls == [1]

    extension_sign.set_wallet({"kind": "hd", "key_id": "synthetic", "seed_envelope_id": "test-seed", "index": 2})
    assert extension_wallet._get_account_snapshot() == ("0xabc", "0x1")
    assert calls == [1, 1]

    os.link(ext(home) / "wallet.json", ext(home) / "alias")
    with pytest.raises(storage.ExtensionStorageError):
        extension_wallet._get_account_snapshot()
    assert calls == [1, 1]
    extension_wallet.reset_account_snapshot_cache()


def test_wallet_snapshot_fingerprint_absent_wallet_is_checked_absence(home: Path) -> None:
    fingerprint = extension_wallet._wallet_config_fingerprint()
    assert fingerprint[1:] == (None,)
    assert not ext(home).exists()


# --------------------------------------------------------------------------- #
# Cross-process serialization                                                 #
# --------------------------------------------------------------------------- #

_PRELUDE = """
import json, sys
from tests.extension._windows_storage_support import enable_checked_storage
enable_checked_storage()
from mordred_hermes.extension import pairing
pairing.se_available = lambda: False
print("ready", flush=True)
"""

_CHILDREN = {
    "consume": """
try:
    pairing._consume_code(sys.argv[1])
    print("ok", flush=True)
except pairing.PairError as exc:
    print(exc.reason, flush=True)
""",
    "revoke": """
print("revoked" if pairing.revoke_code(sys.argv[1]) else "kept", flush=True)
""",
    "replay": """
print(json.dumps(pairing.claim_e2e_replay_identities((sys.argv[1],))), flush=True)
""",
    "commit": """
pairing._commit_pairing(sys.argv[1], pairing.Pairing(b"\\x05" * 32, sys.argv[2], "ext", "hermes", 1.0))
print("committed", flush=True)
""",
    "reader": """
import hashlib
for _ in range(25):
    loaded = pairing.load_pairing()
    print("none" if loaded is None else hashlib.sha256(loaded.ext_token.encode()).hexdigest(), flush=True)
""",
}


def _race(home: Path, children: list[tuple[str, list[str]]]) -> list[list[str]]:
    """Start children while the parent holds the checked lock, then release them together."""
    env = with_package_under_test(os.environ | {"HERMES_HOME": str(home), "PYTHONPATH": ""}, REPO_ROOT)
    processes: list[subprocess.Popen[str]] = []
    lines: list[queue.Queue[str]] = []
    errors: list[list[str]] = []
    collectors: list[threading.Thread] = []

    def drain(stream: Any, sink: Callable[[str], None]) -> None:
        # The only reader of each pipe: never mix with communicate().
        for line in stream:
            sink(line.strip())

    with open_private_directory(ext(home), create=True) as directory, contextlib.ExitStack() as held:
        held.enter_context(directory.transaction())
        for kind, args in children:
            process = subprocess.Popen(
                [sys.executable, "-u", "-c", _PRELUDE + _CHILDREN[kind], *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=REPO_ROOT,
            )
            output: queue.Queue[str] = queue.Queue()
            stderr: list[str] = []
            for stream, sink in ((process.stdout, output.put), (process.stderr, stderr.append)):
                collector = threading.Thread(target=drain, args=(stream, sink), daemon=True)
                collector.start()
                collectors.append(collector)
            processes.append(process)
            lines.append(output)
            errors.append(stderr)
        for output in lines:
            assert output.get(timeout=60) == "ready"
        time.sleep(0.3)
        for output in lines:
            assert output.empty(), "a child crossed the held checked lock"
    for process in processes:
        process.wait(timeout=60)
    for collector in collectors:
        collector.join(timeout=60)
        assert not collector.is_alive()
    results: list[list[str]] = []
    for process, output, stderr in zip(processes, lines, errors, strict=True):
        assert process.returncode == 0, "\n".join(stderr)
        collected: list[str] = []
        while not output.empty():
            collected.append(output.get())
        results.append(collected)
    return results


def test_two_processes_racing_one_code_have_exactly_one_winner(home: Path) -> None:
    code, _expires = pairing.generate_code()
    results = _race(home, [("consume", [code]), ("consume", [code])])
    assert sorted(result[-1] for result in results) == ["already_used", "ok"]
    entry = json.loads((ext(home) / "pending.json").read_bytes())[code]
    assert entry["used"] is True


def test_revoke_and_consume_race_never_commits_a_pairing(home: Path) -> None:
    code, _expires = pairing.generate_code()
    revoke, consume = _race(home, [("revoke", [code]), ("consume", [code])])
    assert revoke[-1] == "revoked"
    assert consume[-1] in {"ok", "already_used"}
    with pytest.raises(pairing.PairError, match="cancelled"):
        pairing._commit_pairing(code, pairing.Pairing(b"\x05" * 32, "token", "ext", "hermes", 1.0))
    assert pairing.load_pairing() is None
    assert pairing.pair_outcome(code) == ("failed", "cancelled")


def test_replay_identity_race_accepts_exactly_once(paired: dict[str, Any], home: Path) -> None:
    results = _race(home, [("replay", [REPLAY_ID]), ("replay", [REPLAY_ID])])
    assert sorted(result[-1] for result in results) == ["false", "true"]
    assert pairing.claim_e2e_replay_identities((REPLAY_ID,)) is False


def test_commit_and_reader_race_never_observes_partial_state(home: Path) -> None:
    code, _expires = pairing.generate_code()
    pairing._consume_code(code)
    token = "T" * 43
    commit, reader = _race(home, [("commit", [code, token]), ("reader", [])])
    assert commit[-1] == "committed"
    token_digest = sha(token)
    assert len(reader) == 25 and set(reader) <= {"none", token_digest}
    committed_token = loaded_token_sha()
    assert committed_token == token_digest
    assert pairing.pair_outcome(code) == ("paired", None)
