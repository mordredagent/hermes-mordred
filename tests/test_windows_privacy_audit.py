"""privacy_check Windows audit factory over real checked custody/audit files.

Only the native P-256 boundary, the token SID and the Windows-only
confidential opener are injected (the C5a/C5d host pattern). Custody,
canonical coordination, C7a sessions, MRKW and MRAL are real.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest

from mordred_hermes import _audit_support
from mordred_hermes._audit_session import AuditSession
from mordred_hermes._config_io import POLICY_TRANSACTION_MARKER
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault._exceptions import WrapNativeUnavailable
from mordred_hermes.privacy_check import _runtime, audit, egress, hooks, install_wrapper
from mordred_hermes.privacy_check._exceptions import AuditWriterRefused, MordredIntegrityRefused
from mordred_hermes.privacy_check._windows_audit import WindowsPlaintextAuditWriter
from tests import test_windows_custody
from tests.test_windows_privacy_policy import write_pair

custody_fixture = test_windows_custody.fs

MRAL_LINE = b'{"fmt":"MRAL","v":1}\n'


@pytest.fixture(name="fs")
def windows_fs(custody_fixture, monkeypatch):
    from mordred_hermes import _audit_session, _config_io
    from mordred_hermes.keyvault import windows_audit

    monkeypatch.setattr(windows_audit, "open_optional_private_directory", _config_io.open_optional_private_directory)
    monkeypatch.setattr(
        _audit_session.fs, "open_optional_private_directory", _config_io.open_optional_private_directory
    )
    from mordred_hermes.privacy_check import _windows_audit

    for name in ("open_optional_private_directory", "open_optional_confidential_directory"):
        monkeypatch.setattr(_windows_audit, name, getattr(_config_io, name))
    monkeypatch.setattr(audit, "_platform", "win32")
    forget_construction_refusals()
    yield custody_fixture
    forget_construction_refusals()


def forget_construction_refusals() -> None:
    from mordred_hermes.privacy_check import _windows_audit

    _windows_audit._forget_construction_refusals_for_tests()


def enroll(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        return session.enroll_role("audit")


def generated(backend) -> int:
    return [op for op, _ in backend.calls].count("generate")


def make(path: Path, home: Path, backend):
    return audit.make_audit_writer(path, keyvault_home=home, backend=backend)


def forbid_file_vault_probe(monkeypatch) -> None:
    from mordred_hermes.privacy_check import _keyvault_probe

    def forbidden(*_args, **_kwargs):
        raise AssertionError("the Windows factory consulted the file-vault probe")

    monkeypatch.setattr(_keyvault_probe, "keyvault_initialized", forbidden)


def private_write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    if os.name != "nt":
        path.chmod(0o600)


def audit_files(directory: Path) -> dict[str, bytes]:
    if not directory.exists():
        return {}
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir()) if p.name.startswith("audit.log")}


def decrypt(path: Path, home: Path, backend) -> list[dict[str, object]]:
    from mordred_hermes.keyvault.windows_audit import decrypt_windows_log_file

    return decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda _event: None)


# --- factory decisions -------------------------------------------------------------


def test_managed_role_routes_to_load_only_native_encrypted_writer(fs, monkeypatch):
    _, _, home, backend = fs
    lease = enroll(fs)
    forbid_file_vault_probe(monkeypatch)
    path = home / "mordred" / "audit.log"
    before = len(backend.calls)
    writer = make(path, home, backend)
    # C5d's load-only lease check is the only native call at construction.
    assert [op for op, _ in backend.calls[before:]] == ["get_pub"]
    assert writer.mode == "encrypted"
    assert writer.refusal is None
    writer.append({"event": "managed"})
    assert [entry["event"] for entry in decrypt(path, home, backend)] == ["managed"]
    assert json.loads(path.read_bytes().splitlines()[0])["native_key_id"] == lease.native_key_id
    assert generated(backend) == 1
    assert not (home / "mordred" / "keyvault").exists()


@pytest.mark.parametrize("exists", [True, False])
def test_managed_custom_directory_follows_c5d_child_rules(fs, exists):
    _, _, home, backend = fs
    enroll(fs)
    custom = home.parent / "custom-audit"
    if exists:
        with open_private_directory(custom, create=True):
            pass
    if exists:
        writer = make(custom / "audit.log", home, backend)
        assert writer.mode == "encrypted"
        writer.append({"event": "custom"})
        assert [entry["event"] for entry in decrypt(custom / "audit.log", home, backend)] == ["custom"]
    else:
        # Same construction-time directory rule as the unmanaged paths; the
        # refusal is recoverable, so creating the directory lets a retry pass.
        with pytest.raises(AuditWriterRefused) as error:
            make(custom / "audit.log", home, backend)
        assert error.value.reason == "audit-unavailable"
        assert not custom.exists()
        with open_private_directory(custom, create=True):
            pass
        assert make(custom / "audit.log", home, backend).mode == "encrypted"
    assert generated(backend) == 1


def test_fresh_unmanaged_profile_gets_checked_plaintext_and_surfaces_downgrade(fs, monkeypatch, caplog):
    _, _, home, backend = fs
    forbid_file_vault_probe(monkeypatch)
    path = home / "mordred" / "audit.log"
    with caplog.at_level(logging.WARNING, logger="mordred.privacy_check.audit"):
        writer = make(path, home, backend)
    assert writer.mode == "plaintext-degraded"
    assert any(record.levelno == logging.WARNING and "plaintext" in record.getMessage() for record in caplog.records)
    assert not (home / "mordred").exists(), "construction must not create state"
    writer.append({"event": "one"})
    writer.append({"event": "two"})
    lines = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [line["event"] for line in lines] == ["one", "two"]
    assert all(isinstance(line["ts"], str) for line in lines)
    if os.name != "nt":
        assert stat.S_IMODE((home / "mordred").stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert backend.calls == []


def test_plaintext_writer_rotates_compresses_and_sweeps_through_checked_session(fs):
    _, _, home, backend = fs
    mordred = home / "mordred"
    with open_private_directory(mordred, create=True):
        pass
    expired = mordred / "audit.log.2000-01-01.gz"
    private_write(expired, gzip.compress(b'{"event":"old"}\n'))
    os.utime(expired, (946684800, 946684800))
    writer = WindowsPlaintextAuditWriter(mordred / "audit.log", home=home, rotate_bytes=220, retention_days=1)
    for n in range(3):
        writer.append({"event": f"e{n}", "pad": "x" * 100})
    assert not expired.exists()
    events = [json.loads(line)["event"] for line in (mordred / "audit.log").read_bytes().splitlines()]
    rotated = sorted(mordred.glob("audit.log.*.gz"))
    assert len(rotated) == 2
    for path in rotated:
        events += [json.loads(line)["event"] for line in gzip.decompress(path.read_bytes()).splitlines()]
    assert sorted(events) == ["e0", "e1", "e2"]
    assert backend.calls == []


def test_plaintext_writer_refuses_mral_active_file_without_rotation(fs):
    _, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    writer.append({"event": "plain"})
    private_write(path, MRAL_LINE + b"opaque\n")
    before = audit_files(path.parent)
    for _ in range(2):
        with pytest.raises(AuditWriterRefused) as error:
            writer.append({"event": "refuse"})
        assert error.value.reason == "retained-ciphertext"
    assert writer.refusal == "retained-ciphertext"
    assert audit_files(path.parent) == before


def test_audit_enrollment_after_construction_stops_the_plaintext_writer(fs):
    _, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    writer.append({"event": "before"})
    enroll(fs)
    before = audit_files(path.parent)
    with pytest.raises(AuditWriterRefused) as error:
        writer.append({"event": "after"})
    assert error.value.reason == "audit-role-enrolled"
    assert writer.refusal == "audit-role-enrolled"
    assert audit_files(path.parent) == before
    assert generated(backend) == 1


def test_plaintext_role_check_precedes_the_writer_mutex(fs):
    import threading

    _, _, home, backend = fs
    writer = make(home / "mordred" / "audit.log", home, backend)
    writer.append({"event": "before"})
    enroll(fs)
    outcome: list[BaseException] = []

    def append() -> None:
        try:
            writer.append({"event": "blocked?"})
        except BaseException as exc:
            outcome.append(exc)

    with writer._lock:
        thread = threading.Thread(target=append)
        thread.start()
        thread.join(timeout=10)
        finished = not thread.is_alive()
    thread.join(timeout=10)
    assert finished, "the role check waited for the writer mutex"
    assert isinstance(outcome[0], AuditWriterRefused)
    assert outcome[0].reason == "audit-role-enrolled"


def test_plaintext_append_in_custody_reuses_the_caller_session(fs):
    c, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    with (
        c.windows_custody_session(home, create=True, backend=backend) as session,
        session.canonical.borrow_mordred_transaction() as loan,
    ):
        writer.append_in_custody({"event": "nested"}, custody=session, transaction=loan)
    assert [json.loads(line)["event"] for line in path.read_bytes().splitlines()] == ["nested"]
    assert backend.calls == []


@pytest.mark.parametrize("managed", [False, True])
def test_oversize_entry_is_a_recoverable_refusal(fs, managed):
    _, _, home, backend = fs
    if managed:
        enroll(fs)
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    with pytest.raises(ValueError):
        writer.append({"event": "huge", "pad": "x" * 5000})
    assert writer.refusal is None
    writer.append({"event": "small"})
    assert writer.refusal is None


def test_late_custody_exit_failure_after_publication_poisons_the_plaintext_writer(fs, monkeypatch):
    c, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    writer.append({"event": "first"})
    original = c.windows_custody_session

    @contextmanager
    def late(home_arg, **kwargs):
        with original(home_arg, **kwargs) as session:
            yield session
        raise PrivateFSError("io", "injected_late_exit")

    monkeypatch.setattr(c, "windows_custody_session", late)
    with pytest.raises(PrivateFSError):
        writer.append({"event": "published-then-failed"})
    monkeypatch.setattr(c, "windows_custody_session", original)
    # The entry was published before the definite-looking late failure, so the
    # outcome is uncertain and the writer stays refused.
    assert writer.refusal == "audit-uncertain"
    events = [json.loads(line)["event"] for line in path.read_bytes().splitlines()]
    assert events == ["first", "published-then-failed"]
    with pytest.raises(AuditWriterRefused):
        writer.append({"event": "refused"})


def test_concurrent_plaintext_writers_preserve_every_entry(fs):
    import threading

    _, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    first, second = make(path, home, backend), make(path, home, backend)
    errors: list[BaseException] = []

    def run(writer, label):
        try:
            for n in range(5):
                writer.append({"event": f"{label}{n}"})
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(w, f"t{i}-")) for i, w in enumerate([first, second, first, second])]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    events = [json.loads(line)["event"] for line in path.read_bytes().splitlines()]
    assert sorted(events) == sorted(f"t{i}-{n}" for i in range(4) for n in range(5))


# --- refusals ------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["active", "history"])
@pytest.mark.parametrize("custody_state", ["lost", "corrupt"])
def test_retained_mral_with_lost_or_unsafe_custody_refuses_untouched(fs, where, custody_state):
    from mordred_hermes.keyvault.windows_audit import WindowsAuditProvider

    _, _, home, backend = fs
    enroll(fs)
    path = home / "mordred" / "audit.log"
    WindowsAuditProvider(home, backend=backend).writer(path).append({"event": "secret"})
    if where == "history":
        data = path.read_bytes()
        path.unlink()
        private_write(path.with_name("audit.log.2026-10-01.gz"), gzip.compress(data))
    manifest = home / "mordred" / "windows-custody.json"
    if custody_state == "lost":
        manifest.unlink()
    else:
        manifest.write_bytes(b"{not json")
    before = audit_files(path.parent)
    calls = len(backend.calls)
    with pytest.raises(AuditWriterRefused) as error:
        make(path, home, backend)
    assert error.value.reason == ("retained-ciphertext" if custody_state == "lost" else "custody-broken")
    assert audit_files(path.parent) == before
    assert backend.calls[calls:] == []


def test_retained_mral_in_custom_directory_without_mordred_refuses(fs):
    _, _, home, backend = fs
    custom = home.parent / "custom-history"
    with open_private_directory(custom, create=True):
        pass
    private_write(custom / "audit.log", MRAL_LINE + b"opaque\n")
    before = audit_files(custom)
    assert not (home / "mordred").exists()
    with pytest.raises(AuditWriterRefused) as error:
        make(custom / "audit.log", home, backend)
    assert error.value.reason == "retained-ciphertext"
    assert audit_files(custom) == before
    assert not (home / "mordred").exists()


def test_unrecognized_history_without_custody_refuses(fs):
    _, _, home, backend = fs
    mordred = home / "mordred"
    with open_private_directory(mordred, create=True):
        pass
    private_write(mordred / "audit.log.2026-10-01.gz", b"not gzip at all")
    before = audit_files(mordred)
    with pytest.raises(AuditWriterRefused) as error:
        make(mordred / "audit.log", home, backend)
    assert error.value.reason == "history-unrecognized"
    assert audit_files(mordred) == before


@pytest.mark.parametrize("orphan", [False, True])
def test_pending_or_orphan_audit_journal_refuses(fs, monkeypatch, orphan):
    c, _, home, backend = fs

    def unavailable(key_id, *, unattended=None):
        raise WrapNativeUnavailable("injected native interruption")

    monkeypatch.setattr(backend, "generate_enclave_key", unavailable)
    with (
        pytest.raises((PrivateFSError, WrapNativeUnavailable)),
        c.windows_custody_session(home, create=True, backend=backend) as session,
    ):
        session.enroll_role("audit")
    journal = home / "mordred" / "windows-audit.pending.json"
    assert journal.exists()
    if orphan:
        (home / "mordred" / "windows-custody.json").unlink()
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, backend)
    # C5e ``role_status`` reports an orphan journal as broken custody.
    assert error.value.reason == ("custody-broken" if orphan else "custody-pending")
    assert journal.exists()
    assert backend.calls == []


def test_copied_profile_manifest_refuses_without_native_use(fs, tmp_path):
    _, _, home, backend = fs
    enroll(fs)
    copied = tmp_path / "copied-home"
    with open_private_directory(copied, create=True), open_private_directory(copied / "mordred", create=True):
        pass
    private_write(copied / "mordred" / "windows-custody.json", (home / "mordred" / "windows-custody.json").read_bytes())
    calls = len(backend.calls)
    with pytest.raises(AuditWriterRefused) as error:
        make(copied / "mordred" / "audit.log", copied, backend)
    assert error.value.reason == "custody-broken"
    assert backend.calls[calls:] == []
    assert audit_files(copied / "mordred") == {}


def test_retained_only_audit_generations_refuse_plaintext(fs):
    c, _, home, backend = fs
    enroll(fs)
    with c.windows_custody_session(home, backend=backend) as session:
        current = session.enroll_role("audit", retain_current=True)
        session.delete_role(current, erase_authorized=True)
    calls = len(backend.calls)
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, backend)
    assert error.value.reason == "custody-retained"
    assert backend.calls[calls:] == []
    assert generated(backend) == 2


def test_missing_native_key_refuses_without_regeneration(fs):
    _, _, home, backend = fs
    enroll(fs)
    backend._keys.clear()
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, backend)
    assert error.value.reason == "native-key-missing"
    assert generated(backend) == 1
    assert audit_files(home / "mordred") == {}


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PrivateFSError("io", "injected", commit_state="uncertain"), "audit-uncertain"),
        (PrivateFSError("unsafe", "injected"), "audit-unsafe"),
    ],
)
def test_uncertain_or_unsafe_custody_storage_refuses(fs, monkeypatch, error, reason):
    c, _, home, backend = fs

    @contextmanager
    def failing(*_args, **_kwargs):
        raise error
        yield  # pragma: no cover

    monkeypatch.setattr(c, "windows_custody_session", failing)
    with pytest.raises(AuditWriterRefused) as raised:
        make(home / "mordred" / "audit.log", home, backend)
    assert raised.value.reason == reason
    assert raised.value.__cause__ is error
    assert backend.calls == []


def test_pending_policy_marker_refuses_construction(fs):
    _, _, home, backend = fs
    with open_private_directory(home / "mordred", create=True):
        pass
    private_write(home / "mordred" / POLICY_TRANSACTION_MARKER, b"pending")
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, backend)
    assert error.value.reason == "policy-pending"
    assert backend.calls == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink fixture; the native junction case is separate")
def test_unsafe_active_audit_object_refuses_without_following(fs, tmp_path):
    _, _, home, backend = fs
    with open_private_directory(home / "mordred", create=True):
        pass
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim")
    (home / "mordred" / "audit.log").symlink_to(victim)
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, backend)
    assert error.value.reason == "audit-unsafe"
    assert victim.read_bytes() == b"victim"
    assert (home / "mordred" / "audit.log").is_symlink()


def test_role_observation_uses_c5e_role_status(fs, monkeypatch):
    c, _, home, backend = fs
    enroll(fs)
    original = c.WindowsCustodySession.role_status
    roles: list[str] = []

    def spy(self, role):
        roles.append(role)
        return original(self, role)

    monkeypatch.setattr(c.WindowsCustodySession, "role_status", spy)
    writer = make(home / "mordred" / "audit.log", home, backend)
    assert writer.mode == "encrypted"
    assert roles == ["audit"]


@pytest.mark.parametrize("mordred", [False, True])
@pytest.mark.parametrize("target", ["missing-custom", "home"])
def test_unmanaged_directory_rules_refuse_at_construction_consistently(fs, mordred, target):
    _, _, home, backend = fs
    if mordred:
        with open_private_directory(home / "mordred", create=True):
            pass
    path = home.parent / "missing-audit" / "audit.log" if target == "missing-custom" else home / "audit.log"
    with pytest.raises(AuditWriterRefused) as error:
        make(path, home, backend)
    assert error.value.reason == ("audit-unavailable" if target == "missing-custom" else "audit-unsafe")
    assert not (home.parent / "missing-audit").exists()
    assert not (home / "audit.log").exists()
    assert (home / "mordred").exists() is mordred
    assert backend.calls == []


def test_sticky_construction_refusal_is_remembered_without_rescanning(fs, monkeypatch):
    c, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    with open_private_directory(home / "mordred", create=True):
        pass
    private_write(path, MRAL_LINE)
    with pytest.raises(AuditWriterRefused) as first:
        make(path, home, backend)
    assert first.value.reason == "retained-ciphertext"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a remembered sticky refusal re-entered custody")

    monkeypatch.setattr(c, "windows_custody_session", forbidden)
    with pytest.raises(AuditWriterRefused) as second:
        make(path, home, backend)
    assert second.value.reason == "retained-ciphertext"


def test_recoverable_construction_refusal_is_retried(fs):
    _, _, home, backend = fs
    custom = home.parent / "later-audit"
    with pytest.raises(AuditWriterRefused) as error:
        make(custom / "audit.log", home, backend)
    assert error.value.reason == "audit-unavailable"
    with open_private_directory(custom, create=True):
        pass
    assert make(custom / "audit.log", home, backend).mode == "plaintext-degraded"


def test_nested_canonical_misuse_is_labelled_and_recoverable(fs, tmp_path):
    from mordred_hermes._config_io import CanonicalPaths, canonical_session

    _, _, home, backend = fs
    path = home / "mordred" / "audit.log"
    writer = make(path, home, backend)
    other = tmp_path / "other-home"
    with open_private_directory(other, create=True):
        pass
    with canonical_session(CanonicalPaths(other), scope="home"):
        with pytest.raises(AuditWriterRefused) as appended:
            writer.append({"event": "nested"})
        with pytest.raises(AuditWriterRefused) as constructed:
            make(path, home, backend)
    assert appended.value.reason == constructed.value.reason == "custody-nesting"
    assert writer.refusal is None
    writer.append({"event": "after"})


def test_invalid_audit_operation_is_not_an_entry_rejection(fs, monkeypatch):
    _, _, home, backend = fs
    writer = make(home / "mordred" / "audit.log", home, backend)

    def invalid(self, *_args, **_kwargs):
        raise ValueError("expected_identity must be a checked FileIdentity")

    monkeypatch.setattr(AuditSession, "probe", invalid)
    with pytest.raises(ValueError):
        writer.append({"event": "x"})
    assert writer.refusal == "audit-invalid"


@pytest.mark.parametrize(("failure", "reason"), [("helper", "native-unavailable"), ("identity", "custody-broken")])
def test_managed_backend_and_identity_failures_have_precise_labels(fs, monkeypatch, failure, reason):
    c, _, home, backend = fs
    enroll(fs)
    if failure == "helper":

        def missing_helper():
            raise c.CustodyError("Windows TPM helper unavailable; install the package-bound helper")

        monkeypatch.setattr(c, "windows_backend", missing_helper)
    else:
        monkeypatch.setattr(c, "windows_backend", lambda: backend)

        def drifted(self):
            # ``WindowsCustodySession.backend`` revalidates identity first.
            raise c.CustodyError("Windows custody session identity changed")

        monkeypatch.setattr(c.WindowsCustodySession, "backend", property(drifted))
    calls = len(backend.calls)
    with pytest.raises(AuditWriterRefused) as error:
        make(home / "mordred" / "audit.log", home, None)
    assert error.value.reason == reason
    assert backend.calls[calls:] == []


def test_keyvault_probe_is_unsupported_without_file_vault_reads_on_windows(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _storage
    from mordred_hermes.privacy_check import _keyvault_probe

    def forbidden(*_args, **_kwargs):
        raise AssertionError("file-vault storage touched on Windows")

    monkeypatch.setattr(_keyvault_probe, "_platform", "win32")
    monkeypatch.setattr(_storage, "resolve_keyvault_dir", forbidden)
    assert _keyvault_probe.keyvault_initialized(tmp_path) is False


# --- hook wiring ---------------------------------------------------------------------


@pytest.fixture
def hooked(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(_runtime, "_platform", "nt")
    monkeypatch.setattr(egress, "_platform", "nt")
    monkeypatch.setattr(install_wrapper, "_platform", "nt")
    monkeypatch.setattr(_runtime, "DEFAULT_HERMES_CONFIG_PATH", home / "config.yaml")
    monkeypatch.setattr(_runtime, "DEFAULT_AUDIT_PATH", home / "mordred" / "audit.log")
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    monkeypatch.setattr(hooks, "_resolve_active_network_path", lambda: None)
    _runtime.reset_state_for_tests()
    _audit_support._reset_audit_writer_registry_for_tests()
    with open_private_directory(home / "mordred", create=True):
        pass
    write_pair(home)
    yield home
    _runtime.reset_state_for_tests()
    _audit_support._reset_audit_writer_registry_for_tests()
    egress._cache.clear()


def uncertain_append(self, *_args, **_kwargs):
    raise PrivateFSError("io", "append", commit_state="uncertain")


def busy(self, *_args, **_kwargs):
    raise PrivateFSError("busy", "injected")


@pytest.mark.parametrize("managed", [False, True])
def test_poisoned_writer_refuses_every_hooked_operation(hooked, fs, monkeypatch, managed):
    if managed:
        enroll(fs)
    assert hooks.pre_tool_call(tool_name="read_file") is None
    writer = _runtime.ensure_state().audit
    assert writer.mode == ("encrypted" if managed else "plaintext-degraded")
    writer.append({"event": "first"})
    with monkeypatch.context() as patch:
        patch.setattr(AuditSession, "append", uncertain_append)
        with pytest.raises(PrivateFSError) as error:
            writer.append({"event": "poison"})
    assert error.value.commit_state == "uncertain"
    assert writer.refusal == "audit-uncertain"
    with pytest.raises(AuditWriterRefused):
        writer.append({"event": "after"})
    result = hooks.pre_tool_call(tool_name="read_file")
    assert result is not None and result["action"] == "block"
    assert "audit-uncertain" in result["message"]
    with pytest.raises(MordredIntegrityRefused):
        hooks.check_plugin_integrity()
    assert _runtime.is_poisoned()


def test_construction_refusal_blocks_tools_and_refuses_sessions(hooked):
    path = hooked / "mordred" / "audit.log"
    private_write(path, MRAL_LINE)
    before = audit_files(path.parent)
    result = hooks.pre_tool_call(tool_name="read_file")
    assert result is not None and result["action"] == "block"
    assert "retained-ciphertext" in result["message"]
    with pytest.raises(MordredIntegrityRefused):
        hooks.on_session_start()
    assert _runtime.is_poisoned()
    assert audit_files(path.parent) == before


def test_recoverable_session_start_audit_failure_refuses_without_poison_and_retries(hooked, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(AuditSession, "create", busy)
        with pytest.raises(MordredIntegrityRefused):
            hooks.on_session_start()
    assert not _runtime.is_poisoned()
    assert _runtime.ensure_state().audit.refusal is None
    assert hooks.pre_tool_call(tool_name="read_file") is None
    # The cause cleared: the next session start records the one-shot marker
    # that the refused attempt could not, exactly once.
    hooks.on_session_start()
    hooks.on_session_start()
    entries = [json.loads(line) for line in (hooked / "mordred" / "audit.log").read_bytes().splitlines()]
    assert [entry["reason"] for entry in entries] == ["mordred.degraded.no_origin_skill"]
    assert not _runtime.is_poisoned()


def test_sticky_session_start_audit_failure_poisons_the_process(hooked, monkeypatch):
    def uncertain_create(self, *_args, **_kwargs):
        raise PrivateFSError("io", "create", commit_state="uncertain")

    with monkeypatch.context() as patch:
        patch.setattr(AuditSession, "create", uncertain_create)
        with pytest.raises(MordredIntegrityRefused):
            hooks.on_session_start()
    assert _runtime.ensure_state().audit.refusal == "audit-uncertain"
    assert _runtime.is_poisoned()
    result = hooks.pre_tool_call(tool_name="read_file")
    assert result is not None and result["action"] == "block"


def test_recoverable_construction_refusal_at_session_start_does_not_poison(hooked, monkeypatch):
    custom = hooked.parent / "session-audit"
    monkeypatch.setattr(_runtime, "DEFAULT_AUDIT_PATH", custom / "audit.log")
    with pytest.raises(MordredIntegrityRefused) as refused_start:
        hooks.on_session_start()
    assert "audit-unavailable" in str(refused_start.value)
    assert not _runtime.is_poisoned()
    blocked = hooks.pre_tool_call(tool_name="read_file")
    assert blocked is not None and blocked["action"] == "block"
    with open_private_directory(custom, create=True):
        pass
    hooks.on_session_start()
    entries = [json.loads(line) for line in (custom / "audit.log").read_bytes().splitlines()]
    assert [entry["reason"] for entry in entries] == ["mordred.degraded.no_origin_skill"]
    assert hooks.pre_tool_call(tool_name="read_file") is None


def test_unrecorded_egress_approval_becomes_a_block(hooked, monkeypatch):
    write_pair(hooked, level="ask")
    args = {"tool_name": "some_unknown_tool", "args": {"x": 1}, "session_id": "c7b"}
    approved = hooks.pre_tool_call(**args)
    assert approved is not None and approved["action"] == "approve"
    with monkeypatch.context() as patch:
        patch.setattr(AuditSession, "append", busy)
        refused_call = hooks.pre_tool_call(**args)
    assert refused_call is not None and refused_call["action"] == "block"
    assert _runtime.ensure_state().audit.refusal is None


def test_hooked_appends_never_nest_custody_inside_a_held_canonical_session(hooked, monkeypatch):
    from mordred_hermes import _config_io as cio
    from mordred_hermes.keyvault import _windows_custody as custody

    original = custody.windows_custody_session
    seen: list[tuple[object, object]] = []

    def spy(home, **kwargs):
        seen.append((kwargs.get("canonical"), getattr(cio._local, "state", None)))
        return original(home, **kwargs)

    monkeypatch.setattr(custody, "windows_custody_session", spy)
    hooks.on_session_start()
    assert seen
    assert all(canonical is None and held is None for canonical, held in seen)


def test_windows_install_refuses_when_its_audit_record_cannot_be_written(hooked):
    class Unwritable:
        def append(self, entry):
            raise PrivateFSError("busy", "injected")

    calls: list[list[str]] = []
    with pytest.raises(install_wrapper.InstallBlocked) as error:
        install_wrapper.run(
            skill_path=Path(__file__).parent / "fixtures" / "tor_skill",
            policy_mode="off",
            audit=Unwritable(),
            runner=lambda cmd: calls.append(cmd),
            config_path=hooked / "config.yaml",
        )
    assert error.value.reason == "audit-unavailable"
    assert calls == []
