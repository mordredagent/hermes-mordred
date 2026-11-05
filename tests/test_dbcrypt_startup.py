"""A scheduled conversion runs at interpreter startup, before any database opens.

Real leases, marker, journal, SQLCipher conversion and shim run here. Hardware is
the software ``FakeBackend``. ``linux``/``win32``/``darwin`` simulate each OS's
policy view on a POSIX host: Windows custody and its checked VFS are exercised by
the explicit native proofs, not by this module.
"""

from __future__ import annotations

import json
import os
import sqlite3 as stdlib_sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("sqlcipher3")

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from mordred_hermes import _runtime_bootstrap, dbcrypt
from mordred_hermes._core._database_contracts import DatabaseBusy, DatabaseRefused
from mordred_hermes._core._database_inventory import scan_dependencies
from mordred_hermes._core._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _capability, _locking, _migrate, _shim, _startup, _windows_vfs
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._maintenance import convert_home
from mordred_hermes.dbcrypt._marker import Marker, read_marker
from tests._dbcrypt_platform_support import policy_sys
from tests.test_dbcrypt_authority import native_root as native_root
from tests.test_dbcrypt_marker import encoded, put

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit"
)

REPOSITORY = Path(__file__).resolve().parents[1]
SECRET = "private 日本語"


def _plain_db(path: Path) -> None:
    connection = stdlib_sqlite3.connect(path)
    connection.execute("CREATE TABLE messages (body TEXT)")
    connection.execute("INSERT INTO messages VALUES (?)", (SECRET,))
    connection.commit()
    connection.close()
    path.chmod(0o600)


def _is_plaintext(path: Path) -> bool:
    try:
        connection = stdlib_sqlite3.connect(path)
        try:
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        finally:
            connection.close()
        return True
    except (stdlib_sqlite3.DatabaseError, UnicodeDecodeError):
        return False


def _keyed_rows(path: Path, material: bytes) -> list[tuple[str]]:
    connection = _migrate._sqlcipher().connect(str(path))
    try:
        _shim.apply_key(connection, derive(material))
        return connection.execute("SELECT body FROM messages").fetchall()
    finally:
        connection.close()


def _configure_policy(monkeypatch: pytest.MonkeyPatch, root: Path, platform: str) -> None:
    view = policy_sys(platform)
    monkeypatch.setattr(dbcrypt._runtime, "sys", view)
    monkeypatch.setattr(_capability, "sys", view)
    monkeypatch.setattr(_startup, "sys", view)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: root / "owned.dll")
    monkeypatch.setattr(sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt._runtime, "_PROVIDER", None)
    monkeypatch.setitem(sys.modules, "sqlite3", stdlib_sqlite3)
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", stdlib_sqlite3.dbapi2)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    monkeypatch.setattr(_startup, "STARTUP_EX_WAIT", 0.2)


def _release_process_state(root: Path) -> None:
    provider = dbcrypt._runtime._PROVIDER
    if provider is not None:
        provider.close()
    entry = _locking._LEASES.pop(root.absolute(), None)
    if entry is not None:
        entry[0].__exit__(None, None, None)


@pytest.fixture(params=["linux", "win32", "darwin"])
def platform(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def home(native_root, monkeypatch, platform):
    """Plaintext, unarmed, enrolled source with a scheduled conversion."""
    root, backend, key, snapshot = native_root
    dbcrypt.marker_path(root).unlink()
    _plain_db(root / "state.db")
    _plain_db(root / "profiles/work/state.db")
    _configure_policy(monkeypatch, root, platform)
    _migrate.schedule(root)
    backend.calls.clear()
    yield SimpleNamespace(root=root, backend=backend, key=key, snapshot=snapshot, platform=platform)
    _release_process_state(root)


def _databases(root: Path) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in root.rglob("*.db")}


def _assert_stayed_plain(home: SimpleNamespace, before: dict[Path, bytes], outcome: str) -> None:
    root = home.root
    assert _databases(root) == before
    assert _migrate.pending_path(root).exists()
    assert not _migrate.journal_path(root).exists()
    assert not dbcrypt.marker_path(root).exists()
    assert not _shim.is_installed()
    assert _startup.read_outcome(root) == outcome
    assert root.absolute() in _locking._LEASES, "a plain start keeps its runtime lease"


def _journal(root: Path, direction: str, *, version: int = 2) -> Path:
    path = _migrate.journal_path(root)
    path.write_text(json.dumps({"version": version, "direction": direction, "files": []}))
    path.chmod(0o600)
    return path


# -- the conversion ------------------------------------------------------------------------


def test_scheduled_conversion_runs_at_native_startup_before_install(home, monkeypatch):
    root = home.root
    install_module = _shim.install_module
    observed = []

    def observe(module):
        observed.append(
            (
                _migrate.pending_path(root).exists(),
                _migrate.journal_path(root).exists(),
                read_marker(root) == Marker(home.snapshot),
                _is_plaintext(root / "state.db"),
            )
        )
        install_module(module)

    monkeypatch.setattr(_shim, "install_module", observe)
    _runtime_bootstrap._install_database_encryption()
    assert observed == [(False, False, True, False)], "the shim must only be installed over a finished conversion"
    assert _shim.is_installed()
    assert dbcrypt._runtime._PROVIDER.authority.root == root
    assert read_marker(root) == Marker(home.snapshot)
    assert not _migrate.pending_path(root).exists()
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()
    for path in (root / "state.db", root / "profiles/work/state.db"):
        assert not _is_plaintext(path)
        assert SECRET.encode() not in path.read_bytes()
        assert _keyed_rows(path, home.key) == [(SECRET,)]


def test_startup_conversion_refuses_without_root_memory_enabled_and_continues_plain(home):
    (home.root / "mordred/memory-vault.marker").unlink()
    before = _databases(home.root)
    assert dbcrypt.install(home=home.root) is False
    assert home.backend.calls == []
    _assert_stayed_plain(home, before, "memory_not_enabled")


def _reader(root: Path) -> subprocess.Popen[str]:
    """Another Hermes process that retains its runtime lease until stdin closes."""
    code = """
import sys
from pathlib import Path
from mordred_hermes.dbcrypt._locking import runtime_lease
with runtime_lease(Path(sys.argv[1])):
    pass
print('ready', flush=True)
sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert child.stdout is not None
    assert child.stdout.readline().strip() == "ready"
    return child


def test_startup_conversion_postpones_when_a_runtime_holds_the_lease(home):
    before = _databases(home.root)
    child = _reader(home.root)
    try:
        assert dbcrypt.install(home=home.root) is False
    finally:
        child.communicate("exit\n", timeout=10)
    assert home.backend.calls == []
    _assert_stayed_plain(home, before, "busy")


_SIBLING = """
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from mordred_hermes import dbcrypt
from mordred_hermes._core import _database_locking_posix as locking
from mordred_hermes.dbcrypt import _capability, _locking, _runtime, _shim, _startup, _windows_vfs
from mordred_hermes.keyvault import _database_authority as custody
from mordred_hermes.keyvault import _memory_key as memory
from tests._dbcrypt_platform_support import policy_sys
from tests._keyvault_fakes import FakeBackend

root = Path(os.environ["HERMES_HOME"])
backend = FakeBackend()
backend._keys = {
    name: load_pem_private_key(pem.encode(), password=None) for name, pem in json.loads(os.environ["FAKE_KEYS"]).items()
}
memory.linux_memory_backend = lambda home: backend
custody.sys = SimpleNamespace(platform="linux")
locking.sys = SimpleNamespace(platform="linux")
view = policy_sys(os.environ["POLICY_PLATFORM"])
_runtime.sys = _capability.sys = _startup.sys = view
_windows_vfs.windows_edition_admitted = lambda: True
_windows_vfs.driver_distribution_qualified = lambda: True
_windows_vfs.packaged_library_path = lambda: root / "owned.dll"
sys.argv = ["hermes"]
_startup.STARTUP_EX_WAIT = 0.1
lease = _startup.runtime_lease

def announced(*args, **kwargs):
    print("waiting-shared", flush=True)
    return lease(*args, **kwargs)

_startup.runtime_lease = announced
installed = dbcrypt.install(home=root)
print(json.dumps({
    "installed": installed,
    "shim": _shim.is_installed(),
    "authority": str(_runtime._PROVIDER.authority.root),
    "unwraps": sum(op == "ecdh" for op, _ in backend.calls),
    "plain_lease": root.absolute() in _locking._LEASES,
}), flush=True)
_runtime._PROVIDER.close()
"""


def test_sibling_startup_waits_for_the_converter_then_authenticates(home):
    root = home.root
    keys = {
        name: key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        for name, key in home.backend._keys.items()
    }
    env = {
        **os.environ,
        "HERMES_HOME": str(root),
        "FAKE_KEYS": json.dumps(keys),
        "POLICY_PLATFORM": home.platform,
    }
    with acquire_exclusive(root) as lease:
        child = subprocess.Popen(
            [sys.executable, "-c", _SIBLING],
            cwd=REPOSITORY,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "waiting-shared"
            # The sibling now waits for SH behind the converter's EX.
            assert _is_plaintext(root / "state.db")
            convert_home(root, lease=lease, decrypting=False)
        except BaseException:
            child.kill()
            child.communicate()
            raise
    out, err = child.communicate(timeout=60)
    assert child.returncode == 0, err
    report = json.loads(out.strip().splitlines()[-1])
    assert report == {
        "installed": True,
        "shim": True,
        "authority": str(root),
        "unwraps": 1,
        "plain_lease": False,
    }
    assert _startup.read_outcome(root) is None
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()
    assert not _migrate.pending_path(root).exists()


def test_polling_sees_a_sibling_publication_and_takes_the_armed_path(home, monkeypatch):
    root = home.root

    def publish_then_busy(*args, **kwargs):
        # The sibling finished while we were waiting.
        put(root, encoded(home.snapshot))
        _migrate.pending_path(root).unlink(missing_ok=True)
        raise DatabaseBusy("sibling")

    monkeypatch.setattr(_startup, "acquire_exclusive", publish_then_busy)
    monkeypatch.setattr(_startup, "runtime_lease", lambda *a, **k: pytest.fail("no SH wait after publication"))
    assert dbcrypt.install(home=root) is True
    assert _shim.is_installed()
    assert _startup.read_outcome(root) is None


def test_sibling_publication_seen_under_shared_lease_releases_it_without_refusal(home, monkeypatch):
    root = home.root
    lease = _startup.runtime_lease

    def busy(*args, **kwargs):
        raise DatabaseBusy("sibling")

    def published_before_shared(base, *, timeout):
        assert timeout == _startup.STARTUP_SIBLING_WAIT
        put(root, encoded(home.snapshot))
        _migrate.pending_path(root).unlink()
        return lease(base, timeout=timeout)

    monkeypatch.setattr(_startup, "acquire_exclusive", busy)
    monkeypatch.setattr(_startup, "runtime_lease", published_before_shared)
    assert dbcrypt.install(home=root) is True
    assert _shim.is_installed()
    assert root.absolute() not in _locking._LEASES, "the temporary shared lease must not be retained"
    assert _startup.read_outcome(root) is None


def test_exclusive_lease_won_after_a_sibling_finished_makes_no_second_conversion(home, monkeypatch):
    """The gate saw pending, but the lease followed the sibling's finished conversion."""
    from mordred_hermes.dbcrypt import _maintenance

    root = home.root
    acquire = _startup.acquire_exclusive

    def after_sibling(base, *, timeout):
        put(root, encoded(home.snapshot))
        _migrate.pending_path(root).unlink(missing_ok=True)
        return acquire(base, timeout=timeout)

    monkeypatch.setattr(_startup, "acquire_exclusive", after_sibling)
    monkeypatch.setattr(_maintenance, "convert_home", lambda *a, **k: pytest.fail("converted a finished home"))
    _record(root, "busy")
    assert dbcrypt.install(home=root) is True
    assert sum(op == "ecdh" for op, _ in home.backend.calls) == 1, "only the runtime authority authenticates"
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()


def test_allow_pending_tolerates_only_an_unarmed_schedule(home):
    refuse = dbcrypt._runtime._refuse_deferred_native_state
    root = home.root
    refuse(root, allow_pending=True)
    with pytest.raises(DatabaseRefused):
        refuse(root)
    put(root, encoded(home.snapshot))
    with pytest.raises(DatabaseRefused):
        refuse(root, allow_pending=True)
    dbcrypt.marker_path(root).unlink()
    _journal(root, "encrypt")
    with pytest.raises(DatabaseRefused):
        refuse(root, allow_pending=True)


def test_a_sibling_failure_journal_seen_under_shared_lease_refuses(home, monkeypatch):
    root = home.root
    lease = _startup.runtime_lease
    before = _databases(root)

    def busy(*args, **kwargs):
        raise DatabaseBusy("sibling")

    def journal_before_shared(base, *, timeout):
        _journal(root, "encrypt")
        return lease(base, timeout=timeout)

    monkeypatch.setattr(_startup, "acquire_exclusive", busy)
    monkeypatch.setattr(_startup, "runtime_lease", journal_before_shared)
    with pytest.raises(DatabaseRefused, match="hermes-mordred databases encrypt"):
        dbcrypt.install(home=root)
    assert root.absolute() not in _locking._LEASES
    assert not _shim.is_installed()
    assert _databases(root) == before


class _Crash(BaseException):
    """The process dying at a durable boundary: no handler observes it."""


@pytest.mark.parametrize("phase", ["prepared", "reserved", "verified", "armed", "swapped", "complete"])
def test_crash_after_marker_publication_is_resumed_at_next_startup(home, monkeypatch, phase):
    root = home.root

    def crash(point):
        if point == phase:
            raise _Crash

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    monkeypatch.setattr(_migrate, "_transition", transition)
    assert _migrate.pending_path(root).exists(), "our own crash always leaves the schedule"
    assert _migrate.journal_path(root).exists()
    assert not _shim.is_installed()
    if phase in {"armed", "swapped", "complete"}:
        assert read_marker(root) == Marker(home.snapshot)
    assert dbcrypt.install(home=root) is True
    assert _shim.is_installed()
    assert read_marker(root) == Marker(home.snapshot)
    assert not _migrate.pending_path(root).exists()
    assert not _migrate.journal_path(root).exists()
    assert _startup.read_outcome(root) is None
    for path in (root / "state.db", root / "profiles/work/state.db"):
        assert not _is_plaintext(path)
        assert _keyed_rows(path, home.key) == [(SECRET,)]


def test_failure_leaving_a_journal_refuses_startup_and_does_not_continue_plain(home, monkeypatch, capsys):
    root = home.root
    monkeypatch.setattr(_startup, "sys", policy_sys(home.platform))  # The stream capsys now owns.

    def fail(point):
        if point == "verified":
            raise _migrate.MigrationError(f"failure naming {root} and {home.key.hex()}")

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", fail)
    with pytest.raises(DatabaseRefused, match="hermes-mordred databases encrypt") as refused:
        dbcrypt.install(home=root)
    assert str(root) not in str(refused.value) and home.key.hex() not in str(refused.value)
    assert refused.value.__suppress_context__
    assert _migrate.journal_path(root).exists()
    assert _migrate.pending_path(root).exists()
    assert not _shim.is_installed()
    assert root.absolute() not in _locking._LEASES, "a refused start retains no lease"
    assert _startup.read_outcome(root) == "refused"
    err = capsys.readouterr().err
    assert home.key.hex() not in err and str(root) not in err

    with pytest.raises(SystemExit):
        _runtime_bootstrap.run(installer=lambda: dbcrypt.install(home=root))

    monkeypatch.setattr(_migrate, "_transition", transition)
    assert dbcrypt.install(home=root) is True
    assert not _migrate.journal_path(root).exists()
    assert not _is_plaintext(root / "state.db")


def _fail_with_holders(monkeypatch, home):
    monkeypatch.setattr(_migrate, "holders", lambda paths: [4242])


def _fail_with_unknown_holders(monkeypatch, home):
    monkeypatch.setattr(_migrate, "holders", lambda paths: None)


def _fail_with_denied_unwrap(monkeypatch, home):
    home.backend.denied_reason = "user_cancelled"


def _fail_with_refusal(monkeypatch, home):
    def refuse(*args, **kwargs):
        raise _migrate.MigrationError(f"secret-bearing text {home.root}")

    monkeypatch.setattr(_migrate, "discover", refuse)


def _fail_with_driver_error(monkeypatch, home):
    def locked(*args, **kwargs):
        raise _migrate._sqlcipher().OperationalError("database is locked")

    monkeypatch.setattr(_migrate, "_checkpoint_source", locked)


@pytest.mark.parametrize(
    ("inject", "outcome"),
    [
        (_fail_with_holders, "holders_open"),
        (_fail_with_unknown_holders, "holders_open"),
        (_fail_with_denied_unwrap, "source_unavailable"),
        (_fail_with_refusal, "refused"),
        (_fail_with_driver_error, "refused"),
    ],
)
def test_failure_without_a_journal_continues_plain_with_a_record(home, monkeypatch, capsys, inject, outcome):
    monkeypatch.setattr(_startup, "sys", policy_sys(home.platform))  # The stream capsys now owns.
    inject(monkeypatch, home)
    before = _databases(home.root)
    assert dbcrypt.install(home=home.root) is False
    _assert_stayed_plain(home, before, outcome)
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and err.startswith("mordred:") and outcome in err
    assert str(home.root) not in err and "secret-bearing" not in err and "pids" not in err


def test_a_later_successful_start_removes_an_earlier_record(home, monkeypatch):
    root = home.root
    holders = _migrate.holders
    monkeypatch.setattr(_migrate, "holders", lambda paths: [4242])
    assert dbcrypt.install(home=root) is False
    assert _startup.read_outcome(root) == "holders_open"
    _release_process_state(root)
    monkeypatch.setattr(_migrate, "holders", holders)
    assert dbcrypt.install(home=root) is True
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()


def test_record_write_failure_is_never_fatal(home, monkeypatch, capsys):
    monkeypatch.setattr(_startup, "sys", policy_sys(home.platform))  # The stream capsys now owns.

    def unavailable(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(_migrate, "_put_json", unavailable)
    (home.root / "mordred/memory-vault.marker").unlink()
    assert dbcrypt.install(home=home.root) is False
    assert (home.root / "mordred" / _startup.RECORD_NAME).exists() is False
    assert "disk full" not in capsys.readouterr().err


# -- every other state keeps the strict refusal --------------------------------------------


def _assert_strict_refusal(home: SimpleNamespace) -> None:
    root = home.root
    files = {
        path: path.read_bytes() for path in root.rglob("*") if path.is_file() and path.name != "db-encryption.lock"
    }
    with pytest.raises(DatabaseRefused):
        dbcrypt.install(home=root)
    after = {
        path: path.read_bytes() for path in root.rglob("*") if path.is_file() and path.name != "db-encryption.lock"
    }
    assert after == files
    assert home.backend.calls == []
    assert not _shim.is_installed()
    assert root.absolute() not in _locking._LEASES


def test_orphan_journal_without_pending_still_refuses_startup(home):
    _migrate.pending_path(home.root).unlink()
    _journal(home.root, "encrypt")
    _assert_strict_refusal(home)


def test_decrypt_pending_still_refuses_startup(home):
    path = _migrate.decrypt_pending_path(home.root)
    path.write_bytes(b"1\n")
    path.chmod(0o600)
    _assert_strict_refusal(home)


def test_armed_home_with_stale_pending_still_refuses_startup(home):
    put(home.root, encoded(home.snapshot))
    _assert_strict_refusal(home)


@pytest.mark.parametrize("direction", ["decrypt", "adopt", "sideways"])
def test_startup_never_resumes_a_decrypt_or_adopt_journal(home, direction):
    _journal(home.root, direction)
    _assert_strict_refusal(home)


@pytest.mark.parametrize(
    "raw", [b"not json", b"[]", b'{"direction": "encrypt"}', b'{"version": 1, "direction": "encrypt"}']
)
def test_unreadable_journal_still_refuses_startup(home, raw):
    path = _migrate.journal_path(home.root)
    path.write_bytes(raw)
    path.chmod(0o600)
    _assert_strict_refusal(home)


def test_unsafe_pending_still_refuses_startup(home, tmp_path_factory):
    pending = _migrate.pending_path(home.root)
    pending.unlink()
    target = tmp_path_factory.mktemp("elsewhere") / "pending"
    target.write_bytes(b"1\n")
    pending.symlink_to(target)
    _assert_strict_refusal(home)


# -- admission before custody --------------------------------------------------------------


def test_windows_workstation_keeps_pending_without_custody(native_root, monkeypatch):
    root, backend, _, _ = native_root
    dbcrypt.marker_path(root).unlink()
    _plain_db(root / "state.db")
    _configure_policy(monkeypatch, root, "win32")
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: False)
    _migrate.schedule(root)
    backend.calls.clear()
    before = _databases(root)
    try:
        assert dbcrypt.install(home=root) is False
        _assert_stayed_plain(SimpleNamespace(root=root), before, "unavailable")
        assert backend.calls == []
    finally:
        _release_process_state(root)


def test_inventory_incomplete_home_is_refused_without_custody(home):
    (home.root / "foreign.db.unknown").write_bytes(b"opaque")
    before = _databases(home.root)
    assert dbcrypt.install(home=home.root) is False
    _assert_stayed_plain(home, before, "refused")
    assert home.backend.calls == []


def test_oversized_home_is_not_converted_at_startup(home, monkeypatch):
    monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 1)
    before = _databases(home.root)
    assert dbcrypt.install(home=home.root) is False
    assert home.backend.calls == []
    _assert_stayed_plain(home, before, "too_large")


def test_oversized_home_with_a_journal_still_resumes(home, monkeypatch):
    root = home.root

    def crash(point):
        if point == "verified":
            raise _Crash

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    monkeypatch.setattr(_migrate, "_transition", transition)
    monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 1)
    assert _startup.conversion_too_large(root)
    assert dbcrypt.install(home=root) is True
    assert not _migrate.journal_path(root).exists()
    assert not _is_plaintext(root / "state.db")


@pytest.mark.parametrize("reason", ["memory", "capability"])
def test_precheck_failure_with_a_journal_refuses_instead_of_continuing_plain(home, monkeypatch, reason):
    root = home.root

    def crash(point):
        if point == "verified":
            raise _Crash

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    monkeypatch.setattr(_migrate, "_transition", transition)
    home.backend.calls.clear()
    if reason == "memory":
        (root / "mordred/memory-vault.marker").unlink()
    else:
        monkeypatch.setattr(_startup, "database_status", lambda base: SimpleNamespace(capability="unavailable"))
    with pytest.raises(DatabaseRefused, match="hermes-mordred databases encrypt"):
        dbcrypt.install(home=root)
    assert home.backend.calls == []
    assert root.absolute() not in _locking._LEASES


def test_conversion_too_large_opens_nothing_and_sums_database_paths(native_root, monkeypatch):
    root, _, _, _ = native_root
    (root / "state.db").write_bytes(b"x" * 10)
    (root / "profiles/work/state.db").write_bytes(b"x" * 10)
    (root / "notes.txt").write_bytes(b"x" * 1000)
    monkeypatch.setattr(os, "open", lambda *a, **k: pytest.fail("the size gate must not open a file"))
    monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 20)
    assert _startup.conversion_too_large(root) is False
    monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 19)
    assert _startup.conversion_too_large(root) is True


# -- the record ----------------------------------------------------------------------------


def test_startup_outcome_record_is_private_non_secret_and_not_a_dependency(home):
    root = home.root
    (root / "mordred/memory-vault.marker").unlink()
    inventory = scan_dependencies(root)
    dependencies = _capability.database_status(root).dependencies
    assert dbcrypt.install(home=root) is False
    path = root / "mordred" / _startup.RECORD_NAME
    assert not _startup.RECORD_NAME.startswith("db-")
    assert stat.S_IMODE(path.lstat().st_mode) == 0o600
    raw = path.read_bytes()
    assert len(raw) <= 4096
    assert str(root).encode() not in raw and home.key.hex().encode() not in raw
    value = json.loads(raw)
    assert set(value) == {"version", "at", "outcome", "converted", "platform"}
    assert value["version"] == 1
    assert type(value["at"]) is int
    assert value["outcome"] == "memory_not_enabled"
    assert value["converted"] is None
    assert value["platform"] == home.platform
    after = scan_dependencies(root)
    assert after.complete is True
    assert len(after.entries) == len(inventory.entries)
    assert _capability.database_status(root).dependencies == dependencies
    assert _capability.database_status(root).reason == "native database authority has not been authenticated"


def _record(root: Path, outcome: str) -> Path:
    path = root / "mordred" / _startup.RECORD_NAME
    path.write_text(json.dumps({"version": 1, "outcome": outcome}))
    path.chmod(0o600)
    return path


def _raw_outcome(root: Path) -> str:
    return json.loads((root / "mordred" / _startup.RECORD_NAME).read_bytes())["outcome"]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"version": 1}',
        b'{"version": 1, "outcome": "unknown-code"}',
        b'{"version": 1, "outcome": ["busy"]}',
        b'{"version": 2, "outcome": "busy"}',
        b'{"version": true, "outcome": "busy"}',
        b'{"version": 1, "outcome": "busy", "pad": "' + b"x" * 4096 + b'"}',
    ],
)
def test_read_outcome_fails_closed_on_a_present_but_invalid_record(tmp_path, raw):
    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o700)
    path = directory / _startup.RECORD_NAME
    path.write_bytes(raw)
    path.chmod(0o600)
    assert _startup.read_outcome(tmp_path) == "refused"


def test_read_outcome_fails_closed_on_an_unsafe_record(tmp_path):
    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o700)
    (tmp_path / "elsewhere").write_text(json.dumps({"version": 1, "outcome": "busy"}))
    (directory / _startup.RECORD_NAME).symlink_to(tmp_path / "elsewhere")
    assert _startup.read_outcome(tmp_path) == "refused"


def test_read_outcome_never_returns_attempting(tmp_path):
    (tmp_path / "mordred").mkdir(mode=0o700)
    _record(tmp_path, "attempting")
    assert "attempting" not in _startup.OUTCOMES
    assert _startup.read_outcome(tmp_path) == "source_unavailable"


def test_read_outcome_accepts_each_closed_code_and_ordinary_absence(tmp_path):
    assert _startup.read_outcome(tmp_path) is None
    assert not (tmp_path / "mordred").exists()
    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o700)
    assert _startup.read_outcome(tmp_path) is None
    closed = {"busy", "memory_not_enabled", "source_unavailable", "holders_open", "too_large", "refused", "unavailable"}
    assert set(_startup.OUTCOMES) == closed
    path = directory / _startup.RECORD_NAME
    for code in _startup.OUTCOMES:
        path.write_text(json.dumps({"version": 1, "outcome": code}))
        path.chmod(0o600)
        assert _startup.read_outcome(tmp_path) == code


def test_stale_record_removed_when_nothing_is_pending(tmp_path, monkeypatch):
    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o700)
    path = directory / _startup.RECORD_NAME
    path.write_text(json.dumps({"version": 1, "outcome": "busy"}))
    path.chmod(0o600)
    assert _startup.run_scheduled_conversion(tmp_path) is False
    assert not path.exists()


def test_ordinary_start_without_mordred_directory_creates_nothing(tmp_path):
    assert _startup.run_scheduled_conversion(tmp_path) is False
    assert list(tmp_path.iterdir()) == []
    absent = tmp_path / "absent"
    assert _startup.run_scheduled_conversion(absent) is False
    assert not absent.exists()


def test_ordinary_armed_start_with_a_late_record_removes_it(native_root, monkeypatch):
    root, _, _, _ = native_root
    _configure_policy(monkeypatch, root, "linux")
    path = root / "mordred" / _startup.RECORD_NAME
    path.write_text(json.dumps({"version": 1, "outcome": "busy"}))
    path.chmod(0o600)
    try:
        assert dbcrypt.install(home=root) is True
        assert not path.exists()
    finally:
        _release_process_state(root)


# -- the attempt record --------------------------------------------------------------------


def test_attempting_is_written_under_exclusive_lease_before_the_first_custody_call(home, monkeypatch):
    from mordred_hermes.dbcrypt import _maintenance

    root = home.root
    observed = []
    require = _maintenance.require_database_memory_enabled

    def first_custody_call(**kwargs):
        observed.append((_raw_outcome(root), list(home.backend.calls)))
        return require(**kwargs)

    monkeypatch.setattr(_maintenance, "require_database_memory_enabled", first_custody_call)
    assert dbcrypt.install(home=root) is True
    assert observed == [("attempting", [])]
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()


def test_killed_during_native_auth_does_not_retry_at_next_startup(home):
    root = home.root
    _record(root, "attempting")
    before = _databases(root)
    assert dbcrypt.install(home=root) is False
    assert home.backend.calls == []
    assert _raw_outcome(root) == "source_unavailable"
    _assert_stayed_plain(home, before, "source_unavailable")


def test_native_auth_kill_is_recorded_for_the_next_start(home, monkeypatch):
    root = home.root

    def killed(*args, **kwargs):
        raise _Crash

    monkeypatch.setattr(_migrate.custody, "load_database_source", killed)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    assert _raw_outcome(root) == "attempting"
    assert _startup.read_outcome(root) == "source_unavailable"
    assert _migrate.pending_path(root).exists() and not _migrate.journal_path(root).exists()
    assert dbcrypt.install(home=root) is False
    assert _raw_outcome(root) == "source_unavailable"


def test_a_handled_native_refusal_is_retried_by_a_normal_restart(home):
    root = home.root
    home.backend.denied_reason = "user_cancelled"
    assert dbcrypt.install(home=root) is False
    assert _raw_outcome(root) == "source_unavailable"
    _release_process_state(root)
    home.backend.denied_reason = None
    assert dbcrypt.install(home=root) is True
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()


@pytest.mark.parametrize("outcome", sorted(_startup.OUTCOMES))
def test_other_outcomes_do_not_block_a_later_attempt(home, outcome):
    _record(home.root, outcome)
    assert dbcrypt.install(home=home.root) is True
    assert not (home.root / "mordred" / _startup.RECORD_NAME).exists()


def test_attempt_record_is_only_judged_under_exclusive_lease(home, monkeypatch):
    """A real sibling holds EX with its attempt in flight; waiting must not call that stale."""
    root = home.root
    record = _record(root, "attempting")
    code = """
import sys
from pathlib import Path
from mordred_hermes._core._database_lifecycle import acquire_exclusive
with acquire_exclusive(Path(sys.argv[1])):
    print('ready', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lease = _startup.runtime_lease
    observed = []

    def sibling_finishes(base, *, timeout):
        observed.append((_raw_outcome(root), list(home.backend.calls)))
        put(root, encoded(home.snapshot))
        _migrate.pending_path(root).unlink()
        record.unlink()
        child.communicate("exit\n", timeout=10)
        return lease(base, timeout=timeout)

    monkeypatch.setattr(_startup, "runtime_lease", sibling_finishes)
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "ready"
        assert dbcrypt.install(home=root) is True
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert observed == [("attempting", [])], "the in-flight attempt was untouched while EX was unobtainable"
    assert not record.exists()


def test_busy_does_not_erase_a_dead_attempt(home):
    """Under SH no attempt can be in flight; overwriting it would re-enable the hang."""
    root = home.root
    _record(root, "attempting")
    child = _reader(root)
    try:
        assert dbcrypt.install(home=root) is False
    finally:
        child.communicate("exit\n", timeout=10)
    assert home.backend.calls == []
    assert _raw_outcome(root) == "attempting"
    assert _startup.read_outcome(root) == "source_unavailable"


def test_attempting_with_journal_still_resumes(home, monkeypatch):
    root = home.root

    def crash(point):
        if point == "verified":
            raise _Crash

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    monkeypatch.setattr(_migrate, "_transition", transition)
    assert _raw_outcome(root) == "attempting"
    assert _migrate.journal_path(root).exists()
    assert dbcrypt.install(home=root) is True
    assert not _migrate.journal_path(root).exists()
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()
    assert not _is_plaintext(root / "state.db")


def test_attempting_with_journal_refuses_when_the_resume_fails(home, monkeypatch):
    root = home.root

    def crash(point):
        if point == "verified":
            raise _Crash

    transition = _migrate._transition
    monkeypatch.setattr(_migrate, "_transition", crash)
    with pytest.raises(_Crash):
        dbcrypt.install(home=root)
    monkeypatch.setattr(_migrate, "_transition", transition)
    home.backend.denied_reason = "user_cancelled"
    with pytest.raises(DatabaseRefused, match="hermes-mordred databases encrypt"):
        dbcrypt.install(home=root)
    assert _raw_outcome(root) == "source_unavailable"
    assert root.absolute() not in _locking._LEASES
    assert _migrate.journal_path(root).exists()
    assert not _shim.is_installed()


def test_unschedule_clears_the_record_and_allows_a_new_attempt(home):
    root = home.root
    _record(root, "attempting")
    assert dbcrypt.install(home=root) is False
    assert _raw_outcome(root) == "source_unavailable"
    _release_process_state(root)
    _migrate.unschedule(root)
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()
    assert not _migrate.pending_path(root).exists()
    _migrate.schedule(root)
    assert dbcrypt.install(home=root) is True
    assert not _is_plaintext(root / "state.db")


def test_an_unwritable_attempt_record_makes_no_custody_call(home, monkeypatch):
    root = home.root
    before = _databases(root)

    def unavailable(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(_migrate, "_put_json", unavailable)
    assert dbcrypt.install(home=root) is False
    assert home.backend.calls == []
    assert _databases(root) == before
    assert _migrate.pending_path(root).exists()


# -- the seam ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes-mordred", "databases", "status"],
        ["hermes-mordred", "databases", "encrypt"],
        ["hermes-mordred", "--no-color", "databases", "encrypt", "--dry-run"],
        ["hermes-mordred", "--no-col", "uninstall", "--dry-run"],
        ["hermes", "--model", "mordred", "--no-restore-cwd", "mordred", "--profile", "work", "databases", "status"],
        ["hermes", "--profile=work", "mordred", "uninstall", "--dry-run"],
        ["hermes", "mordred", "-p", "work", "databases", "encrypt", "--dry-run"],
        ["hermes", "--profile", "work", "--model=x", "mordred", "databases", "status"],
    ],
)
def test_startup_seam_skips_maintenance_processes(home, monkeypatch, argv):
    root = home.root
    before = _databases(root)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(_startup, "run_scheduled_conversion", lambda base: pytest.fail("maintenance entered the seam"))
    assert dbcrypt.install(home=root) is False
    assert _databases(root) == before
    assert _migrate.pending_path(root).exists()
    assert home.backend.calls == []
    assert not (root / "mordred" / _startup.RECORD_NAME).exists()
    assert root.absolute() not in _locking._LEASES


def test_exclusive_lease_is_released_before_the_runtime_lease(home, monkeypatch):
    """_database_lifecycle refuses SH while this process holds EX and refuses upgrade."""
    from mordred_hermes._core._database_lifecycle import current_thread_exclusive_leases

    root = home.root
    observed = []
    build = _shim.build_module

    def observe(*args, **kwargs):
        observed.append(current_thread_exclusive_leases())
        return build(*args, **kwargs)

    monkeypatch.setattr(_shim, "build_module", observe)
    assert dbcrypt.install(home=root) is True
    assert observed == [()]


def test_second_install_in_a_process_reuses_the_armed_authority(home):
    """A second process-level install reuses the armed authority without reconverting."""
    root = home.root
    assert dbcrypt.install(home=root) is True
    calls = list(home.backend.calls)
    assert dbcrypt.install(home=root) is True
    assert home.backend.calls == calls
