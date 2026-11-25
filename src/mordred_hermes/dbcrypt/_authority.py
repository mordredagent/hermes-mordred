"""A root-native database key and shared lease with terminal invalidation."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .._core._database_contracts import DatabaseRefused, GuardedConnection, NativeSnapshot
from .._core._database_lifecycle import RuntimeLease, acquire_runtime
from .._private_fs import PrivateFSError, open_private_directory
from ..keyvault._database_authority import (
    CheckedDatabaseDomain,
    load_database_source,
    observe_database_source,
    resolve_database_domain,
)
from ._key import DatabaseKey, derive
from ._marker import Marker, read_marker

#: While the key is held, the full metadata observation (lease, home, marker,
#: native source) runs at most once per this many seconds; checks in between
#: only refuse a forked or terminal authority. Reads are frequent (every SQL
#: callback), so a change of custody is noticed within this window instead of
#: on the next callback.
RECHECK_SECONDS = 30.0
#: Shortens (never lengthens) the window; ``0`` observes on every check.
RECHECK_ENV = "MORDRED_DB_RECHECK_SECONDS"


def recheck_seconds() -> float:
    """The recheck window: :data:`RECHECK_SECONDS`, or a shorter one from :data:`RECHECK_ENV`."""
    raw = os.environ.get(RECHECK_ENV)
    if raw is None:
        return RECHECK_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return RECHECK_SECONDS
    return value if 0 <= value < RECHECK_SECONDS else RECHECK_SECONDS


class Authority:
    """One checked root/generation lifetime; the native key loads on first use.

    Acquisition takes the shared lease and checks the marker against the native
    source, which needs no hardware authentication. The key itself is unwrapped
    (Secure Enclave, possibly Touch ID) only when a connection first needs it,
    so a process that never opens a database never asks for it.
    """

    def __init__(
        self,
        domain: CheckedDatabaseDomain,
        snapshot: NativeSnapshot,
        key: DatabaseKey | None,
        lease: RuntimeLease,
        resources: ExitStack,
    ) -> None:
        self._domain = domain
        self._snapshot = snapshot
        self._key: DatabaseKey | None = key
        #: Serialises the one native unwrap without holding ``_lock``, so
        #: revocation never waits behind an authentication prompt.
        self._load_lock = threading.Lock()
        self._lease = lease
        self._resources = resources
        self._pid = os.getpid()
        self._terminal = False
        self._operations = 0
        self._connections: list[GuardedConnection] = []
        self._lock = threading.RLock()
        self._observed_at: float | None = None
        #: Files whose every page passed ``cipher_integrity_check`` under this key,
        #: by path and identity. Later opens skip the whole-file pass; SQLCipher
        #: still authenticates each page as it is read.
        self.verified_files: set[tuple[str, tuple[int, ...]]] = set()

    @classmethod
    def acquire(cls, home: Path) -> Authority:
        """Admit existing native root custody under preceding shared exclusion; no unwrap yet."""
        domain = resolve_database_domain(home)
        with ExitStack() as resources:
            lease = resources.enter_context(acquire_runtime(domain.root))
            if lease.root != domain.identities[0]:
                raise DatabaseRefused("database runtime root changed during acquisition")
            _require_recovered(domain.root)
            marker = read_marker(domain.root)
            if not isinstance(marker, Marker):
                raise DatabaseRefused("database runtime requires an adopted native marker")
            snapshot = observe_database_source(root=domain.root)
            if marker.snapshot != snapshot:
                raise DatabaseRefused("database marker and native source disagree")
            result = cls(domain, snapshot, None, lease, resources.pop_all())
            try:
                result.check()
            except BaseException:
                result.close()
                raise
            return result

    @property
    def home(self) -> Path:
        return self._domain.home

    @property
    def root(self) -> Path:
        return self._domain.root

    @property
    def snapshot(self) -> NativeSnapshot:
        return self._snapshot

    @property
    def terminal(self) -> bool:
        return self._terminal

    @property
    def key(self) -> DatabaseKey:
        self.check()
        with self._lock:
            if self._terminal:
                raise DatabaseRefused("database runtime authority is terminal")
            if self._key is not None:
                return self._key
        return self._load_key()

    def _load_key(self) -> DatabaseKey:
        """Unwrap the native source once, against the snapshot admitted at acquisition."""
        with self._load_lock:
            with self._lock:
                if self._terminal:
                    raise DatabaseRefused("database runtime authority is terminal")
                if self._key is not None:
                    return self._key
            try:
                key = derive(load_database_source(root=self.root, expected=self._snapshot))
            except BaseException:
                # As a failed acquisition did: refuse for good and release the lease.
                self.invalidate("native database source unavailable")
                raise
            with self._lock:
                # Revoked while authenticating: the key must not outlive the authority.
                if self._terminal:
                    raise DatabaseRefused("database runtime authority is terminal")
                self._key = key
                # Custody may have changed while the native load waited for
                # authentication: observe it in full before the key is used.
                self._observed_at = None
            self.check()
            return key

    def _check_pid(self) -> None:
        """Refuse inherited authority before touching any inherited lock."""
        # Never wait on an RLock inherited from a vanished parent thread.
        if self._pid != os.getpid():
            self._lock = threading.RLock()
            self.invalidate("forked runtime")
            raise DatabaseRefused("database runtime authority cannot survive fork")

    def check(self) -> None:
        """Metadata-only checks never reauthenticate hardware or change generation.

        The full observation is repeated only after :func:`recheck_seconds`.
        """
        self._check_pid()
        with self._lock:
            if self._terminal:
                raise DatabaseRefused("database runtime authority is terminal")
            if self._observed_at is not None and time.monotonic() - self._observed_at < recheck_seconds():
                return
            try:
                self._lease.check()
                if resolve_database_domain(self._domain.home) != self._domain:
                    raise DatabaseRefused("database runtime home relationship changed")
                if read_marker(self.root) != Marker(self._snapshot):
                    raise DatabaseRefused("database runtime marker changed")
                if observe_database_source(root=self.root) != self._snapshot:
                    raise DatabaseRefused("database runtime native source changed")
                self._lease.check()
                self._observed_at = time.monotonic()
            except Exception:
                self.invalidate("authority metadata unavailable or changed")
                raise DatabaseRefused("database runtime authority is no longer valid") from None

    def register_connection(self, connection: GuardedConnection) -> None:
        self._check_pid()
        with self._lock:
            self.check()
            if not any(existing is connection for existing in self._connections):
                self._connections.append(connection)

    @contextmanager
    def operation(self, *, check: bool = True) -> Iterator[None]:
        """Count work in flight so terminal invalidation defers the lease release.

        The lock covers only admission and the counter. SQL, busy waits and the
        caller's workflow run outside it, so connections progress independently
        and revocation never waits behind them. Fork is checked before the lock.
        """
        # Cleanup admission skips metadata/terminal checks, but never fork refusal.
        self._check_pid()
        with self._lock:
            if check:
                self.check()
            self._operations += 1
        try:
            yield
        finally:
            if self._pid != os.getpid():
                self._lock = threading.RLock()  # Never wait on a vanished parent thread.
            with self._lock:
                self._operations -= 1
                if self._terminal and not self._operations:
                    self._resources.close()

    def unregister_connection(self, connection: GuardedConnection) -> None:
        # Called during terminal invalidation as well as normal close.
        if self._pid != os.getpid():
            self._lock = threading.RLock()
        with self._lock:
            self._connections = [existing for existing in self._connections if existing is not connection]

    def invalidate(self, reason: str) -> None:
        """Refuse permanently, invalidate all held objects, then release exclusion.

        The reason is deliberately not retained or logged: callers may pass
        native exception text. GuardedConnection owns rollback and close.
        """
        if self._pid != os.getpid():
            self._lock = threading.RLock()
        with self._lock:
            if self._terminal:
                return
            self._terminal = True
            self._key = None
            connections, self._connections = self._connections, []
            try:
                for connection in connections:
                    try:
                        connection.invalidate()
                    except BaseException:  # noqa: S112 - every held object must still be invalidated
                        # A broken callback cannot leave another held object live.
                        continue
            finally:
                # RuntimeLease.close is PID-bound and cannot unlock the parent.
                if not self._operations or self._pid != os.getpid():
                    self._resources.close()

    def close(self) -> None:
        self.invalidate("runtime closed")


def _require_recovered(root: Path) -> None:
    """Metadata-only, no-follow admission before any native unwrap."""
    try:
        with open_private_directory(root / "mordred") as directory:
            for name in ("db-encryption.journal.json", "db-encryption.pending", "db-decryption.pending"):
                try:
                    directory.stat(name)
                except PrivateFSError as exc:
                    if exc.reason == "missing":
                        continue
                    raise
                raise DatabaseRefused("database maintenance must finish before runtime acquisition")
    except PrivateFSError:
        raise DatabaseRefused("database recovery state cannot be checked safely") from None
