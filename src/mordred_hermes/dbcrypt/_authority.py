"""A root-native database key and shared lease with terminal invalidation."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .._database_contracts import DatabaseRefused, GuardedConnection, NativeSnapshot
from .._database_lifecycle import RuntimeLease, acquire_runtime
from .._private_fs import PrivateFSError, open_private_directory
from ..keyvault._database_authority import (
    CheckedDatabaseDomain,
    load_database_source,
    observe_database_source,
    resolve_database_domain,
)
from ._key import DatabaseKey, derive
from ._marker import Marker, read_marker


class Authority:
    """One checked root/generation lifetime; fresh acquisition always loads native."""

    def __init__(
        self,
        domain: CheckedDatabaseDomain,
        snapshot: NativeSnapshot,
        key: DatabaseKey,
        lease: RuntimeLease,
        resources: ExitStack,
    ) -> None:
        self._domain = domain
        self._snapshot = snapshot
        self._key: DatabaseKey | None = key
        self._lease = lease
        self._resources = resources
        self._pid = os.getpid()
        self._terminal = False
        self._operations = 0
        self._connections: list[GuardedConnection] = []
        self._lock = threading.RLock()

    @classmethod
    def acquire(cls, home: Path) -> Authority:
        """Load only existing native root custody under preceding shared exclusion."""
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
            material = load_database_source(root=domain.root, expected=snapshot)
            result = cls(domain, snapshot, derive(material), lease, resources.pop_all())
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
            if self._key is None:
                raise DatabaseRefused("database runtime authority is terminal")
            return self._key

    def check(self) -> None:
        """Metadata-only checks never reauthenticate hardware or change generation."""
        # Never wait on an RLock inherited from a vanished parent thread.
        if self._pid != os.getpid():
            self._lock = threading.RLock()
            self.invalidate("forked runtime")
            raise DatabaseRefused("database runtime authority cannot survive fork")
        with self._lock:
            if self._terminal:
                raise DatabaseRefused("database runtime authority is terminal")
            try:
                self._lease.check()
                if resolve_database_domain(self._domain.home) != self._domain:
                    raise DatabaseRefused("database runtime home relationship changed")
                if read_marker(self.root) != Marker(self._snapshot):
                    raise DatabaseRefused("database runtime marker changed")
                if observe_database_source(root=self.root) != self._snapshot:
                    raise DatabaseRefused("database runtime native source changed")
                self._lease.check()
            except Exception:
                self.invalidate("authority metadata unavailable or changed")
                raise DatabaseRefused("database runtime authority is no longer valid") from None

    def register_connection(self, connection: GuardedConnection) -> None:
        self.check()
        with self._lock:
            self.check()
            if not any(existing is connection for existing in self._connections):
                self._connections.append(connection)

    @contextmanager
    def operation(self, *, check: bool = True) -> Iterator[None]:
        """Serialize SQL and revocation, checking fork before the inherited lock."""
        if self._pid != os.getpid() or check:
            self.check()
        with self._lock:
            if check:
                self.check()
            self._operations += 1
            try:
                yield
            finally:
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
                    except BaseException:
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
