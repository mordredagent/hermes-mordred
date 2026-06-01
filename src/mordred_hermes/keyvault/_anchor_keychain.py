"""Production macOS Keychain ``AnchorStore`` (design note §8.1).

The device-bound vault freshness anchor (:mod:`mordred_hermes.keyvault.anchor`)
pins two non-secret values an offline attacker can read but not write. On macOS
that store is a **Keychain generic-password** item with
``AfterFirstUnlock`` + ``ThisDeviceOnly`` accessibility — a powered-off /
stolen / imaged device cannot mint or edit it.

Unlike Secure-Enclave *key* persistence (blocked by ``errSecMissingEntitlement``
/ ``-34018`` from a non-provisioned interpreter — see ``_seckey_helper.py``),
generic-password writes succeed from a plain ``uv`` / ``pip`` Python, so this
store works in production without a provisioning profile.

Two layers, mirroring :mod:`mordred_hermes.keyvault._seckey_backend`:

1. :class:`_KeychainOps` — the narrowest possible pyobjc-touching surface
   (add / get / update / delete a generic-password by ``service`` + ``account``).
   Each method returns plain ``bytes`` / ``None`` or raises :class:`_OpsError`
   carrying the ``OSStatus``; no ``Security.framework`` object crosses the
   boundary. The production implementation imports ``Security`` lazily so this
   module imports on any platform.
2. :class:`KeychainAnchorStore` — implements
   :class:`mordred_hermes.keyvault.anchor.AnchorStore` (read / write / delete by
   label), orchestrating the add-or-update upsert and translating
   :class:`_OpsError` into a fail-closed :class:`KeychainAnchorError`.
"""

from __future__ import annotations

from typing import Any, Final, Protocol

from . import native
from .anchor import AnchorError

# OSStatus values we branch on (Security/SecBase.h). Mirrored from
# ``_seckey_backend.py`` rather than imported, to keep this module independent.
# (generic-password writes do NOT hit errSecMissingEntitlement / -34018 — see
# the module docstring — so unlike ``_seckey_backend`` there is no fallback path
# and no need to branch on it here.)
errSecSuccess: Final = 0
errSecItemNotFound: Final = -25300
errSecDuplicateItem: Final = -25299

# Keychain ``kSecAttrService`` for every vault anchor item. The per-vault
# ``anchor_label`` becomes the ``kSecAttrAccount`` within this service.
DEFAULT_SERVICE: Final = "mordred-hermes.vault.anchor"


class KeychainAnchorError(AnchorError):
    """A Keychain operation failed with an unexpected ``OSStatus``.

    A subclass of :class:`~mordred_hermes.keyvault.anchor.AnchorError`: a
    Keychain I/O failure *is* a failure to establish freshness, so it fails
    closed through the same ``except AnchorError`` paths the vault already
    uses — never swallowed into a "missing anchor" (which would read as a
    clean re-init opportunity). ``status`` carries the raw ``OSStatus``.
    """

    def __init__(self, status: int, message: str = "") -> None:
        self.status = status
        detail = f"{message} " if message else ""
        super().__init__(f"{detail}(OSStatus {status})")


class _OpsError(Exception):
    """A raw ``OSStatus`` failure from the pyobjc ops layer.

    Internal to this module: :class:`KeychainAnchorStore` catches it and either
    handles it (``errSecDuplicateItem`` → update, ``errSecItemNotFound`` →
    absent) or re-raises it as :class:`KeychainAnchorError`.
    """

    def __init__(self, status: int, message: str = "") -> None:
        self.status = status
        super().__init__(message or f"OSStatus {status}")


class _KeychainOps(Protocol):
    """The narrowest pyobjc-touching surface the anchor store needs."""

    def add(self, service: str, account: str, value: bytes) -> None:
        """Add a new generic-password item.

        Raises :class:`_OpsError` (``errSecDuplicateItem`` when the
        ``(service, account)`` item already exists)."""
        ...

    def get(self, service: str, account: str) -> bytes | None:
        """Return the item's data, or ``None`` when absent (``errSecItemNotFound``)."""
        ...

    def update(self, service: str, account: str, value: bytes) -> None:
        """Overwrite an existing item's data. Raises :class:`_OpsError`."""
        ...

    def delete(self, service: str, account: str) -> None:
        """Remove the item. A missing item (``errSecItemNotFound``) is success."""
        ...


def _status(result: Any) -> int:
    """Normalize a pyobjc return to an ``OSStatus`` int.

    pyobjc functions with an output parameter return ``(status, out)``;
    others return the bare status.
    """
    return int(result[0]) if isinstance(result, tuple) else int(result)


class _PyobjcKeychainOps:
    """Production :class:`_KeychainOps` over ``Security.framework``.

    ``Security`` is imported lazily (via :func:`native._lazy_import_security`,
    which raises on non-Darwin / missing pyobjc) so this module stays importable
    everywhere; the import happens only when an operation actually runs.
    """

    def _security(self) -> Any:
        return native._lazy_import_security()

    def _query(self, sec: Any, service: str, account: str) -> dict[Any, Any]:
        return {
            sec.kSecClass: sec.kSecClassGenericPassword,
            sec.kSecAttrService: service,
            sec.kSecAttrAccount: account,
        }

    def add(self, service: str, account: str, value: bytes) -> None:
        sec = self._security()
        attrs = self._query(sec, service, account)
        attrs[sec.kSecValueData] = value
        attrs[sec.kSecAttrAccessible] = sec.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        status = _status(sec.SecItemAdd(attrs, None))
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemAdd failed")

    def get(self, service: str, account: str) -> bytes | None:
        sec = self._security()
        query = self._query(sec, service, account)
        query[sec.kSecReturnData] = True
        query[sec.kSecMatchLimit] = sec.kSecMatchLimitOne
        result = sec.SecItemCopyMatching(query, None)
        status = _status(result)
        if status == errSecItemNotFound:
            return None
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemCopyMatching failed")
        data = result[1] if isinstance(result, tuple) and len(result) > 1 else None
        if data is None:
            # Success with no data is ambiguous (would read as a present-but-empty
            # anchor and wrongly block re-init). Treat it as a hard failure.
            raise _OpsError(status, "SecItemCopyMatching returned success but no data")
        return bytes(data)

    def update(self, service: str, account: str, value: bytes) -> None:
        sec = self._security()
        query = self._query(sec, service, account)
        # Re-assert accessibility on update so the ThisDeviceOnly guarantee the
        # threat model depends on cannot be silently inherited as something
        # weaker from a foreign / older item.
        attrs = {
            sec.kSecValueData: value,
            sec.kSecAttrAccessible: sec.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        }
        status = _status(sec.SecItemUpdate(query, attrs))
        if status != errSecSuccess:
            raise _OpsError(status, "SecItemUpdate failed")

    def delete(self, service: str, account: str) -> None:
        sec = self._security()
        status = _status(sec.SecItemDelete(self._query(sec, service, account)))
        # A missing item is success — delete is idempotent (matches the
        # AnchorStore Protocol's "no-op when already absent").
        if status not in (errSecSuccess, errSecItemNotFound):
            raise _OpsError(status, "SecItemDelete failed")


class KeychainAnchorStore:
    """``anchor.AnchorStore`` backed by a macOS Keychain generic-password item.

    Each vault's ``anchor_label`` is stored as the ``kSecAttrAccount`` under a
    single shared ``service``. ``ops`` defaults to the production pyobjc
    implementation; tests inject a software fake.
    """

    def __init__(self, *, service: str = DEFAULT_SERVICE, ops: _KeychainOps | None = None) -> None:
        self._service = service
        self._ops: _KeychainOps = ops if ops is not None else _PyobjcKeychainOps()

    def read(self, label: str) -> bytes | None:
        try:
            return self._ops.get(self._service, label)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"reading anchor {label!r}") from exc

    def write(self, label: str, value: bytes) -> None:
        # Upsert: add a fresh item, or update in place if one already exists.
        # SecItemAdd reports errSecDuplicateItem rather than overwriting, so the
        # duplicate is the expected signal to switch to SecItemUpdate.
        try:
            self._ops.add(self._service, label, value)
            return
        except _OpsError as exc:
            if exc.status != errSecDuplicateItem:
                raise KeychainAnchorError(exc.status, f"writing anchor {label!r}") from exc
        try:
            self._ops.update(self._service, label, value)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"updating anchor {label!r}") from exc

    def delete(self, label: str) -> None:
        try:
            self._ops.delete(self._service, label)
        except _OpsError as exc:
            raise KeychainAnchorError(exc.status, f"deleting anchor {label!r}") from exc
