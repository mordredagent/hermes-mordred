"""Shared fakes and builders for the vault CLI test modules."""

from __future__ import annotations

from pathlib import Path

from mordred_hermes.keyvault import vault
from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorError
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault._storage import KeyvaultPermissionError

from ._keyvault_fakes import FakeAnchorStore, FakeBackend


class _ReadRaisesStore(FakeAnchorStore):
    """AnchorStore whose ``read`` raises a Keychain I/O error (not item-not-found).

    Models a transient real-Keychain failure (e.g. errSecInteractionNotAllowed)
    so the CLI's fail-closed handling can be exercised cross-platform.
    """

    def read(self, label: str) -> bytes | None:
        raise KeychainAnchorError(-25308, "keychain locked")


class _GenerateRaisesBackend(FakeBackend):
    """Backend whose wrapping-key generation fails with a non-duplicate WrapError."""

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        raise WrapError("simulated device key store failure")


class _FailOnNthEnrollStore(FakeAnchorStore):
    """AnchorStore that fails its ``arm``-th write after :meth:`arm` is called.

    The anchor write is ``enroll_file``'s commit point, so failing the Nth
    write simulates a device-anchor failure partway through a multi-file
    ``migrate`` (after earlier files have already committed).
    """

    def __init__(self, *, fail_on: int) -> None:
        super().__init__()
        self._armed = False
        self._writes = 0
        self._fail_on = fail_on

    def arm(self) -> None:
        self._armed = True
        self._writes = 0

    def write(self, label: str, value: bytes) -> None:
        if self._armed:
            self._writes += 1
            if self._writes == self._fail_on:
                raise KeychainAnchorError(-25308, "simulated anchor-commit failure mid-migrate")
        super().write(label, value)


class _ReadOSErrorVault:
    """Stub :class:`OpenVault` whose ``.env`` read raises an ``OSError``.

    Models ``_storage.KeyvaultPermissionError`` (an ``OSError`` subclass) from a
    bad-mode / symlink / I/O failure during ``read_file`` so ``set_memory_key``'s
    fail-closed handling of that path can be exercised cross-platform.
    """

    def list_files(self) -> list[str]:
        return [".env"]

    def read_file(self, name: str) -> bytes:
        raise KeyvaultPermissionError(13, "permission denied")

    def close(self) -> None:
        pass

    def __enter__(self) -> _ReadOSErrorVault:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


_KEY_ID = "vault-cli-test-key"
_LABEL = "mordred.vault.cli.test"
_PASSPHRASE = "correct horse battery staple"


class _PromptIO:
    """Minimal scripted :class:`~mordred_hermes.wizard.configure.PromptIO`.

    ``password`` gives a single fixed answer to every ``ask_password`` call;
    ``passwords`` gives a queue popped in order (``init`` asks for the
    passphrase twice). ``ask_text`` is unused here but present for the protocol.
    """

    def __init__(self, *, password: str = "", passwords: list[str] | None = None) -> None:
        self._password = password
        self._passwords = list(passwords) if passwords is not None else None

    def ask_text(self, label: str, default: str = "") -> str:
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        if self._passwords is not None:
            return self._passwords.pop(0)
        return self._password


def _build_vault(root: Path, *, files: dict[str, bytes] | None = None) -> None:
    """Materialize a real vault at ``root`` sealed under ``_PASSPHRASE``.

    Uses the software fakes for init/enroll (the hot path) so the on-disk
    ``recovery.mrkv`` + ``manifest.<gen>`` the cold path reads back are
    genuine. The returned vault is closed; callers open it via the CLI.
    """
    backend = FakeBackend()
    backend.generate_enclave_key(_KEY_ID)
    store = FakeAnchorStore()
    opened = vault.init_vault(
        root, key_id=_KEY_ID, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=_LABEL
    )
    try:
        for name, plaintext in (files or {}).items():
            opened.enroll_file(name, plaintext)
    finally:
        opened.close()
