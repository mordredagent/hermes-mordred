"""Test-only native backend and checked-storage emulation for proof children.

The installed-runtime proof child loads this file by path, and only when the
parent preserved ``MORDRED_TEST_INJECT_BACKEND`` (a pytest run from the source
checkout naming a module under ``tests/``). The child cannot import the
``tests`` package, so this module is self-contained. Parent fixtures apply the
same patches through ``monkeypatch.setattr``.

Native keys are software P-256 PEM files stored beside the profile
(``<HERMES_HOME>/../native-keys``) so that a parent and its children share one
injected key store. Nothing here prints or returns symmetric key bytes.

Not a ``test_*`` module, so pytest does not collect it.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mordred_hermes import _windows_runtime
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists, WrapKeyNotFound

#: Same binary SID as ``tests.test_windows_custody_profile.SID``.
SID = bytes.fromhex("010200000000000515000000e8030000")
#: The child reports this file as its injected native helper.
HELPER = os.path.abspath(__file__)

_REAL_ENVIRONMENT_ROOT = _windows_runtime.environment_root


def environment_root(python: Path) -> Path | None:
    """C4 admission, plus the POSIX ``bin/python`` venv layout for host tests."""
    root = _REAL_ENVIRONMENT_ROOT(python)
    if root is not None:
        return root
    if python.name not in ("python", "python3") or python.parent.name != "bin" or not python.is_file():
        return None
    root = python.parent.parent
    return root if (root / "pyvenv.cfg").is_file() else None


class FileBackend:
    """Software P-256 native boundary persisted under one test-owned directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.calls: list[tuple[str, str]] = []

    def _path(self, key_id: str) -> Path:
        return self.directory / (hashlib.sha256(key_id.encode("utf-8")).hexdigest() + ".pem")

    def _load(self, key_id: str) -> ec.EllipticCurvePrivateKey:
        try:
            data = self._path(key_id).read_bytes()
        except FileNotFoundError:
            raise WrapKeyNotFound(f"no key for {key_id!r}") from None
        key = serialization.load_pem_private_key(data, password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return key

    @staticmethod
    def _public(key: ec.EllipticCurvePrivateKey) -> bytes:
        return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        self.calls.append(("generate", key_id))
        key = ec.generate_private_key(ec.SECP256R1())
        data = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        try:
            with open(self._path(key_id), "xb") as handle:
                handle.write(data)
        except FileExistsError:
            raise WrapKeyAlreadyExists(f"key {key_id!r} already exists") from None
        return self._public(key)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        self.calls.append(("get_pub", key_id))
        return self._public(self._load(key_id))

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        self._path(key_id).unlink(missing_ok=True)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", key_id))
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._load(key_id).exchange(ec.ECDH(), peer)


def backend_for(home: Path) -> FileBackend:
    return FileBackend(home.parent / "native-keys")


@contextmanager
def _optional(path: str | Path) -> Iterator[Any]:
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(open_private_directory(path))
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            directory = None
        yield directory


def emulate(set_attr: Callable[[object, str, object], None], backend: FileBackend) -> None:
    """Host emulation of Windows checked storage, principal, runtime and CNG."""
    from mordred_hermes import _config_io as cio
    from mordred_hermes.keyvault import _memory_storage as storage
    from mordred_hermes.keyvault import _seckey_helper
    from mordred_hermes.keyvault import _windows_custody as custody

    set_attr(cio, "open_confidential_directory", open_private_directory)
    for owner in (cio, custody, storage):
        set_attr(owner, "open_optional_confidential_directory", _optional)
    set_attr(cio, "open_optional_private_directory", _optional)
    set_attr(custody, "current_principal_id", lambda: SID)
    set_attr(custody, "windows_backend", lambda: backend)
    set_attr(storage, "open_confidential_directory", open_private_directory)
    set_attr(_windows_runtime, "environment_root", environment_root)
    set_attr(_seckey_helper, "find_winkey_helper", lambda: HELPER)


def install() -> None:
    """Child entry point: emulate against the profile named by HERMES_HOME."""
    emulate(setattr, backend_for(Path(os.environ["HERMES_HOME"])))
