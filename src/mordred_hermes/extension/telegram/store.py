"""Encrypted at-rest archive of imported Telegram messages.

Layout under ``<home>/mordred/telegram/`` (directory 0700, files 0600)::

    index.enc              dialog list + sync cursors
    dialogs/<name>.enc     one file per dialog (all imported messages)
    .lock                  cross-process flock (CLI sync vs. the server)

Every file is ``MTG1 || nonce(12) || AES-256-GCM(ciphertext)`` under the
``store_key`` held in the vault (see :mod:`.secrets`). The AAD binds each blob
to its logical name, so swapping two dialog files, or renaming one onto the
index, fails authentication instead of silently mixing conversations.

Dialog file names are ``HMAC-SHA256(store_key, "dialog:" + dialog_id)`` so the
directory listing does not reveal which chats exist. Message count and sizes
are still observable from file lengths; that is an accepted leak.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, NoReturn

_MAGIC = b"MTG1"
_NONCE_LEN = 12
_AAD_PREFIX = b"mordred-telegram-store-v1|"
_INDEX_NAME = "index"
_INDEX_VERSION = 1


class StoreError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class StoredMessage:
    id: int
    date: int  # unix seconds (UTC)
    sender: str  # display name at import time ("" when unknown)
    text: str
    out: bool = False  # sent by the account owner
    reply_to: int | None = None
    media: str | None = None  # media kind placeholder, e.g. "photo"; bytes are never imported


@dataclass
class DialogInfo:
    dialog_id: int  # Telethon "marked" peer id
    kind: str  # "user" | "group" | "channel" | "bot"
    title: str
    last_message_id: int = 0
    message_count: int = 0
    last_date: int = 0
    archived: bool = False


@dataclass
class ArchiveIndex:
    account_label: str = ""
    account_id: int = 0
    last_sync: int = 0
    dialogs: dict[int, DialogInfo] = field(default_factory=dict)


def telegram_dir() -> Path:
    from ..._home import hermes_home

    return hermes_home() / "mordred" / "telegram"


def _ensure_private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise StoreError("store_path_unsafe")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise StoreError("store_path_unsafe")
    os.chmod(path, 0o700)
    return path


class ArchiveStore:
    """Read/write the encrypted archive with one ``store_key``."""

    def __init__(self, key: bytes, root: Path | None = None) -> None:
        if len(key) != 32:
            raise StoreError("store_key_invalid")
        self._key = key
        self._root = root if root is not None else telegram_dir()

    # -- low-level blob codec ---------------------------------------------

    def _seal(self, name: str, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(_NONCE_LEN)
        return _MAGIC + nonce + AESGCM(self._key).encrypt(nonce, plaintext, _AAD_PREFIX + name.encode("ascii"))

    def _open(self, name: str, blob: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(blob) < len(_MAGIC) + _NONCE_LEN + 16 or not blob.startswith(_MAGIC):
            raise StoreError("store_undecryptable")
        nonce = blob[len(_MAGIC) : len(_MAGIC) + _NONCE_LEN]
        try:
            return AESGCM(self._key).decrypt(
                nonce, blob[len(_MAGIC) + _NONCE_LEN :], _AAD_PREFIX + name.encode("ascii")
            )
        except InvalidTag as exc:
            raise StoreError("store_undecryptable") from exc

    def _write(self, rel: str, name: str, payload: Any) -> None:
        from ...keyvault._storage import atomic_write

        path = self._root / rel
        _ensure_private_dir(path.parent)
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        atomic_write(path, self._seal(name, data))

    def _read(self, rel: str, name: str) -> Any | None:
        path = self._root / rel
        if path.is_symlink():
            raise StoreError("store_path_unsafe")
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            return json.loads(self._open(name, blob).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise StoreError("store_undecryptable") from exc

    # -- naming -------------------------------------------------------------

    def dialog_name(self, dialog_id: int) -> str:
        mac = hmac.new(self._key, f"dialog:{dialog_id}".encode("ascii"), hashlib.sha256).hexdigest()
        return mac[:40]

    # -- index ----------------------------------------------------------------

    def load_index(self) -> ArchiveIndex:
        payload = self._read(f"{_INDEX_NAME}.enc", _INDEX_NAME)
        if payload is None:
            return ArchiveIndex()
        if not isinstance(payload, dict) or payload.get("version") != _INDEX_VERSION:
            raise StoreError("store_undecryptable")
        dialogs: dict[int, DialogInfo] = {}
        for raw in payload.get("dialogs", []):
            try:
                info = DialogInfo(**raw)
            except TypeError as exc:
                raise StoreError("store_undecryptable") from exc
            dialogs[info.dialog_id] = info
        return ArchiveIndex(
            account_label=str(payload.get("account_label", "")),
            account_id=int(payload.get("account_id", 0)),
            last_sync=int(payload.get("last_sync", 0)),
            dialogs=dialogs,
        )

    def save_index(self, index: ArchiveIndex) -> None:
        self._write(
            f"{_INDEX_NAME}.enc",
            _INDEX_NAME,
            {
                "version": _INDEX_VERSION,
                "account_label": index.account_label,
                "account_id": index.account_id,
                "last_sync": index.last_sync,
                "dialogs": [asdict(d) for d in index.dialogs.values()],
            },
        )

    # -- dialogs --------------------------------------------------------------

    def load_messages(self, dialog_id: int) -> list[StoredMessage]:
        name = self.dialog_name(dialog_id)
        payload = self._read(f"dialogs/{name}.enc", name)
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise StoreError("store_undecryptable")
        try:
            return [StoredMessage(**raw) for raw in payload]
        except TypeError as exc:
            raise StoreError("store_undecryptable") from exc

    def append_messages(self, dialog_id: int, new: list[StoredMessage]) -> list[StoredMessage]:
        """Merge *new* into the dialog file (dedup by id, ascending); return all."""
        merged = {m.id: m for m in self.load_messages(dialog_id)}
        for message in new:
            merged[message.id] = message
        ordered = [merged[k] for k in sorted(merged)]
        name = self.dialog_name(dialog_id)
        self._write(f"dialogs/{name}.enc", name, [asdict(m) for m in ordered])
        return ordered

    # -- lifecycle ------------------------------------------------------------

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Exclusive cross-process lock (one sync at a time)."""
        from ..._file_lock import private_flock

        _ensure_private_dir(self._root)
        with private_flock(self._root / ".lock", on_unsafe=_unsafe_lock):
            yield

    def wipe(self) -> None:
        """Delete every archive file (used by ``telegram logout --wipe``)."""
        wipe_archive(self._root)


def _unsafe_lock(_path: Path) -> NoReturn:
    raise StoreError("store_path_unsafe")


def wipe_archive(root: Path | None = None) -> None:
    base = root if root is not None else telegram_dir()
    if base.is_symlink() or not base.exists():
        return
    dialogs = base / "dialogs"
    if dialogs.is_dir() and not dialogs.is_symlink():
        for child in dialogs.iterdir():
            if child.is_file() and not child.is_symlink():
                child.unlink()
        dialogs.rmdir()
    for child in base.iterdir():
        if child.is_file() and not child.is_symlink() and child.suffix == ".enc":
            child.unlink()
