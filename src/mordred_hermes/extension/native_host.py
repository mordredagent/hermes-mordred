"""The browser's native-messaging host: how the Mordred extension finds and enrolls with this Mac.

The installer registers ``com.mordred.hermes`` with each Chromium browser it
finds (Brave, Chrome). Its manifest names the only extension IDs the browser
lets launch it, so only the Mordred extension can reach it. The host answers
two questions:

- ``discover``: the extension server's address (its port is chosen at install
  time, so the extension never asks the user for it);
- ``attest``: a ticket for one pending approval. The extension server accepts
  a new browser only with a ticket for that connection's check code, so another
  program (another extension, or a process on the Mac that forges an
  extension's ``Origin``) cannot raise the Touch ID approval by itself.

The ticket is an HMAC under a per-home secret (``mordred/native-host.key``,
mode 0600) over the calling extension's origin and the check code. The host
issues it only when its parent process is a browser signed by a known team and
the browser named an allowed extension. A program running as the same user can
still read that file: the ticket keeps other extensions and web pages out and
makes local programs work for it, it is not a boundary against malware that
already runs as the user.

Messages are the browser's native-messaging frames: a 4-byte native-endian
length, then UTF-8 JSON.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import IO, Any, Final

HOST_NAME: Final = "com.mordred.hermes"
#: The Chrome Web Store ID of the Mordred extension (from its manifest key).
STORE_EXTENSION_ID: Final = "hjdjaknfdfcmlndipbcoflplecpofdbl"
_IDS_FILE: Final = "extension-ids"
_SECRET_FILE: Final = "native-host.key"  # noqa: S105 - a file name, not a secret
_ENDPOINT_FILE: Final = "extension-endpoint.json"
_TICKET_CONTEXT: Final = b"mordred-native-attest-v1\n"
_MAX_MESSAGE: Final = 64 * 1024

#: Browsers whose native-messaging hosts this installs, by their per-user folder,
#: and the code-signing team each must be signed by (measured with codesign).
BROWSERS: Final[Mapping[str, tuple[str, str]]] = {
    "Brave": ("BraveSoftware/Brave-Browser", "KL8N8XSYF4"),
    "Chrome": ("Google/Chrome", "EQHXZ8M8AV"),
}


def _state(home: Path) -> Path:
    return home / "mordred"


# --- the allowed extensions ---------------------------------------------------------------


def _valid_id(extension_id: str) -> bool:
    return len(extension_id) == 32 and all("a" <= c <= "p" for c in extension_id)


def allowed_extension_ids(home: Path) -> frozenset[str] | None:
    """The extension IDs this home accepts; ``None`` when none were set (any extension, as before)."""
    try:
        text = (_state(home) / _IDS_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return frozenset(line.strip() for line in text.splitlines() if _valid_id(line.strip()))


def allow_extension_ids(home: Path, extension_ids: Iterable[str]) -> frozenset[str]:
    """Add IDs to the allowed list (written 0600); returns the whole list."""
    wanted = set(allowed_extension_ids(home) or ())
    for extension_id in extension_ids:
        if not _valid_id(extension_id):
            raise ValueError(f"not an extension ID: {extension_id!r}")
        wanted.add(extension_id)
    _write_private(_state(home) / _IDS_FILE, "".join(f"{i}\n" for i in sorted(wanted)).encode())
    return frozenset(wanted)


def extension_id_of(origin: str | None) -> str | None:
    """``chrome-extension://<id>/`` (as a browser names it) → ``<id>``; ``None`` otherwise."""
    if not origin or not origin.startswith("chrome-extension://"):
        return None
    extension_id = origin[len("chrome-extension://") :].rstrip("/")
    return extension_id if _valid_id(extension_id) else None


# --- the secret and tickets ---------------------------------------------------------------


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def ensure_secret(home: Path) -> None:
    """Create this home's ticket secret once (32 random bytes, 0600)."""
    path = _state(home) / _SECRET_FILE
    if not path.exists():
        _write_private(path, secrets.token_bytes(32))


def read_secret(home: Path) -> bytes | None:
    """The ticket secret, or ``None`` when this home has no native host (tickets not required)."""
    path = _state(home) / _SECRET_FILE
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        data = os.read(fd, 64)
    finally:
        os.close(fd)
    if len(data) != 32:
        raise ValueError("the native host secret is damaged")
    return data


def ticket(secret: bytes, extension_id: str, code: str) -> str:
    mac = hmac.new(secret, _TICKET_CONTEXT + f"{extension_id}\n{code}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def ticket_valid(secret: bytes, extension_id: str, code: str, presented: object) -> bool:
    return isinstance(presented, str) and hmac.compare_digest(ticket(secret, extension_id, code), presented)


# --- the endpoint ---------------------------------------------------------------------------


def write_endpoint(home: Path, host: str, port: int) -> None:
    """Record where ``extension serve`` listens (``extension agent install`` calls this)."""
    data = json.dumps({"url": f"ws://{host}:{port}/ext"}, sort_keys=True).encode()
    _write_private(_state(home) / _ENDPOINT_FILE, data)


def read_endpoint(home: Path) -> str | None:
    try:
        url = json.loads((_state(home) / _ENDPOINT_FILE).read_text(encoding="utf-8")).get("url")
    except (FileNotFoundError, ValueError, AttributeError):
        return None
    return url if isinstance(url, str) and url.startswith("ws://127.0.0.1:") else None


# --- registration ---------------------------------------------------------------------------


def manifest(executable: Path, extension_ids: Iterable[str]) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": "Mordred: connects the Mordred extension to this Mac",
        "path": str(executable),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{i}/" for i in sorted(extension_ids)],
    }


def install(home: Path, launcher: Path, *, support: Path | None = None) -> list[Path]:
    """Write the host's start script and register it with each installed browser.

    ``launcher`` is this home's ``hermes-mordred`` command. Returns the browser
    manifests written (none when no supported browser is installed yet).
    """
    ids = allowed_extension_ids(home) or allow_extension_ids(home, [STORE_EXTENSION_ID])
    ensure_secret(home)
    script = home / "bin" / "mordred-native-host"
    script.parent.mkdir(parents=True, exist_ok=True)
    # The browser starts the host with its own environment: name this home here.
    script.write_text(
        f'#!/bin/sh\nHERMES_HOME="{home}"\nexport HERMES_HOME\nexec "{launcher}" extension native-host "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    root = support if support is not None else Path.home() / "Library" / "Application Support"
    written = []
    for folder, _team in BROWSERS.values():
        browser = root / folder
        if not browser.is_dir():
            continue
        target = browser / "NativeMessagingHosts" / f"{HOST_NAME}.json"
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(manifest(script, ids), indent=2) + "\n", encoding="utf-8")
        written.append(target)
    return written


# --- the host itself ------------------------------------------------------------------------


def _parent_is_browser(pid: int) -> bool:
    """Whether ``pid`` runs code signed by one of :data:`BROWSERS`' teams (checked live by codesign)."""
    for _folder, team in BROWSERS.values():
        requirement = f'=anchor apple generic and certificate leaf[subject.OU] = "{team}"'
        result = subprocess.run(  # noqa: S603 - fixed argv
            ["/usr/bin/codesign", "--verify", "-R", requirement, str(pid)],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode == 0:
            return True
    return False


def _read_message(stream: IO[bytes]) -> dict[str, Any] | None:
    header = stream.read(4)
    if len(header) < 4:
        return None
    (size,) = struct.unpack("=I", header)
    if size > _MAX_MESSAGE:
        raise ValueError("message too large")
    message = json.loads(stream.read(size).decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("message is not an object")
    return message


def _write_message(stream: IO[bytes], message: Mapping[str, Any]) -> None:
    data = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def answer(message: Mapping[str, Any], *, home: Path, extension_id: str | None, parent_ok: bool) -> dict[str, Any]:
    """The reply to one message from the extension named by ``extension_id``."""
    allowed = allowed_extension_ids(home)
    if extension_id is None or (allowed is not None and extension_id not in allowed):
        return {"ok": False, "error": "extension_not_allowed"}
    if not parent_ok:
        return {"ok": False, "error": "browser_not_verified"}
    kind = message.get("type")
    if kind == "discover":
        url = read_endpoint(home)
        return {"ok": True, "url": url} if url else {"ok": False, "error": "server_not_installed"}
    if kind == "attest":
        code = message.get("code")
        secret = read_secret(home)
        if not isinstance(code, str) or not code or len(code) > 16:
            return {"ok": False, "error": "invalid_request"}
        if secret is None:
            return {"ok": False, "error": "server_not_installed"}
        return {"ok": True, "ticket": ticket(secret, extension_id, code)}
    return {"ok": False, "error": "invalid_request"}


def main(argv: list[str]) -> int:
    """Serve one browser connection: the browser passes the calling extension's origin first."""
    from .._core._home import hermes_home

    # Only native-messaging frames may reach the browser: anything else printed
    # while running (warnings, logging) goes to stderr instead.
    out = os.fdopen(os.dup(sys.stdout.fileno()), "wb")
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    home = Path(hermes_home())
    extension_id = extension_id_of(argv[0] if argv else None)
    parent_ok = sys.platform == "darwin" and _parent_is_browser(os.getppid())
    try:
        while (message := _read_message(sys.stdin.buffer)) is not None:
            _write_message(out, answer(message, home=home, extension_id=extension_id, parent_ok=parent_ok))
    except (ValueError, OSError) as exc:
        print(f"mordred native host: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0
