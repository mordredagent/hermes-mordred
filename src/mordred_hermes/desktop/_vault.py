"""The macOS vault and memory ceremonies of the Desktop page: prepare → acknowledge → commit.

``/vault/prepare`` generates the recovery passphrase in memory only (a
:class:`VaultFlow`, TTL 600 s, one at a time) and the page shows it; only after
the owner acknowledged it does ``/vault/{flow_id}/commit`` create the vault
with THAT passphrase (``_vault_lifecycle.init`` reuses a passphrase remembered
in the :class:`~..wizard._flow_session.FlowSession`, the CLI's typed-passphrase
path), create an empty ``.env`` when there is none, and enroll ``.env``. A
lost answer after commit therefore never loses the phrase. ``/memory/enable``
is memory-only. Both workers run in a thread under the route's ceremony lock.

Nothing here prints the passphrase, logs it, or puts it in a job or event; the
flow's repr is redacted and the reference is dropped on commit, replacement,
expiry and shutdown.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ._capture import captured_output

__all__ = [
    "VAULT_TTL_S",
    "VaultFlow",
    "VaultFlows",
    "commit",
    "diagnose_anchor",
    "enable_memory",
    "facts",
    "vault_dir_clean",
]

_log = logging.getLogger(__name__)
VAULT_TTL_S: Final = 600.0


# -- flows ----------------------------------------------------------------------------------------


@dataclass
class VaultFlow:
    """One prepared vault ceremony; ``passphrase`` is ``None`` when the vault exists already (reuse)."""

    flow_id: str
    passphrase: str | None = field(repr=False)
    created: float

    def __repr__(self) -> str:  # never print the passphrase
        return f"VaultFlow(flow_id={self.flow_id!r}, reuse={self.passphrase is None})"


class VaultFlows:
    """At most one prepared ceremony, kept in memory for ``ttl`` seconds; thread-safe."""

    def __init__(
        self,
        generate: Callable[[], str],
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = VAULT_TTL_S,
    ) -> None:
        self._generate = generate
        self._clock = clock
        self._ttl = ttl
        self._lock = threading.Lock()
        self._flow: VaultFlow | None = None

    def __repr__(self) -> str:
        return f"VaultFlows(pending={self._flow is not None})"

    def prepare(self, *, reuse: bool) -> VaultFlow:
        """A new flow (a fresh passphrase unless ``reuse``); it replaces any pending one."""
        flow = VaultFlow(secrets.token_urlsafe(12), None if reuse else self._generate(), self._clock())
        with self._lock:
            self._flow = flow
        return flow

    def get(self, flow_id: str) -> VaultFlow | None:
        self.reap()
        with self._lock:
            flow = self._flow
        if flow is None or not secrets.compare_digest(flow.flow_id.encode(), flow_id.encode("utf-8", "replace")):
            return None
        return flow

    def discard(self, flow_id: str) -> None:
        with self._lock:
            if self._flow is not None and self._flow.flow_id == flow_id:
                self._flow = None

    def reap(self) -> int:
        """Drop an expired flow; returns how many were dropped."""
        with self._lock:
            if self._flow is not None and self._clock() - self._flow.created >= self._ttl:
                self._flow = None
                return 1
        return 0

    def cancel_all(self) -> None:
        with self._lock:
            self._flow = None


# -- facts ----------------------------------------------------------------------------------------


def facts(home: Path, root: Path, *, platform: str) -> dict[str, Any]:
    """``/status.vault``: file facts only (no Keychain, no key, no prompt).

    ``unattended`` is ``None``: the effective policy of an existing device key
    cannot be read back from the key store with the current ``keyvault`` API
    (the Secure Enclave access control is opaque and no record of it is kept),
    and the requested policy is never reported in its place.
    """
    from ..keyvault._runtime_env import _env_optout_marker_path
    from ..keyvault.vault import artifacts_present
    from ..wizard.encryption_cli import _enrolled_names

    enrolled = ".env" in _enrolled_names(root)
    optout = _env_optout_marker_path(home).exists()
    return {
        "exists": artifacts_present(root),
        "env_enrolled": enrolled,
        "env_injecting": enrolled and not optout and platform == "darwin",
        "optout": optout,
        "unattended": None,
    }


# -- stale anchor -----------------------------------------------------------------------------------


def vault_dir_clean(root: Path) -> bool:
    """No recoverable vault state at ``root``: absent, or no manifest, no recovery sidecar and no blobs."""
    if not root.exists():
        return True
    if any(root.glob("manifest.*.mvmf")) or (root / "recovery.mrkv").exists():
        return False
    blobs = root / "blobs"
    if not blobs.exists():
        return True
    try:
        return blobs.is_dir() and not any(blobs.iterdir())
    except OSError:
        return False


def _legacy_anchor_store() -> Any:
    from ..keyvault._anchor_keychain import KeychainAnchorStore

    return KeychainAnchorStore()


def _helper_anchor_store() -> Any | None:
    """The helper-owned store WITHOUT a legacy fallback (so a read never migrates); ``None`` without a helper."""
    from ..keyvault._anchor_keychain import HelperAnchorStore, _HelperAnchorOps
    from ..keyvault._seckey_helper import find_sekey_helper

    binary = find_sekey_helper()
    return None if binary is None else HelperAnchorStore(_HelperAnchorOps(binary), legacy=None)


def _read(store: Any, identity: str) -> str:
    try:
        return "present" if store.read(identity) is not None else "absent"
    except Exception as exc:  # an old helper, a Keychain error: we cannot tell
        _log.info("vault anchor read failed (%s)", type(exc).__name__)
        return "unknown"


def _anchor_store(identity: str, *, require_present: bool) -> str | None:
    """Where an anchor for ``identity`` is: ``helper``, ``legacy``, ``unknown``, or ``None`` (nowhere).

    The helper store is read first (no prompt), WITHOUT a legacy fallback, so
    nothing migrates. A legacy item next to a helper that could not be read
    (an old helper, a failed read) is ``unknown``: the helper may hold one too,
    and deleting the legacy item alone would not be the remedy. With
    ``require_present``, ``unknown`` needs an anchor actually found.
    """
    helper = _helper_anchor_store()
    helper_state = "none" if helper is None else _read(helper, identity)
    if helper_state == "present":
        return "helper"
    legacy_state = _read(_legacy_anchor_store(), identity)
    if legacy_state == "present":
        return "unknown" if helper_state == "unknown" else "legacy"
    if require_present or "unknown" not in (helper_state, legacy_state):
        return None
    return "unknown"


def diagnose_anchor(root: Path, *, require_present: bool = False) -> dict[str, Any] | None:
    """``vault_anchor_stale`` when an anchor remains without a vault, else ``None``.

    Never ``default_anchor_store().read()`` (it can migrate the legacy item and
    prompt). The ``security`` command (``remedy``) is offered only for an anchor
    known to be in the legacy store alone, over a vault directory with no
    recoverable state; otherwise the answer is informational.
    """
    from ..keyvault._anchor_keychain import DEFAULT_SERVICE
    from ..keyvault._identity import vault_identity

    identity = vault_identity(root)
    store = _anchor_store(identity, require_present=require_present)
    if store is None:
        return None
    answer: dict[str, Any] = {
        "ok": False,
        "error": "vault_anchor_stale",
        "anchor_store": store,
        "anchor_identity": identity,
    }
    if store == "legacy" and vault_dir_clean(root):
        answer["remedy"] = f"security delete-generic-password -s {DEFAULT_SERVICE} -a {identity}"
    return answer


# -- ceremonies -----------------------------------------------------------------------------------


class _NoPassphrase:
    """PromptIO for the page's ceremonies: never supplies a passphrase, takes every default.

    The commit's passphrase reaches ``init`` only through the flow session, so
    no other prompt can obtain it; ``init`` refuses an empty answer.
    """

    def ask_password(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return ""

    def ask_bool(self, label: str, default: bool, *, description: str | None = None) -> bool:
        return default

    def ask_text(self, label: str, default: str = "", *, description: str | None = None) -> str:
        return default

    def ask_choice(self, label: str, choices: Any, default: Any = None, **_: Any) -> Any:
        return default if default is not None else choices[0]

    def ask_multi(self, label: str, choices: Any, default: Any = ()) -> tuple[str, ...]:
        return tuple(default)


def _commit_session(unattended: bool | None, passphrase: str | None) -> Any:
    """A FlowSession that remembers the prepared passphrase and records whether ``init`` took it."""
    from ..wizard._flow_session import FlowSession

    class _CommitSession(FlowSession):
        __slots__ = ("consumed",)

        def __init__(self) -> None:
            super().__init__(unattended=unattended)
            self.consumed = False

        @property
        def passphrase(self) -> str | None:
            value = FlowSession.passphrase.fget(self)  # type: ignore[attr-defined]
            if value:
                self.consumed = True
            return value  # type: ignore[no-any-return]

    session = _CommitSession()
    if passphrase:
        session.remember_passphrase(passphrase)
    return session


def _ensure_env_file(home: Path) -> None:
    """An empty ``0600`` ``.env`` when there is none, so ``encryption enable env`` has a file to enroll."""
    with contextlib.suppress(FileExistsError):
        fd = os.open(home / ".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)


def commit(
    *,
    home: Path,
    root: Path,
    platform: str,
    flow: VaultFlow,
    flows: VaultFlows,
    unattended: bool | None,
) -> dict[str, Any]:
    """Create the vault with the prepared passphrase (or reuse the existing one) and enroll ``.env``."""
    from ..keyvault.vault import artifacts_present
    from ..wizard import env_decrypt_cli

    state = facts(home, root, platform=platform)
    if state["optout"]:
        return {"ok": False, "error": "env_optout"}
    if state["exists"] and state["env_enrolled"]:
        flows.discard(flow.flow_id)
        return {"ok": False, "error": "vault_exists"}
    if vault_dir_clean(root):
        # Before the wizard: its default_anchor_store().read() would MIGRATE a legacy anchor into
        # the helper store (and delete the legacy item), turning the actionable case into a deferred one.
        stale = diagnose_anchor(root, require_present=True)
        if stale is not None:
            return stale
    _ensure_env_file(home)
    session = _commit_session(unattended, flow.passphrase)
    try:
        with session as active, captured_output():
            rc = env_decrypt_cli.enable(
                home=home, root=root, platform=platform, prompt_io=_NoPassphrase(), flow_session=active
            )
    except Exception as exc:
        _log.warning("mordred desktop vault commit failed (%s)", type(exc).__name__)
        rc = 1
    created = artifacts_present(root)
    if created:
        flows.discard(flow.flow_id)  # the phrase is in use (or another one is): never offered again
    if rc == 0:
        return {"ok": True, "passphrase_reused": not (session.consumed and created)}
    if not created and not session.consumed:
        stale = diagnose_anchor(root)
        if stale is not None:
            return stale
    return {"ok": False, "error": "memory_encryption_failed"}


def enable_memory(*, home: Path, root: Path, platform: str, active: Callable[[], bool]) -> dict[str, Any]:
    """Memory encryption only, over an existing vault whose ``.env`` is enrolled and injecting.

    The prerequisites come first, then the idempotent answer: ``vault_required``
    without a vault, ``env_required`` until ``.env`` is enrolled and injecting
    (no opt-out), and only then ``already`` when memory encryption is on. The
    vault is opened on the hot path (one device-key unwrap: a Touch ID prompt
    when the vault key is attended); no passphrase can be asked for or created.
    """
    from ..wizard import memory_cli
    from ..wizard._flow_session import FlowSession

    state = facts(home, root, platform=platform)
    if not state["exists"]:
        return {"ok": False, "error": "vault_required"}
    if not (state["env_enrolled"] and state["env_injecting"] and not state["optout"]):
        return {"ok": False, "error": "env_required"}
    if active():
        return {"ok": True, "already": True}
    try:
        with FlowSession() as flow, captured_output():
            rc = memory_cli.enable(
                home=home, root=root, platform=platform, prompt_io=_NoPassphrase(), flow_session=flow
            )
    except Exception as exc:
        _log.warning("mordred desktop memory enable failed (%s)", type(exc).__name__)
        rc = 1
    if rc != 0 or not active():
        return {"ok": False, "error": "memory_encryption_failed"}
    return {"ok": True, "restart_required": True}


def prepare_answer(flows: VaultFlows, state: Mapping[str, Any]) -> dict[str, Any]:
    """``/vault/prepare``: a passphrase for a new vault, a reuse flow for an existing one without ``.env``."""
    if state["optout"]:
        return {"ok": False, "error": "env_optout"}
    if state["exists"] and state["env_enrolled"]:
        return {"ok": False, "error": "vault_exists"}
    flow = flows.prepare(reuse=bool(state["exists"]))
    words = None if flow.passphrase is None else flow.passphrase.split()
    return {"ok": True, "flow_id": flow.flow_id, "passphrase": words, "passphrase_reused": flow.passphrase is None}
