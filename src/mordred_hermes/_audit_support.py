"""Process-wide audit-writer plumbing shared by every Mordred plugin.

Single-sources the following audit-log concerns:

* :class:`AuditWriter` -- the structural Protocol mirroring
  :class:`mordred_hermes.privacy_check.audit.Writer`. Declared here (rather
  than imported) so the plugins stay free of a hard import dependency on
  ``privacy_check`` at plugin-discovery time; the real ``NDJSONWriter`` is
  duck-compatible.
* :func:`safe_audit_append` -- best-effort append that must NOT fail the
  caller open. The strict-mode refusal paths raise a ``BaseException``-derived
  error so it escapes Hermes' ``except Exception:`` filters; if the audit
  write itself raised a plain ``Exception`` (disk full, permission denied,
  broken NDJSON path) *before* that refusal fired, Hermes would catch it and
  continue -- a fail-open bypass. Swallowing the audit-side error here keeps
  the refusal authoritative while logging the cause on the caller's logger.
* :func:`build_audit_writer` -- lazily delegates to
  ``privacy_check.audit.make_audit_writer`` so ``network`` / ``llm_guard`` get
  the SAME encryption-aware writer ``privacy_check`` uses for the shared
  ``audit.log`` (``EncryptedWriter`` when the keyvault is initialized, else
  ``NDJSONWriter``). A process-wide registry, keyed by the resolved absolute
  path, owns exactly one writer for that file. Module-local ``lru_cache``
  wrappers remain useful as cheap references and preserve their test
  ``cache_clear()`` API, but clearing one never closes or replaces the shared
  writer that another plugin may still be using.

The registry deliberately retains writers until process shutdown. In
particular, policy reloads must not wipe an ``EncryptedWriter``'s active DEK
while network, LLM-guard, or extension-sign hooks still hold the same writer.
If a keyvault is initialized inside an already-running process whose shared
writer is plaintext, the registry records and logs a restart-required warning;
it cannot swap the writer behind existing references safely. Normal
``hermes-mordred keyvault init`` runs in its own CLI process, so the next
Hermes process selects encryption immediately.
An ``atexit`` hook closes each unique writer once, after normal plugin work has
quiesced.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .privacy_check.audit import Writer


class AuditWriter(Protocol):
    """Structural mirror of :class:`mordred_hermes.privacy_check.audit.Writer`.

    Declared here, not imported, to keep ``network`` / ``llm_guard`` free of a
    hard dependency on ``privacy_check``; the wired ``NDJSONWriter`` satisfies
    it structurally.
    """

    def append(self, entry: Mapping[str, Any]) -> None: ...


def safe_audit_append(audit: AuditWriter, entry: Mapping[str, Any], *, logger: logging.Logger) -> None:
    """Append ``entry`` to ``audit``, swallowing audit-side failures.

    A strict-mode refusal (a ``BaseException``-derived error) must still
    propagate even when the audit write raises a plain ``Exception``; catching
    it here prevents a fail-open bypass. The underlying error is logged on the
    caller-supplied ``logger`` so operators can investigate.
    """
    try:
        audit.append(entry)
    except Exception as e:
        logger.error("audit append failed for entry %r: %s", entry, e)


_WRITER_REGISTRY: dict[Path, tuple[Path, Writer]] = {}
_WRITER_REGISTRY_LOCK = threading.Lock()
_PLAINTEXT_RESTART_WARNED: set[Path] = set()


def _normalized_audit_path(path: Path) -> Path:
    """Return a stable process-local registry key for ``path``.

    Relative paths and ``..`` components are folded, and existing parent
    directories are canonicalized. The final component is deliberately not
    resolved: an ``audit.log`` symlink must reach the writer's no-follow
    checks instead of silently turning into authorization to chmod/write its
    target.
    """
    try:
        expanded = path.expanduser()
    except (OSError, RuntimeError):
        expanded = path
    lexical = Path(os.path.abspath(os.fspath(expanded)))
    try:
        return lexical.parent.resolve(strict=False) / lexical.name
    except (OSError, RuntimeError):
        return lexical


def build_audit_writer(path: Path, *, keyvault_home: Path | None = None) -> Writer:
    """Return the process-wide encryption-aware writer for ``path``.

    Delegates to :func:`mordred_hermes.privacy_check.audit.make_audit_writer`
    so ``network`` / ``llm_guard`` obtain the SAME writer kind ``privacy_check``
    uses for the shared ``audit.log``: an ``EncryptedWriter`` once the Mordred
    keyvault is initialized, an ``NDJSONWriter`` otherwise. Routing all three
    plugins through one factory prevents a plaintext writer from splicing
    cleartext lines into an MRAL-encrypted log (which would leak audit metadata
    at rest and make ``audit decrypt`` fail for the whole day's trail).

    The import is local so ``privacy_check`` — and, only when the keyvault is
    actually initialized, the keyvault crypto stack — is not loaded at
    plugin-discovery time (keeps each plugin's ``register`` cheap and
    side-effect-free until invoked).

    The normalized absolute path is both the registry key and the path handed
    to the writer. Consequently ``audit.log`` and ``./audit.log`` cannot
    acquire independent DEKs. A symlink in the final component remains
    visible and is refused by the writer rather than followed.

    The default log is ``<HERMES_BASE>/mordred/audit.log``, so its keyvault
    home is ``path.parent.parent``. Privacy-check passes ``keyvault_home``
    explicitly because it permits a custom audit path while the keyvault still
    belongs to the directory containing ``config.yaml``.
    """
    from .privacy_check.audit import make_audit_writer

    normalized = _normalized_audit_path(path)
    normalized_home = _normalized_audit_path(keyvault_home) if keyvault_home is not None else normalized.parent.parent
    with _WRITER_REGISTRY_LOCK:
        registered = _WRITER_REGISTRY.get(normalized)
        if registered is None:
            writer = make_audit_writer(normalized, keyvault_home=normalized_home)
            _WRITER_REGISTRY[normalized] = (normalized_home, writer)
        else:
            registered_home, writer = registered
            if registered_home != normalized_home:
                raise ValueError(
                    f"audit path {normalized} is already bound to keyvault home "
                    f"{registered_home}, not {normalized_home}"
                )
            _warn_if_plaintext_restart_required(normalized, normalized_home, writer)
        return writer


def _warn_if_plaintext_restart_required(path: Path, keyvault_home: Path, writer: Writer) -> None:
    """Warn once if in-process keyvault init cannot upgrade live references."""
    from .privacy_check._keyvault_probe import keyvault_initialized
    from .privacy_check.audit import NDJSONWriter

    if path in _PLAINTEXT_RESTART_WARNED or not isinstance(writer, NDJSONWriter):
        return
    try:
        initialized = keyvault_initialized(keyvault_home)
    except Exception:
        return
    if not initialized:
        return

    _PLAINTEXT_RESTART_WARNED.add(path)
    detail = (
        "keyvault became initialized after the shared plaintext audit writer "
        "was created; restart Hermes to enable MRAL audit encryption safely"
    )
    logger = logging.getLogger("mordred.audit")
    logger.warning("%s (%s)", detail, path)
    safe_audit_append(
        writer,
        {
            "event": "mordred.audit_writer",
            "decision": "warn",
            "reason": "mordred.degraded.audit_encryption_unavailable",
            "detail": detail,
        },
        logger=logger,
    )


def _close_registered_audit_writers() -> None:
    """Close and forget every registered writer.

    Production calls this only from ``atexit``, after normal plugin activity
    has stopped. Tests may call
    :func:`_reset_audit_writer_registry_for_tests` after clearing their
    module-local memoizers. Clearing the registry during live plugin activity
    is intentionally not a public lifecycle operation: doing so could create a
    second writer while another component still owns the first one's DEK.
    """
    with _WRITER_REGISTRY_LOCK:
        writers = tuple({id(writer): writer for _keyvault_home, writer in _WRITER_REGISTRY.values()}.values())
        _WRITER_REGISTRY.clear()
        _PLAINTEXT_RESTART_WARNED.clear()

    for writer in writers:
        close = getattr(writer, "close", None)
        if not callable(close):
            continue
        try:
            close()
        except Exception as exc:  # pragma: no cover - defensive shutdown path
            logging.getLogger("mordred.audit").warning("audit writer close failed during shutdown: %s", exc)


def _reset_audit_writer_registry_for_tests() -> None:
    """Test-only reset after callers clear module-local writer memoizers."""
    _close_registered_audit_writers()


atexit.register(_close_registered_audit_writers)
