"""Shared audit-writer plumbing for the ``network`` / ``llm_guard`` plugins.

Single-sources three things that were independently copy-pasted across
``network`` and ``llm_guard`` (and had begun to drift in their docstrings):

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
  ``NDJSONWriter``). The import is inside the call so plugin discovery stays
  cheap. Callers wrap this in their own ``functools.lru_cache`` so the
  per-process cache (and the ``cache_clear()`` the tests drive) stays
  module-local rather than shared across plugins.
"""

from __future__ import annotations

import logging
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


def build_audit_writer(path: Path) -> Writer:
    """Construct the encryption-aware audit writer ``privacy_check`` provides.

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
    side-effect-free until invoked). Callers memoise the result themselves.

    ``path`` is ``<HERMES_BASE>/mordred/audit.log``, so the keyvault home is
    ``<HERMES_BASE>`` == ``path.parent.parent``. We pass it explicitly — the
    same way privacy_check does (``make_audit_writer(keyvault_home=
    config_path.parent)``) — so the encryption decision is bound to the
    keyvault that owns THIS log, not the ambient default home. That keeps the
    three plugins in agreement in production and keeps the choice deterministic
    under tests that redirect the audit path to a scratch directory.
    """
    from .privacy_check.audit import make_audit_writer

    return make_audit_writer(path, keyvault_home=path.parent.parent)
