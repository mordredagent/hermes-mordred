"""Lazy resolution of the wizard's injectable production defaults.

Nearly every keyvault-facing wizard command takes ``backend=`` / ``store=`` /
``prompt_io=`` seams that tests inject fakes into, with ``None`` meaning
"build the production implementation". The build-on-``None`` block was
copy-pasted at ~19 call sites across the vault / keyvault / audit CLIs; these
helpers single-source it so the seams cannot drift (e.g. one site defaulting
to a different backend than the rest).

The backend/store definitions live in :mod:`..keyvault._identity` — the same
resolvers the startup shims use — so the wizard CLIs and the hot-path shims
cannot default differently; this module only adds the wizard-owned
``prompt_io`` resolver and re-exports the pair for its CLI importers.

CRITICAL: the imports stay *inside* the functions (and the re-exported
resolvers keep theirs). The production classes pull the ``cryptography``
stack (``_SecKeyBackend``), the macOS Keychain bindings
(``KeychainAnchorStore``), and ``prompt_toolkit`` (``PromptToolkitIO``) — none
of which may load at module-import time, because CLI modules such as
``audit_cli`` must stay importable without the ``[keyvault]`` extra
(regression-guarded by ``tests/test_audit_cli.py::TestMinimalInstallImport``).
``keyvault._identity`` itself is stdlib-only, so the module-level re-export
import below is safe under that contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..keyvault._identity import resolve_backend as resolve_backend
from ..keyvault._identity import resolve_store as resolve_store

if TYPE_CHECKING:
    from .configure import PromptIO

__all__ = ["resolve_backend", "resolve_prompt_io", "resolve_store"]


def resolve_prompt_io(prompt_io: PromptIO | None) -> PromptIO:
    """Return ``prompt_io``, or build the production prompt_toolkit-backed IO."""
    if prompt_io is not None:
        return prompt_io
    from .configure import PromptToolkitIO

    return PromptToolkitIO()
