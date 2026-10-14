"""Dependency-free file-vault error base.

Kept free of the keyvault crypto stack so the Windows capability guards (and
the stdlib-only callers that reach them, such as the privacy keyvault probe
and the env reseal path) stay importable on a minimal install.
:mod:`mordred_hermes.keyvault.vault` re-exports :class:`VaultError` unchanged.
"""

from __future__ import annotations


class VaultError(Exception):
    """A vault operation failed closed.

    Raised for vault-level faults: an uninitialized / already-initialized
    root, a missing authoritative manifest, a name that is not enrolled, a
    ciphertext blob that is missing or does not match its content address,
    an AEAD failure, or use of a closed vault. Distinct from
    :class:`mordred_hermes.keyvault.anchor.AnchorError` (freshness-pin
    failures) and :class:`mordred_hermes.keyvault.manifest.ManifestError`
    (manifest authentication failures), which propagate as themselves so a
    caller can tell a tamper attempt from an operational error — but all
    three are hard failures that prevent the vault from opening or reading.
    """
