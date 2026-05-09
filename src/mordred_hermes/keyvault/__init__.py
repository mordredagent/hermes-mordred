"""mordred_keyvault — Secure Enclave-backed key management (macOS).

Phase 0 scaffold: register() is a no-op stub. Phase 4.1 will wire:
- public API: generate / encrypt / decrypt / export_backup / import_backup / verify_digest
- AES-GCM DEK + Secure Enclave-wrapped KEK
- Argon2id-wrapped backup blob with embedded verification digest
- audit log encryption layer (slot-in to Phase 1 Writer interface)
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point. Phase 0 stub — no keyvault API registered yet."""
    return None
