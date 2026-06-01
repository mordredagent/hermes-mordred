"""mordred_keyvault — Secure Enclave-backed key management (macOS).

Phase 0 scaffold: register() is a no-op stub. Phase 4.1 will wire:
- public API: generate / encrypt / decrypt / export_backup / import_backup / verify_digest
- AES-GCM DEK + Secure Enclave-wrapped KEK
- Argon2id-wrapped backup blob with embedded verification digest
- audit log encryption layer (slot-in to Phase 1 Writer interface)
"""

from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point.

    Installs the runtime env transparent-decrypt shim (design note §8.2 item 3):
    on macOS, secrets enrolled in the at-rest vault are decrypted and injected
    into ``os.environ`` at startup, so an unattended process reads them from the
    vault instead of plaintext on disk. Fail-closed — a present-but-unverifiable
    vault raises rather than starting with unverified secret provisioning. A no-op
    where no vault is set up or off macOS.
    """
    from ._runtime_env import install_vault_env_decrypt

    install_vault_env_decrypt()
