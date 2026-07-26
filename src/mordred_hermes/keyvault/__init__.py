"""mordred_keyvault — Secure Enclave-backed key management (macOS).

Phase 0 scaffold: register() is a no-op stub. Phase 4.1 will wire:
- public API: generate / encrypt / decrypt / export_backup / import_backup / verify_digest
- AES-GCM DEK + Secure Enclave-wrapped KEK
- Argon2id-wrapped backup blob with embedded verification digest
- audit log encryption layer (slot-in to Phase 1 Writer interface)
"""

import contextlib
from typing import Any


def register(ctx: Any) -> None:
    """Hermes plugin entry point.

    Installs the runtime env transparent-decrypt shim (design note §8.2 item 3):
    on macOS, secrets enrolled in the at-rest vault are decrypted and injected
    into ``os.environ`` at startup, so an unattended process reads them from the
    vault instead of plaintext on disk. Fail-closed — a present-but-unverifiable
    vault raises rather than starting with unverified secret provisioning. A no-op
    where no vault is set up or off macOS.

    Also installs the write-side guard: it wraps the host ``.env`` writer so a
    ``hermes config set`` / setup write made while the env target is sealed is
    resealed back into the vault (merged, not clobbered) instead of leaving a
    partial plaintext at rest. Best-effort and fail-open — it must never break
    startup or a host config write (unlike the fail-closed read shim above).

    Finally, registers a session-boundary reseal sweep on ``on_session_start`` and
    ``on_session_end``: the read shim injects from the vault but never deletes an
    on-disk plaintext, and the write guard only catches writes through the host
    writer — so a plaintext left by another path (e.g. ``gateway setup``) would
    stay ``[exposed]`` until a manual ``encryption enable env``. The sweep heals it
    automatically at each session boundary (macOS only, opt-out-aware, fail-open).
    A resealed *changed* value takes effect for the next process; the running
    process keeps whatever the read shim injected at startup.
    """
    from ._runtime_env import install_vault_env_decrypt

    install_vault_env_decrypt()
    from ..privacy_check.hooks import check_plugin_integrity

    # This gate is intentionally not best-effort: every live runtime sibling
    # must still detect when privacy_check itself was explicitly disabled.
    ctx.register_hook("on_session_start", check_plugin_integrity)

    try:
        from ._env_write_guard import install_env_write_guard

        install_env_write_guard()
    except Exception:  # fail-open: never break startup — but leave a debug breadcrumb
        import logging

        logging.getLogger(__name__).debug("env write guard not installed", exc_info=True)

    # Heal stray plaintext `.env` drift at session boundaries. Best-effort and
    # fail-open: a missing or rejecting ``register_hook`` (older / vendored host)
    # must never break startup, and each hook registers independently.
    for _hook_name in ("on_session_start", "on_session_end"):
        with contextlib.suppress(Exception):
            ctx.register_hook(_hook_name, _on_session_reseal)


def _on_session_reseal(**_kwargs: Any) -> None:
    """``on_session_start`` / ``on_session_end`` callback: reseal a stray plaintext
    ``.env`` back into the vault. Fail-open — a reseal problem must never break a
    session boundary (mirrors the write guard's swallow)."""
    with contextlib.suppress(Exception):
        from ._env_write_guard import reseal_stray_env_if_present

        reseal_stray_env_if_present()
