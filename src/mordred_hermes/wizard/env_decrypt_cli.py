"""``hermes mordred encryption {enable,disable,purge} env`` — .env at-rest toggle.

The ``.env`` target mirrors config.yaml's toggle but with ``.env``'s memory-only
runtime model: on enable the plaintext is removed (the runtime shim injects the
enrolled copy into ``os.environ`` at startup — see
:mod:`mordred_hermes.keyvault._runtime_env`), so no secret is left at rest.

Three state transitions (not symmetric — documented per verb):

- **enable**  — enroll ``<home>/.env`` into the vault, clear the opt-out marker,
  and (on macOS) remove the plaintext. Off macOS the runtime shim is a no-op, so
  the plaintext is kept to avoid stranding Hermes.
- **disable** — restore a readable plaintext ``<home>/.env`` (decrypting from the
  vault if enable had removed it; never overwriting a diverging on-disk copy) and
  write the opt-out marker so the runtime stops injecting. *Reversible*: the vault
  copy is kept.
- **purge**   — restore the plaintext, ``unenroll_file('.env')`` from the vault,
  and clear the marker. *Destructive*: back to plain, unencrypted.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge", "reseal"]

_ENV_NAME = ".env"


def _vault_present(root: Path) -> bool:
    """Whether a vault exists at ``root`` (a manifest on disk) — no key needed."""
    return any(root.glob("manifest.*.mvmf"))


def _env_enrolled(root: Path) -> bool:
    """Whether ``.env`` is enrolled per the manifest — cheap, no device unlock.

    Reads the newest manifest's *unverified* plaintext body (the ``files`` keys
    are operational metadata, not secret), so the drift / reseal decision needs
    neither the master key nor a passphrase. Mirrors
    :func:`...wizard.encryption_cli._enrolled_names` but scoped to ``.env``.
    """
    from ..keyvault import manifest, vault

    try:
        generation = vault._latest_manifest_generation(root)
        if generation is None:
            return False
        blob = vault._manifest_path(root, generation).read_bytes()
        return _ENV_NAME in manifest.parse_unverified(blob).files
    except (OSError, manifest.ManifestError):
        return False


def _merge_env_text(base_text: str, overrides: dict[str, str]) -> str:
    """Apply ``overrides`` onto ``base_text``, set-or-append, preserving the rest.

    ``base_text`` is the vault's authoritative ``.env`` (the full set of enrolled
    secrets); ``overrides`` are the keys a host write just set on disk. Each
    override replaces its key in place (keeping the base file's comments, order,
    and untouched lines) or is appended if new. Keys present only in ``base_text``
    are **kept** — a host write after the seal produces a *partial* file, so a key
    missing from ``overrides`` means "untouched", never "delete". Mirrors the
    host's own set-or-append in ``hermes_cli.config.save_env_value``.
    """
    lines = base_text.splitlines(keepends=True)
    remaining = dict(overrides)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            lines[i] = f"{key}={remaining.pop(key)}\n"
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    for key, value in remaining.items():
        lines.append(f"{key}={value}\n")
    return "".join(lines)


def _write_optout_marker(home: Path) -> None:
    marker = _env_optout_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("opt-out\n", encoding="utf-8")


def _read_vault_env(
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
) -> bytes | None:
    """The enrolled ``.env`` bytes, or ``None`` if the vault has none / cannot open.

    A read-only hot-path open (one device-key unlock). Used by :func:`reseal` to
    fetch the authoritative vault copy as the merge base; the simpler
    :func:`enable` path reads its verify copy back through ``add_and_verify``'s
    single open instead.
    """
    from . import vault_cli

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return None
    try:
        return opened.read_file(_ENV_NAME) if _ENV_NAME in opened.list_files() else None
    finally:
        opened.close()


def _restore_plaintext(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None,
    store: AnchorStore | None,
) -> int:
    """Guarantee a readable plaintext ``<home>/.env`` without losing operator edits.

    - No vault here → nothing enrolled to restore; keep whatever plaintext exists.
    - Vault present, ``.env`` enrolled, plaintext missing → decrypt it back.
    - Vault present, ``.env`` enrolled, plaintext **present** → keep the on-disk
      copy (it is the live one); warn if it diverges from the vault copy rather
      than silently overwriting it.

    Returns 0 normally; 1 only when the plaintext is missing *and* the vault is
    present but cannot be opened to recover it (fail-closed — do not pretend a
    secret is on disk when it is not).
    """
    from ..keyvault import _storage
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not _vault_present(root):
        return 0

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        return 0 if env_path.exists() else 1
    try:
        if _ENV_NAME not in opened.list_files():
            return 0
        vault_bytes = opened.read_file(_ENV_NAME)
    finally:
        opened.close()

    if env_path.exists():
        if env_path.read_bytes() != vault_bytes:
            _term.emit_warn(
                f".env drift — the on-disk {env_path} differs from the vault copy; "
                "keeping the on-disk one (not overwriting)."
            )
        return 0

    _storage.atomic_write(env_path, vault_bytes)
    return 0


def reseal(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Reconcile a plaintext ``.env`` that reappeared while the vault still seals it.

    The sealed state (``.env`` enrolled, injection ON, macOS) must hold **no**
    plaintext ``.env``. When a host write puts one back (e.g.
    ``hermes_cli.config.save_env_value`` after ``enable`` removed the plaintext),
    that file is *partial*: the host starts from an empty file because the sealed
    plaintext was deleted, so it carries only the just-written keys. Adopting it
    wholesale would drop every other enrolled secret — so this **merges** the
    on-disk keys onto the vault copy (the authoritative base), re-enrolls the
    merged result, and removes the plaintext.

    For the macOS sealed state only — callers gate on platform. A no-op (returns
    0) when there is no plaintext, ``.env`` is not enrolled, or the env target is
    in the reversible *disabled* state (opt-out marker present: the on-disk
    plaintext is then the intentional live copy, not drift). Returns 1 when the
    vault is present but cannot be opened, or the merged re-enroll cannot be
    verified — the plaintext is kept so no secret is stranded.
    """
    from ..keyvault import _storage
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        return 0  # no stray plaintext → nothing to reconcile
    if _env_optout_marker_path(home).exists():
        return 0  # disabled state: the plaintext is the live copy, not drift
    if not _env_enrolled(root):
        return 0  # not vault-managed → first-time enable handles enrollment

    base = _read_vault_env(root, backend, store)
    if base is None:
        _term.emit_error(
            ".env is enrolled but the vault copy could not be read to reseal a stray plaintext "
            "— leaving the plaintext in place (run `encryption status`)."
        )
        return 1

    try:
        disk_text = env_path.read_text(encoding="utf-8")
        base_text = base.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _term.emit_warn(f"cannot reseal .env (unreadable / non-UTF-8): {exc} — leaving the plaintext in place.")
        return 0

    from io import StringIO

    from dotenv import dotenv_values

    overrides = {k: v for k, v in dotenv_values(stream=StringIO(disk_text), interpolate=False).items() if v is not None}
    merged = _merge_env_text(base_text, overrides).encode("utf-8")

    if merged == base:
        # The stray plaintext added / changed nothing the vault does not already
        # hold — just drop the redundant on-disk copy; the vault is unchanged.
        env_path.unlink(missing_ok=True)
        print(".env: removed a redundant plaintext copy (the vault copy already held these values).")
        return 0

    # Enroll the merged result from a fresh 0o600 temp file rather than
    # overwriting the stray plaintext in place: the stray may be loose-mode (a
    # host write that did not tighten perms), which `atomic_write` would refuse,
    # and writing through it would also destroy it before the enroll is verified.
    reseal_tmp = home / ".env.reseal.tmp"
    reseal_tmp.unlink(missing_ok=True)  # clear any stale temp from a prior crash
    try:
        _storage.atomic_write(reseal_tmp, merged)
        rc, enrolled = vault_cli.add_and_verify(
            root=root, name=_ENV_NAME, source=reseal_tmp, backend=backend, store=store
        )
    finally:
        reseal_tmp.unlink(missing_ok=True)
    if rc != 0:
        return rc  # add_and_verify printed the reason; the stray plaintext is kept
    if enrolled != merged:
        _term.emit_warn(
            ".env was merged + enrolled but the vault read-back does not match (changed during reseal?) "
            "— leaving the plaintext in place; re-run enable."
        )
        return 0
    try:
        env_path.unlink()
    except OSError as exc:
        _term.emit_warn(
            f".env merged into the vault but the plaintext at {env_path} could not be removed: {exc} "
            "— remove it by hand (it is still readable at rest)."
        )
        return 0
    print(".env resealed: merged the new value(s) into the vault and removed the plaintext.")
    return 0


def enable(
    *,
    home: Path,
    root: Path,
    platform: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
) -> int:
    """Enroll ``<home>/.env`` into the vault and turn runtime injection on.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when there is no
    ``.env`` to protect, the vault cannot be created, or the enroll fails
    (unverifiable vault, device key-store error). On macOS the plaintext is
    removed only after a clean enroll, so a failure never strands the operator
    without a readable ``.env``.
    """
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        _term.emit_error(f"no .env at {env_path} — nothing to protect.")
        return 1

    # Drift reconciliation: the vault already manages .env, injection is ON (no
    # opt-out marker), and we are on macOS, yet a plaintext is on disk. That means
    # a host write slipped a *partial* .env past the seal — re-enrolling it
    # wholesale here would drop every other enrolled secret, so merge instead.
    if platform == "darwin" and not _env_optout_marker_path(home).exists() and _env_enrolled(root):
        return reseal(home=home, root=root, backend=backend, store=store)

    rc = vault_cli.ensure_initialised(root=root, prompt_io=prompt_io, backend=backend, store=store)
    if rc != 0:
        return rc  # could not create the vault (reason already printed)

    # Enroll and read the enrolled copy back through the *same* vault open, so the
    # device key (Secure Enclave / Touch ID) is unlocked once for both — the
    # pre-delete verify below no longer costs a second prompt.
    rc, enrolled = vault_cli.add_and_verify(root=root, name=_ENV_NAME, source=env_path, backend=backend, store=store)
    if rc != 0:
        return rc  # vault_cli.add_and_verify already printed the reason

    _env_optout_marker_path(home).unlink(missing_ok=True)  # injection ON

    if platform == "darwin":
        # Only remove the plaintext if it provably matches the enrolled copy: a
        # concurrent edit between add_and_verify()'s read and now must NOT be
        # deleted unvaulted, and an unlink failure must NOT be reported as success
        # while the plaintext remains at rest.
        try:
            current: bytes | None = env_path.read_bytes()
        except OSError:
            current = None
        # `enrolled` is bytes whenever add_and_verify returned rc==0, so the None
        # check is a defensive belt-and-suspenders: if that contract ever loosens,
        # fail safe and keep the plaintext rather than delete it unverified.
        if enrolled is None or current != enrolled:
            _term.emit_warn(
                ".env was enrolled but the on-disk copy no longer matches the vault "
                "(changed during enable?) — leaving the plaintext in place; re-run enable."
            )
            return 0
        try:
            env_path.unlink()
        except OSError as exc:
            _term.emit_warn(
                f".env enrolled but the plaintext at {env_path} could not be removed: {exc} "
                "— remove it by hand (it is still readable at rest)."
            )
            return 0
        print(".env is now vault-managed; the plaintext was removed (the runtime injects it at startup).")
    else:
        print(
            ".env enrolled into the vault, but the runtime decrypt shim is macOS-only — the plaintext was "
            "kept so Hermes still reads it on this OS (status: inactive on this OS)."
        )
    return 0


def disable(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Restore a readable plaintext ``.env`` and stop runtime injection (reversible).

    The vault copy is left intact so re-enabling is immediate. Returns 0 on
    success, 1 only when a sealed-away plaintext cannot be recovered from the
    vault (fail-closed).
    """
    rc = _restore_plaintext(home=home, root=root, backend=backend, store=store)
    if rc != 0:
        return rc
    _write_optout_marker(home)
    print(".env decryption disabled (opt-out marker written); the vault copy is kept for re-enable.")
    return 0


def purge(
    *,
    home: Path,
    root: Path,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
) -> int:
    """Remove ``.env`` from the vault entirely, restoring the plaintext first.

    Destructive: the encrypted copy is gone afterwards. The vault copy is never
    lost silently — if it is the only copy it is restored to ``<home>/.env``, and
    if the on-disk ``.env`` *diverges* from it the vault copy is saved to a
    ``.env.vault-purged`` sidecar before unenrolling. Returns 0 on success, 1 when
    the vault is present but cannot be opened to recover / unenroll.
    """
    from ..keyvault import _storage, anchor, vault
    from . import vault_cli

    env_path = home / _ENV_NAME

    if _vault_present(root):
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        if opened is None:
            return 0 if env_path.exists() else 1
        try:
            if _ENV_NAME in opened.list_files():
                vault_bytes = opened.read_file(_ENV_NAME)
                if not env_path.exists():
                    _storage.atomic_write(env_path, vault_bytes)  # restore the only copy
                elif env_path.read_bytes() != vault_bytes:
                    backup = home / ".env.vault-purged"
                    _storage.atomic_write(backup, vault_bytes)
                    _term.emit_warn(
                        f"on-disk .env differs from the vault copy — saved the vault copy to {backup} "
                        "before purging (nothing is lost)."
                    )
                opened.unenroll_file(_ENV_NAME)
        except (vault.VaultError, anchor.AnchorError, OSError) as exc:
            _term.emit_error(f"cannot purge .env from the vault: {exc}")
            return 1
        finally:
            opened.close()

    _env_optout_marker_path(home).unlink(missing_ok=True)
    print(".env purged from the vault; the plaintext is on disk and unencrypted.")
    return 0
