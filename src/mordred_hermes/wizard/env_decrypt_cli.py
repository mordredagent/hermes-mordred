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

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..keyvault._runtime_env import _env_optout_marker_path
from . import _term

if TYPE_CHECKING:
    from pathlib import Path

    from ..keyvault.anchor import AnchorStore
    from ..keyvault.vault import OpenVault
    from ..keyvault.wrap import NativeBackend
    from .configure import PromptIO

__all__ = ["disable", "enable", "purge", "reseal"]

_ENV_NAME = ".env"

#: Runtime-injection probe signature: called ``probe(home=...)`` -> ``(ok, detail)``.
#: Injected into :func:`enable` so tests can fake the runtime check (matching the
#: ``backend=`` / ``store=`` injection style); production uses
#: :func:`_default_runtime_probe`.
RuntimeProbe = Callable[..., "tuple[bool, str]"]


def _default_runtime_probe(*, home: Path) -> tuple[bool, str]:
    """Production runtime probe: can the interpreter that runs ``hermes`` decrypt
    a sealed ``.env``? Imported lazily so this module stays import-light."""
    from ..keyvault._runtime_probe import runtime_env_injection_available

    return runtime_env_injection_available(home=home)


def _runtime_gate(
    *,
    home: Path,
    platform: str,
    runtime_probe: RuntimeProbe | None,
    force_runtime_unverified: bool,
) -> int:
    """Fail-closed macOS gate for the destructive seal.

    Returns 1 (after printing actionable guidance) when the interpreter that runs
    ``hermes`` cannot inject a sealed ``.env`` at startup, else 0. A no-op (0) off
    macOS — the plaintext is kept there anyway — and when
    ``force_runtime_unverified`` is set.
    """
    if platform != "darwin" or force_runtime_unverified:
        return 0
    ok, detail = (runtime_probe or _default_runtime_probe)(home=home)
    if ok:
        return 0
    _term.emit_error(
        "refusing to vault-seal .env — " + detail + ".\n"
        "  A sealed .env is injected at startup only by the mordred plugin in the\n"
        "  interpreter that runs `hermes`. Install it there, e.g.:\n"
        "    VIRTUAL_ENV=<that venv> uv pip install 'mordred-hermes[macos]'\n"
        "  then re-run `encryption enable env`. To seal anyway (secrets stay\n"
        "  unreadable until the runtime has mordred), pass --force-runtime-unverified."
    )
    return 1


def _handle_missing_plaintext(root: Path, home: Path, env_path: Path) -> int:
    """Resolve ``enable`` when there is no plaintext ``<home>/.env`` to enroll.

    Returns 0 — a success **no-op** — when env is already in the sealed steady
    state (enrolled, injection ON, no plaintext at rest): re-running ``enable env``
    (or ``enable all``) must not report "nothing to protect" for something that is
    in fact already enabled. Otherwise returns 1 (genuinely nothing to protect).
    """
    if _env_enrolled(root) and not _env_optout_marker_path(home).exists():
        print(".env is already vault-managed and sealed (no plaintext at rest); nothing to do.")
        return 0
    _term.emit_error(f"no .env at {env_path} — nothing to protect.")
    return 1


#: Legacy reseal temp file. Older ``reseal`` builds staged the merged ``.env``
#: through this 0o600 file before enrolling; the current :func:`reseal` enrolls the
#: merged bytes through a single vault open and never creates it. Kept so the
#: status reader can still flag — and :func:`enable` can still sweep — a leftover
#: one that an interrupted older reseal may have stranded at rest during upgrade.
_RESEAL_TMP_NAME = ".env.reseal.tmp"


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


def _render_env_value(value: str) -> str:
    """Render ``value`` for the right-hand side of a ``KEY=`` line so it round-trips
    back through ``dotenv`` to the same string.

    A bare ``KEY=value`` re-emission is lossy for anything ``dotenv`` parses
    specially: a space-then-``#`` is truncated at the inline comment, a newline ends
    the line, quotes are mis-read. Such values are double-quoted (with backslash,
    quote, and newline escaped), mirroring how the host writes them; plain tokens
    (the common case) and the empty string stay bare.
    """
    if value == "" or not any(c in value for c in " \t\n\r\"'#=$`\\"):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


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
            lines[i] = f"{key}={_render_env_value(remaining.pop(key))}\n"
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    for key, value in remaining.items():
        lines.append(f"{key}={_render_env_value(value)}\n")
    return "".join(lines)


def _write_optout_marker(home: Path) -> None:
    marker = _env_optout_marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("opt-out\n", encoding="utf-8")


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


def _reseal_within_open(opened: OpenVault, overrides: dict[str, str]) -> tuple[bool, str | None]:
    """Merge ``overrides`` onto the enrolled ``.env`` inside an already-open vault.

    Re-enrolls only when the merge changes the bytes, and verifies the read-back
    through the *same* handle (one device-key unlock). Returns
    ``(remove_plaintext, success_message)``: ``remove_plaintext`` is ``False``
    (message ``None``) when the caller should keep the on-disk plaintext — a race
    (``.env`` no longer enrolled), a non-UTF-8 vault copy, or a read-back mismatch
    — and a warning has already been emitted.
    """
    if _ENV_NAME not in opened.list_files():
        return False, None  # raced: no longer enrolled — nothing to reconcile
    base = opened.read_file(_ENV_NAME)
    try:
        base_text = base.decode("utf-8")
    except UnicodeDecodeError as exc:
        _term.emit_warn(f"cannot reseal .env (vault copy is not UTF-8): {exc} — leaving the plaintext in place.")
        return False, None

    merged = _merge_env_text(base_text, overrides).encode("utf-8")
    if merged == base:
        # The stray plaintext changed nothing the vault does not already hold.
        return True, ".env: removed a redundant plaintext copy (the vault copy already held these values)."

    opened.enroll_file(_ENV_NAME, merged)
    if opened.read_file(_ENV_NAME) != merged:
        _term.emit_warn(
            ".env was merged + enrolled but the vault read-back does not match (changed during "
            "reseal?) — leaving the plaintext in place; re-run enable."
        )
        return False, None
    return True, ".env resealed: merged the new value(s) into the vault and removed the plaintext."


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
    vault is present but cannot be opened or the re-enroll itself fails; on a
    read-back mismatch or an unremovable plaintext it returns 0 — in every
    non-clean case the plaintext is kept so no secret is stranded.
    """
    from . import vault_cli

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        return 0  # no stray plaintext → nothing to reconcile
    if _env_optout_marker_path(home).exists():
        return 0  # disabled state: the plaintext is the live copy, not drift
    if not _env_enrolled(root):
        return 0  # not vault-managed → first-time enable handles enrollment

    try:
        disk_text = env_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _term.emit_warn(f"cannot reseal .env (unreadable / non-UTF-8 plaintext): {exc} — leaving it in place.")
        return 0

    from io import StringIO

    from dotenv import dotenv_values

    overrides = {k: v for k, v in dotenv_values(stream=StringIO(disk_text), interpolate=False).items() if v is not None}

    # One device-key unlock (one Touch ID) covers read-base → enroll-merged →
    # verify-read-back through the *same* open (see :func:`_reseal_within_open`).
    # Enrolling the merged bytes directly means the full plaintext is never staged
    # in a temp file at rest, so an interrupted reseal leaves no plaintext behind.
    from ..keyvault import anchor, vault
    from ..keyvault._exceptions import WrapError

    opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
    if opened is None:
        _term.emit_error(
            ".env is enrolled but the vault could not be opened to reseal a stray plaintext "
            "— leaving the plaintext in place (run `encryption status`)."
        )
        return 1

    try:
        remove_plaintext, success_msg = _reseal_within_open(opened, overrides)
    except (vault.VaultError, anchor.AnchorError, WrapError, OSError) as exc:
        _term.emit_error(f"cannot reseal .env into the vault: {exc} — leaving the plaintext in place.")
        return 1
    finally:
        opened.close()

    if not remove_plaintext:
        return 0  # a warning was already emitted; the plaintext is kept

    # The vault is closed and consistent; only now remove the stray plaintext — and
    # report success only once it is actually gone.
    try:
        env_path.unlink()
    except OSError as exc:
        _term.emit_warn(
            f".env was reconciled into the vault but the plaintext at {env_path} could not be removed: {exc} "
            "— remove it by hand (it is still readable at rest)."
        )
        return 0
    print(success_msg)
    return 0


def enable(
    *,
    home: Path,
    root: Path,
    platform: str,
    backend: NativeBackend | None = None,
    store: AnchorStore | None = None,
    prompt_io: PromptIO | None = None,
    runtime_probe: RuntimeProbe | None = None,
    force_runtime_unverified: bool = False,
) -> int:
    """Enroll ``<home>/.env`` into the vault and turn runtime injection on.

    If no vault exists yet, one is created first (prompting once for a recovery
    passphrase) — ``encryption enable`` drives the vault, so a fresh install need
    not run ``vault init`` by hand. Returns 0 on success, 1 when there is no
    ``.env`` to protect, the vault cannot be created, or the enroll fails
    (unverifiable vault, device key-store error). On macOS the plaintext is
    removed only after a clean enroll, so a failure never strands the operator
    without a readable ``.env``.

    On macOS the seal is **fail-closed on the runtime**: before any destructive
    step it probes the interpreter that actually runs ``hermes`` (see
    :mod:`...keyvault._runtime_probe`) and refuses (rc 1) when that runtime lacks
    the mordred injection shim — otherwise the deleted plaintext would be
    undecryptable at startup. ``runtime_probe`` is injectable for tests;
    ``force_runtime_unverified`` bypasses the check (advanced; seals anyway).
    """
    from . import vault_cli

    # Sweep a reseal temp stranded by a prior crash (a 0o600 plaintext at rest):
    # `reseal` removes its own on success/failure, so a leftover is always garbage,
    # and sweeping here makes `encryption enable env` the reliable cleanup remedy.
    (home / _RESEAL_TMP_NAME).unlink(missing_ok=True)

    env_path = home / _ENV_NAME
    if not env_path.is_file():
        return _handle_missing_plaintext(root, home, env_path)

    # Fail-closed runtime check (macOS only): sealing deletes the plaintext and
    # relies on the startup shim to re-inject it — but that shim runs only if the
    # interpreter that actually runs `hermes` has mordred installed. The dev venv
    # driving this command is often NOT that runtime, and the managed runtime venv
    # is recreated (dropping the non-PyPI mordred) on every `hermes` self-update.
    # Gating here — before the reseal branch and the enroll/delete below — covers
    # every destructive path. Off macOS the plaintext is kept anyway, so no gate.
    gate = _runtime_gate(
        home=home, platform=platform, runtime_probe=runtime_probe, force_runtime_unverified=force_runtime_unverified
    )
    if gate != 0:
        return gate

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
