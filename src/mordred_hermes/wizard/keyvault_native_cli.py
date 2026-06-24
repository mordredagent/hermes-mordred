"""``hermes mordred keyvault {enable-se,enable-tpm}`` — native-helper build CLI.

Extracted from :mod:`keyvault_cli` (v2-OS2 follow-up b). These are the commands
that build + install the platform hardware-helper binaries from source:

- ``enable-se``  — macOS Secure Enclave helper (``native/sekey-helper``).
- ``enable-tpm`` — Linux TPM 2.0 helper (``native/tpmkey-helper``).

Each build step is a module-level seam so the orchestration is unit-testable
with no Swift/Rust toolchain and no hardware (the build / probe are mocked).
The argparse adapters (``cli_enable_*``) are wired in :mod:`cli`.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import _term

__all__ = [
    "cli_enable_se",
    "cli_enable_tpm",
    "enable_se",
    "enable_tpm",
]


# -----------------------------------------------------------------------------
# enable-se — build + ad-hoc-sign + install the Secure Enclave helper.
#
# Upgrades the keyvault wrapping key from the software P-256 fallback to the
# real hardware Secure Enclave via the CryptoKit ``dataRepresentation`` helper
# (``native/sekey-helper``). That helper needs only an ad-hoc codesign — no
# entitlement, no provisioning profile, no paid Apple Developer account.
#
# Each step is a module-level seam so the orchestration is unit-testable with
# no Swift toolchain and no Secure Enclave (the build / probe are mocked).
# -----------------------------------------------------------------------------


def _se_platform_reason() -> str | None:
    """Return why the SE helper can't be built here, or ``None`` when it can.

    The CryptoKit ``SecureEnclave`` APIs exist only on macOS (Apple Silicon or
    a T2 Mac). A coarse ``Darwin`` guard is enough; true SE *presence* is
    confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Darwin":
        return f"Secure Enclave requires macOS on Apple Silicon (this host is {platform.system() or 'unknown'})"
    return None


def _missing_build_tools() -> list[str]:
    """Return the build tools (``swift``, ``codesign``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("swift", "codesign") if shutil.which(tool) is None]


def _locate_sekey_source() -> Path | None:
    """Locate the ``sekey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_helper_source()


def _run_sekey_build(src: Path, *, install_dir: Path | None, unattended: bool | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` / ``unattended`` are forwarded as the env vars the build
    script and helper honour (``MORDRED_SEKEY_INSTALL_DIR`` /
    ``MORDRED_SEKEY_UNATTENDED``).
    """
    import os
    import subprocess

    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_SEKEY_INSTALL_DIR"] = str(install_dir)
    if unattended is not None:
        env["MORDRED_SEKEY_UNATTENDED"] = "1" if unattended else "0"
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_sekey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm Secure Enclave access.

    When ``install_dir`` is given (``enable-se --install-dir``), the binary just
    installed there is preferred — ``_find_helper`` only searches
    ``MORDRED_SEKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    (Mirror of :func:`_verify_tpmkey_helper`.)
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper._find_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_se(
    *,
    install_dir: Path | None = None,
    unattended: bool | None = None,
    home: Path | None = None,
) -> int:
    """Build + ad-hoc-sign + install the SE helper, then verify it works.

    Returns ``0`` on success, ``1`` on any guard / build / verify failure. On
    failure the keyvault keeps using the software P-256 fallback, so the
    at-rest guarantee never downgrades. ``home`` is accepted for symmetry with
    the other keyvault commands; the helper resolves its key-blob store from
    ``HERMES_HOME`` itself.
    """
    del home  # the helper resolves its store via HERMES_HOME; accepted for symmetry

    reason = _se_platform_reason()
    if reason is not None:
        _term.emit_error(reason)
        return 1

    missing = _missing_build_tools()
    if missing:
        _term.emit_error(
            f"missing build tool(s): {', '.join(missing)}. "
            "Install the Xcode command-line tools first (xcode-select --install)."
        )
        return 1

    src = _locate_sekey_source()
    if src is None:
        _term.emit_error(
            "could not locate the sekey-helper sources (native/sekey-helper). "
            "Build from a source checkout of mordred-hermes."
        )
        return 1

    rc, output = _run_sekey_build(src, install_dir=install_dir, unattended=unattended)
    if rc != 0:
        _term.emit_error(f"sekey-helper build failed:\n{output}")
        return 1

    if not _verify_sekey_helper(install_dir=install_dir):
        _term.emit_error(
            "helper installed but the Secure Enclave probe failed; the keyvault will keep using the software fallback."
        )
        return 1

    print(output.strip() or "Secure Enclave helper installed.")
    print("Hardware Secure Enclave is now active for the keyvault.")
    return 0


def cli_enable_se(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-se [--install-dir P] [--unattended]``.

    ``--unattended`` absent → ``None`` (let ``MORDRED_SEKEY_UNATTENDED`` / the
    interactive default decide), not ``False``.
    """
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    unattended = True if getattr(args, "unattended", False) else None
    return enable_se(install_dir=install_dir, unattended=unattended)


# -----------------------------------------------------------------------------
# enable-tpm — build + install the Linux TPM 2.0 helper (v2-OS2 Phase 2c).
#
# The Linux counterpart to enable-se: builds the ``mordred-hermes-tpmkey`` Rust
# helper (``native/tpmkey-helper``) and verifies it. The TPM is Tier 2
# (machine-bound) — the key cannot leave the chip, but there is no per-use
# user-presence gate, so (unlike enable-se) there is no ``--unattended`` flag.
# Each step is a module-level seam so the orchestration is unit-testable with
# no Rust toolchain and no TPM.
# -----------------------------------------------------------------------------


def _tpm_platform_reason() -> str | None:
    """Return why the TPM helper can't be built here, or ``None`` when it can.

    The ``tss-esapi`` / libtss2 backend is Linux-only (Windows TPM via CNG is a
    separate future helper). A coarse ``Linux`` guard is enough; true TPM
    *presence* is confirmed by the post-install probe.
    """
    import platform

    if platform.system() != "Linux":
        return f"TPM 2.0 keyvault requires Linux (this host is {platform.system() or 'unknown'})"
    return None


def _missing_tpm_build_tools() -> list[str]:
    """Return the build tools (``cargo``) not found on ``PATH``."""
    import shutil

    return [tool for tool in ("cargo",) if shutil.which(tool) is None]


def _locate_tpmkey_source() -> Path | None:
    """Locate the ``tpmkey-helper`` source tree (delegates to ``_seckey_helper``)."""
    from ..keyvault import _seckey_helper

    return _seckey_helper._locate_tpmkey_source()


def _run_tpmkey_build(src: Path, *, install_dir: Path | None) -> tuple[int, str]:
    """Run ``build.sh`` in ``src``; return ``(returncode, combined_output)``.

    ``install_dir`` is forwarded as ``MORDRED_TPMKEY_INSTALL_DIR``. The TPM is
    Tier 2 with no per-use gate, so there is no ``unattended`` env var (cf.
    :func:`_run_sekey_build`).
    """
    import os
    import subprocess

    env = dict(os.environ)
    if install_dir is not None:
        env["MORDRED_TPMKEY_INSTALL_DIR"] = str(install_dir)
    try:
        proc = subprocess.run(
            ["bash", str(src / "build.sh")],
            cwd=str(src),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"failed to run build.sh: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _verify_tpmkey_helper(*, install_dir: Path | None = None) -> bool:
    """Probe the freshly-installed helper to confirm TPM access.

    When ``install_dir`` is given (``enable-tpm --install-dir``), the binary
    just installed there is preferred — ``find_tpmkey_helper`` only searches
    ``MORDRED_TPMKEY_HELPER`` / ``~/.local/bin`` / ``PATH``, so a custom,
    not-on-PATH install dir would otherwise yield a false verification failure.
    """
    from ..keyvault import _seckey_helper

    binary: str | None = None
    if install_dir is not None:
        candidate = install_dir / _seckey_helper._TPM_HELPER_NAME
        if candidate.is_file():
            binary = str(candidate)
    if binary is None:
        binary = _seckey_helper.find_tpmkey_helper()
    if binary is None:
        return False
    try:
        _seckey_helper._HelperSecKeyOps(binary).probe()
        return True
    except Exception:
        return False


def enable_tpm(
    *,
    install_dir: Path | None = None,
    home: Path | None = None,
) -> int:
    """Build + install the TPM helper, then verify it works.

    Returns ``0`` on success, ``1`` on any guard / build / verify failure. On
    failure the keyvault keeps using the software P-256 fallback, so the
    at-rest guarantee never downgrades. ``home`` is accepted for symmetry with
    the other keyvault commands; the helper resolves its key-blob store from
    ``HERMES_HOME`` itself.
    """
    del home  # the helper resolves its store via HERMES_HOME; accepted for symmetry

    reason = _tpm_platform_reason()
    if reason is not None:
        _term.emit_error(reason)
        return 1

    missing = _missing_tpm_build_tools()
    if missing:
        _term.emit_error(
            f"missing build tool(s): {', '.join(missing)}. Install the Rust toolchain first (https://rustup.rs)."
        )
        return 1

    src = _locate_tpmkey_source()
    if src is None:
        _term.emit_error(
            "could not locate the tpmkey-helper sources (native/tpmkey-helper). "
            "Build from a source checkout of mordred-hermes."
        )
        return 1

    rc, output = _run_tpmkey_build(src, install_dir=install_dir)
    if rc != 0:
        _term.emit_error(f"tpmkey-helper build failed:\n{output}")
        return 1

    if not _verify_tpmkey_helper(install_dir=install_dir):
        _term.emit_error(
            "helper installed but the TPM probe did not succeed, so no "
            "hardware key is active. On Linux the keyvault fails closed (there is "
            "no software fallback off macOS), so keyvault operations needing a "
            "hardware key error until a working helper is in place. Check that "
            "this host exposes a TPM 2.0 device (/dev/tpmrm0 or /dev/tpm0) and "
            "that your user may access it (commonly membership in the `tss` "
            "group), then re-run `hermes-mordred keyvault enable-tpm`."
        )
        return 1

    print(output.strip() or "TPM 2.0 helper installed.")
    print("Hardware TPM 2.0 is now active for the keyvault.")
    return 0


def cli_enable_tpm(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault enable-tpm [--install-dir P]``.

    The TPM is Tier 2 (machine-bound) with no per-use gate, so there is no
    ``--unattended`` flag (cf. :func:`cli_enable_se`).
    """
    install_dir = Path(args.install_dir) if getattr(args, "install_dir", None) else None
    return enable_tpm(install_dir=install_dir)
