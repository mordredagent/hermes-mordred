"""The Hermes Desktop page's Windows contract (C11): syntax and explicit-metadata selection.

``plugin.js`` runs only inside Hermes Desktop, so this checks what can be
checked without it: the module parses (``node --input-type=module --check``
when Node is installed), the page asks for ``client_version=3``, the Windows
branch is chosen by ``hardware_kind`` and every capability name, reason code
and step the Windows API can return has an explicit label. Readiness is never
derived from matching English text.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from importlib import resources

import pytest

from mordred_hermes.wizard import _windows_gates

PAGE = resources.files("mordred_hermes.desktop").joinpath("assets", "desktop", "plugin.js")
CAPABILITIES = (
    "memory_custody",
    "native_audit",
    "telegram_hardware",
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
    "secret_store",
)
DESKTOP_REASONS = ("gateways-unknown", "gateways-running", "gateways", "ceremony-refused", "lifecycle-partial")
STEPS = ("capabilities", "gate", "ceremony", "proof", "lifecycle")
CODES = (
    "storage_unavailable",
    "storage_uncertain",
    "storage_error",
    "telegram_not_enrolled",
    "presence_acknowledgement_required",
    "presence_unsupported",
    "custody_unsafe",
    "custody_uncertain",
    "custody_broken",
    "memory_encryption_refused",
    "memory_disable_refused",
    "memory_operation_in_progress",
)


def source() -> str:
    return PAGE.read_text(encoding="utf-8")


def block(name: str) -> str:
    match = re.search(rf"const {name} = \{{(.*?)\n\}}", source(), re.S)
    assert match, f"{name} table missing"
    return match.group(1)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_page_is_a_valid_es_module():
    completed = subprocess.run(
        ["node", "--input-type=module", "--check"],
        input=source(),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_page_requests_the_windows_capable_status_and_selects_by_hardware_kind():
    text = source()
    assert "/status?client_version=3" in text
    assert "hardware_kind === 'cng'" in text
    assert "acknowledge_cng_no_recovery: noRecovery, acknowledge_no_presence: noPresence" in text
    assert "acknowledge_no_presence: true" in text


def test_every_windows_label_comes_from_an_explicit_table():
    labels, reasons, steps, messages = (
        block("CAPABILITY_LABELS"),
        block("REASONS"),
        block("STEP_LABELS"),
        block("MESSAGES"),
    )
    for name in CAPABILITIES:
        assert re.search(rf"\b{name}:", labels), name
    every_reason = set(_windows_gates._REMEDIES) | set(_windows_gates._PROOF_REMEDIES) | set(DESKTOP_REASONS)
    for code in sorted(every_reason):
        assert f"'{code}':" in reasons or re.search(rf"\b{re.escape(code)}:", reasons), code
    for step in STEPS:
        assert re.search(rf"\b{step}:", steps), step
    for code in CODES:
        assert re.search(rf"\b{code}:", messages), code


def test_no_readiness_is_derived_from_english_text():
    text = source()
    assert ".test(String(" not in text, "error handling selects by code, not by matching the message"
    assert "/expired/" not in text
    assert "e.code === 'login_flow_expired'" in text


def test_logout_stays_reachable_and_forget_sends_the_typed_phrase():
    text = source()
    assert "status.telegram_supported && loggedIn ? jsx(WindowsLogout" in text, "logout does not depend on the gate"
    assert "confirm: phrase" in text
    assert re.search(r"\bforget_confirm_mismatch:", block("MESSAGES"))
    assert re.search(r"\bcustody_busy:", block("MESSAGES"))
