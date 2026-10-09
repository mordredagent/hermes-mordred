"""Hermes Desktop setup API on Windows (C11): status, helper state, CNG memory flow, Telegram gating.

Portable: ``api.sys`` says ``win32`` and the C5e/C6 seams say ``win32`` (the
wizard memory slice's ``win`` / ``seeded`` fixtures), so every memory transition
runs the real checked files, real MRKW/AES-GCM, real custody ceremony and a real
installed-runtime proof child from the proof slice's harness, with only the CNG
boundary, principal and platform admission injected. Each refusal asserts the
step it names and that memory files, markers and custody are unchanged. No test
contacts Telegram, binds a port or touches the real ``~/.hermes``; key bytes and
Telegram secrets never appear in an assertion operand.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.desktop import api
from mordred_hermes.extension.telegram import memory_guard
from mordred_hermes.extension.telegram import secrets as tg_secrets
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
from mordred_hermes.keyvault import _seckey_helper, _windows_capability
from mordred_hermes.keyvault._runtime_probe import GatewayRuntime
from mordred_hermes.wizard import keyvault_windows_cli
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_lifecycle import (
    MARKER,
    OPTOUT,
    ORIGINALS,
    Fault,
    assert_all_sealed,
    expected_hashes,
    files,
    fresh_process_read,
    markers,
    normalized,
    put,
)
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env
from tests.test_wizard_windows_memory import Inventory, generated, memory_lease, snapshot
from tests.test_wizard_windows_memory import seeded as seeded
from tests.test_wizard_windows_memory import win as win

ACKS = {"acknowledge_cng_no_recovery": True, "acknowledge_no_presence": True}
CAPABILITY_ORDER = [
    "memory_custody",
    "native_audit",
    "telegram_hardware",
    "file_vault",
    "env_config_workspace_seals",
    "recovery",
    "presence",
    "secret_store",
]
SECRET_HASH = "ab" * 16
SECRET_CODE = "24680"
SECRET_VENICE = "venice-WINDOWS-secret"


def desktop_windows():
    from mordred_hermes.desktop import _windows

    return _windows


def client() -> TestClient:
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/mordred")
    return TestClient(app)


def get(http: TestClient, path: str) -> dict[str, Any]:
    response = http.get(f"/api/plugins/mordred{path}")
    assert response.status_code == 200  # Desktop logs non-2xx; failures are ok:false bodies
    return response.json()


def post(http: TestClient, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    response = http.post(f"/api/plugins/mordred{path}", json=body if body is not None else {})
    assert response.status_code == 200
    return response.json()


class CustodyStore(WindowsCustodySecretStore):
    """The C10b store type (so it counts as selected) with recorded, file-free behavior."""

    def __init__(self, flags: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._flags = flags
        self.value: tg_secrets.TelegramSecrets | None = None
        self.ensure_calls: list[dict[str, Any]] = []
        self.updates = 0

    def flags(self) -> dict[str, Any] | None:
        return self._flags

    def ensure_key(self, *, require_presence: bool = True) -> None:
        self.ensure_calls.append({"require_presence": require_presence})
        if require_presence:
            raise tg_secrets.TelegramSecretsError("presence_unsupported")

    def load(self, *, fresh: bool = True) -> tg_secrets.TelegramSecrets | None:
        return self.value

    def load_snapshot(self) -> tuple[tg_secrets.TelegramSecrets | None, bytes | None]:
        return self.value, (b"token" if self.value is not None else None)

    def store(self, value: tg_secrets.TelegramSecrets) -> None:
        self.value = value

    def update(self, mutate: Any) -> Any:
        self.updates += 1
        self.value = mutate(self.value)
        return self.value

    def update_from_snapshot(self, snapshot: Any, mutate: Any) -> Any:
        return self.update(mutate)


@pytest.fixture
def windows_api(monkeypatch):
    """Route ``desktop.api`` to Windows; Telegram's own memory guard must never be consulted."""
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="win32", executable="C:/Hermes/python.exe"))
    monkeypatch.setattr(api, "_FLOWS", None)
    monkeypatch.setattr(api, "_SERVICE", None)

    def posix_guard(*args, **kwargs):
        pytest.fail("Windows must not use the POSIX memory_encryption_active guard")

    monkeypatch.setattr(memory_guard, "memory_encryption_active", posix_guard)

    async def model_ok() -> dict[str, Any]:
        return {"model": "local-model", "kind": "local", "private": True, "ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model_ok)
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)


@pytest.fixture
def desktop(win, windows_api, monkeypatch):
    """The real Windows memory flow on the proof harness, reached through the Desktop API."""
    monkeypatch.setattr(api, "_home", lambda: win.home)
    store = CustodyStore()
    monkeypatch.setattr(api, "_store", lambda: store)
    return SimpleNamespace(env=win, http=client(), store=store)


@pytest.fixture
def desktop_seeded(seeded, desktop):
    return desktop


def no_launches(env) -> None:
    assert env.launches.argv == [], "status must not launch a subprocess"


def no_native_unwrap(env) -> None:
    assert not [op for op, _ in env.backend.calls if op in ("ecdh", "generate", "delete")], env.backend.calls


# -----------------------------------------------------------------------------
# /status
# -----------------------------------------------------------------------------
@pytest.mark.parametrize("client_version", [1, 2])
def test_old_client_on_windows_keeps_the_unsupported_shape_without_side_effects(monkeypatch, client_version):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(api, "_JOBS", {})

    def unexpected(*args, **kwargs):
        pytest.fail("an older client must not reach capabilities, memory, credentials or a provider")

    monkeypatch.setattr(_windows_capability, "windows_capabilities", unexpected)
    monkeypatch.setattr(_windows_capability, "windows_capability", unexpected)
    monkeypatch.setattr(api, "hermes_model_check", unexpected)
    monkeypatch.setattr(api, "_store", unexpected)
    monkeypatch.setattr(api, "_hermes_venice_key", unexpected)
    monkeypatch.setattr("mordred_hermes.wizard._windows_memory.observe", unexpected)

    result = asyncio.run(api.status(client_version=client_version))

    assert result == {
        "ok": True,
        "platform": "win32",
        "telegram_supported": False,
        "telegram_platform_supported": False,
        "hardware_kind": None,
        "user_presence_supported": False,
        "checks": {},
        "jobs": [],
    }


def test_windows_status_lists_each_capability_without_an_aggregate(desktop):
    result = get(desktop.http, "/status?client_version=3")

    assert result["ok"] is True and result["platform"] == "win32"
    assert result["hardware_kind"] == "cng"
    assert result["user_presence_supported"] is False
    assert result["presence_reason"] == "excluded-on-windows"
    rows = result["capabilities"]
    assert [row["name"] for row in rows] == CAPABILITY_ORDER
    assert all(set(row) == {"name", "supported", "available", "reason"} for row in rows)
    by_name = {row["name"]: row for row in rows}
    assert by_name["memory_custody"] == {
        "name": "memory_custody",
        "supported": True,
        "available": False,
        "reason": "not-enrolled",
    }
    assert by_name["file_vault"]["reason"] == "excluded-on-windows"
    assert by_name["secret_store"]["reason"] == "not-ported-on-windows"
    assert result["capabilities_error"] is None
    # No aggregate readiness answer anywhere in the payload.
    flat = json.dumps(result)
    for aggregate in ('"ready"', '"windows_ready"', '"all_ready"', '"readiness"'):
        assert aggregate not in flat
    assert result["telegram_platform_supported"] is True, "C10b store selected and telegram_hardware supported"
    assert result["telegram_supported"] is True
    assert result["telegram_custody"] == {
        "enrolled": False,
        "reason": "not-enrolled",
        "ceremony_available": False,
        "ceremony_command": None,
    }
    assert result["acknowledgements"] == {
        "memory_enable": ["acknowledge_cng_no_recovery", "acknowledge_no_presence"],
        "telegram": ["acknowledge_no_presence"],
    }
    assert result["custody_notice"] == keyvault_windows_cli.CUSTODY_NOTICE
    assert result["memory"]["state"] == "off" and result["memory"]["active"] is False
    assert result["checks"]["memory_encryption"]["ok"] is False
    assert result["checks"]["telegram_custody"]["ok"] is False
    assert result["uninstall"] == {"erase_supported": False, "purge_scope": "memory_custody_key"}
    assert result["helper"]["install_command"] == "hermes-mordred keyvault enable-winkey"
    no_launches(desktop.env)
    no_native_unwrap(desktop.env)


def test_windows_status_requires_the_c10b_store_for_telegram_support(desktop, monkeypatch):
    from mordred_hermes.extension.telegram.tee import TeeSecretStore

    monkeypatch.setattr(api, "_store", lambda: TeeSecretStore())
    result = get(desktop.http, "/status?client_version=3")
    assert result["telegram_platform_supported"] is False and result["telegram_supported"] is False
    assert result["checks"] == {} or "login" not in result["checks"]
    assert [row["name"] for row in result["capabilities"]] == CAPABILITY_ORDER


def test_windows_status_reports_a_capability_failure_instead_of_raising(desktop, monkeypatch):
    def busy(home):
        raise PrivateFSError("busy", "canonical_lock")

    monkeypatch.setattr(_windows_capability, "windows_capabilities", busy)
    result = get(desktop.http, "/status?client_version=3")
    assert result["ok"] is True
    assert result["capabilities"] == [] and result["capabilities_error"] == "custody-uncertain"
    assert result["telegram_platform_supported"] is False and result["telegram_supported"] is False
    assert result["presence_reason"] == "excluded-on-windows"


def test_windows_status_follows_memory_and_telegram_state_load_only(desktop_seeded):
    desktop = desktop_seeded
    env = desktop.env
    assert post(desktop.http, "/memory/enable", ACKS)["ok"] is True
    env.launches.argv.clear()
    env.backend.calls.clear()
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        owner.enroll_role("telegram")  # stands in for the (absent) wizard Telegram ceremony
    env.backend.calls.clear()
    desktop.store._flags = {"logged_in": True, "llm_backend": "local", "llm_model": "m", "api_configured": True}

    result = get(desktop.http, "/status?client_version=3")

    assert result["memory"]["state"] == "on" and result["memory"]["active"] is True
    assert result["checks"]["memory_encryption"]["ok"] is True
    assert result["telegram_custody"]["enrolled"] is True
    assert result["checks"]["telegram_custody"]["ok"] is True
    assert result["checks"]["login"]["ok"] is True and result["checks"]["privacy_llm"]["ok"] is True
    assert result["telegram_api"] is True
    no_launches(env)
    no_native_unwrap(env)


# -----------------------------------------------------------------------------
# /hardware/build — the owned helper state, never a build
# -----------------------------------------------------------------------------
@pytest.mark.parametrize("state", ["missing", "installed", "validated", "uncertain"])
def test_windows_hardware_build_reports_the_helper_state_and_never_builds(windows_api, monkeypatch, tmp_path, state):
    from mordred_hermes.wizard import _windows_install, keyvault_native_cli

    home = tmp_path / "Hermes home ü"
    (home / "bin").mkdir(parents=True)
    monkeypatch.setattr(api, "_home", lambda: home)
    owned = home / "bin" / "mordred-hermes-winkey.exe"
    elsewhere = tmp_path / "PATH dir" / "mordred-hermes-winkey.exe"

    def find():
        if state == "uncertain":
            raise OSError("PATH could not be read")
        return {"missing": None, "installed": str(elsewhere), "validated": str(owned)}[state]

    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", find)
    monkeypatch.setattr(_windows_install, "is_owned", lambda path: Path(path) == owned)

    def build(*args, **kwargs):
        pytest.fail("the Desktop API must never build or install the helper")

    for name in ("enable_tpm", "enable_se", "enable_winkey", "cli_enable_winkey"):
        monkeypatch.setattr(keyvault_native_cli, name, build, raising=False)
    monkeypatch.setattr(api, "_start_job", build)

    result = post(client(), "/hardware/build", {})

    assert result["ok"] is True and result["built"] is False and result["hardware_kind"] == "cng"
    helper = result["helper"]
    assert helper["state"] == state
    assert helper["install_command"] == "hermes-mordred keyvault enable-winkey"
    expected_path = {"missing": None, "uncertain": None, "installed": str(elsewhere), "validated": str(owned)}
    assert helper["path"] == expected_path[state]


# -----------------------------------------------------------------------------
# /memory/enable — capabilities -> gate -> ceremony -> proof -> lifecycle
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"acknowledge_cng_no_recovery": True},
        {"acknowledge_no_presence": True},
        {"acknowledge_tpm_no_recovery": True, "acknowledge_no_presence": True},
        {"acknowledge_cng_no_recovery": "true", "acknowledge_no_presence": True},
    ],
)
def test_windows_memory_enable_requires_both_acknowledgements(desktop_seeded, monkeypatch, body):
    desktop = desktop_seeded

    def unexpected(*args, **kwargs):
        pytest.fail("an unacknowledged request must not reach custody")

    monkeypatch.setattr(_windows_capability, "windows_capability", unexpected)
    before = snapshot(desktop.env)
    response = desktop.http.post("/api/plugins/mordred/memory/enable", json=body)
    assert response.json() == {"ok": False, "error": "telegram_platform_unsupported"}
    assert snapshot(desktop.env) == before and generated(desktop.env) == 0


def test_windows_memory_enable_runs_the_c6_sequence_end_to_end(desktop_seeded):
    desktop = desktop_seeded
    env = desktop.env

    result = post(desktop.http, "/memory/enable", ACKS)

    assert result["ok"] is True and result["restart_required"] is True
    assert result["sealed"] == 3 and result["already_sealed"] == 0
    assert result["enrolled"]["created"] is True and result["enrolled"]["generation"]
    assert result["custody_notice"] == keyvault_windows_cli.CUSTODY_NOTICE
    assert result["runtime"]["python"] == str(env.python)
    assert_all_sealed(env)
    assert markers(env.home) == {MARKER}
    assert fresh_process_read(env) == expected_hashes()
    with env.custody.windows_custody_session(env.home, backend=env.backend) as owner:
        key = owner.load_memory_key()
        assert owner.role_status("audit").current is None, "Desktop memory enable never enrolls audit"
    assert key.hex() not in json.dumps(result)

    assert post(desktop.http, "/memory/enable", ACKS) == {"ok": True, "already": True}
    assert generated(env) == 1, "an enrolled key is reused, never re-created"


def test_windows_memory_enable_ignores_a_force_flag_and_still_gates(desktop_seeded, monkeypatch):
    desktop = desktop_seeded
    env = desktop.env
    Inventory(monkeypatch, state="known", running=(GatewayRuntime(4242, env.python),))
    before = snapshot(env)
    result = post(desktop.http, "/memory/enable", {**ACKS, "force_runtime_unverified": True, "force": True})
    assert result["ok"] is False and result["step"] == "gate" and result["reason"] == "gateways-running"
    assert snapshot(env) == before and generated(env) == 0


def _helper_missing(env, monkeypatch):
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: None)


def _inventory_unknown(env, monkeypatch):
    Inventory(monkeypatch, state="unknown")


def _gateway_running(env, monkeypatch):
    Inventory(monkeypatch, state="known", running=(GatewayRuntime(31337, env.python),))


def _native_creation_denied(env, monkeypatch):
    def denied(*args, **kwargs):
        raise env.custody.CustodyError("native creation failed")

    monkeypatch.setattr(env.backend, "generate_enclave_key", denied)


def _invalid_interpreter(env, monkeypatch):
    monkeypatch.setenv("MORDRED_HERMES_PYTHON", str(env.home.parent / "missing" / "python.exe"))


def _broken_seal_after_enrollment(env, monkeypatch):
    assert keyvault_windows_cli.native_init(home=env.home) == 0
    put(env.home, "memories", "BROKEN.md", b"HERMES-MEMORY-ENC-v1\nnot-a-seal")


@pytest.mark.parametrize(
    ("arrange", "step", "reason", "key_created"),
    [
        (_helper_missing, "capabilities", "helper-missing", False),
        (_inventory_unknown, "gate", "gateways-unknown", False),
        (_gateway_running, "gate", "gateways-running", False),
        (_native_creation_denied, "ceremony", "ceremony-refused", False),
        (_invalid_interpreter, "proof", "interpreter-invalid", True),
        (_broken_seal_after_enrollment, "lifecycle", None, False),
    ],
    ids=["capabilities", "gate-unknown", "gate-running", "ceremony", "proof", "lifecycle"],
)
def test_windows_memory_enable_reports_the_refusing_step_without_changes(
    desktop_seeded, monkeypatch, arrange, step, reason, key_created
):
    desktop = desktop_seeded
    env = desktop.env
    arrange(env, monkeypatch)
    before_files, before_markers = files(env.home), markers(env.home)

    result = post(desktop.http, "/memory/enable", ACKS)

    assert result["ok"] is False and result["error"] == "memory_encryption_refused"
    assert result["step"] == step
    if reason is not None:
        assert result["reason"] == reason
    assert isinstance(result.get("remedy"), str)
    assert files(env.home) == before_files and markers(env.home) == before_markers
    assert MARKER not in markers(env.home)
    if step == "gate":
        assert result["gateways"]["state"] in ("known", "unknown")
        if reason == "gateways-unknown":
            assert result["gateways"]["running"] is None, "unknown is never reported as none"
    if key_created:
        assert result["enrolled"]["created"] is True
        assert result["custody_notice"] == keyvault_windows_cli.CUSTODY_NOTICE
        assert memory_lease(env) is not None, "the inert key is kept for a retry"
    if step in ("capabilities", "gate"):
        assert generated(env) == 0


def test_windows_memory_enable_partial_lifecycle_failure_reports_counts(desktop_seeded, monkeypatch):
    desktop = desktop_seeded
    env = desktop.env
    with monkeypatch.context() as patch:
        fault = Fault(patch, "replace_bytes", "MEMORY.md.bak.1700000000", after=True)
        result = post(desktop.http, "/memory/enable", ACKS)
        assert fault.fired
    assert result["ok"] is False and result["step"] == "lifecycle" and result["reason"] == "lifecycle-partial"
    assert (result["completed"], result["remaining"], result["armed"]) == (1, 2, False)
    assert MARKER not in markers(env.home)
    rerun = post(desktop.http, "/memory/enable", ACKS)
    assert rerun["ok"] is True
    assert_all_sealed(env)


def test_windows_memory_disable_is_symmetric_and_keeps_the_key(desktop_seeded, monkeypatch):
    desktop = desktop_seeded
    env = desktop.env
    assert post(desktop.http, "/memory/disable", {}) == {"ok": True, "already": True}, "unmanaged: nothing to do"
    assert post(desktop.http, "/memory/enable", ACKS)["ok"] is True
    lease = memory_lease(env)

    with monkeypatch.context() as patch:
        Inventory(patch, state="known", running=(GatewayRuntime(7, env.python),))
        sealed = snapshot(env)
        refused = post(desktop.http, "/memory/disable", {"force_runtime_unverified": True})
        assert refused["ok"] is False and refused["error"] == "memory_disable_refused"
        assert (refused["step"], refused["reason"]) == ("gate", "gateways-running")
        assert snapshot(env) == sealed

    result = post(desktop.http, "/memory/disable", {})
    assert result["ok"] is True and result["decrypted"] == 3 and result["key_kept"] is True
    assert result["restart_required"] is True
    assert files(env.home) == {name: normalized(data).encode() for name, data in ORIGINALS.items()}
    assert markers(env.home) == {OPTOUT}
    assert memory_lease(env) == lease
    assert post(desktop.http, "/memory/disable", {}) == {"ok": True, "already": True}
    status = get(desktop.http, "/status?client_version=3")
    assert status["memory"]["state"] == "paused"


@pytest.mark.parametrize("state", ["unknown", "known-empty", "known-running"])
def test_windows_memory_status_reports_the_typed_gateway_inventory(desktop, monkeypatch, state):
    env = desktop.env
    if state == "unknown":
        Inventory(monkeypatch, state="unknown")
    elif state == "known-running":
        Inventory(monkeypatch, state="known", running=(GatewayRuntime(4040, env.python),))
    else:
        Inventory(monkeypatch)

    result = get(desktop.http, "/memory/status")

    assert result["ok"] is True and result["memory"]["state"] == "off"
    gateways = result["gateways"]
    if state == "unknown":
        assert gateways["state"] == "unknown" and gateways["running"] is None
        assert gateways["reasons"] == ["scan:inventory-unavailable"]
    elif state == "known-running":
        assert gateways == {"state": "known", "running": 1, "found": 1, "pids": [4040], "reasons": []}
    else:
        assert gateways == {"state": "known", "running": 0, "found": 0, "pids": [], "reasons": []}


def test_windows_gateway_inventory_failure_is_unknown_not_empty(windows_api, monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes

    def broken(home, **kwargs):
        raise OSError("process table unavailable")

    monkeypatch.setattr(_windows_processes, "inspect_windows_gateway_runtimes", broken)
    inventory = desktop_windows().gateway_inventory(tmp_path)
    assert inventory["state"] == "unknown" and inventory["running"] is None and inventory["reasons"]


def test_windows_memory_transitions_are_serialized(desktop_seeded):
    desktop = desktop_seeded
    lock = desktop_windows()._MEMORY_LOCK
    assert lock.acquire(blocking=False)
    try:
        result = post(desktop.http, "/memory/enable", ACKS)
    finally:
        lock.release()
    assert result == {"ok": False, "error": "memory_operation_in_progress"}
    assert generated(desktop.env) == 0


def test_desktop_proof_routing_prefers_the_desktop_interpreter(monkeypatch):
    from mordred_hermes.keyvault._windows_proof import WindowsRuntimeProofError

    routing = desktop_windows().desktop_proof_python
    monkeypatch.setenv("MORDRED_HERMES_PYTHON", "C:/override/python.exe")
    assert routing("C:/Desktop/runtime/pythonw.exe") is None, "the explicit override stays authoritative"
    monkeypatch.delenv("MORDRED_HERMES_PYTHON")
    assert routing("C:/Desktop/runtime/pythonw.exe") == Path("C:/Desktop/runtime/pythonw.exe")
    with pytest.raises(WindowsRuntimeProofError, match=r"\(interpreter-invalid\)"):
        routing("")


def test_windows_memory_off_windows_endpoints_refuse(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    http = client()
    assert post(http, "/memory/disable", {}) == {"ok": False, "error": "telegram_platform_unsupported"}
    assert get(http, "/memory/status") == {"ok": False, "error": "telegram_platform_unsupported"}
    assert post(http, "/telegram/logout", {}) == {"ok": False, "error": "telegram_platform_unsupported"}


# -----------------------------------------------------------------------------
# Telegram on Windows: C10b store, enrolled role, no-presence acknowledgement
# -----------------------------------------------------------------------------
@dataclass
class _Capability:
    name: str
    supported: bool
    available: bool
    reason: str


class _Client:
    def __init__(self) -> None:
        self.session = "WINDOWS-SESSION"
        self.logged_out = False
        self.disconnected = False

    async def connect(self) -> None:
        return None

    async def send_code_request(self, phone: str) -> None:
        return None

    async def sign_in(self, **kwargs: Any) -> Any:
        if kwargs.get("code") != SECRET_CODE:
            raise type("PhoneCodeInvalidError", (Exception,), {})()
        return object()

    async def is_user_authorized(self) -> bool:
        return True

    async def log_out(self) -> None:
        self.logged_out = True

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.fixture
def telegram(windows_api, monkeypatch, tmp_path):
    from mordred_hermes.extension.telegram.login_flow import LoginFlows

    state = {"telegram": "enrolled", "memory_active": True}
    real_capability = _windows_capability.windows_capability

    def capability(home, name):
        if name == "telegram_hardware":
            reason = state["telegram"]
            return _Capability(name, True, reason == "enrolled", reason)
        return real_capability(home, name)

    monkeypatch.setattr(_windows_capability, "windows_capability", capability)
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    store = CustodyStore()
    monkeypatch.setattr(api, "_store", lambda: store)
    monkeypatch.setattr(
        desktop_windows(),
        "memory_summary",
        lambda home: {"state": "on" if state["memory_active"] else "off", "active": state["memory_active"]},
    )
    tg = _Client()
    original_flows = LoginFlows

    def flows(store_arg: Any) -> Any:
        return original_flows(store_arg, client_factory=lambda *a, **k: tg, save_session=lambda c: c.session)

    monkeypatch.setattr("mordred_hermes.extension.telegram.login_flow.LoginFlows", flows)
    monkeypatch.setattr(desktop_windows(), "_client_factory", lambda: lambda *a, **k: tg)
    return SimpleNamespace(http=client(), store=store, state=state, client=tg, home=tmp_path)


LOGIN = {"phone": "+81 90 0000 0000", "api_id": "12345", "api_hash": SECRET_HASH}


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        ("not-enrolled", "telegram_not_enrolled"),
        ("custody-broken", "custody_broken"),
        ("custody-unsafe", "custody_unsafe"),
        ("custody-uncertain", "custody_uncertain"),
        ("helper-missing", "tee_unavailable"),
    ],
)
def test_windows_login_refuses_until_the_telegram_role_is_enrolled(telegram, reason, code):
    telegram.state["telegram"] = reason
    result = post(telegram.http, "/telegram/login/start", {**LOGIN, "acknowledge_no_presence": True})
    assert result["ok"] is False and result["error"] == code
    if code == "telegram_not_enrolled":
        assert result["ceremony_available"] is False and result["ceremony_command"] is None
    assert telegram.store.ensure_calls == [] and telegram.store.value is None


def test_windows_login_requires_the_no_presence_acknowledgement(telegram):
    refused = post(telegram.http, "/telegram/login/start", LOGIN)
    assert refused == {"ok": False, "error": "presence_acknowledgement_required"}
    assert telegram.store.ensure_calls == []

    started = post(telegram.http, "/telegram/login/start", {**LOGIN, "acknowledge_no_presence": True})
    assert started["ok"] is True and started["step"] == "code"
    assert telegram.store.ensure_calls == [{"require_presence": False}]
    done = post(telegram.http, f"/telegram/login/{started['flow_id']}/code", {"code": SECRET_CODE})
    assert done == {"ok": True, "step": "done"}
    assert telegram.store.value is not None and telegram.store.value.session == "WINDOWS-SESSION"
    for secret in (SECRET_HASH, SECRET_CODE, "WINDOWS-SESSION"):
        assert secret not in json.dumps([started, done])


def test_windows_login_requires_windows_memory_encryption(telegram):
    telegram.state["memory_active"] = False
    result = post(telegram.http, "/telegram/login/start", {**LOGIN, "acknowledge_no_presence": True})
    assert result == {"ok": False, "error": "memory_encryption_required"}
    assert telegram.store.ensure_calls == []


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/llm/venice", {"api_key": SECRET_VENICE}),
        ("/llm/local", {"endpoint": "http://127.0.0.1:11434/v1", "model": "qwen3"}),
    ],
)
def test_windows_question_model_needs_the_role_and_the_acknowledgement(telegram, path, body):
    assert post(telegram.http, path, body) == {"ok": False, "error": "presence_acknowledgement_required"}
    telegram.state["telegram"] = "not-enrolled"
    assert post(telegram.http, path, {**body, "acknowledge_no_presence": True})["error"] == "telegram_not_enrolled"
    assert telegram.store.ensure_calls == [] and telegram.store.value is None
    telegram.state["telegram"] = "enrolled"
    result = post(telegram.http, path, {**body, "acknowledge_no_presence": True})
    assert result["ok"] is True
    assert telegram.store.ensure_calls == [{"require_presence": False}]
    assert telegram.store.value is not None and telegram.store.value.backend in ("venice", "local")
    assert SECRET_VENICE not in json.dumps(result)


def test_windows_api_store_is_the_c10b_custody_store(monkeypatch):
    from mordred_hermes.extension.telegram import store as tg_store

    monkeypatch.setattr(tg_store, "_platform", lambda: "win32")
    assert isinstance(api._store(), WindowsCustodySecretStore)
    monkeypatch.setattr(tg_store, "_platform", lambda: "darwin")
    from mordred_hermes.extension.telegram.tee import TeeSecretStore

    assert isinstance(api._store(), TeeSecretStore), "macOS/Linux keep the Enclave/TPM store"


def test_windows_import_service_uses_the_load_only_memory_guard(telegram, monkeypatch):
    captured: dict[str, Any] = {}

    class _Service:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("mordred_hermes.extension.telegram.service.TelegramService", _Service)
    api._service()
    guard = captured["memory_guard"]
    telegram.state["memory_active"] = True
    guard()
    telegram.state["memory_active"] = False
    with pytest.raises(memory_guard.MemoryEncryptionRequired):
        guard()


def test_windows_logout_keeps_the_archive_and_drops_only_the_session(telegram, monkeypatch):
    from mordred_hermes.extension.telegram import store as tg_store

    wiped: list[dict[str, Any]] = []
    monkeypatch.setattr(tg_store, "wipe_archive", lambda *a, **k: wiped.append(k))
    telegram.store.value = tg_secrets.TelegramSecrets(
        api_id=1, api_hash=SECRET_HASH, store_key=b"k" * 32, session="WINDOWS-SESSION"
    )
    result = post(telegram.http, "/telegram/logout", {})
    assert result == {"ok": True, "forgot": False, "revoked": True}
    assert telegram.client.logged_out and telegram.client.disconnected
    assert telegram.store.value is not None and telegram.store.value.session is None
    assert telegram.store.value.api_hash == SECRET_HASH, "logout keeps the API credentials"
    assert wiped == []


def test_windows_forget_runs_the_custody_wipe_and_no_delete_key(telegram, monkeypatch):
    from mordred_hermes.extension.telegram import store as tg_store

    wiped: list[dict[str, Any]] = []
    monkeypatch.setattr(tg_store, "wipe_archive", lambda *a, **k: wiped.append(k))
    telegram.store.value = tg_secrets.TelegramSecrets(
        api_id=1, api_hash=SECRET_HASH, store_key=b"k" * 32, session="WINDOWS-SESSION"
    )
    assert not hasattr(telegram.store, "delete_key")
    result = post(telegram.http, "/telegram/logout", {"forget": True})
    assert result == {"ok": True, "forgot": True, "revoked": True}
    assert wiped == [{"forget": True}]
    assert telegram.store.updates == 0, "forget deletes through the validated wipe plan, not a rewrite"


def test_windows_forget_reports_a_classified_wipe_refusal(telegram, monkeypatch):
    from mordred_hermes.extension.telegram import store as tg_store

    def busy(*args, **kwargs):
        raise tg_store.StoreError("sync_in_progress")

    monkeypatch.setattr(tg_store, "wipe_archive", busy)
    result = post(telegram.http, "/telegram/logout", {"forget": True})
    assert result["ok"] is False and result["error"] == "sync_in_progress"


def test_windows_logout_refuses_when_credentials_cannot_be_read(telegram, monkeypatch):
    from mordred_hermes.extension.telegram import store as tg_store

    def unreadable() -> Any:
        raise tg_secrets.TelegramSecretsError("custody_broken")

    monkeypatch.setattr(telegram.store, "load_snapshot", unreadable)
    monkeypatch.setattr(tg_store, "wipe_archive", lambda *a, **k: pytest.fail("nothing is deleted after a refusal"))
    assert post(telegram.http, "/telegram/logout", {"forget": True}) == {"ok": False, "error": "custody_broken"}


# -----------------------------------------------------------------------------
# Unchanged elsewhere
# -----------------------------------------------------------------------------
def test_windows_routes_are_never_taken_on_macos_or_linux(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("macOS/Linux must not reach the Windows Desktop module")

    for name in ("status_payload", "helper_report", "enable_memory", "telegram_refusal"):
        monkeypatch.setattr(desktop_windows(), name, unexpected)
    for platform in ("darwin", "linux"):
        monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))
        monkeypatch.setattr("mordred_hermes.wizard.telegram_setup_cli.run_checks", lambda: [])

        async def model() -> dict[str, Any]:
            return {"ok": False}

        monkeypatch.setattr(api, "hermes_model_check", model)
        monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {}))
        monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)
        result = asyncio.run(api.status(client_version=3))
        assert result["hardware_kind"] == {"darwin": "secure_enclave", "linux": "tpm"}[platform]
        assert "capabilities" not in result


def test_status_payload_never_spawns_processes(desktop, monkeypatch):
    def spawn(*args, **kwargs):
        pytest.fail("status must not launch a subprocess")

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(subprocess, "run", spawn)
    result = get(desktop.http, "/status?client_version=3")
    assert result["ok"] is True and result["hardware_kind"] == "cng"
    no_native_unwrap(desktop.env)
