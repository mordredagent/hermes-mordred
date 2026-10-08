"""Windows process discovery refuses uncertainty without leaking process secrets."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import get_args

import psutil
import pytest

import mordred_hermes._private_fs as fs
from mordred_hermes._private_fs import FileIdentity, FileMetadata, PrivateFSError
from mordred_hermes._private_fs._types import Reason
from mordred_hermes.keyvault import _runtime_probe as runtime


class Process:
    def __init__(self, pid=42, *, owner="HOST\\alice", name="python.exe", argv=None, denied=None, gone=False, born=1.0):
        self.pid, self.owner, self.image = pid, owner, name
        self.argv = (
            argv if argv is not None else [r"C:\日本 space\python.exe", "-m", "hermes_cli.main", "gateway", "run"]
        )
        self.denied, self.gone, self.born = denied, gone, born

    def value(self, field, value):
        if self.gone:
            raise psutil.NoSuchProcess(self.pid)
        if field == self.denied:
            raise psutil.AccessDenied(self.pid, name="TOP_SECRET")
        return value

    def username(self):
        return self.value("owner", self.owner)

    def name(self):
        return self.value("name", self.image)

    def exe(self):
        return self.value("exe", self.argv[0])

    def cmdline(self):
        return self.value("argv", self.argv)

    def create_time(self):
        return self.value("born", self.born)


def never_inspected(path):
    raise AssertionError("this record must never reach managed image inspection")


class Managed:
    """Injected managed-image capability: records every submitted image path."""

    def __init__(self, outcome=None):
        self.outcome, self.calls = outcome, []

    def __call__(self, path):
        self.calls.append(path)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            return self.outcome(path)
        return FileMetadata(FileIdentity(7, b"image"), 1, 0)


def scan(monkeypatch, tmp_path, processes, *, replacement=None, hints=(), managed=never_inspected):
    from mordred_hermes.keyvault import _windows_processes as win

    current = Process(os.getpid(), argv=["python.exe", "-m", "pytest"])
    table = {p.pid: p for p in processes}
    monkeypatch.setattr(psutil, "pids", lambda: list(table))
    monkeypatch.setattr(
        psutil, "Process", lambda pid=None: current if pid in (None, os.getpid()) else (replacement or table[pid])
    )
    monkeypatch.setattr(win, "_read_state_pid", lambda home: None)
    monkeypatch.setattr(win, "_gateway_python", lambda exe: Path(exe))
    # The module-level seam replaces only the shared capability, never its policy.
    monkeypatch.setattr(win, "inspect_managed_installation_image", managed)
    return win.inspect_windows_gateway_runtimes(tmp_path, hinted_pids=hints)


def test_windows_inventory_contract_exists():
    assert hasattr(runtime, "require_stopped_windows_gateways")


def test_live_unicode_argv_is_gateway_without_shell_parsing(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process()])
    assert found.state == "known"
    assert [(p.pid, str(p.python)) for p in found.runtimes] == [(42, r"C:\日本 space\python.exe")]


@pytest.mark.parametrize("field", ["owner", "name", "exe", "argv", "born"])
def test_denied_plausible_process_is_unknown_and_secret_free(monkeypatch, tmp_path, field):
    found = scan(monkeypatch, tmp_path, [Process(denied=field)])
    assert found.state == "unknown"
    assert found.reasons and "42" in str(found.reasons)
    assert "TOP_SECRET" not in str(found)


def test_foreign_process_is_excluded_only_with_positive_owner(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(owner="HOST\\bob", denied="argv")])
    assert found.state == "known" and found.runtimes == ()


def test_protected_system_process_does_not_hide_inventory(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(4, name="System", denied="owner")])
    assert found.state == "known" and not found.runtimes


def test_exited_process_is_not_access_denial(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(gone=True)])
    assert found.state == "known" and not found.runtimes


def test_current_user_non_gateway_does_not_block(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(argv=["python.exe", "-m", "pytest"])])
    assert found.state == "known" and not found.runtimes


def test_pid_reuse_refuses(monkeypatch, tmp_path):
    original = Process()
    calls = 0

    def born():
        nonlocal calls
        calls += 1
        return float(calls)

    original.create_time = born
    found = scan(monkeypatch, tmp_path, [original])
    assert found.state == "unknown" and not found.runtimes


def test_hint_for_unrecognized_current_user_process_refuses(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(argv=["custom.exe", "serve"])], hints=(42,))
    assert found.state == "unknown"


def test_diagnostics_are_bounded(monkeypatch, tmp_path):
    found = scan(monkeypatch, tmp_path, [Process(pid, denied="argv") for pid in range(100, 300)])
    assert found.state == "unknown"
    assert len(found.reasons) <= 33 and len(str(found.reasons)) < 2048


@pytest.mark.parametrize(
    "state, runtimes", [("unknown", ()), ("known", (runtime.GatewayRuntime(42, Path("python.exe")),))]
)
def test_lifecycle_gate_refuses_unknown_or_running(monkeypatch, tmp_path, state, runtimes):
    from mordred_hermes.keyvault import _windows_processes as win

    monkeypatch.setattr(
        win, "inspect_windows_gateway_runtimes", lambda home: win.GatewayInventory(state, runtimes, ("pid=42:denied",))
    )
    with pytest.raises(runtime.GatewayDiscoveryUnavailable):
        runtime.require_stopped_windows_gateways(tmp_path)


def test_list_api_does_not_translate_unknown_to_empty(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(
        win, "inspect_windows_gateway_runtimes", lambda home: win.GatewayInventory("unknown", (), ("scan:denied",))
    )
    with pytest.raises(runtime.GatewayDiscoveryUnavailable):
        runtime.discover_running_gateway_runtimes(tmp_path)


def test_python_flags_cannot_hide_gateway(monkeypatch, tmp_path):
    p = Process(argv=["python.exe", "-X", "utf8", "-u", "-m", "hermes_cli.main", "gateway", "run"])
    assert scan(monkeypatch, tmp_path, [p]).runtimes


def test_unknown_state_file_does_not_mean_no_gateway(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def unreadable(home):
        raise OSError("TOP_SECRET")

    monkeypatch.setattr(win, "_read_state_pid", unreadable)
    found = win.inspect_windows_gateway_runtimes(tmp_path)
    assert found.state == "unknown" and "TOP_SECRET" not in str(found)


def test_unverified_interpreter_is_unknown(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [Process()])
    monkeypatch.setattr(win, "_gateway_python", lambda *args: None)
    assert win.inspect_windows_gateway_runtimes(tmp_path).state == "unknown"


def test_invalid_authoritative_windows_python_never_falls_back(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    fake = tmp_path / "python.exe"
    fake.write_bytes(b"not a Python environment")
    assert runtime.discover_runtime_python(tmp_path, explicit=fake) is None
    monkeypatch.setenv(runtime.RUNTIME_PYTHON_ENV, str(fake))
    assert runtime.discover_runtime_python(tmp_path) is None


def test_windows_valid_override_uses_shared_validation(monkeypatch, tmp_path):
    import json
    import subprocess

    root = tmp_path / "custom 日本"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    exe = scripts / "python.exe"
    exe.touch()
    (root / "pyvenv.cfg").touch()
    monkeypatch.setattr(runtime.sys, "platform", "win32")

    def run(argv, **kwargs):
        assert argv[0] == str(exe)
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(dict(executable=str(exe), prefix=str(root), hermes=True, environment=True)), ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert runtime.discover_runtime_python(tmp_path, explicit=exe) == exe


@pytest.mark.skipif(os.name != "nt", reason="ordinary-user Windows process acceptance")
def test_native_gateway_child_is_discovered_without_cim(tmp_path):
    import subprocess
    import sys

    from mordred_hermes.keyvault import _windows_processes as win

    # The child only sleeps: its argv models a gateway without starting one.
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "hermes_cli.main", "gateway", "run"])
    try:
        inventory = win.inspect_windows_gateway_runtimes(tmp_path)
        assert child.pid in [p.pid for p in inventory.runtimes], inventory
        with pytest.raises(runtime.GatewayDiscoveryUnavailable):
            runtime.require_stopped_windows_gateways(tmp_path)
    finally:
        child.terminate()
        child.wait(timeout=10)
    stopped = win.inspect_windows_gateway_runtimes(tmp_path)
    assert stopped.state == "known" and not stopped.runtimes, stopped
    runtime.require_stopped_windows_gateways(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="ordinary-user Windows process acceptance")
def test_native_managed_image_submissions_are_recorded(tmp_path, monkeypatch, record_property, capsys):
    """Record which denied images reached the real capability and its results.

    Only sanitized image basenames and classified refusal codes are emitted,
    one ``gateway-inventory-image`` line per distinct outcome, for comparison
    with the controller's managed-image API probe log.
    """
    import json
    import ntpath
    import time
    from collections import Counter

    from mordred_hermes.keyvault import _windows_processes as win

    real = win.inspect_managed_installation_image
    outcomes: Counter[tuple[str, str]] = Counter()

    def recording(path):
        image = ntpath.basename(os.fspath(path))
        try:
            result = real(path)
        except PrivateFSError as exc:
            outcomes[(image, f"refused:{exc.reason}:{exc.operation}")] += 1
            raise
        except (OSError, ValueError) as exc:
            outcomes[(image, f"error:{type(exc).__name__}")] += 1
            raise
        outcomes[(image, "admitted")] += 1
        return result

    monkeypatch.setattr(win, "inspect_managed_installation_image", recording)
    started = time.monotonic()
    inventory = win.inspect_windows_gateway_runtimes(tmp_path)
    elapsed = round(time.monotonic() - started, 3)
    lines = [
        json.dumps({"image": image, "result": result, "count": count}, sort_keys=True)
        for (image, result), count in sorted(outcomes.items())
    ]
    summary = json.dumps(
        {"elapsed_seconds": elapsed, "state": inventory.state, "reasons": list(inventory.reasons)}, sort_keys=True
    )
    record_property("gateway_inventory_images", "\n".join(lines))
    record_property("gateway_inventory_summary", summary)
    with capsys.disabled():
        for line in lines:
            print("gateway-inventory-image " + line, flush=True)
        print("gateway-inventory-summary " + summary, flush=True)
    # Plausible interpreters, Hermes/Desktop images and generic hosts never reach admission.
    assert not [image for image, _ in outcomes if win._PLAUSIBLE.matches(image)]
    if any(result != "admitted" for _, result in outcomes):
        assert inventory.state == "unknown"
        assert any(reason.endswith(":image-unverified") for reason in inventory.reasons)


def test_explicit_probe_python_is_validated_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime.sys, "platform", "win32")
    bogus = tmp_path / "python.exe"
    bogus.touch()
    selected, reason = runtime._resolve_runtime_python(tmp_path, bogus)
    assert selected is None and reason


@pytest.mark.parametrize("payload", [b'{"pid": true}', b'{"pid": 0}', b'{"pid": "42"}', b"not JSON"])
def test_malformed_state_pid_refuses(monkeypatch, tmp_path, payload):
    from contextlib import contextmanager

    from mordred_hermes.keyvault import _windows_processes as win

    class Directory:
        def read_bytes(self, name, *, max_bytes):
            assert name == "gateway_state.json" and max_bytes <= 65536
            return payload

    @contextmanager
    def opened(path):
        yield Directory()

    monkeypatch.setattr(win, "open_optional_confidential_directory", opened)
    with pytest.raises(ValueError):
        win._read_state_pid(tmp_path)


def test_state_argv_cannot_select_interpreter(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from mordred_hermes.keyvault import _windows_processes as win

    class Directory:
        def read_bytes(self, name, *, max_bytes):
            return b'{"pid": 42, "argv": ["secret-bogus-python", "gateway", "run"]}'

    @contextmanager
    def opened(path):
        yield Directory()

    monkeypatch.setattr(win, "open_optional_confidential_directory", opened)
    assert win._read_state_pid(tmp_path) == 42


def test_enumeration_denied_refuses(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def denied():
        raise psutil.AccessDenied(name="SECRET")

    monkeypatch.setattr(psutil, "pids", denied)
    inventory = win.inspect_windows_gateway_runtimes(tmp_path)
    assert inventory.state == "unknown" and "SECRET" not in str(inventory)


def test_inventory_never_executes_gateway_interpreter(monkeypatch, tmp_path):
    import subprocess

    from mordred_hermes.keyvault import _windows_processes as win

    root = tmp_path / "gateway env"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    exe = scripts / "python.exe"
    exe.touch()
    (root / "pyvenv.cfg").touch()

    def no_exec(*args, **kwargs):
        raise AssertionError("Inventory cannot launch bootstrap while custody locks may be held")

    monkeypatch.setattr(subprocess, "run", no_exec)
    assert win._gateway_python(str(exe)) == exe


def test_deeply_nested_state_is_typed_unknown(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _windows_processes as win

    scan(monkeypatch, tmp_path, [])

    def excessive_nesting(home):
        raise RecursionError("untrusted state payload")

    monkeypatch.setattr(win, "_read_state_pid", excessive_nesting)
    assert win.inspect_windows_gateway_runtimes(tmp_path).state == "unknown"


def test_custom_python_launcher_cannot_hide_gateway(monkeypatch, tmp_path):
    process = Process(argv=["python.exe", r"C:\日本\custom-launcher.py", "gateway", "run"])
    assert scan(monkeypatch, tmp_path, [process]).runtimes


SYSTEM32 = "C:\\Windows\\System32\\"


def denied(name, image, pid=42):
    return Process(pid, name=name, argv=[image], denied="owner")


def test_fixed_os_image_list_and_system_directory_lookup_are_removed():
    import inspect

    from mordred_hermes.keyvault import _windows_processes as win

    for removed in ("_PROTECTED_OS_IMAGES", "_system_directory", "_protected_os_image"):
        assert not hasattr(win, removed), removed
    assert "GetSystemDirectoryW" not in inspect.getsource(win)
    assert win.inspect_managed_installation_image is fs.inspect_managed_installation_image


def test_system32_image_is_classified_by_managed_capability_not_by_name(monkeypatch, tmp_path):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied("svchost.exe", SYSTEM32 + "svchost.exe")], managed=managed)
    assert found.state == "known" and not found.runtimes
    assert managed.calls == [SYSTEM32 + "svchost.exe"]


def test_system32_basename_refused_by_capability_remains_unknown(monkeypatch, tmp_path):
    managed = Managed(PrivateFSError("unsafe", "managed_image_acl"))
    found = scan(monkeypatch, tmp_path, [denied("svchost.exe", SYSTEM32 + "svchost.exe")], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-unverified",)
    assert managed.calls == [SYSTEM32 + "svchost.exe"]


@pytest.mark.parametrize(
    "name, image",
    [
        ("python3.13.exe", "C:\\Program Files\\Python313\\python3.13.exe"),
        ("python.exe", SYSTEM32 + "python.exe"),
        ("pythonw.exe", "C:\\Program Files\\Python313\\pythonw.exe"),
        ("Python3.12.EXE", "C:\\Program Files\\Python312\\Python3.12.EXE"),
        ("py.exe", "C:\\Windows\\py.exe"),
        ("pyw.exe", "C:\\Windows\\pyw.exe"),
        ("hermes.exe", SYSTEM32 + "hermes.exe"),
        ("Hermes Desktop.exe", "C:\\Program Files\\Hermes\\Hermes Desktop.exe"),
        ("mordred-hermes-winkey.exe", "C:\\Program Files\\Mordred\\mordred-hermes-winkey.exe"),
        ("cmd.exe", SYSTEM32 + "cmd.exe"),
        ("powershell.exe", SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"),
        ("powershell_ise.exe", SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell_ise.exe"),
        ("pwsh.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
        ("rundll32.exe", SYSTEM32 + "rundll32.exe"),
        ("mshta.exe", SYSTEM32 + "mshta.exe"),
        ("wscript.exe", SYSTEM32 + "wscript.exe"),
        ("cscript.exe", SYSTEM32 + "cscript.exe"),
        # Either the reported name or the image basename makes a record plausible.
        ("svchost.exe", SYSTEM32 + "pythonw.exe"),
        ("python.exe", SYSTEM32 + "svchost.exe"),
    ],
)
def test_denied_plausible_basename_is_unknown_even_when_capability_would_admit(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:owner-denied-plausible",)
    assert managed.calls == []


@pytest.mark.parametrize(
    "name, image",
    [
        ("cmd.com", SYSTEM32 + "cmd.com"),
        ("CMD", SYSTEM32 + "CMD"),
        ("pwsh.scr", "C:\\Program Files\\PowerShell\\7\\pwsh.scr"),
        ("py.cmd", "C:\\Windows\\py.cmd"),
        ("pyw.bat", "C:\\Windows\\pyw.bat"),
        ("PowerShell_ISE.pif", SYSTEM32 + "PowerShell_ISE.pif"),
        ("powershell.com", SYSTEM32 + "powershell.com"),
        ("rundll32.scr", SYSTEM32 + "rundll32.scr"),
        ("mshta.hta", SYSTEM32 + "mshta.hta"),
        ("wscript.com", SYSTEM32 + "wscript.com"),
        ("cscript.bat", SYSTEM32 + "cscript.bat"),
    ],
)
def test_generic_host_or_launcher_stem_under_any_extension_is_plausible(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:owner-denied-plausible",)
    assert managed.calls == []


@pytest.mark.parametrize(
    "name, image",
    [
        ("cmdkey.exe", SYSTEM32 + "cmdkey.exe"),
        ("pyramid.exe", "C:\\Program Files\\Vendor\\pyramid.exe"),
        ("wscript2.exe", SYSTEM32 + "wscript2.exe"),
        ("cmd.exe.bak", SYSTEM32 + "cmd.exe.bak"),
    ],
)
def test_host_stem_rule_is_exact_not_a_prefix(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "known" and managed.calls == [image]


@pytest.mark.parametrize(
    "name, image",
    [
        ("svchost.exe", SYSTEM32 + "LogonUI.exe"),
        ("agent.exe", "C:\\Program Files\\Vendor\\agent-real.exe"),
        ("", SYSTEM32 + "svchost.exe"),
        ("svchost.exe", ""),
        ("svchost.exe", SYSTEM32),
    ],
    ids=["other-image", "renamed", "empty-name", "empty-image", "directory-only"],
)
def test_denied_image_must_match_its_reported_name_before_admission(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-name-mismatch",)
    assert managed.calls == []


def test_reported_name_matches_image_basename_case_insensitively(monkeypatch, tmp_path):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied("SVCHOST.EXE", SYSTEM32 + "svchost.exe")], managed=managed)
    assert found.state == "known" and managed.calls == [SYSTEM32 + "svchost.exe"]


@pytest.mark.parametrize(
    "name, image",
    [
        ("svchost.exe", SYSTEM32 + "svchost.exe"),
        ("LogonUI.exe", SYSTEM32 + "LogonUI.exe"),
        ("csrss.exe", SYSTEM32 + "csrss.exe"),
        ("conhost.exe", SYSTEM32 + "conhost.exe"),
        ("sshd.exe", SYSTEM32 + "OpenSSH\\sshd.exe"),
        ("MicrosoftEdgeUpdate.exe", "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"),
        ("amazon-ssm-agent.exe", "C:\\Program Files\\Amazon\\SSM\\amazon-ssm-agent.exe"),
        (
            "MsMpEng.exe",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\MsMpEng.exe",
        ),
        ("サービス.exe", "C:\\Program Files\\日本 space\\サービス.exe"),
    ],
)
def test_denied_noncandidate_image_admitted_by_capability_is_outside_supported_set(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "known" and not found.runtimes and not found.reasons
    assert managed.calls == [image]


@pytest.mark.parametrize("name", ["Registry", "MemCompression"])
def test_literal_kernel_pseudo_image_is_outside_supported_set_without_capability(monkeypatch, tmp_path, name):
    found = scan(monkeypatch, tmp_path, [denied(name, name)])
    assert found.state == "known" and not found.runtimes


@pytest.mark.parametrize(
    "name, image",
    [
        ("svchost.exe", "C:\\Users\\alice\\svchost.exe"),
        ("Registry", "C:\\Users\\alice\\Registry"),
        ("Registry", "registry"),
        ("unknown.exe", SYSTEM32 + "unknown.exe"),
        ("svchost.exe", "C:\\Windows\\System32-other\\svchost.exe"),
    ],
)
def test_denied_unrecognized_image_refused_by_capability_remains_unknown(monkeypatch, tmp_path, name, image):
    managed = Managed(PrivateFSError("unsafe", "managed_image_acl"))
    found = scan(monkeypatch, tmp_path, [denied(name, image)], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-unverified",)
    assert managed.calls == [image]


@pytest.mark.parametrize("reason", get_args(Reason))
def test_every_capability_refusal_reason_keeps_record_unknown(monkeypatch, tmp_path, reason):
    managed = Managed(PrivateFSError(reason, "TOP_SECRET", native_code=5))
    found = scan(monkeypatch, tmp_path, [denied("agent.exe", "C:\\Program Files\\Vendor\\agent.exe")], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-unverified",)
    assert "TOP_SECRET" not in str(found)


@pytest.mark.parametrize(
    "error",
    [OSError("TOP_SECRET"), PermissionError("TOP_SECRET"), FileNotFoundError("TOP_SECRET"), ValueError("TOP_SECRET")],
    ids=["OSError", "PermissionError", "FileNotFoundError", "ValueError"],
)
def test_capability_query_failure_keeps_record_unknown(monkeypatch, tmp_path, error):
    managed = Managed(error)
    found = scan(monkeypatch, tmp_path, [denied("agent.exe", "C:\\Program Files\\Vendor\\agent.exe")], managed=managed)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-unverified",)
    assert "TOP_SECRET" not in str(found)


@pytest.mark.parametrize(
    "image",
    [
        "\\Device\\HarddiskVolume3\\Program Files\\Vendor\\agent.exe",
        "\\\\?\\C:\\Program Files\\Vendor\\agent.exe",
        "\\\\server\\share\\agent.exe",
        "\\Program Files\\Vendor\\agent.exe",
        "\\??\\C:\\Program Files\\Vendor\\agent.exe",
    ],
    ids=["nt-device", "verbatim", "unc", "rooted", "nt-object"],
)
def test_non_dos_image_path_is_refused_by_the_real_capability_and_unknown(monkeypatch, tmp_path, image):
    from mordred_hermes._private_fs import _windows_managed

    def no_native(*args, **kwargs):
        raise AssertionError("non-DOS image paths are refused before native use")

    # Exercise the real shared capability's Windows path parser on every host.
    monkeypatch.setattr(fs, "_platform", "nt")
    monkeypatch.setattr(_windows_managed, "get_api", no_native)
    found = scan(monkeypatch, tmp_path, [denied("agent.exe", image)], managed=fs.inspect_managed_installation_image)
    assert found.state == "unknown" and found.reasons == ("pid=42:image-unverified",)


@pytest.mark.parametrize(
    "name, image", [("svchost.exe", SYSTEM32 + "svchost.exe"), ("Registry", "Registry")], ids=["admitted", "kernel"]
)
@pytest.mark.parametrize("changed", ["born", "name", "exe"])
def test_excluded_image_identity_change_is_unknown(monkeypatch, tmp_path, changed, name, image):
    p = denied(name, image)
    calls = 0
    field = {"born": "create_time", "name": "name", "exe": "exe"}[changed]
    original = getattr(p, field)

    def read():
        nonlocal calls
        calls += 1
        if calls > 1:
            return 2.0 if changed == "born" else "different"
        return original()

    setattr(p, field, read)
    found = scan(monkeypatch, tmp_path, [p], managed=Managed())
    assert found.state == "unknown" and found.reasons == ("pid=42:process-changed",)


@pytest.mark.parametrize("field", ["create_time", "name", "exe"])
def test_admitted_image_denied_recheck_remains_unknown(monkeypatch, tmp_path, field):
    p = denied("svchost.exe", SYSTEM32 + "svchost.exe")
    calls = 0
    original = getattr(p, field)

    def read():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise psutil.AccessDenied(p.pid, name="TOP_SECRET")
        return original()

    setattr(p, field, read)
    found = scan(monkeypatch, tmp_path, [p], managed=Managed())
    assert found.state == "unknown" and found.reasons == ("pid=42:process-changed",)
    assert "TOP_SECRET" not in str(found)


def test_admitted_image_that_exits_before_recheck_is_absent(monkeypatch, tmp_path):
    p = denied("svchost.exe", SYSTEM32 + "svchost.exe")
    managed = Managed(lambda path: setattr(p, "gone", True) or FileMetadata(FileIdentity(7, b"image"), 1, 0))
    found = scan(monkeypatch, tmp_path, [p], managed=managed)
    assert found.state == "known" and not found.runtimes and managed.calls == [SYSTEM32 + "svchost.exe"]


@pytest.mark.parametrize(
    "name, image", [("svchost.exe", SYSTEM32 + "svchost.exe"), ("Registry", "Registry"), ("pwsh.exe", "pwsh.exe")]
)
def test_hinted_pid_never_reaches_managed_image_capability(monkeypatch, tmp_path, name, image):
    managed = Managed()
    found = scan(monkeypatch, tmp_path, [denied(name, image)], hints=(42,), managed=managed)
    assert found.state == "unknown" and managed.calls == []


@pytest.mark.parametrize(
    "process",
    [
        Process(name="svchost.exe", argv=[SYSTEM32 + "svchost.exe", "-k", "netsvcs"]),
        Process(name="agent.exe", argv=["C:\\Program Files\\Vendor\\agent.exe", "gateway", "run"]),
        Process(argv=["python.exe", "-m", "pytest"]),
        Process(owner="HOST\\bob", name="svchost.exe", argv=[SYSTEM32 + "svchost.exe"]),
    ],
    ids=["owned-system32", "owned-gateway-pair", "owned-python", "foreign"],
)
def test_positively_owned_process_never_reaches_managed_image_capability(monkeypatch, tmp_path, process):
    # The default seam raises if called: owned records keep the full argv scan.
    found = scan(monkeypatch, tmp_path, [process])
    assert found.state == "known"
    gateway = process.owner == "HOST\\alice" and "gateway" in process.argv
    assert [p.pid for p in found.runtimes] == ([42] if gateway else [])


def test_owned_gateway_with_ordinary_host_image_is_still_found(monkeypatch, tmp_path):
    process = Process(name="svchost.exe", argv=[SYSTEM32 + "svchost.exe", "gateway", "run"])
    assert [p.pid for p in scan(monkeypatch, tmp_path, [process]).runtimes] == [42]


@pytest.mark.parametrize("count", [1, 2])
def test_deadline_exhaustion_during_capability_calls_is_inventory_limit(monkeypatch, tmp_path, count):
    from mordred_hermes.keyvault import _windows_processes as win

    now = [100.0]
    monkeypatch.setattr(win, "time", SimpleNamespace(monotonic=lambda: now[0]))

    def slow(path):
        now[0] += 11.0
        return FileMetadata(FileIdentity(7, b"image"), 1, 0)

    managed = Managed(slow)
    processes = [denied("svchost.exe", SYSTEM32 + "svchost.exe", pid) for pid in range(100, 100 + count)]
    found = scan(monkeypatch, tmp_path, processes, managed=managed)
    assert found.state == "unknown" and any(r.endswith("inventory-limit") for r in found.reasons)
    # The admission returned after the deadline is not used, and no later PID is inspected.
    assert len(managed.calls) == 1


def test_capability_calls_count_toward_the_entry_bound(monkeypatch, tmp_path):
    managed = Managed()
    processes = [denied("svchost.exe", SYSTEM32 + "svchost.exe", pid) for pid in range(100, 100 + 4097)]
    found = scan(monkeypatch, tmp_path, processes, managed=managed)
    assert found.state == "unknown" and found.reasons == ("scan:inventory-limit",)
    assert len(managed.calls) == 4096


@pytest.mark.parametrize("image", ["D:\\Windows\\System32\\svchost.exe", SYSTEM32 + "svchost.exe"])
def test_environment_never_selects_or_admits_an_image(monkeypatch, tmp_path, image):
    monkeypatch.setenv("SYSTEMROOT", "C:\\Windows")
    monkeypatch.setenv("WINDIR", "C:\\Windows")
    managed = Managed(PrivateFSError("unsafe", "managed_image_acl"))
    found = scan(monkeypatch, tmp_path, [denied("svchost.exe", image)], managed=managed)
    # The capability receives psutil's reported image, never an environment root.
    assert found.state == "unknown" and managed.calls == [image]
