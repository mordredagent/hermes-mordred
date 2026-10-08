"""Windows decision consumers with the real coordinator on isolated files."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._config_io import POLICY_TRANSACTION_MARKER
from mordred_hermes.privacy_check import _runtime, egress, hooks
from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused
from tests.test_private_fs_confidential_windows import shared_home as shared_home


class Audit:
    def append(self, entry: dict[str, Any]) -> None:
        pass


@pytest.fixture
def profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    if os.name == "nt":
        tmp_path = request.getfixturevalue("shared_home")
    monkeypatch.setattr(_runtime, "_platform", "nt", raising=False)
    monkeypatch.setattr(egress, "_platform", "nt", raising=False)
    monkeypatch.setattr(_runtime, "DEFAULT_HERMES_CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(_runtime, "build_audit_writer", lambda *a, **kw: Audit())
    if os.name != "nt":
        from mordred_hermes._private_fs import open_private_directory

        @contextmanager
        def optional(path):
            if not path.exists():
                yield None
            else:
                with open_private_directory(path) as directory:
                    yield directory

        # The confidentiality adapter exists only on Windows; substitute the
        # stricter POSIX capability beneath the real coordinator on this host.
        monkeypatch.setattr(cio, "open_optional_confidential_directory", optional)
        monkeypatch.setattr(cio, "open_optional_private_directory", optional)
    _runtime.reset_state_for_tests()
    if os.name != "nt":
        (tmp_path / "mordred").mkdir(mode=0o700)
    write_pair(tmp_path)
    yield tmp_path
    _runtime.reset_state_for_tests()
    egress._cache.clear()


def write_pair(home: Path, *, mode: str = "off", level: str = "off") -> None:
    section = {"policy": mode, "tool_egress": {"level": level}}
    config = {"plugins": {"enabled": ["mordred"], "mordred_privacy_check": section}}
    for path, data in [(home / "config.yaml", config), (home / "mordred/policy.json", {"policy": mode})]:
        if os.name == "nt" and path.name == "policy.json":
            from mordred_hermes._private_fs import open_private_directory

            with open_private_directory(path.parent, create=True) as directory, directory.transaction() as tx:
                if path.exists():
                    tx.replace_bytes(path.name, json.dumps(data).encode())
                else:
                    tx.create_bytes(path.name, json.dumps(data).encode())
        else:
            path.write_text(json.dumps(data), encoding="utf-8")
            if os.name != "nt":
                path.chmod(0o600)


def test_cached_tool_allow_refuses_pending_generation(profile: Path) -> None:
    assert hooks.pre_tool_call(tool_name="web_search") is None
    (profile / "mordred" / POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    result = hooks.pre_tool_call(tool_name="read_file")
    assert result is not None and result["action"] == "block"


def test_egress_cached_off_refuses_marker(profile: Path) -> None:
    config = profile / "config.yaml"
    assert egress.load_policy(config).level == "off"
    (profile / "mordred" / POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    with pytest.raises((OSError, ValueError)):
        egress.load_policy(config)


@pytest.mark.parametrize("damage", ["json-root", "yaml-root", "plugins", "section", "conflict", "mode", "egress"])
def test_invalid_pair_blocks_even_local_tools(profile: Path, damage: str) -> None:
    assert hooks.pre_tool_call(tool_name="read_file") is None
    config = profile / "config.yaml"
    if damage == "json-root":
        (profile / "mordred/policy.json").write_text("[]")
    elif damage == "conflict":
        (profile / "mordred/policy.json").write_text('{"policy":"strict"}')
    else:
        values = {
            "yaml-root": [],
            "plugins": {"plugins": []},
            "section": {"plugins": {"mordred_privacy_check": []}},
            "mode": {"plugins": {"mordred_privacy_check": {"policy": []}}},
            "egress": {"plugins": {"mordred_privacy_check": {"policy": "off", "tool_egress": {"level": "typo"}}}},
        }
        config.write_text(json.dumps(values[damage]))
    result = hooks.pre_tool_call(tool_name="read_file")
    assert result is not None and result["action"] == "block"


def test_invalid_state_integrity_refuses_even_complete_plugin(profile: Path) -> None:
    _runtime.ensure_state()
    (profile / "mordred" / POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    with pytest.raises(MordredIntegrityRefused):
        hooks.check_plugin_integrity()


def test_fresh_snapshot_refreshes_mode_and_egress_together(profile: Path) -> None:
    assert hooks.pre_tool_call(tool_name="web_search") is None
    write_pair(profile, mode="strict", level="lockdown")
    result = hooks.pre_tool_call(tool_name="web_search")
    assert result is not None and result["action"] == "block"


def test_one_generation_per_tool_decision(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.privacy_check import _checked_policy

    original = _checked_policy.read_canonical_snapshot
    reads = []

    def read(paths):
        result = original(paths)
        reads.append(result)
        write_pair(profile, mode="strict", level="off")
        return result

    monkeypatch.setattr(_checked_policy, "read_canonical_snapshot", read)
    monkeypatch.setattr(hooks, "_resolve_active_network_path", lambda: None)
    assert hooks.pre_tool_call(tool_name="web_search") is None
    assert len(reads) == 1
    assert hooks.pre_tool_call(tool_name="web_search")["action"] == "block"


def test_install_cannot_authorize_with_caller_stale_off(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.privacy_check import install_wrapper
    from tests.test_install_wrapper import CLEARNET

    write_pair(profile, mode="strict")
    monkeypatch.setattr(install_wrapper, "_platform", "nt", raising=False)

    def forbidden(*args):
        pytest.fail("unsafe install reached a provider or installer")

    with pytest.raises(install_wrapper.InstallBlocked):
        install_wrapper.run(
            skill_path=CLEARNET, policy_mode="off", audit=Audit(), runner=forbidden, keyvault_probe=forbidden
        )


def test_install_pending_blocks_even_local_only_skill(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.privacy_check import install_wrapper
    from tests.test_install_wrapper import TOR

    (profile / "mordred" / POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    monkeypatch.setattr(install_wrapper, "_platform", "nt", raising=False)

    def forbidden(*args):
        pytest.fail("unsafe install reached a provider or installer")

    with pytest.raises(install_wrapper.InstallBlocked):
        install_wrapper.run(
            skill_path=TOR, policy_mode="off", audit=Audit(), runner=forbidden, keyvault_probe=forbidden
        )


def test_checked_absence_preserves_fresh_install_defaults(profile: Path) -> None:
    (profile / "config.yaml").unlink()
    (profile / "mordred/policy.json").unlink()
    assert _runtime.get_active_policy_mode() == "lenient"
    assert egress.load_policy(profile / "config.yaml").level == "ask"


def test_custom_config_leaf_is_checked(profile: Path) -> None:
    custom = profile / "custom.yaml"
    (profile / "config.yaml").rename(custom)
    assert egress.load_policy(custom).level == "off"
    (profile / "mordred" / POLICY_TRANSACTION_MARKER).write_bytes(b"pending")
    with pytest.raises(OSError):
        egress.load_policy(custom)


@pytest.mark.parametrize("fault", ["unsafe", "busy", "io"])
def test_failure_after_snapshot_is_not_cached_allow(profile: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.privacy_check import _checked_policy

    assert hooks.pre_tool_call(tool_name="web_search") is None

    def read(paths):
        raise PrivateFSError(fault, "cleanup", commit_state="uncertain")

    monkeypatch.setattr(_checked_policy, "read_canonical_snapshot", read)
    monkeypatch.setattr(hooks, "_resolve_active_network_path", lambda: pytest.fail("unsafe policy reached provider"))
    assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"


@pytest.mark.skipif(os.name != "nt", reason="actual inherited Windows ACL admission")
def test_native_cached_allow_rejects_broadened_acl_without_repair(profile: Path) -> None:
    from tests.test_private_fs_confidential_windows import descriptor, powershell

    path = profile / "config.yaml"
    parent_before = descriptor(profile)
    inherited_before = descriptor(path)
    assert "ID;" in inherited_before
    assert hooks.pre_tool_call(tool_name="web_search") is None
    assert descriptor(path) == inherited_before
    before = path.read_bytes()
    powershell(
        path,
        """
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $s=New-Object Security.Principal.SecurityIdentifier('S-1-1-0');
    $r=New-Object Security.AccessControl.FileSystemAccessRule($s,'Read','Allow');
    $a.AddAccessRule($r); Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    unsafe = descriptor(path)
    assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"
    assert descriptor(path) == unsafe
    assert descriptor(profile) == parent_before
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="actual Windows hardlink admission")
def test_native_cached_allow_rejects_hardlinked_replacement(profile: Path) -> None:
    assert hooks.pre_tool_call(tool_name="read_file") is None
    path = profile / "config.yaml"
    original = path.read_bytes()
    path.rename(profile / "held-config")
    os.link(profile / "held-config", path)
    assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"
    assert path.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="actual Windows process lock")
def test_native_busy_generation_blocks_without_waiting(profile: Path) -> None:
    import subprocess
    import sys

    assert hooks.pre_tool_call(tool_name="read_file") is None
    script = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, canonical_session
with canonical_session(CanonicalPaths(Path(sys.argv[1])), scope="policy"):
    print("locked", flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(profile)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        from tests.test_config_io_windows import line

        assert line(process) == "locked"
        assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"
    finally:
        process.communicate("done\n", timeout=20)
    assert process.returncode == 0


@pytest.mark.parametrize(
    "section",
    [
        {"policy": "off", "allow_cloud_llm": "false"},
        {"policy": "off", "cloud_provider_allowlist": [42]},
        {"policy": "off", "tool_egress": {"level": "off", "taint": "false"}},
        {"policy": "off", "tool_egress": {"level": "off", "blocklist": [42]}},
        {"policy": "off", "tool_egress": None},
    ],
    ids=["cloud-bool", "providers", "taint-bool", "domains", "null-egress"],
)
def test_malformed_permissions_do_not_authorize(profile: Path, section: dict[str, Any]) -> None:
    (profile / "config.yaml").write_text(json.dumps({"plugins": {"mordred_privacy_check": section}}))
    assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"


@pytest.mark.parametrize(
    "document",
    [b"", b"\xff", b"plugins: [", b"x" * (8 * 1024 * 1024 + 1)],
    ids=["empty", "encoding", "syntax", "oversize"],
)
def test_invalid_config_document_blocks(profile: Path, document: bytes) -> None:
    (profile / "config.yaml").write_bytes(document)
    assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"


def test_callback_can_acquire_canonical_lock_after_snapshot(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A new thread cannot borrow the reader's same-thread nested session.
    from concurrent.futures import ThreadPoolExecutor

    def network():
        with ThreadPoolExecutor(max_workers=1) as executor:
            snapshot = executor.submit(cio.read_canonical_snapshot, cio.CanonicalPaths(profile)).result(timeout=10)
        assert snapshot.config is not None
        return None

    monkeypatch.setattr(hooks, "_resolve_active_network_path", network)
    assert hooks.pre_tool_call(tool_name="read_file") is None


@pytest.mark.skipif(os.name != "nt", reason="actual Windows junction admission")
def test_native_cached_allow_rejects_policy_directory_junction(profile: Path) -> None:
    import subprocess

    assert hooks.pre_tool_call(tool_name="read_file") is None
    path = profile / "mordred"
    held = profile / "held-policy"
    path.rename(held)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(held)], check=True, capture_output=True)
    try:
        assert hooks.pre_tool_call(tool_name="read_file")["action"] == "block"
    finally:
        os.rmdir(path)
        held.rename(path)


def test_integrity_mode_and_enabled_list_share_one_generation(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.privacy_check import _checked_policy

    original = _checked_policy.read_canonical_snapshot
    write_pair(profile, mode="strict", level="off")
    reads = []

    def read(paths):
        result = original(paths)
        reads.append(result)
        (profile / "config.yaml").write_text('{"plugins":{"mordred_privacy_check":{"policy":"strict"}}}')
        return result

    monkeypatch.setattr(_checked_policy, "read_canonical_snapshot", read)
    hooks.check_plugin_integrity()
    assert len(reads) == 1
    with pytest.raises(MordredIntegrityRefused):
        hooks.check_plugin_integrity()
