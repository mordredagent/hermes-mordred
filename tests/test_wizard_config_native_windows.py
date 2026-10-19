"""Native public Windows writer acceptance; host doubles do not replace this suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from mordred_hermes._config_io import CanonicalPaths, PolicyPendingError, read_canonical_snapshot
from mordred_hermes._private_fs import PrivateFSError
from mordred_hermes.wizard._uninstall_config import apply_config_cleanup, apply_env_cleanup
from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter
from tests._checked_fixture_helpers import assert_confidential_file, assert_private
from tests.test_config_io_windows import line
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows public configuration writers")


@pytest.fixture
def writer(shared_home):
    # The inherited fixture supplies profile-style permissions and a Unicode,
    # space-containing path. Replace its generic byte fixture with valid YAML.
    from mordred_hermes._private_fs import open_confidential_directory

    with open_confidential_directory(shared_home) as directory, directory.transaction() as tx:
        tx.replace_bytes("config.yaml", b'# retained\nmodel: "original"\n')
    return PolicyWriter(shared_home / "config.yaml", shared_home / "mordred" / "policy.json", shared_home / "mordred")


def private_file(path):
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    with get_api().open(str(path)) as handle:
        validate_private(handle, directory=False)


@pytest.mark.parametrize("nested_backup", [False, True])
def test_native_configure_rerun_and_private_backups(writer, nested_backup):
    w = writer
    program = """
import argparse
from mordred_hermes.wizard.configure import cli_handler
raise SystemExit(cli_handler(argparse.Namespace(non_interactive=True, policy='strict')))
"""
    kwargs = dict(
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=os.environ | {"HERMES_HOME": str(w.config_path.parent)},
    )
    parent = descriptor(w.config_path.parent)
    subprocess.run([sys.executable, "-c", program], **kwargs)
    before = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    config_acl = descriptor(w.config_path)
    subprocess.run([sys.executable, "-c", program], **kwargs)
    assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == before
    assert descriptor(w.config_path) == config_acl
    assert descriptor(w.config_path.parent) == parent
    JSONCredentialsWriter().write_network(
        w.mordred_dir / "credentials" / "network.json",
        mullvad_account_id_env="MORDRED_ACCOUNT",
        mullvad_relay_country="auto",
        mullvad_killswitch=True,
    )
    DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_ACCOUNT", value="test-secret")
    config = apply_config_cleanup(w.config_path, lock_dir=w.mordred_dir, stamp="native")
    save_dir = w.mordred_dir / "uninstall" if nested_backup else w.mordred_dir
    env = apply_env_cleanup(w.config_path.parent / ".env", save_dir=save_dir, stamp="native")
    assert config.backup and env.saved_to == save_dir / "env-removed-native.env"
    for path in (
        w.config_path,
        w.policy_json_path,
        config.backup,
        env.saved_to,
        w.mordred_dir / "credentials" / "network.json",
    ):
        private_file(path)
    DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_ACCOUNT", value="new-secret")
    with pytest.raises(PrivateFSError, match="exists"):
        apply_env_cleanup(w.config_path.parent / ".env", save_dir=save_dir, stamp="native")
    assert "new-secret" in (w.config_path.parent / ".env").read_text()


def test_native_fresh_process_config_and_dotenv_updates(writer):
    w = writer
    w.write(PolicySnapshot("strict"))
    program = """
import sys
from pathlib import Path
from mordred_hermes.wizard.policy_writer import PolicyWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
home=Path(sys.argv[1]); index=sys.argv[2]
w=PolicyWriter(home/'config.yaml', home/'mordred'/'policy.json', home/'mordred')
w.merge_mordred_sections({'mordred_wizard': {'worker'+index: True}})
DotEnvFileWriter().upsert(home/'.env', key='WORKER_'+index, value='retained')
"""
    children = [
        subprocess.Popen(
            [sys.executable, "-c", program, str(w.config_path.parent), str(i)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for i in range(4)
    ]
    try:
        for child in children:
            _stdout, stderr = child.communicate(timeout=45)
            assert child.returncode == 0, stderr
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
    config = w.config_path.read_text()
    dotenv = (w.config_path.parent / ".env").read_text()
    for i in range(4):
        assert f"worker{i}: true" in config
        assert f"WORKER_{i}=retained" in dotenv


def test_native_public_writer_crash_and_explicit_recovery(writer):
    w = writer
    program = """
import sys
from pathlib import Path
from mordred_hermes._private_fs import _windows_io
from mordred_hermes.wizard.policy_writer import PolicyWriter, PolicySnapshot
original=_windows_io._Transaction.create_bytes
def paused(self, name, data):
    if name=='policy.json':
        print('partial', flush=True)
        sys.stdin.readline()
    return original(self, name, data)
_windows_io._Transaction.create_bytes=paused
home=Path(sys.argv[1])
PolicyWriter(home/'config.yaml', home/'mordred'/'policy.json', home/'mordred').write(PolicySnapshot('strict'))
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(w.config_path.parent)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert line(child) == "partial"
        child.kill()
        child.communicate(timeout=20)
        with pytest.raises(PolicyPendingError):
            w.merge_mordred_sections({"mordred_wizard": {"done": True}})
        w.write(PolicySnapshot("strict"))
        pair = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
        assert json.loads(pair.policy.data)["policy"] == "strict"
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


def test_native_unsafe_config_acl_is_refused_without_repair(writer):
    w = writer
    original = w.config_path.read_bytes()
    subprocess.run(["icacls.exe", str(w.config_path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = descriptor(w.config_path)
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert w.config_path.read_bytes() == original
    assert descriptor(w.config_path) == before


def test_native_unsafe_pending_marker_cannot_be_recovered(writer):
    from mordred_hermes._private_fs import open_private_directory

    w = writer
    w.write(PolicySnapshot("strict"))
    with open_private_directory(w.mordred_dir) as directory, directory.transaction() as transaction:
        transaction.create_bytes(".policy-write.pending", b"interrupted")
    marker = w.mordred_dir / ".policy-write.pending"
    subprocess.run(["icacls.exe", str(marker), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = w.config_path.read_bytes(), w.policy_json_path.read_bytes(), descriptor(marker)
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert (w.config_path.read_bytes(), w.policy_json_path.read_bytes(), descriptor(marker)) == before


def test_native_hardlinked_config_refused_by_public_writer(writer):
    w = writer
    os.link(w.config_path, w.config_path.with_name("operator-alias.yaml"))
    before = w.config_path.read_bytes()
    with pytest.raises(PrivateFSError, match="unsafe"):
        w.write(PolicySnapshot("off"))
    assert w.config_path.read_bytes() == before


def test_native_busy_explicit_backup_destination_preserves_source(writer):
    w = writer
    w.write(PolicySnapshot("strict"))
    dotenv = w.config_path.parent / ".env"
    DotEnvFileWriter().upsert(dotenv, key="MORDRED_ACCOUNT", value="test-secret")
    before = dotenv.read_bytes()
    destination = w.mordred_dir / "uninstall"
    program = """
import sys
from pathlib import Path
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(Path(sys.argv[1]), create=True) as d, d.transaction():
    print('locked', flush=True)
    sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-u", "-c", program, str(destination)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert line(child) == "locked"
        with pytest.raises(PrivateFSError, match="busy"):
            apply_env_cleanup(dotenv, save_dir=destination, stamp="native")
        assert dotenv.read_bytes() == before
        assert not (destination / "env-removed-native.env").exists()
    finally:
        child.kill()
        child.communicate(timeout=20)


def test_native_network_selected_home_secret_blank_clear_and_use(writer, monkeypatch, capsys):
    import argparse

    from mordred_hermes.wizard import network_cli
    from tests.test_wizard_network_init import _ScriptedPromptIO

    w = writer
    home = w.config_path.parent
    parent_acl = descriptor(home)
    prompts = _ScriptedPromptIO(["vpn", "mullvad", "selected-secret", "jp", True])
    monkeypatch.setattr(network_cli, "PromptToolkitIO", lambda: prompts)
    monkeypatch.setattr(network_cli, "_runtime_registered", lambda: False)
    args = argparse.Namespace(config_path=w.config_path, non_interactive=False)
    assert network_cli.handle_init(args) == 0
    assert (home / ".env").read_bytes() == b"MORDRED_MULLVAD_ACCOUNT=selected-secret\n"
    assert json.loads((w.mordred_dir / "credentials" / "network.json").read_bytes())["mullvad"]["relay_country"] == "jp"
    for path in (w.config_path, home / ".env", w.mordred_dir / "credentials" / "network.json"):
        private_file(path)
    before = (home / ".env").read_bytes(), descriptor(home / ".env")
    prompts = _ScriptedPromptIO(["vpn", "mullvad", "", "jp", True])
    assert network_cli.handle_init(args) == 0
    assert ((home / ".env").read_bytes(), descriptor(home / ".env")) == before
    assert network_cli.handle_use(argparse.Namespace(config_path=w.config_path, path="clearnet")) == 0
    snapshot = read_canonical_snapshot(CanonicalPaths(home))
    assert b"default_path: clearnet" in snapshot.config.data
    assert b"mullvad_relay_country: jp" in snapshot.config.data
    assert (
        network_cli.handle_init(
            argparse.Namespace(config_path=w.config_path, non_interactive=True, clear_mullvad=True, path="clearnet")
        )
        == 0
    )
    assert (home / ".env").read_bytes() == b""
    assert descriptor(home) == parent_acl
    captured = capsys.readouterr()
    assert "selected-secret" not in captured.out + captured.err


def _native_legacy_source(w, *, base_present=True, config=None):
    from mordred_hermes._private_fs import open_confidential_directory

    root = w.config_path.parent / "legacy OpenClaw"
    with open_confidential_directory(root, create=True) as directory:
        if config is not None:
            body = {"plugins": {"entries": {"mordred-privacy-check": {"config": config}}}}
            with directory.transaction() as transaction:
                transaction.create_bytes("openclaw.json", json.dumps(body).encode())
    base = root / "mordred"
    if base_present:
        with open_confidential_directory(base, create=True):
            pass
    return base


def _native_legacy_evidence(w, base, *, source_only=False):
    """Record own NTFS descriptors/identities without traversing reparse entries."""
    import stat

    from mordred_hermes._private_fs._windows_api import get_api

    api = get_api()
    pending = [base.parent if source_only else w.config_path.parent]
    evidence = {}
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        reparse = bool(getattr(metadata, "st_reparse_tag", 0))
        with api.open(str(path)) as handle:
            own = api.descriptor(handle), api.metadata(handle).identity
        content = os.readlink(path) if reparse else path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        evidence[str(path)] = (own, metadata.st_mode, metadata.st_mtime_ns, content)
        if stat.S_ISDIR(metadata.st_mode) and not reparse:
            pending.extend(path.iterdir())
    return evidence


@pytest.mark.parametrize("artifact", ["audit.log", "KEYVAULT", "Credentials"])
@pytest.mark.parametrize("kind", ["empty-file", "file", "directory", "nonempty-directory", "junction"])
@pytest.mark.parametrize("entrypoint", ["upgrade", "migrate", "read"])
def test_native_legacy_refusal_precedes_all_publication(writer, monkeypatch, artifact, kind, entrypoint):
    from mordred_hermes.keyvault import _windows_custody
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade
    from tests.test_openclaw_migration import _publication_tripwires

    w = writer
    w.write(PolicySnapshot("strict"))
    base = _native_legacy_source(w)
    from mordred_hermes._private_fs import open_private_directory

    with open_private_directory(w.mordred_dir) as directory, directory.transaction() as transaction:
        transaction.create_bytes(migration.MARKER_FILENAME, b"retained marker")
    entry = base / artifact
    if kind in ("directory", "nonempty-directory"):
        entry.mkdir()
        if kind == "nonempty-directory":
            (entry / "retained.bin").write_bytes(b"retained-secret")
    elif kind == "junction":
        subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(entry), str(base / "missing")], check=True, capture_output=True
        )
    else:
        entry.write_bytes(b"" if kind == "empty-file" else b"retained-secret")
    before = _native_legacy_evidence(w, base)
    calls = _publication_tripwires(monkeypatch, w)

    def forbid_backend():
        calls.append("native-custody")
        pytest.fail("native custody before source refusal")

    monkeypatch.setattr(_windows_custody, "windows_backend", forbid_backend)
    from mordred_hermes._private_fs._windows_api import get_api

    api = get_api()
    real_open = api.open

    def no_unsupported_open(path, **kwargs):
        if os.path.normcase(path.removeprefix("\\\\?\\")) == os.path.normcase(str(entry)):
            calls.append("unsupported-child-open")
            pytest.fail("admission opened an unsupported child")
        return real_open(path, **kwargs)

    with monkeypatch.context() as source_patch:
        source_patch.setattr(api, "open", no_unsupported_open)
        with pytest.raises(SystemExit, match="unsupported on Windows; retained data is unchanged"):
            if entrypoint == "upgrade":
                upgrade.run(
                    options=upgrade.UpgradeOptions(reset=True),
                    policy_writer=w,
                    target_snapshot=PolicySnapshot("off"),
                    openclaw_base=base,
                )
            elif entrypoint == "migrate":
                migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions(reset=True))
            else:
                migration.read_policy_snapshot(base, w)
    assert calls == []
    assert _native_legacy_evidence(w, base) == before


@pytest.mark.parametrize("choice", ["keep-existing", "overwrite", "abort", "reset"])
def test_native_policy_only_conflicts_and_idempotent_pair(writer, choice):
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    w = writer
    w.write(PolicySnapshot("lenient", provider_overrides=["opaque-retained"]))
    base = _native_legacy_source(w, config={"policy": "strict"})
    source_before = _native_legacy_evidence(w, base, source_only=True)
    options = upgrade.UpgradeOptions(reset=choice == "reset", policy_conflict=None if choice == "reset" else choice)
    before = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    if choice == "abort":
        with pytest.raises(SystemExit, match="abort"):
            migration.migrate(openclaw_base=base, policy_writer=w, options=options)
        assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == before
        assert _native_legacy_evidence(w, base, source_only=True) == source_before
        return
    action = "noop" if choice == "keep-existing" else "migrated"
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=options) == action
    assert json.loads(w.policy_json_path.read_bytes())["provider_overrides"] == ["opaque-retained"]
    after = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=options) == action
    assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == after
    assert not (w.mordred_dir / ".policy-write.pending").exists()
    assert _native_legacy_evidence(w, base, source_only=True) == source_before


@pytest.mark.parametrize("layout", ["absent-root", "absent-base", "sibling-policy", "empty", "policy"])
def test_native_upgrade_supported_source_and_marker_only(writer, layout):
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    w = writer
    w.write(PolicySnapshot("lenient"))
    base = (
        w.config_path.parent / "missing OpenClaw" / "mordred"
        if layout == "absent-root"
        else _native_legacy_source(
            w,
            base_present=layout not in ("absent-base", "sibling-policy"),
            config={"policy": "strict"} if layout in ("policy", "sibling-policy") else None,
        )
    )
    with open_private_directory(w.mordred_dir) as directory, directory.transaction() as tx:
        tx.create_bytes(migration.MARKER_FILENAME, b"retained marker")
    marker = w.mordred_dir / migration.MARKER_FILENAME
    marker_before = marker.read_bytes(), descriptor(marker), marker.stat().st_ino
    report = upgrade.run(options=upgrade.UpgradeOptions(reset=True), policy_writer=w, openclaw_base=base)
    assert report.story1_5_action == ("migrated" if layout == "policy" else "noop")
    assert (marker.read_bytes(), descriptor(marker), marker.stat().st_ino) == marker_before
    before = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    again = upgrade.run(options=upgrade.UpgradeOptions(reset=True), policy_writer=w, openclaw_base=base)
    assert again.story1_action == "noop"
    assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == before


@pytest.mark.parametrize("bad", ["malformed", "utf8", "oversize", "hardlink", "acl", "invalid-field"])
def test_native_unsafe_policy_refuses_without_repair(writer, monkeypatch, bad):
    from mordred_hermes._config_io import CONFIG_LIMIT
    from mordred_hermes.wizard import upgrade
    from tests.test_openclaw_migration import _publication_tripwires

    w = writer
    w.write(PolicySnapshot("strict"))
    base = _native_legacy_source(w, config={"policy": None} if bad == "invalid-field" else {})
    policy = base.parent / "openclaw.json"
    if bad in ("malformed", "utf8", "oversize"):
        policy.write_bytes(
            {"malformed": b"SECRET-INVALID", "utf8": b"\xff", "oversize": b" " * (CONFIG_LIMIT + 1)}[bad]
        )
    elif bad == "hardlink":
        os.link(policy, policy.with_suffix(".linked"))
    elif bad == "acl":
        subprocess.run(["icacls.exe", str(policy), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = _native_legacy_evidence(w, base)
    calls = _publication_tripwires(monkeypatch, w)
    with pytest.raises(SystemExit, match=r"refusing (invalid OpenClaw policy|unsafe OpenClaw source)"):
        upgrade.run(
            options=upgrade.UpgradeOptions(reset=True),
            policy_writer=w,
            target_snapshot=PolicySnapshot("off"),
            openclaw_base=base,
        )
    assert calls == []
    assert _native_legacy_evidence(w, base) == before


@pytest.mark.parametrize("unsafe", ["root-junction", "base-junction", "root-acl", "base-acl", "policy-junction"])
def test_native_unsafe_legacy_ancestors_refuse_before_publication(writer, monkeypatch, unsafe):
    from mordred_hermes.wizard import upgrade
    from tests.test_openclaw_migration import _publication_tripwires

    w = writer
    w.write(PolicySnapshot("strict"))
    base = _native_legacy_source(w, config={})
    path = base.parent if unsafe.startswith("root") else base
    if unsafe == "policy-junction":
        path = base.parent / "openclaw.json"
    if unsafe.endswith("junction"):
        target = path.with_name(path.name + "-saved")
        if unsafe == "policy-junction":
            target.mkdir()
            path.rename(target / "retained.json")
        else:
            path.rename(target)
        subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(path), str(target)], check=True, capture_output=True)
    else:
        subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(W)"], check=True, capture_output=True)
    before = _native_legacy_evidence(w, base)
    calls = _publication_tripwires(monkeypatch, w)
    with pytest.raises(SystemExit, match="refusing unsafe OpenClaw source"):
        upgrade.run(
            options=upgrade.UpgradeOptions(reset=True),
            policy_writer=w,
            target_snapshot=PolicySnapshot("off"),
            openclaw_base=base,
        )
    assert calls == []
    assert _native_legacy_evidence(w, base) == before


@pytest.mark.parametrize("missing", ["mirror", "stale-mirror", "llm-plugin"])
def test_native_matching_privacy_still_reconciles_legacy_policy(writer, missing):
    from mordred_hermes._private_fs import open_confidential_directory, open_private_directory
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    w = writer
    w.write(PolicySnapshot("strict"))
    base = _native_legacy_source(w, config={"policy": "strict"})
    source_before = _native_legacy_evidence(w, base, source_only=True)
    if missing in ("mirror", "stale-mirror"):
        with open_private_directory(w.mordred_dir) as directory, directory.transaction() as transaction:
            if missing == "mirror":
                transaction.delete_file("policy.json", expected_identity=transaction.stat("policy.json").identity)
            else:
                body = json.loads(transaction.read_bytes("policy.json", max_bytes=8 * 1024 * 1024))
                body["policy"] = "off"
                transaction.replace_bytes("policy.json", json.dumps(body).encode())
    else:
        with open_confidential_directory(w.config_path.parent) as directory, directory.transaction() as transaction:
            config = transaction.read_bytes("config.yaml", max_bytes=8 * 1024 * 1024).decode()
            config = config.replace("    - mordred\n", "    - mordred_network\n").replace(
                "harness_primary: none", "harness_primary: stale"
            )
            transaction.replace_bytes("config.yaml", config.encode())
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions()) == "migrated"
    assert json.loads(w.policy_json_path.read_bytes())["policy"] == "strict"
    config = w.config_path.read_bytes()
    assert b"harness_primary: none" in config and b"mordred_network\n" not in config
    settled = read_canonical_snapshot(CanonicalPaths(w.config_path.parent))
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions()) == "migrated"
    assert read_canonical_snapshot(CanonicalPaths(w.config_path.parent)) == settled
    assert _native_legacy_evidence(w, base, source_only=True) == source_before


@pytest.mark.parametrize("consumer", ["policy", "slack"])
def test_native_widened_file_acl_refuses_without_repair(writer, consumer):
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes.extension.api import _upsert_env_vars

    w = writer
    w.write(PolicySnapshot("strict"))
    target = w.policy_json_path if consumer == "policy" else w.config_path.parent / ".env"
    if consumer == "slack":
        _upsert_env_vars(target, {"SLACK_BOT_TOKEN": "old-token"})
    assert_private(target)
    original = target.read_bytes()
    api = get_api()
    with api.open(str(target)) as handle:
        identity = api.metadata(handle).identity
    subprocess.run(["icacls.exe", str(target), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = descriptor(target)
    with pytest.raises(PrivateFSError, match="unsafe"):
        if consumer == "policy":
            # An identical write may not silently repair an unsafe descriptor.
            w.emit_policy_json(PolicySnapshot("strict"))
        else:
            _upsert_env_vars(target, {"SLACK_BOT_TOKEN": "new-token"})
    assert target.read_bytes() == original
    assert descriptor(target) == before
    with api.open(str(target)) as handle:
        assert api.metadata(handle).identity == identity


def test_native_existing_confidential_dotenv_noop_preserves_descriptor_and_identity(shared_home):
    from mordred_hermes import _dotenv_io
    from mordred_hermes._private_fs._windows_api import get_api
    from mordred_hermes._private_fs._windows_security import validate_private

    # Reuse the deliberate inherited/owner-controlled fixture without creating
    # a raw file or substituting an exact-private assertion for its contract.
    source = shared_home / "config.yaml"
    assert_confidential_file(source)
    path = shared_home / ".env"
    source.rename(path)
    api = get_api()
    with api.open(str(path)) as handle:
        identity = api.metadata(handle).identity
        with pytest.raises(PrivateFSError, match="unsafe"):
            validate_private(handle, directory=False)
    before = path.read_bytes(), descriptor(path), descriptor(shared_home)
    _dotenv_io.update_dotenv_file(path, lambda existing: existing)
    assert (path.read_bytes(), descriptor(path), descriptor(shared_home)) == before
    assert_confidential_file(path)
    with api.open(str(path)) as handle:
        assert api.metadata(handle).identity == identity


def test_native_raw_generic_writer_refuses_before_creation(writer):
    from mordred_hermes.wizard.policy_writer import _atomic_write_text

    target = writer.mordred_dir / "generic-secret.json"
    before = writer.config_path.read_bytes(), descriptor(writer.config_path.parent)
    with pytest.raises(PrivateFSError) as refusal:
        _atomic_write_text(target, "never-published", mode=0o600)
    assert refusal.value.reason == "unsupported"
    assert refusal.value.operation == "generic_configuration_write_requires_checked_consumer"
    assert not target.exists()
    assert (writer.config_path.read_bytes(), descriptor(writer.config_path.parent)) == before
    assert not list(writer.config_path.parent.rglob("*.tmp"))
