"""Manual candidate-wheel acceptance using only an isolated native macOS fixture.

Run with HERMES_HOME=<mktemp mordred-uninstall-wheel-...>/home and this
home's hermes-agent/venv/bin/python after installing the candidate wheel.
MORDRED_SEKEY_UNATTENDED=1 creates test-only keys without presence prompts.
Phases: prepare, uninstall, without-package, reinstall the wheel externally,
export, purge-blocked, prepare-purge, enroll-main, purge, without-package.
The isolated user_home prevents removal of installed user launchers/helpers.
Never point this driver at a real Hermes home. No Linux/Windows claim is made.
"""

import hashlib
import os
import sqlite3
import sys
from pathlib import Path

home = Path(os.environ["HERMES_HOME"]).resolve(strict=True)
assert home.name == "home" and home.parent.name.startswith("mordred-uninstall-wheel-")
assert Path(sys.prefix) == home / "hermes-agent/venv"
phase = sys.argv[1]
vault_root = home / "mordred/vault"
backup = home.parent / "retained.backup"
paths = [home / "state.db", home / "profiles/work/state.db"]
if phase == "prepare":
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _backup, _migrate, arm
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.keyvault._config_bootstrap import reseal_config
    from mordred_hermes.keyvault._database_authority import enroll_database_source
    from mordred_hermes.wizard import config_decrypt_cli, env_decrypt_cli, memory_cli, vault_cli

    class Prompt:
        def ask_password(self, *args, **kwargs):
            return "isolated acceptance fixture passphrase"

    (home / "config.yaml").write_text("model: isolated-test\nplugins:\n  enabled: [mordred]\n")
    (home / ".env").write_text("USER_SETTING=preserved\n")
    (home / "memories").mkdir()
    (home / "memories/MEMORY.md").write_text("- preserve this isolated memory\n")
    assert vault_cli.init(root=vault_root, prompt_io=Prompt()) == 0
    options = dict(home=home, root=vault_root, platform="darwin", force_runtime_unverified=True)
    assert config_decrypt_cli.enable(**options) == 0
    assert reseal_config(root=vault_root, home=home) == 1
    assert env_decrypt_cli.enable(**options) == 0
    assert memory_cli.enable(**options) == 0
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE messages(body TEXT)")
            connection.execute("INSERT INTO messages VALUES ('native recovery 日本語')")
        connection.close()
        path.chmod(0o600)
    with acquire_exclusive(home) as lease:
        enroll_database_source(root=home, lease=lease)
    _migrate.migrate(home, None, arm=arm)
    owner = Authority.acquire(home)
    try:
        _backup.backup_database(paths[0], backup, authority=owner)
    finally:
        owner.close()
    (home.parent / "backup-sha256").write_text(hashlib.sha256(backup.read_bytes()).hexdigest())
    assert list((home / "mordred/keyvault/sekey").glob("*.bin")), "real Enclave blob missing"
    print("PREPARED: real Secure Enclave; two encrypted databases; memory/config/env; registered backup")
elif phase in {"uninstall", "purge-blocked", "purge"}:
    import shutil

    from mordred_hermes.wizard.uninstall_cli import UninstallContext, UninstallOptions, run_uninstall

    ctx = UninstallContext(
        home=home,
        vault_root=vault_root,
        user_home=home.parent / "user",
        which=lambda name: str(home / "hermes-agent/venv/bin/hermes") if name == "hermes" else shutil.which(name),
        interactive=False,
    )
    if phase == "uninstall":
        assert run_uninstall(ctx, UninstallOptions(yes=True)) == 0
    else:
        from dataclasses import replace

        from mordred_hermes.wizard.uninstall_cli import PURGE_PHRASE

        class Confirm:
            def ask_bool(self, *args, **kwargs):
                return True

            def ask_text(self, *args, **kwargs):
                return PURGE_PHRASE

        ctx = replace(ctx, prompt_io=Confirm())
        observed = [*paths, home / "config.yaml", home / ".env", home / "memories/MEMORY.md"]
        if phase == "purge-blocked":
            observed.append(backup)
            before = {path: path.read_bytes() for path in observed}
            assert run_uninstall(ctx, UninstallOptions(purge_data=True)) == 1
            assert {path: path.read_bytes() for path in observed} == before
            print("REFUSED: retained encrypted backup blocked purge before changes")
        else:
            assert run_uninstall(ctx, UninstallOptions(purge_data=True)) == 0
            assert not vault_root.exists()
            assert not (home / "mordred/db-key-source.json").exists()
            assert not (home / "mordred/keyvault").exists()
            print("PURGED: native keys deleted; plaintext retained")
elif phase == "without-package":
    import importlib.util

    assert importlib.util.find_spec("mordred_hermes") is None
    for path in paths:
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert connection.execute("SELECT body FROM messages").fetchall() == [("native recovery 日本語",)]
        connection.close()
    assert "isolated-test" in (home / "config.yaml").read_text()
    assert "USER_SETTING=preserved" in (home / ".env").read_text()
    assert (home / "memories/MEMORY.md").read_text() == "- preserve this isolated memory\n"
    if backup.exists():
        assert hashlib.sha256(backup.read_bytes()).hexdigest() == (home.parent / "backup-sha256").read_text()
    print("REMOVED: package absent; plaintext databases, config, env and memory readable")
elif phase == "enroll-main":
    from mordred_hermes.keyvault import api
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend

    seed, password, work = "isolated acceptance one two three", "test only", bytes(range(32))
    handle, digest = api.prepare_generate(seed, password, work)
    handle.consume()
    api.generate(
        seed,
        password,
        work,
        digest,
        key_id="isolated-acceptance-main",
        backend=_SecKeyBackend(),
        audit_sink=lambda event: None,
        home=home,
        unattended=True,
    )
    print("ENROLLED: checked main ownership for independent keyvault-reset precondition")
elif phase == "prepare-purge":
    from mordred_hermes.dbcrypt import _backup, _migrate, arm
    from mordred_hermes.dbcrypt._authority import Authority

    _migrate.migrate(home, None, arm=arm)
    owner = Authority.acquire(home)
    try:
        _backup.delete_backup(backup, authority=owner)
    finally:
        owner.close()
    assert not backup.exists()
    print("PREPARED PURGE: active encrypted databases; checked backup deletion completed")
elif phase == "export":
    import subprocess

    output = home.parent / "recovered.db"
    subprocess.run(
        [
            str(Path(sys.prefix) / "bin/hermes-mordred"),
            "databases",
            "backup",
            "export",
            "--source",
            str(backup),
            "--output",
            str(output),
        ],
        check=True,
    )
    with sqlite3.connect(output) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT body FROM messages").fetchall() == [("native recovery 日本語",)]
    connection.close()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == (home.parent / "backup-sha256").read_text()
    print("RECOVERED: fresh process after wheel reinstall; original physical home and native source; backup unchanged")
else:
    raise AssertionError(phase)
