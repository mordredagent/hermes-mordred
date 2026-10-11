"""Explicit real-CNG wizard flow on a fresh UUID profile (C6 live recipe).

Gated: Windows, an ordinary token, ``MORDRED_TEST_WINDOWS_WIZARD_LIVE=1``, an
existing retained ``MORDRED_WINDOWS_CUSTODY_TEST_ROOT``, the installed Hermes
interpreter in ``MORDRED_HERMES_PYTHON`` (which must also run this test) and
an owned helper in ``MORDRED_WINKEY_HELPER``. Through the real CLI it runs
``keyvault native init`` -> ``encryption enable memory`` -> a fresh
installed-runtime read -> ``encryption status`` -> ``encryption disable
memory`` -> ``encryption purge memory --yes``. Only the new profile and its own
fresh CNG key are created; the purge deletes that key through the C5a journal.
Failures preserve the profile and its journals (no recursive removal); only
paths and shapes are printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

READER = r"""
import hashlib, json, os
from pathlib import Path
from mordred_hermes.keyvault._memory_storage import windows_memory_session
with windows_memory_session(Path(os.environ["HERMES_HOME"])) as session:
    rows = {
        row.name: hashlib.sha256(session.read_plaintext(row.name).encode()).hexdigest()
        for row in session.inventory()
    }
print(json.dumps(rows, sort_keys=True))
"""
CONTENT = "synthetic wizard smoke\n§\nsecond entry"


def _fresh_read(python: str, home: Path) -> dict[str, str]:
    from mordred_hermes._windows_runtime import scrubbed_environment

    env = {k: v for k, v in scrubbed_environment(os.environ).items() if k.upper() != "HERMES_MEMORY_KEY"}
    env.update(HERMES_HOME=str(home), PYTHONUTF8="1", MORDRED_CONFIG_DECRYPT="0")
    child = subprocess.run([python, "-c", READER], env=env, capture_output=True, text=True, timeout=120, check=False)
    assert child.returncode == 0, child.stderr[-2048:]
    result: dict[str, str] = json.loads(child.stdout)
    return result


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("MORDRED_TEST_WINDOWS_WIZARD_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG wizard acceptance",
)
def test_wizard_ceremony_enable_status_disable_purge_real_cng(monkeypatch, capsys):
    import ctypes

    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.keyvault._memory_storage import windows_memory_runtime_admitted
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault.memory_crypto import is_sealed
    from mordred_hermes.wizard import cli

    assert not ctypes.windll.shell32.IsUserAnAdmin(), "ordinary-user acceptance required"
    assert windows_memory_runtime_admitted(), "run pytest with the admitted installed Hermes interpreter"
    python = os.environ.get("MORDRED_HERMES_PYTHON")
    assert python, "explicit installed Hermes interpreter required"
    assert os.environ.get("MORDRED_WINKEY_HELPER"), "explicit owned helper required"
    root_value = os.environ.get("MORDRED_WINDOWS_CUSTODY_TEST_ROOT")
    assert root_value, "explicit retained isolated root required"
    root = Path(root_value)
    with open_confidential_directory(root):
        pass
    home = root / ("wizard-memory-" + uuid.uuid4().hex)
    monkeypatch.setenv("HERMES_HOME", str(home))
    expected = {"MEMORY.md": hashlib.sha256(CONTENT.encode("utf-8")).hexdigest()}
    try:
        with open_confidential_directory(home, create=True):
            pass
        with open_confidential_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
            tx.create_bytes("MEMORY.md", CONTENT.encode("utf-8"))

        assert cli.main(["keyvault", "native", "init"]) == 0
        with windows_custody_session(home) as owner:
            lease = owner.memory_state().lease
        assert lease is not None
        assert not (home / "mordred" / "memory-vault.marker").exists(), "the ceremony must stay inert"

        assert cli.main(["encryption", "enable", "memory"]) == 0
        assert is_sealed((home / "memories" / "MEMORY.md").read_bytes()), "enable left plaintext"
        assert _fresh_read(python, home) == expected, "fresh installed-runtime read failed"

        capsys.readouterr()
        assert cli.main(["encryption", "status", "--json"]) == 0
        memory = next(row for row in json.loads(capsys.readouterr().out) if row["target"] == "memory")
        print(json.dumps({"memory_active": memory["active"], "detail": memory["detail"]}))
        assert memory["active"] is True

        assert cli.main(["encryption", "disable", "memory"]) == 0
        assert (home / "memories" / "MEMORY.md").read_bytes() == CONTENT.encode("utf-8")
        assert _fresh_read(python, home) == expected

        assert cli.main(["encryption", "purge", "memory", "--yes"]) == 0
        with windows_custody_session(home) as owner:
            assert owner.memory_state().lease is None
    except BaseException as exc:
        exc.add_note(f"retained isolated wizard profile and journals: {home}")
        raise
