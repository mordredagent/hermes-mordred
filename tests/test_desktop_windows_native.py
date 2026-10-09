"""Native NTFS Hermes Desktop placement and Desktop status on Windows (C11).

Real confidential/private admission on a profile-style shared home whose name
has a space and non-ASCII characters (``共有 home``), and the real ``win32``
platform decision (nothing patches ``install._platform`` or the openers).
Host-skipped off Windows; selected by the scoped Windows CI job. The live,
real-CNG Desktop memory flow is the gated recipe in
``tests/test_desktop_windows_live.py``. Correct by reading until a Windows run.
"""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.desktop import install
from tests.test_private_fs_confidential_windows import descriptor, powershell
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS Desktop placement")


def page_dir(home):
    return home / "desktop-plugins" / "mordred"


@pytest.fixture
def desktop_home(shared_home):
    """The shared home with a mapping ``config.yaml`` (the fixture seeds a scalar) for the plugin-enable step."""
    (shared_home / "config.yaml").write_bytes(b"plugins:\n  enabled: []\n")
    return shared_home


def test_native_install_and_removal_in_a_unicode_home(desktop_home, capsys):
    home = desktop_home
    home_before = descriptor(home)
    assert install.install(home) == 0
    out = capsys.readouterr().out
    assert f'"{page_dir(home) / "plugin.js"}"' in out
    for directory in (page_dir(home), home / "plugins" / "mordred", home / "plugins" / "mordred" / "dashboard"):
        with open_private_directory(directory):  # the exact private DACL validates
            pass
    assert descriptor(home) == home_before, "no ACL repair on the inherited home"
    assert install.ensure_page(home) is False

    assert install.uninstall(home) == 0
    assert not (page_dir(home) / "plugin.js").exists()
    assert page_dir(home).is_dir() and (page_dir(home) / ".mordred-fs.lock").exists(), "directories and locks stay"
    assert install.status(home) == 1


def test_native_inherited_mordred_folder_refuses_without_acl_repair(desktop_home, capsys):
    home = desktop_home
    os.makedirs(page_dir(home))  # inherited, not the exact private DACL
    before = descriptor(page_dir(home))
    assert install.install(home) == 1
    err = capsys.readouterr().err
    assert "(unsafe)" in err and f'"{page_dir(home)}"' in err
    assert descriptor(page_dir(home)) == before
    assert not (page_dir(home) / "plugin.js").exists()


def test_native_broadened_shared_parent_refuses_before_any_mordred_write(desktop_home, capsys):
    home = desktop_home
    shared = home / "plugins"
    shared.mkdir()
    powershell(
        shared,
        """
    $a=Get-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE;
    $f='ContainerInherit,ObjectInherit';
    $r=New-Object Security.AccessControl.FileSystemAccessRule('Everyone','Modify',$f,'None','Allow');
    $a.AddAccessRule($r); Set-Acl -LiteralPath $env:MORDRED_ACL_FIXTURE -AclObject $a
    """,
    )
    before = descriptor(shared)
    assert install.install(home) == 1
    assert "(unsafe)" in capsys.readouterr().err
    assert descriptor(shared) == before
    assert list(shared.iterdir()) == []
    assert not page_dir(home).exists(), "no Mordred folder or asset is created after a refused parent"


def test_native_desktop_status_reads_real_predicates_without_a_subprocess(shared_home, monkeypatch):
    pytest.importorskip("fastapi")
    from mordred_hermes.desktop import api

    monkeypatch.setattr(api, "_home", lambda: shared_home)

    async def model() -> dict[str, object]:
        return {"ok": False, "kind": "other", "model": None, "private": None}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)

    def spawn(*args, **kwargs):
        pytest.fail("status must not launch a subprocess")

    monkeypatch.setattr(subprocess, "Popen", spawn)
    result = asyncio.run(api.status(client_version=3))
    assert result["hardware_kind"] == "cng" and result["user_presence_supported"] is False
    names = [row["name"] for row in result["capabilities"]]
    assert names[:3] == ["memory_custody", "native_audit", "telegram_hardware"]
    assert result["memory"]["state"] in ("off", "unavailable")
    old = asyncio.run(api.status(client_version=2))
    assert old["telegram_supported"] is False and old["checks"] == {}


def test_native_status_and_removal_on_a_home_without_desktop_folders(desktop_home, capsys):
    """The real Windows opener reports a missing ``plugins``/``desktop-plugins`` as ``missing``/``open``: absence."""
    home = desktop_home
    assert install.status(home) == 1
    err = capsys.readouterr().err
    assert "not installed" in err and "could not be checked" not in err
    assert install.uninstall(home) == 0
    captured = capsys.readouterr()
    assert "Removed" not in captured.out and "could not be checked" not in captured.err
    assert not (home / "desktop-plugins").exists() and not (home / "plugins").exists(), "reads create nothing"
    with pytest.raises(PrivateFSError), open_private_directory(home / "absent" / "mordred", create=True):
        pass
    assert not (home / "absent").exists()
