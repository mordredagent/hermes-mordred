"""Explicit activity acceptance using existing native custody and real SQLCipher.

No provisioning or qualification override occurs here. Native execution belongs
 to the parent/operator. All fixtures, registered backups and keys are retained.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("MORDRED_DBCRYPT_ACTIVITY_NATIVE_TEST") != "1",
        reason="explicit native activity database acceptance",
    ),
]

_SCRIPT = r"""
import os, sys, uuid
from pathlib import Path
root = Path(os.environ['MORDRED_DBCRYPT_TEST_ROOT'])
assert os.environ['HERMES_HOME'] == str(root)
from mordred_hermes.keyvault import kek
kek._noop_audit = lambda entry: None
import sqlcipher3.dbapi2 as driver
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.activity._gate import ActivityRefused, _open_guarded, check_protection
from mordred_hermes.activity._paths import store_path
from mordred_hermes.activity.contracts import normalize_event
from mordred_hermes.activity.store import ActivityStore, restore_activity_store
from mordred_hermes.dbcrypt import _migrate
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._marker import Marker, read_marker
from mordred_hermes.imports._protected_destination import checked_import_source
if os.name == 'nt':
    import ctypes
    from mordred_hermes.dbcrypt._windows_vfs import NATIVE_QUALIFIED
    assert not ctypes.windll.shell32.IsUserAnAdmin(), 'ordinary token required'
    assert NATIVE_QUALIFIED, 'native VFS qualification remains incomplete; no override is permitted here'
assert isinstance(read_marker(root), Marker), 'pre-enrolled/adopted native fixture required'
name = 'activity-native-' + uuid.uuid4().hex
with open_private_directory(root), open_private_directory(root / 'profiles', create=True):
    pass
home = root / 'profiles' / name
with open_private_directory(home, create=True):
    pass
print('Retained native activity fixture:', home, flush=True)
authority = Authority.acquire(home)
def opening(path):
    return _open_guarded(path, authority=authority, timeout=2)
try:
    path = store_path(home)
    store = ActivityStore(path, opening, authority=authority)
    store.initialize(home)
    if sys.argv[1] == 'roundtrip':
        raw = {
            'event_id': '1029743a-d98a-48bb-a6dc-655062261e38', 'seq': 1,
            'episode_id': 'native-japanese', 'source': 'operator', 'actor': 'human',
            'observed_at': 1001.0, 'phase': 'boundary',
            'action': {'op': 'task_start', 'site': 'example.com'},
            'text': '今日は東京で日本語を勉強します',
            'result': {'status': 'unknown'}, 'quality': {'coverage': 'selected_tab'},
            'session_ref': {'hermes_session_id': 'previous-native-session'},
        }
        event = normalize_event(raw, excluded_sites=frozenset())
        assert store.append_batch('operator:native', 'native-producer', [event]).accepted == 1
        assert store.append_batch('operator:native', 'native-producer', [event]).accepted == 0
        from mordred_hermes.activity import history
        found = history.episodes_for_terms(store, {'日本', '本語'}, excluded_sites=frozenset(), since=0, until=2000)
        assert [item.episode_id for item in found.episodes] == ['native-japanese']
        assert [item.event_id for item in store.events_for_episode('native-japanese')] == [raw['event_id']]
        original = store.events_for_episode('native-japanese')
        generation = store.meta().store_generation
        backup = root.parent / (root.name + '-' + name + '.backup')
        store.backup(backup)
        print('Retained native registered backup:', backup, flush=True)
    else:
        assert os.name == 'nt'
        directory = home / 'extension'
        with open_private_directory(directory, create=True):
            pass
        source = directory / 'peer-export.jsonl'
        source.write_bytes(b'{"producer":"original"}\n')
        from mordred_hermes._private_fs._windows_paths import checked_directory
        from mordred_hermes._private_fs._windows_security import validate_confidential_file
        with checked_directory(directory) as parent:
            api = parent.handle.api
            bound = parent.path.rstrip('\\') + '\\' + source.name
            with api.open(bound, share=1) as held:
                validate_confidential_file(held)
                replacement = directory / 'replacement.jsonl'
                replacement.write_bytes(b'{"producer":"replacement"}\n')
                try:
                    os.replace(replacement, source)
                except OSError:
                    pass
                else:
                    raise AssertionError('native checked read handle permitted a swapped source')
                with checked_import_source(source, home=home) as checked:
                    assert checked.read() == b'{"producer":"original"}\n'
        for kind in ('hardlink', 'reparse'):
            alias = directory / (kind + '.jsonl')
            if kind == 'hardlink':
                os.link(source, alias)
            else:
                os.symlink(source, alias)
            try:
                try:
                    with checked_import_source(alias, home=home):
                        raise AssertionError('unsafe peer source was admitted')
                except ActivityRefused:
                    pass
                assert store.status().counts['activity_events'] == 0
            finally:
                alias.unlink()
finally:
    authority.close()
if sys.argv[1] == 'roundtrip':
    assert _migrate.holders([path, backup]) == [], 'real native quiescence proof required'
    with acquire_exclusive(root) as lease:
        meta = restore_activity_store(backup, home=home, lease=lease)
    authority = Authority.acquire(home)
    try:
        restarted = ActivityStore(path, opening, authority=authority)
        assert restarted.events_for_episode('native-japanese') == original
        assert meta.store_generation != generation
        assert restarted.episode('native-japanese').session_ref_state == 'unavailable'
    finally:
        authority.close()
"""


def _run(operation: str) -> None:
    selected = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    assert selected, "explicit pre-provisioned synthetic root required"
    root = Path(selected)
    assert root.is_absolute() and root.is_dir() and root == root.resolve(strict=True)
    assert root.name.startswith("mordred-dbcrypt-")
    production = Path.home() / ".hermes"
    assert root != production and production not in root.parents
    assert sys.platform in {"linux", "win32"}, "native activity gate requires TPM or CNG"
    helper_name = "MORDRED_TPMKEY_HELPER" if sys.platform == "linux" else "MORDRED_WINKEY_HELPER"
    helper = os.environ.get(helper_name)
    assert helper and Path(helper).is_absolute() and Path(helper).is_file(), "explicit installed native helper required"
    assert not os.environ.get("MORDRED_TPM_TEST"), "emulators are not native acceptance"
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT, operation],
        env={**os.environ, "HERMES_HOME": str(root)},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_activity_roundtrip_dedup_search_restart_backup() -> None:
    _run("roundtrip")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows checked peer source handles")
def test_windows_peer_swap_refuses() -> None:
    _run("sources")
