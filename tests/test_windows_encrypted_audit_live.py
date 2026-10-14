"""Controller-only live CNG in a new UUID audit fixture, never an existing role.

Requires MORDRED_TEST_WINDOWS_AUDIT_LIVE=1 and an already existing retained
MORDRED_WINDOWS_AUDIT_TEST_ROOT. Failure leaves fixture/journals untouched for
reconciliation. Cleanup follows successful authentication of every known log.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_CHILD = """
import sys
from pathlib import Path
from mordred_hermes.keyvault.windows_audit import WindowsAuditProvider, decrypt_windows_log_file
home=Path(sys.argv[1]); path=home/'mordred'/'audit.log'
writer=WindowsAuditProvider(home).writer(path)
writer.append({'event':'live-child'})
writer.close()
entries=decrypt_windows_log_file(path, home=home, audit_sink=lambda event: None)
assert len(entries)==1 and entries[0]['event']=='live-child', 'audit roundtrip failed'
print('audit-child-verified', flush=True)
"""


@pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("MORDRED_TEST_WINDOWS_AUDIT_LIVE") != "1",
    reason="explicit ordinary-user Windows CNG audit fixture only",
)
def test_live_unique_audit_role_fresh_process_and_retained_history():
    from mordred_hermes._audit_session import audit_session
    from mordred_hermes._log_rotation import audit_rotation_names
    from mordred_hermes._private_fs import open_confidential_directory
    from mordred_hermes.keyvault._runtime_probe import require_stopped_windows_gateways
    from mordred_hermes.keyvault._windows_custody import windows_custody_session
    from mordred_hermes.keyvault.windows_audit import WindowsAuditProvider, decrypt_windows_log_file

    value = os.environ.get("MORDRED_WINDOWS_AUDIT_TEST_ROOT")
    if not value:
        pytest.fail("a retained isolated audit validation root is required")
    root = Path(value)
    with open_confidential_directory(root):
        pass
    home = root / ("audit-" + uuid.uuid4().hex)
    require_stopped_windows_gateways(home)
    print(f"Isolated audit fixture: {home}")
    path = home / "mordred" / "audit.log"
    with windows_custody_session(home, create=True) as session:
        old = session.enroll_role("audit")
    writer = WindowsAuditProvider(home).writer(path)
    writer.append({"event": "live-parent"})
    writer.close()
    result = subprocess.run([sys.executable, "-c", _CHILD, str(home)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, "fresh-process audit verification failed"
    assert result.stdout.strip() == "audit-child-verified"
    with windows_custody_session(home) as session:
        current = session.enroll_role("audit", retain_current=True)
    writer = WindowsAuditProvider(home).writer(path)
    writer.append({"event": "live-current"})
    writer.close()
    known = [path, *path.parent.glob("audit.log.*.gz")]
    events = []
    for candidate in known:
        events += decrypt_windows_log_file(candidate, home=home, audit_sink=lambda event: None)
    assert sorted(event["event"] for event in events) == ["live-child", "live-current", "live-parent"]
    # Only known UUID fixture roles/history are erased. No unknown custom path,
    # old fixture key, user profile, or recursive tree is part of this recipe.
    with windows_custody_session(home) as session, session.canonical.borrow_mordred_transaction() as loan:
        with audit_session(path, transaction=loan) as audit:
            names = [path.name, *(row[0] for row in audit_rotation_names(audit))]
            assert set(names) == {candidate.name for candidate in known}, "audit history inventory changed"
            for name in names:
                snapshot = audit.snapshot(name, max_bytes=16 * 1024 * 1024 + 65536)
                assert snapshot is not None
                audit.delete(name, expected_identity=snapshot.metadata.identity)
        session.delete_role(old, erase_authorized=True)
        session.delete_role(current, erase_authorized=True)
