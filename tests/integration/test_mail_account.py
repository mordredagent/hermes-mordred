"""Separately opted-in real IMAP connectivity; never part of native DB acceptance.

MORDRED_MAIL_ACCOUNT_TEST=1 explicitly authorizes LOGIN/LIST/LOGOUT on the
isolated test account. MORDRED_MAIL_ACCOUNT_FILE points to a pre-existing private
0600 MailCredentials JSON file injected by the operator, never written by tests.
No credentials, account address, mailbox names, or server output are printed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_opted_in_mail_account_connectivity() -> None:
    if os.environ.get("MORDRED_MAIL_ACCOUNT_TEST") != "1":
        pytest.skip("requires separate MORDRED_MAIL_ACCOUNT_TEST=1 authorization")
    selected = os.environ.get("MORDRED_MAIL_ACCOUNT_FILE")
    if not selected:
        pytest.fail("explicit private account fixture is required", pytrace=False)
    path = Path(selected)
    if not path.is_absolute() or path != path.resolve(strict=True):
        pytest.fail("account fixture must have a canonical absolute path", pytrace=False)
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.imports.mail.imap import IoLimits, connect
    from mordred_hermes.imports.mail.secrets import decode

    try:
        with open_private_directory(path.parent) as directory:
            credentials = decode(directory.read_bytes(path.name, max_bytes=65536))
        session = connect(credentials.imap_host, credentials.imap_port, limits=IoLimits.for_budget(30))
        try:
            session.login(credentials.address, credentials.app_password)
            assert isinstance(session.list_mailboxes(), list)
        finally:
            session.logout()
    except Exception:
        # Do not expose traceback frames that can hold the injected credential.
        pytest.fail("explicit account connectivity failed", pytrace=False)
