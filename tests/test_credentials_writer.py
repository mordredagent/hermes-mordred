"""Tests for ``mordred_hermes.wizard.credentials_writer`` (Phase 3 PR3a Task #6b).

JSONCredentialsWriter persists ``~/.hermes/mordred/credentials/network.json``
with env-var REFERENCES (not the secrets themselves). The dir is 0700 + the
file 0600 to match PATHS.md §192 (Phase 3 credentials directory contract).

Tests cover:
- Creates the credentials directory at mode 0700 when absent
- Creates the file at mode 0600
- JSON shape matches the documented contract (env-var refs only, no
  secret values inline)
- Idempotent (no mtime change on repeat write)
- Atomic (tempfile + replace; partial writes recover from prior content)
- Refuses to embed a value that looks like a secret rather than an
  env-var name
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest


class TestJSONCredentialsWriter:
    def test_creates_dir_at_0700_and_file_at_0600(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

        credentials_path = tmp_path / "credentials" / "network.json"
        w = JSONCredentialsWriter()
        w.write_network(
            credentials_path,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
        assert credentials_path.exists()
        dir_mode = stat.S_IMODE(os.stat(credentials_path.parent).st_mode)
        file_mode = stat.S_IMODE(os.stat(credentials_path).st_mode)
        assert dir_mode == 0o700, f"dir mode 0o{dir_mode:o}"
        assert file_mode == 0o600, f"file mode 0o{file_mode:o}"

    def test_json_shape_matches_contract(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

        path = tmp_path / "network.json"
        JSONCredentialsWriter().write_network(
            path,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
        )
        body = json.loads(path.read_text(encoding="utf-8"))
        assert body == {
            "mullvad": {
                "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
                "relay_country": "jp",
                "killswitch": True,
            }
        }

    def test_idempotent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

        path = tmp_path / "network.json"
        w = JSONCredentialsWriter()
        w.write_network(
            path,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        first_mtime = path.stat().st_mtime_ns
        w.write_network(
            path,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        assert path.stat().st_mtime_ns == first_mtime

    def test_no_secret_value_inline(self, tmp_path: Path) -> None:
        """The contract is env-var-ref-only. Passing an actual secret-shaped
        value (no MORDRED_ prefix? trailing digits? — anything that doesn't
        look like an env-var name) must be refused."""
        from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

        path = tmp_path / "network.json"
        w = JSONCredentialsWriter()
        for bad_env_ref in (
            "actual-account-1234567",  # looks like a secret
            "mullvad-account",  # lowercase + hyphens — not a valid env name
            "MORDRED MULLVAD",  # space
        ):
            with pytest.raises(ValueError):
                w.write_network(
                    path,
                    mullvad_account_id_env=bad_env_ref,
                    mullvad_relay_country="auto",
                    mullvad_killswitch=False,
                )

    def test_atomic_write_no_lingering_tmp(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

        path = tmp_path / "credentials" / "network.json"
        JSONCredentialsWriter().write_network(
            path,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        leftovers = sorted(p.name for p in tmp_path.rglob("*.tmp"))
        assert leftovers == [], f"unexpected .tmp leftovers: {leftovers}"


class TestCredentialsWriterProtocol:
    def test_json_writer_satisfies_protocol(self) -> None:
        from mordred_hermes.wizard.credentials_writer import (
            CredentialsWriter,
            JSONCredentialsWriter,
        )

        w: CredentialsWriter = JSONCredentialsWriter()
        assert w is not None
