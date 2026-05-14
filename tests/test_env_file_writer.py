"""Tests for ``mordred_hermes.wizard.env_file_writer`` (Phase 3 PR3a Task #6b).

The DotEnvFileWriter upserts ``KEY=value`` lines into ``~/.hermes/.env`` at
mode 0600 without disturbing unrelated lines a user may have hand-edited.
PolicyWriter's atomic-write pipeline (tempfile + os.replace) is reused so a
crash mid-write leaves the previous file intact.

Tests cover:
- Creates file with mode 0600 when absent
- Creates parent directory with mode 0700
- Upserts a key value idempotently (no mtime change on repeat write)
- Replaces a value when the same key already exists
- Preserves unrelated lines (other env vars + comments)
- Refuses non-uppercase / non-identifier keys (defence against
  shell-injection from policy.json)
- Empty value short-circuits to "remove the line if present"
- Protocol structural conformance
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


class TestDotEnvFileWriter:
    def test_creates_file_with_0600_mode_when_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / "subdir" / ".env"
        w = DotEnvFileWriter()
        w.upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="abc123")

        assert env_path.exists()
        mode = stat.S_IMODE(os.stat(env_path).st_mode)
        assert mode == 0o600, f"expected 0o600, got 0o{mode:o}"

    def test_creates_parent_dir_with_0700_mode(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / "freshdir" / ".env"
        DotEnvFileWriter().upsert(env_path, key="FOO", value="bar")
        parent_mode = stat.S_IMODE(os.stat(env_path.parent).st_mode)
        assert parent_mode == 0o700, f"parent mode {parent_mode:o}"

    def test_idempotent_repeat_does_not_touch_mtime(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        w = DotEnvFileWriter()
        w.upsert(env_path, key="FOO", value="bar")
        first_mtime = env_path.stat().st_mtime_ns
        w.upsert(env_path, key="FOO", value="bar")
        assert env_path.stat().st_mtime_ns == first_mtime

    def test_replaces_existing_value(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        env_path.write_text("FOO=old\nBAR=keep\n", encoding="utf-8")
        DotEnvFileWriter().upsert(env_path, key="FOO", value="new")

        body = env_path.read_text(encoding="utf-8")
        assert "FOO=new" in body
        assert "FOO=old" not in body
        assert "BAR=keep" in body

    def test_preserves_comments_and_unrelated_lines(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        env_path.write_text(
            "# user-owned env file\n"
            "# Mordred extends -- do not delete this header\n"
            "MY_OPENAI_KEY=sk-redacted\n"
            "PATH_HACK=/opt/bin\n",
            encoding="utf-8",
        )
        DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="acc-xyz")

        body = env_path.read_text(encoding="utf-8")
        assert "# user-owned env file" in body
        assert "MY_OPENAI_KEY=sk-redacted" in body
        assert "PATH_HACK=/opt/bin" in body
        assert "MORDRED_MULLVAD_ACCOUNT=acc-xyz" in body

    def test_appends_to_end_when_key_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        env_path.write_text("EXISTING=1\n", encoding="utf-8")
        DotEnvFileWriter().upsert(env_path, key="NEW_KEY", value="2")

        body = env_path.read_text(encoding="utf-8")
        lines = body.strip().splitlines()
        assert lines[-1] == "NEW_KEY=2"

    def test_empty_value_removes_existing_line(self, tmp_path: Path) -> None:
        """When the user clears the Mullvad account prompt, the writer must
        remove the line rather than leaving an empty ``KEY=`` (which some
        env loaders interpret as the empty string and pass to ``mullvad``)."""
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        env_path.write_text("FOO=existing\nBAR=keep\n", encoding="utf-8")
        DotEnvFileWriter().upsert(env_path, key="FOO", value="")

        body = env_path.read_text(encoding="utf-8")
        assert "FOO=" not in body
        assert "BAR=keep" in body

    def test_empty_value_no_op_when_key_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        env_path.write_text("BAR=keep\n", encoding="utf-8")
        first_mtime = env_path.stat().st_mtime_ns
        DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="")
        assert env_path.stat().st_mtime_ns == first_mtime, "empty value + absent key must no-op"

    def test_refuses_invalid_key(self, tmp_path: Path) -> None:
        """Keys must be valid POSIX env-var names. ``foo`` lowercase, or
        anything with ``;`` or spaces, could be shell-injection vectors via
        downstream tools that ``eval`` .env files."""
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        w = DotEnvFileWriter()
        for bad_key in ("foo", "FOO BAR", "FOO=BAD", "FOO\nBAR"):
            with pytest.raises(ValueError):
                w.upsert(env_path, key=bad_key, value="x")

    def test_refuses_value_with_newline(self, tmp_path: Path) -> None:
        """A newline in the value would create a second KEY=... line."""
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        with pytest.raises(ValueError):
            DotEnvFileWriter().upsert(env_path, key="FOO", value="bar\nINJECTED=evil")


class TestEnvFileWriterProtocol:
    def test_dotenvfilewriter_satisfies_protocol(self) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter, EnvFileWriter

        w: EnvFileWriter = DotEnvFileWriter()
        assert w is not None
