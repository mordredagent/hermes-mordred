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
import threading
from pathlib import Path

import pytest

from tests._checked_fixture_helpers import assert_private, seed_private_file, seed_private_text
from tests._checked_fixture_helpers import file_symlink as file_symlink
from tests._checked_fixture_helpers import tmp_path as tmp_path


class TestDotEnvFileWriter:
    def test_creates_file_with_0600_mode_when_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / "subdir" / ".env"
        w = DotEnvFileWriter()
        w.upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="abc123")

        assert env_path.exists()
        assert_private(env_path)

    def test_creates_parent_dir_with_0700_mode(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / "freshdir" / ".env"
        DotEnvFileWriter().upsert(env_path, key="FOO", value="bar")
        assert_private(env_path.parent, directory=True)

    def test_unreadable_existing_file_is_never_replaced(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import _config_text_io
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        original = b"OPENAI_API_KEY=keep-me\n"
        seed_private_file(env_path, original)
        hits = []
        if os.name == "nt":
            from mordred_hermes._private_fs import PrivateFSError, _windows_io

            real_read = _windows_io._Transaction.read_bytes

            def deny_read(tx, name, *, max_bytes):
                if name == ".env":
                    hits.append(name)
                    raise PrivateFSError("unsafe", "injected_dotenv_read")
                return real_read(tx, name, max_bytes=max_bytes)

            monkeypatch.setattr(_windows_io._Transaction, "read_bytes", deny_read)
            expected, message = PrivateFSError, "injected_dotenv_read"
        else:
            real_open = _config_text_io.os.open

            def deny_target_read(path: object, *args: object, **kwargs: object) -> int:
                if os.fspath(path) == os.fspath(env_path):
                    hits.append(".env")
                    raise PermissionError("simulated ACL denial")
                return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

            monkeypatch.setattr(_config_text_io.os, "open", deny_target_read)
            expected, message = PermissionError, "ACL denial"
        with pytest.raises(expected, match=message):
            DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="new")
        assert hits == [".env"]

        assert env_path.read_bytes() == original

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
        seed_private_text(env_path, "FOO=old\nBAR=keep\n", encoding="utf-8")
        DotEnvFileWriter().upsert(env_path, key="FOO", value="new")

        body = env_path.read_text(encoding="utf-8")
        assert "FOO=new" in body
        assert "FOO=old" not in body
        assert "BAR=keep" in body

    def test_preserves_comments_and_unrelated_lines(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        seed_private_text(
            env_path,
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
        seed_private_text(env_path, "EXISTING=1\n", encoding="utf-8")
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
        seed_private_text(env_path, "FOO=existing\nBAR=keep\n", encoding="utf-8")
        DotEnvFileWriter().upsert(env_path, key="FOO", value="")

        body = env_path.read_text(encoding="utf-8")
        assert "FOO=" not in body
        assert "BAR=keep" in body

    def test_empty_value_no_op_when_key_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        seed_private_file(env_path, b"BAR=keep\n")
        first_mtime = env_path.stat().st_mtime_ns
        DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="")
        assert env_path.stat().st_mtime_ns == first_mtime, "empty value + absent key must no-op"

    def test_crlf_normalizes_once_then_is_a_true_no_op(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        seed_private_file(env_path, b"BAR=old\r\n")
        writer = DotEnvFileWriter()
        writer.upsert(env_path, key="BAR", value="keep")
        assert env_path.read_bytes() == b"BAR=keep\n"
        before = env_path.stat()
        writer.upsert(env_path, key="BAR", value="keep")
        after = env_path.stat()
        assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
        assert env_path.read_bytes() == b"BAR=keep\n"
        assert_private(env_path)

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

    def test_dedupes_when_existing_file_has_multiple_matching_lines(self, tmp_path: Path) -> None:
        """M2 (review 2026-05-14): if the .env was hand-edited and ended up
        with two lines for the same key, the upsert must collapse them to
        a single line with the new value -- not preserve the duplicate.

        Before the fix, _replace_or_strip_key rewrote every matching line
        in place, leaving the duplicate intact (``KEY=new\\nKEY=new``).
        After the fix, only the first match is kept; subsequent matches
        are stripped.
        """
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        seed_private_text(
            env_path, "OTHER=keep\nMORDRED_MULLVAD_ACCOUNT=old1\nMORDRED_MULLVAD_ACCOUNT=old2\n", encoding="utf-8"
        )

        DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="new")

        text = env_path.read_text(encoding="utf-8")
        occurrences = [line for line in text.splitlines() if line.startswith("MORDRED_MULLVAD_ACCOUNT=")]
        assert occurrences == ["MORDRED_MULLVAD_ACCOUNT=new"], (
            f"M2: expected exactly one MORDRED_MULLVAD_ACCOUNT line after dedupe, got {occurrences}; "
            "duplicates from hand-edit must collapse"
        )
        # Unrelated line must survive.
        assert "OTHER=keep" in text

    def test_dedupes_on_empty_value_removal(self, tmp_path: Path) -> None:
        """M2 corollary: removal (empty value) of a key that appears twice
        must strip both lines, not just the first."""
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        seed_private_text(
            env_path, "OTHER=keep\nMORDRED_MULLVAD_ACCOUNT=old1\nMORDRED_MULLVAD_ACCOUNT=old2\n", encoding="utf-8"
        )

        DotEnvFileWriter().upsert(env_path, key="MORDRED_MULLVAD_ACCOUNT", value="")

        text = env_path.read_text(encoding="utf-8")
        assert "MORDRED_MULLVAD_ACCOUNT" not in text, (
            f"M2: empty-value removal must strip ALL duplicate lines for the key, got:\n{text}"
        )
        assert "OTHER=keep" in text

    def test_refuses_symlink_without_touching_target(self, tmp_path: Path, file_symlink: None) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        target = tmp_path / "outside.env"
        seed_private_text(target, "KEEP=secret\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.symlink_to(target)

        with pytest.raises(OSError, match="unsafe" if os.name == "nt" else "regular file"):
            DotEnvFileWriter().upsert(env_path, key="FOO", value="bar")

        assert env_path.is_symlink()
        assert target.read_text(encoding="utf-8") == "KEEP=secret\n"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
    def test_refuses_fifo_without_blocking(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter

        env_path = tmp_path / ".env"
        os.mkfifo(env_path, mode=0o600)
        done = threading.Event()
        failures: list[BaseException] = []

        def attempt() -> None:
            try:
                DotEnvFileWriter().upsert(env_path, key="FOO", value="bar")
            except OSError:
                pass
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)
            finally:
                done.set()

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        assert done.wait(timeout=1), "dotenv reader blocked while opening a FIFO"
        worker.join(timeout=1)
        assert failures == []

    def test_slack_and_wizard_writers_share_one_rmw_lock(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes import _dotenv_io
        from mordred_hermes.extension import api as extension_api
        from mordred_hermes.wizard import env_file_writer

        env_path = tmp_path / ".env"
        seed_private_text(env_path, "KEEP=unchanged\n", encoding="utf-8")
        real_updated_env_text = extension_api._updated_env_text
        slack_in_transform = threading.Event()
        release_slack = threading.Event()
        wizard_done = threading.Event()
        failures: list[BaseException] = []

        def delayed_transform(existing: str, updates: dict[str, str]) -> str:
            # The transform runs inside both the POSIX and Windows transactions.
            slack_in_transform.set()
            if not release_slack.wait(timeout=5):
                raise RuntimeError("test release timed out")
            return real_updated_env_text(existing, updates)

        def write_slack() -> None:
            try:
                extension_api._upsert_env_vars(env_path, {"SLACK_BOT_TOKEN": "xoxb-new"})
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        def write_wizard() -> None:
            try:
                env_file_writer.DotEnvFileWriter().upsert(
                    env_path,
                    key="MORDRED_MULLVAD_ACCOUNT",
                    value="account",
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                failures.append(exc)
            finally:
                wizard_done.set()

        monkeypatch.setattr(extension_api, "_updated_env_text", delayed_transform)
        slack = threading.Thread(target=write_slack, name="slack-writer")
        wizard = threading.Thread(target=write_wizard, name="wizard-writer")
        slack.start()
        try:
            assert slack_in_transform.wait(timeout=5)
            wizard.start()
            assert not wizard_done.wait(timeout=0.1), "wizard bypassed the shared dotenv lock"
        finally:
            release_slack.set()
            slack.join(timeout=5)
            if wizard.ident is not None:
                wizard.join(timeout=5)

        assert not slack.is_alive() and not wizard.is_alive()
        assert failures == []
        text = env_path.read_text(encoding="utf-8")
        assert "KEEP=unchanged" in text
        assert "SLACK_BOT_TOKEN=xoxb-new" in text
        assert "MORDRED_MULLVAD_ACCOUNT=account" in text
        if not _dotenv_io._windows():
            assert stat.S_IMODE((tmp_path / ".env.lock").stat().st_mode) == 0o600


class TestEnvFileWriterProtocol:
    def test_dotenvfilewriter_satisfies_protocol(self) -> None:
        from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter, EnvFileWriter

        w: EnvFileWriter = DotEnvFileWriter()
        assert w is not None
