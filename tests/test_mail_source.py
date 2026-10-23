"""Read-only mail sources: mbox splitting, escapes, size guard and file-type refusal."""

from __future__ import annotations

import os
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

from mordred_hermes.imports.mail import source as source_mod
from mordred_hermes.imports.mail.source import (
    EmlBytes,
    EmlSource,
    MboxBytes,
    MboxSource,
    SourceError,
    iter_raw,
)

FIXTURES = Path(__file__).parent / "fixtures" / "mail"
PACKAGE = Path(source_mod.__file__).parent


def _raw(source: object) -> tuple[list[bytes], Counter[str]]:
    stats: Counter[str] = Counter()
    return [item.data for item in iter_raw(source, stats)], stats  # type: ignore[arg-type]


def test_takeout_mbox_splits_every_message_in_order() -> None:
    stats: Counter[str] = Counter()
    raws = list(iter_raw(MboxSource(FIXTURES / "takeout_small.mbox"), stats))
    assert [raw.origin_index for raw in raws] == list(range(7))
    assert all(raw.data.startswith(b"X-GM-THRID: ") for raw in raws)
    assert not stats


def test_mboxo_escapes_are_undone_and_body_from_lines_do_not_split() -> None:
    first, second = _raw(MboxSource(FIXTURES / "mboxo_from_escape.mbox"))[0]
    assert b"\nFrom the start of this line, escaped by the writer.\n" in first
    assert b"\n>From a line that really began with a greater-than sign.\n" in first
    assert b"\nFrom here on this is body text, not a separator.\n" in first
    assert b">From the start" not in first
    # The blank line that precedes the next From_ line is mbox framing, not content.
    assert first.endswith(b"not a separator.\n")
    assert second.endswith(b"CANARY-ESC-2\r\n")
    assert b"\r\nSubject: crlf message\r\n" in second


def test_crlf_separator_lines_are_recognised() -> None:
    data = (
        b"From a@b Mon Oct  5 10:00:00 2026\r\nSubject: one\r\n\r\nx\r\n\r\n"
        b"From a@b Mon Oct  5 11:00:00 2026\r\nSubject: two\r\n\r\ny\r\n"
    )
    messages, _stats = _raw(MboxBytes(data))
    assert [m.split(b"\r\n", 1)[0] for m in messages] == [b"Subject: one", b"Subject: two"]


def test_oversize_messages_are_skipped_and_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_mod, "MAX_MESSAGE_BYTES", 200)
    big = b"Subject: big\n\n" + b"x" * 400 + b"\n"
    data = b"From a Mon Oct  5 10:00:00 2026\nSubject: s1\n\none\n\n"
    data += b"From a Mon Oct  5 10:00:00 2026\n" + big + b"\n"
    data += b"From a Mon Oct  5 10:00:00 2026\nSubject: s3\n\nthree\n"
    stats: Counter[str] = Counter()
    raws = list(iter_raw(MboxBytes(data), stats))
    assert [raw.origin_index for raw in raws] == [0, 2]
    assert stats["skipped_oversize"] == 1
    assert list(iter_raw(EmlBytes([big]), stats)) == []
    assert stats["skipped_oversize"] == 2


def test_very_long_lines_arrive_intact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_mod, "_CHUNK", 64)
    line = b"From " + b"y" * 300 + b"\n"  # starts with From_ but is one long body line
    data = b"From a Mon Oct  5 10:00:00 2026\nSubject: s\n\nbody\n" + line
    (message,), _stats = _raw(MboxBytes(data))
    assert message.endswith(line)


def test_leading_content_without_separator_is_counted_not_imported() -> None:
    data = b"stray text\n\nFrom a Mon Oct  5 10:00:00 2026\nSubject: s\n\nbody\n"
    messages, stats = _raw(MboxBytes(data))
    assert len(messages) == 1
    assert stats["skipped_no_separator"] == 1


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:  # e.g. Windows without the symlink privilege
        pytest.skip("symlinks unavailable")


def test_symlink_directory_and_missing_paths_are_refused(tmp_path: Path) -> None:
    link = tmp_path / "link.mbox"
    _symlink(link, FIXTURES / "takeout_small.mbox")
    for source, code in (
        (MboxSource(link), "not_regular_file"),
        (MboxSource(tmp_path), "not_regular_file"),
        (MboxSource(tmp_path / "missing.mbox"), "not_found"),
        (EmlSource(tmp_path / "missing.eml"), "not_found"),
    ):
        with pytest.raises(SourceError) as info:
            list(iter_raw(source, Counter()))
        assert info.value.code == code
    assert not (tmp_path / "missing.mbox").exists()  # a missing source is never created


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFOs")
def test_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.mbox"
    os.mkfifo(fifo)
    with pytest.raises(SourceError) as info:
        list(iter_raw(MboxSource(fifo), Counter()))
    assert info.value.code == "not_regular_file"


def test_eml_directory_is_sorted_by_name_and_skips_non_regular_entries(tmp_path: Path) -> None:
    (tmp_path / "b.eml").write_bytes(b"Subject: b\n\nB\n")
    (tmp_path / "a.eml").write_bytes(b"Subject: a\n\nA\n")
    (tmp_path / "notes.txt").write_bytes(b"ignored")
    _symlink(tmp_path / "c.eml", FIXTURES / "bot_noreply.eml")
    messages, stats = _raw(EmlSource(tmp_path))
    assert messages == [b"Subject: a\n\nA\n", b"Subject: b\n\nB\n"]
    assert stats["skipped_not_regular"] == 1


def test_sources_are_only_opened_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    flags: list[int] = []
    real_open = os.open

    def recording_open(path: object, flag: int, *args: object) -> int:
        flags.append(flag)
        return real_open(path, flag, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(source_mod.os, "open", recording_open)
    list(iter_raw(MboxSource(FIXTURES / "takeout_small.mbox"), Counter()))
    list(iter_raw(EmlSource(FIXTURES), Counter()))
    assert flags
    assert all(flag & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC) == 0 for flag in flags)


def test_package_never_uses_mailbox_tempfile_or_logging() -> None:
    forbidden = re.compile(r"^\s*(?:import|from)\s+(?:mailbox|tempfile|logging)\b", re.MULTILINE)
    for path in sorted(PACKAGE.glob("*.py")):
        assert not forbidden.search(path.read_text(encoding="utf-8")), path.name
