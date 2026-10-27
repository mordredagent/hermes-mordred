"""Import one local source into ``mordred.db``: changed files only, one run, one writer.

- One writer per source and home: ``<home>/mordred/imports/local-<source>.lock``
  (``flock``); a second import while one runs is refused with ``import_running``.
- A file is read again only when its size or mtime changed since the cursor
  ``local.<source>.f<digest of its path>`` was written. Cursors move in the same
  transaction that publishes the run (:meth:`ImportStore.commit_batch`), so a
  failed import leaves them where they were.
- Every message is decided by the store's idempotency rules: an entry already
  stored with the same text is a duplicate and is not written again.

Counts only leave this module; no path, title or text is returned.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from ..records import RecordError, Source
from . import claude_code, codex, grok_bot
from ._model import LOCAL_SOURCES, Transcript, to_records

Progress = Callable[[dict[str, int]], None]
Opener = Callable[[Path], Any]

_LOCK_DIR: Final = ("mordred", "imports")


class LocalImportError(Exception):
    """A refusal with a stable, content-free ``code``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class LocalImportResult:
    source: str
    files_seen: int = 0
    files_changed: int = 0
    files_unreadable: int = 0
    conversations: int = 0
    inserted: int = 0
    duplicates: int = 0
    revised: int = 0
    conflicts: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_root(source: Source, home_dir: Path | None = None) -> Path:
    """Where the agent app writes its transcripts for the current user."""
    base = home_dir if home_dir is not None else Path.home()
    if source is Source.CODEX:
        return base / ".codex" / "sessions"
    if source is Source.CLAUDE_CODE:
        return base / ".claude" / "projects"
    if source is Source.GROK_BOT:
        return base / "Library" / "Application Support" / "Grok Bot" / "sand-client-persistence"
    raise LocalImportError("unknown_source")


def _checked_source(source: Source | str) -> Source:
    try:
        value = Source(source)
    except ValueError:
        raise LocalImportError("unknown_source") from None
    if value not in LOCAL_SOURCES:
        raise LocalImportError("unknown_source")
    return value


def _files(source: Source, root: Path) -> Iterator[Path]:
    if source is Source.CODEX:
        yield from codex.files(root)
    elif source is Source.CLAUDE_CODE:
        yield from claude_code.files(root)
    else:
        yield from grok_bot.files(root)


def _cursor_key(source: Source, path: Path) -> str:
    digest = hashlib.sha256(str(path).encode("utf-8", "surrogateescape")).hexdigest()
    return f"local.{source.value}.f{digest[:31]}"


def _signature(path: Path) -> str | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return f"{stat.st_size}.{stat.st_mtime_ns}"


@contextlib.contextmanager
def _writer_lock(home: Path, source: Source) -> Iterator[None]:
    if sys.platform == "win32":  # no mordred.db on Windows
        raise LocalImportError("unsupported_platform")
    import fcntl  # POSIX only

    directory = home.joinpath(*_LOCK_DIR)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory / f"local-{source.value}.lock", flags, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LocalImportError("import_running") from None
        yield
    finally:
        os.close(fd)


def _default_opener(home: Path) -> Any:
    from ..store import open_import_store

    return open_import_store(home)


def _read(source: Source, path: Path, names: dict[str, str]) -> list[Transcript]:
    if source is Source.CODEX:
        return codex.read(path)
    if source is Source.CLAUDE_CODE:
        return claude_code.read(path)
    return grok_bot.read(path, names)


def run_local_import(
    source: Source | str,
    *,
    home: Path,
    root: Path | None = None,
    opener: Opener | None = None,
    progress: Progress | None = None,
    now: Callable[[], float] = time.time,
) -> LocalImportResult:
    """Import the changed transcript files of ``source``; counts only.

    Refusals raise :class:`LocalImportError` (``unknown_source``,
    ``source_not_found``, ``import_running``, ``unsupported_platform``); a store
    refusal raises the store's ``ImportRefused`` unchanged.
    """
    kind = _checked_source(source)
    base = root if root is not None else default_root(kind)
    if not base.is_dir():
        raise LocalImportError("source_not_found")
    result = LocalImportResult(source=kind.value)
    with _writer_lock(home, kind):
        store = (opener or _default_opener)(home)
        cursors = store.meta_items(f"local.{kind.value}.")
        changed: list[tuple[Path, str, str]] = []
        for path in _files(kind, base):
            result.files_seen += 1
            signature = _signature(path)
            key = _cursor_key(kind, path)
            if signature is not None and cursors.get(key) != signature:
                changed.append((path, key, signature))
        if not changed:
            return result
        names = grok_bot.bot_names(base) if kind is Source.GROK_BOT else {}
        run_id = store.run_begin(kind)
        try:
            meta = _write_changed(store, run_id, kind, changed, names, result, int(now()), progress)
            store.commit_batch(run_id, _counts(result), meta)
        except BaseException:
            with contextlib.suppress(Exception):
                store.run_fail(run_id, _counts(result))
            raise
    return result


def _write_changed(
    store: Any,
    run_id: str,
    kind: Source,
    changed: list[tuple[Path, str, str]],
    names: dict[str, str],
    result: LocalImportResult,
    imported_at: int,
    progress: Progress | None,
) -> dict[str, str | None]:
    """Write every changed file under ``run_id``; the cursors to move once the run is published."""
    meta: dict[str, str | None] = {}
    for path, key, signature in changed:
        try:
            transcripts = _read(kind, path, names)
        except OSError:
            result.files_unreadable += 1
            continue
        for transcript in transcripts:
            try:
                conversation, messages = to_records(kind, transcript, imported_at=imported_at)
            except RecordError:
                result.files_unreadable += 1
                continue
            written = store.write_thread(run_id, messages, conversation=conversation, merge_conversation=True)
            result.conversations += 1
            result.inserted += written.inserted
            result.duplicates += written.duplicates
            result.revised += written.revised
            result.conflicts += written.conflicts
        meta[key] = signature
        result.files_changed += 1
        if progress is not None:
            progress({"files_done": result.files_changed, "files_total": len(changed)})
    return meta


def _counts(result: LocalImportResult) -> dict[str, int]:
    return {key: value for key, value in result.as_dict().items() if isinstance(value, int)}


def local_status(home_dir: Path | None = None) -> dict[str, dict[str, bool]]:
    """Per local source: whether its transcript folder exists for this user (no files are read)."""
    return {source.value: {"available": default_root(source, home_dir).is_dir()} for source in LOCAL_SOURCES}
