"""Text of a mail's document attachments (PDF, Word, Excel, PowerPoint, OpenDocument, RTF, text).

Images are not read. Everything else that holds text is turned into plain text
in memory, with no temporary file and no network:

- PDF: macOS PDFKit (``pyobjc-framework-Quartz``, already a macOS dependency);
- ``.docx`` / ``.xlsx`` / ``.pptx`` and OpenDocument (``.odt`` / ``.ods`` /
  ``.odp``): the ZIP container and its XML read with the standard library;
- legacy ``.doc`` and ``.rtf``: macOS ``textutil``, fed on stdin and read from
  stdout;
- ``text/*``, CSV, JSON and calendar files: decoded as text; HTML converted
  like an HTML body.

Attachments are untrusted input, so every step is bounded: the attachment's
size (:data:`MAX_ATTACHMENT_BYTES`), ZIP members read and their decompressed
size, PDF pages, the ``textutil`` run time, and the text kept
(:data:`MAX_TEXT_BYTES`). A file that cannot be read yields nothing; it is
still counted by kind as before. File names are never kept.
"""

from __future__ import annotations

import io
import re
import subprocess
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from email.message import Message
from typing import Final
from xml.etree import ElementTree

from ._charset import decode_bytes
from ._text import cap_utf8, clean_text

__all__ = ["MAX_ATTACHMENT_BYTES", "MAX_TEXT_BYTES", "attachment_format", "attachment_text"]

#: Larger attachments are not read (their kind is still counted).
MAX_ATTACHMENT_BYTES: Final = 15 * 1024 * 1024
#: Text kept per attachment (stored as at most three 64 KiB parts).
MAX_TEXT_BYTES: Final = 192 * 1024
#: PDF pages read at most.
MAX_PDF_PAGES: Final = 200
#: ZIP members looked at, and bytes decompressed from them in all.
MAX_ZIP_MEMBERS: Final = 4000
MAX_ZIP_READ_BYTES: Final = 64 * 1024 * 1024
#: Seconds ``textutil`` may run.
TEXTUTIL_TIMEOUT_S: Final = 20.0
_TEXTUTIL: Final = "/usr/bin/textutil"

_EXTENSIONS: Final[dict[str, str]] = {
    "pdf": "pdf",
    "docx": "docx",
    "docm": "docx",
    "xlsx": "xlsx",
    "xlsm": "xlsx",
    "pptx": "pptx",
    "pptm": "pptx",
    "odt": "odf",
    "ods": "odf",
    "odp": "odf",
    "doc": "doc",
    "rtf": "rtf",
    "txt": "text",
    "csv": "text",
    "tsv": "text",
    "md": "text",
    "json": "text",
    "ics": "text",
    "html": "html",
    "htm": "html",
}
_TYPES: Final[dict[str, str]] = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.oasis.opendocument.text": "odf",
    "application/vnd.oasis.opendocument.spreadsheet": "odf",
    "application/vnd.oasis.opendocument.presentation": "odf",
    "application/msword": "doc",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "text/html": "html",
    "application/json": "text",
}


def attachment_format(part: Message) -> str | None:
    """The readable format of ``part`` (``pdf``, ``docx``, ...), or ``None`` (images, unknown)."""
    ctype = part.get_content_type()
    if part.get_content_maintype() == "image":
        return None
    name = part.get_filename() or ""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in _EXTENSIONS:
        return _EXTENSIONS[ext]
    if ctype in _TYPES:
        return _TYPES[ctype]
    if part.get_content_maintype() == "text":
        return "text"
    return None


def attachment_text(part: Message, stats: Counter[str]) -> tuple[str, str] | None:
    """``(format, text)`` read from ``part``, or ``None`` when it holds no readable text."""
    fmt = attachment_format(part)
    if fmt is None:
        return None
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes) or not payload:
        return None
    if len(payload) > MAX_ATTACHMENT_BYTES:
        stats[f"attachment_text_too_large:{fmt}"] += 1
        return None
    try:
        raw = _READERS[fmt](payload, part)
    except Exception:  # a damaged or hostile file: count it, keep the mail
        stats[f"attachment_text_failed:{fmt}"] += 1
        return None
    text, cut = cap_utf8(clean_text(raw or "").strip(), MAX_TEXT_BYTES)
    if not text.strip():
        stats[f"attachment_text_empty:{fmt}"] += 1
        return None
    stats[f"attachment_text:{fmt}"] += 1
    stats["attachment_text_truncated"] += cut
    return fmt, text


# ---- readers ------------------------------------------------------------------------------


def _text(data: bytes, part: Message) -> str:
    return decode_bytes(data[: 4 * MAX_TEXT_BYTES], part.get_content_charset(), Counter())


def _html(data: bytes, part: Message) -> str:
    from .body import html_to_text

    return html_to_text(_text(data, part), max_chars=MAX_TEXT_BYTES)


def _pdf(data: bytes, _part: Message) -> str:
    from Foundation import NSData
    from Quartz import PDFDocument

    doc = PDFDocument.alloc().initWithData_(NSData.dataWithBytes_length_(data, len(data)))
    if doc is None or doc.isLocked():
        return ""
    pages: list[str] = []
    size = 0
    for index in range(min(int(doc.pageCount()), MAX_PDF_PAGES)):
        page = doc.pageAtIndex_(index)
        text = str(page.string() or "") if page is not None else ""
        pages.append(text)
        size += len(text)
        if size > MAX_TEXT_BYTES:
            break
    return "\n\n".join(pages)


class _Zip:
    """A ZIP container read with bounds on members and decompressed bytes."""

    def __init__(self, data: bytes) -> None:
        self.zf = zipfile.ZipFile(io.BytesIO(data))
        infos = self.zf.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            raise ValueError("too many members")
        self.names = {info.filename: info for info in infos}
        self.budget = MAX_ZIP_READ_BYTES

    def read(self, name: str) -> bytes | None:
        info = self.names.get(name)
        if info is None or info.file_size > self.budget:
            return None
        with self.zf.open(info) as handle:
            data = handle.read(self.budget + 1)  # never trust the declared size alone
        if len(data) > self.budget:
            raise ValueError("decompressed size over budget")
        self.budget -= len(data)
        return data


_DECLARATION = re.compile(rb"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _parse(data: bytes, events: tuple[str, ...]) -> Iterator[tuple[str, ElementTree.Element]]:
    """Parse an Office/OpenDocument XML part; one with a DTD or an entity declaration is refused.

    Those formats never declare either, and refusing them up front removes entity
    expansion ("billion laughs") and external entities from what the parser sees.
    """
    if _DECLARATION.search(data):
        raise ValueError("xml declares a DTD or an entity")
    return ElementTree.iterparse(io.BytesIO(data), events=events)  # noqa: S314 - DTD/entities refused above


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


#: Elements whose text is not content: Excel's phonetic guides (furigana) of a cell.
_SKIP: Final = frozenset({"rPh", "phoneticPr"})


def _xml_paragraphs(data: bytes, paragraph: str, run: str) -> list[str]:
    """Each ``paragraph`` element's text, from its ``run`` elements (skipping :data:`_SKIP`)."""
    out: list[str] = []
    buffer: list[str] = []
    skipping = 0
    for event, elem in _parse(data, ("start", "end")):
        name = _local(elem.tag)
        if name in _SKIP:
            skipping += 1 if event == "start" else -1
            continue
        if event == "start" or skipping:
            continue
        if name == run and elem.text:
            buffer.append(elem.text)
        elif name == "tab":
            buffer.append("\t")
        elif name in ("br", "cr"):
            buffer.append("\n")
        elif name == paragraph:
            out.append("".join(buffer))
            buffer = []
            elem.clear()
    if buffer:
        out.append("".join(buffer))
    return out


def _numbered(names: Iterable[str], pattern: str) -> list[str]:
    """``names`` matching ``pattern`` (one number group), in numeric order."""
    found = [(int(m.group(1)), name) for name in names if (m := re.fullmatch(pattern, name))]
    return [name for _n, name in sorted(found)]


def _docx(data: bytes, _part: Message) -> str:
    zf = _Zip(data)
    parts = ["word/document.xml", "word/footnotes.xml", "word/endnotes.xml"]
    texts: list[str] = []
    for name in parts:
        xml = zf.read(name)
        if xml:
            texts.extend(_xml_paragraphs(xml, "p", "t"))
    return "\n".join(texts)


def _xlsx(data: bytes, _part: Message) -> str:
    zf = _Zip(data)
    texts: list[str] = []
    shared = zf.read("xl/sharedStrings.xml")
    if shared:
        texts.extend(_xml_paragraphs(shared, "si", "t"))
    for name in _numbered(zf.names, r"xl/worksheets/sheet(\d+)\.xml"):
        xml = zf.read(name)
        if xml:  # inline strings only; shared strings are above, numbers are not text
            texts.extend(t for t in _xml_paragraphs(xml, "is", "t") if t)
    return "\n".join(texts)


def _pptx(data: bytes, _part: Message) -> str:
    zf = _Zip(data)
    slides: list[str] = []
    for name in _numbered(zf.names, r"ppt/slides/slide(\d+)\.xml"):
        xml = zf.read(name)
        if xml:
            slides.append("\n".join(t for t in _xml_paragraphs(xml, "p", "t") if t))
    return "\n\n".join(slides)


def _odf(data: bytes, _part: Message) -> str:
    zf = _Zip(data)
    xml = zf.read("content.xml")
    if not xml:
        return ""
    out: list[str] = []
    for _event, elem in _parse(xml, ("end",)):
        if _local(elem.tag) in ("p", "h"):
            out.append("".join(elem.itertext()))
            elem.clear()
    return "\n".join(out)


def _textutil(fmt: str) -> Callable[[bytes, Message], str]:
    def read(data: bytes, _part: Message) -> str:
        done = subprocess.run(  # noqa: S603 - a fixed system tool, fixed arguments, the file on stdin
            [_TEXTUTIL, "-stdin", "-stdout", "-format", fmt, "-convert", "txt", "-encoding", "UTF-8"],
            input=data,
            capture_output=True,
            timeout=TEXTUTIL_TIMEOUT_S,
            check=True,
        )
        return done.stdout[: 4 * MAX_TEXT_BYTES].decode("utf-8", "replace")

    return read


_READERS: Final[dict[str, Callable[[bytes, Message], str]]] = {
    "pdf": _pdf,
    "docx": _docx,
    "xlsx": _xlsx,
    "pptx": _pptx,
    "odf": _odf,
    "doc": _textutil("doc"),
    "rtf": _textutil("rtf"),
    "text": _text,
    "html": _html,
}
