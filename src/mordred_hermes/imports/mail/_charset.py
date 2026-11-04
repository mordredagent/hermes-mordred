"""Charset decoding with counted, content-free fallbacks.

ISO-2022-JP mail from Japanese clients often carries characters outside JIS X
0208 (NEC special characters such as circled digits, IBM extensions, half-width
katakana). Python's ``iso2022_jp`` codec refuses them, so decoding falls back
to ``iso2022_jp_ext`` and then to a JIS → Shift_JIS transcoding decoded as
``cp932`` (the CP50220 behaviour of Windows clients). Every fallback is counted
under ``charset_fallback``; nothing here records the decoded text.
"""

from __future__ import annotations

import codecs
from collections import Counter
from typing import Final

_ISO2022JP: Final = frozenset({"iso-2022-jp", "iso2022jp", "iso2022_jp", "csiso2022jp", "iso-2022-jp-ms", "cp50220"})
_SJIS: Final = frozenset({"shift_jis", "shift-jis", "sjis", "x-sjis", "ms_kanji", "csshiftjis", "windows-31j", "cp932"})
_ESC: Final = 0x1B


def _codec_name(charset: str | None) -> str | None:
    if not charset:
        return None
    name = charset.strip().strip('"').lower().split("*", 1)[0]
    try:
        codecs.lookup(name)
    except LookupError:
        return None
    return name


def _jis_pair_to_sjis(j1: int, j2: int) -> bytes:
    if j1 % 2:
        s2 = j2 + 0x1F
        if s2 >= 0x7F:
            s2 += 1
    else:
        s2 = j2 + 0x7E
    s1 = (j1 + 1) // 2 + 0x70
    if s1 >= 0xA0:
        s1 += 0x40
    return bytes((s1, s2))


def _escape_mode(data: bytes, i: int) -> tuple[str, int] | None:
    """Recognise an ISO-2022-JP escape at ``data[i]``; return (mode, length)."""
    seq = data[i : i + 4]
    if seq[:3] in {b"\x1b(B", b"\x1b(J"}:
        return "ascii", 3
    if seq[:3] == b"\x1b(I":
        return "kana", 3
    if seq[:3] in {b"\x1b$@", b"\x1b$B"}:
        return "kanji", 3
    if seq in {b"\x1b$(Q", b"\x1b$(O", b"\x1b$(D"}:
        return "kanji", 4
    return None


def iso2022jp_via_cp932(data: bytes) -> str:
    """Transcode ISO-2022-JP (including CP50220 extensions) to Shift_JIS and decode as cp932."""
    out = bytearray()
    mode = "ascii"
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == _ESC and (escape := _escape_mode(data, i)) is not None:
            mode, length = escape
            i += length
            continue
        if byte in {0x0A, 0x0D}:
            out.append(byte)
            i += 1
        elif mode == "kanji" and i + 1 < len(data) and 0x21 <= byte <= 0x7E and 0x21 <= data[i + 1] <= 0x7E:
            out += _jis_pair_to_sjis(byte, data[i + 1])
            i += 2
        elif mode == "kana" and 0x21 <= byte <= 0x5F:
            out.append(byte + 0x80)
            i += 1
        else:
            out.append(byte)
            i += 1
    return out.decode("cp932", errors="replace")


def _strict(data: bytes, codec: str) -> str | None:
    try:
        return data.decode(codec)
    except (UnicodeDecodeError, LookupError):
        return None


def _decode_iso2022jp(data: bytes, stats: Counter[str]) -> str:
    text = _strict(data, "iso2022_jp")
    if text is not None:
        return text
    stats["charset_fallback"] += 1
    text = _strict(data, "iso2022_jp_ext")
    if text is not None:
        return text
    return iso2022jp_via_cp932(data)


def decode_bytes(data: bytes, charset: str | None, stats: Counter[str]) -> str:
    """Decode ``data`` declared as ``charset``; fallbacks are counted, never raised."""
    name = _codec_name(charset)
    if name is not None and (name in _ISO2022JP or codecs.lookup(name).name == "iso2022_jp"):
        return _decode_iso2022jp(data, stats)
    if name is not None and name in _SJIS:
        text = _strict(data, "cp932")
        if text is not None:
            return text
    elif name is not None:
        text = _strict(data, name)
        if text is not None:
            return text
    if data.isascii() and name is None and not charset:
        return data.decode("ascii")
    return _fallback(data, stats)


def _fallback(data: bytes, stats: Counter[str]) -> str:
    stats["charset_fallback"] += 1
    for codec in ("utf-8", "cp932"):
        text = _strict(data, codec)
        if text is not None:
            return text
    if _ESC in data:
        return _decode_iso2022jp(data, Counter())
    return data.decode("utf-8", errors="replace")


def decode_raw_header(value: str, stats: Counter[str]) -> str:
    """Recover 8-bit header bytes that the parser kept as surrogate escapes."""
    if not any("\udc80" <= char <= "\udcff" for char in value):
        return value
    data = value.encode("ascii", errors="surrogateescape")
    text = _strict(data, "utf-8")
    if text is not None:
        return text
    return _fallback(data, stats)
