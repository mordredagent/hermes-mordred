"""Date parsing for headers and quote attributions. Unknown is ``None``, never "now"."""

from __future__ import annotations

import datetime as dt
import email.utils
import re
from typing import Final

_MAX_TIMESTAMP: Final = 253_402_300_799
_MONTHS: Final = {
    name: index
    for index, names in enumerate(
        (
            ("jan", "january"),
            ("feb", "february"),
            ("mar", "march"),
            ("apr", "april"),
            ("may",),
            ("jun", "june"),
            ("jul", "july"),
            ("aug", "august"),
            ("sep", "sept", "september"),
            ("oct", "october"),
            ("nov", "november"),
            ("dec", "december"),
        ),
        start=1,
    )
    for name in names
}
_TIME: Final = r"(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?"
_JA_DATE_RE: Final = re.compile(
    r"(?P<year>\d{4})\s*年\s*(?P<month>\d{1,2})\s*月\s*(?P<day>\d{1,2})\s*日"
    r"(?:\s*[(\uff08][^)\uff09]{0,4}[)\uff09])?(?:\s*\S{1,3}曜日)?\s*" + _TIME
)
_YMD_RE: Final = re.compile(r"(?P<year>\d{4})[/-](?P<month>\d{1,2})[/-](?P<day>\d{1,2})[\s,T]+" + _TIME)
_EN_DATE_RE: Final = re.compile(
    r"(?P<mon>[A-Za-z]{3,9})\.?\s+(?P<day>\d{1,2}),?\s+(?P<year>\d{4}),?\s*(?:at\s+)?" + _TIME + r"\s*"
    r"(?P<ampm>[AaPp]\.?[Mm]\.?)?(?:\s*(?:GMT|UTC)\s*(?P<tzh>[+-]\d{1,2})(?::?(?P<tzm>\d{2}))?)?"
)
_EN_DAY_FIRST_RE: Final = re.compile(
    r"(?P<day>\d{1,2})\s+(?P<mon>[A-Za-z]{3,9})\.?\s+(?P<year>\d{4}),?\s*(?:at\s+)?" + _TIME
)


def _checked(moment: dt.datetime) -> int | None:
    try:
        value = int(moment.timestamp())
    except (OverflowError, OSError, ValueError):
        return None
    return value if 0 <= value <= _MAX_TIMESTAMP else None


def parse_header_date(value: str | None) -> tuple[int | None, int | None]:
    """RFC 5322 ``Date`` → (unix seconds, UTC offset minutes); invalid → (None, None)."""
    if not value or not value.strip():
        return None, None
    try:
        moment = email.utils.parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None, None
    offset: int | None = None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.UTC)
    else:
        delta = moment.utcoffset()
        offset = None if delta is None else int(delta.total_seconds()) // 60
    return _checked(moment), offset


def _build(fields: dict[str, int], offset_minutes: int | None) -> int | None:
    if offset_minutes is None:
        return None
    try:
        zone = dt.timezone(dt.timedelta(minutes=offset_minutes))
        moment = dt.datetime(
            fields["year"],
            fields["month"],
            fields["day"],
            fields["hour"],
            fields["minute"],
            fields.get("second", 0),
            tzinfo=zone,
        )
    except (ValueError, OverflowError):
        return None
    return _checked(moment)


def _numeric(match: re.Match[str]) -> dict[str, int]:
    keys = ("year", "month", "day", "hour", "minute", "second")
    return {key: int(match.group(key)) for key in keys if key in match.re.groupindex and match.group(key)}


def _english(match: re.Match[str], default_offset: int | None) -> int | None:
    month = _MONTHS.get(match.group("mon").lower())
    if month is None:
        return None
    fields = _numeric(match)
    fields["month"] = month
    ampm = (match.groupdict().get("ampm") or "").lower().replace(".", "")
    if ampm == "pm" and fields["hour"] < 12:
        fields["hour"] += 12
    elif ampm == "am" and fields["hour"] == 12:
        fields["hour"] = 0
    offset = default_offset
    tzh = match.groupdict().get("tzh")
    if tzh:
        sign = -1 if tzh.startswith("-") else 1
        offset = sign * (abs(int(tzh)) * 60 + int(match.groupdict().get("tzm") or 0))
    return _build(fields, offset)


def parse_loose_date(text: str, default_offset_minutes: int | None) -> int | None:
    """Parse a date written by a mail client in an attribution or forward header.

    A date without a zone is read in ``default_offset_minutes`` (the containing
    message's zone); without that it is unknown. Ambiguous numeric forms such
    as ``10/5/26`` are unknown.
    """
    value = text.strip()
    if not value:
        return None
    ts, offset = parse_header_date(value)
    if ts is not None and offset is not None:
        return ts
    for pattern in (_JA_DATE_RE, _YMD_RE):
        match = pattern.search(value)
        if match is not None:
            return _build(_numeric(match), default_offset_minutes)
    for pattern in (_EN_DATE_RE, _EN_DAY_FIRST_RE):
        match = pattern.search(value)
        if match is not None:
            return _english(match, default_offset_minutes)
    return None
