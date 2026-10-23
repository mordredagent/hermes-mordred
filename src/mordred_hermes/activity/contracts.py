"""The activity event contract (``activity_batch_v1``): enums, limits and normalization.

Collectors are paired peers: their transport origin is authenticated, the
truth of what they report is not. The capture policy is *record everything a
collector reports except secrets*, so :func:`normalize_event` reduces every
raw event to bounded, allowlisted fields before anything is stored:

* URLs keep their query string and fragment wherever they appear (target
  labels, free text, page title and text, ``query``), but the value of every
  credential parameter (``token``, ``password``, ``*_secret``, ...), every
  JWT-looking value and any userinfo password becomes ``redacted`` (exclusion
  ``url_params_redacted``). ``site`` is a lower-case host and ``route`` the
  path only; a route's scrubbed ``?query#fragment`` (or a collector's own
  top-level ``query``) is kept separately in ``query``.
* ``target`` / ``text`` / ``route`` / ``query`` / ``page_title`` /
  ``page_text`` are bounded (120 / 4000 / 200 / 1000 / 300 / 8000 chars) and
  ``args`` keeps only allowlisted keys as canonical JSON of at most 512 bytes.
* Free text is kept for ``correction`` and ``boundary`` phases. A ``type`` /
  ``search`` operation keeps what was typed (top-level ``text``, else a string
  ``args.text`` / ``args.value``) when ``args.field_kind`` classifies the field
  as non-sensitive; a ``sensitive`` field (or, outside those two phases, an
  unclassified one) keeps nothing (exclusion ``typed_text_dropped``). Other
  operations drop free text outside those phases (``text_dropped``).
* Page title and page text are kept for every event, whitespace-normalized.
* A collector may claim, never verify: ``verified_*`` becomes ``claimed_*``
  with the exclusion ``verification_claim_dropped``.
* Unknown enum values are ``malformed``; an event on a site excluded by
  configuration (nothing is excluded by default) is ``source_excluded``; an
  event whose normalized form exceeds the per-event limit is
  ``event_too_large``. Each refuses the whole batch upstream.

Rejections carry a code only. Nothing here logs or echoes event content.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from itertools import pairwise
from typing import Any, Final, NamedTuple
from urllib.parse import parse_qsl, urlencode, urlsplit

SCHEMA_VERSION: Final = 1


@dataclass(frozen=True)
class PeerPrincipal:
    """Authenticated submitter of activity batches.

    ``peer_id`` is ``operator:<12 hex>`` for an activity peer and ``extension``
    for the paired browser extension. ``trust`` and ``permitted_use`` come from
    the authentication path, never from a payload.
    """

    peer_id: str
    kind: str  # "operator" | "browser"
    trust: str = "paired_peer"
    permitted_use: str = "learning"


PHASES: Final = frozenset(
    {"intended", "dispatched", "observed", "cancelled", "timed_out", "boundary", "correction", "gap"}
)
RESULT_STATUSES: Final = frozenset(
    {"unknown", "claimed_success", "claimed_failure", "verified_success", "verified_failure"}
)
RESULT_METHODS: Final = frozenset({"page_signature_change"})
SOURCES: Final = frozenset({"operator", "browser", "hermes", "user_correction"})
ACTORS: Final = frozenset({"human", "agent", "unknown"})
OPS: Final = frozenset(
    {
        "click",
        "type",
        "scroll",
        "hscroll",
        "key",
        "navigate",
        "back",
        "forward",
        "wait",
        "close_tab",
        "search",
        "task_start",
        "task_end",
        "other",
    }
)
COVERAGES: Final = frozenset({"selected_tab", "partial", "gap"})
#: Higher is worse; an episode's coverage is the worst any of its events reported.
COVERAGE_RANK: Final[Mapping[str, int]] = {"selected_tab": 0, "partial": 1, "gap": 2}
PRODUCER_KINDS: Final = frozenset({"operator", "browser"})

MAX_BATCH_EVENTS: Final = 100
MAX_EVENT_BYTES: Final = 16384
MAX_BATCH_BYTES: Final = 262144
MAX_TARGET_CHARS: Final = 120
MAX_TEXT_CHARS: Final = 4000
MAX_ROUTE_CHARS: Final = 200
MAX_QUERY_CHARS: Final = 1000
MAX_PAGE_TITLE_CHARS: Final = 300
MAX_PAGE_TEXT_CHARS: Final = 8000
MAX_ARGS_BYTES: Final = 512
MAX_EVIDENCE_REFS: Final = 16
MAX_EXCLUSIONS: Final = 16

#: Phases whose free text is the point of the event (what the user said was wrong, the task asked for).
TEXT_PHASES: Final = frozenset({"correction", "boundary"})
#: Operations whose free text is what was typed; kept unless the field is sensitive or unclassified.
TYPED_OPS: Final = frozenset({"type", "search"})
#: ``args.field_kind`` of a field whose content is a secret (password, card number, one-time code).
SENSITIVE_FIELD_KIND: Final = "sensitive"

#: Built-in site exclusions: none. The activity store records every site; an
#: operator excludes hosts (and their subdomains) only through
#: ``plugins.mordred_activity.excluded_sites`` in configuration.
DEFAULT_EXCLUDED_SITES: Final[frozenset[str]] = frozenset()

EXCLUSION_VERIFICATION_DROPPED: Final = "verification_claim_dropped"
#: What was typed into a sensitive or unclassified field was withheld.
EXCLUSION_TYPED_TEXT: Final = "typed_text_dropped"
EXCLUSION_TEXT: Final = "text_dropped"
EXCLUSION_ARGS: Final = "args_dropped"
#: A credential parameter, JWT or userinfo password inside a URL was replaced with :data:`REDACTED`.
EXCLUSION_URL_PARAMS: Final = "url_params_redacted"
#: A collector's own quality exclusion marking a sensitive field; its typed text is withheld too.
COLLECTOR_SENSITIVE_MARK: Final = "sensitive_field"

#: Replacement for a credential value inside a URL.
REDACTED: Final = "redacted"
#: URL parameter names (lower-cased) whose values are credentials.
CREDENTIAL_PARAMS: Final = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth",
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "sig",
        "signature",
        "code",
        "otp",
        "nonce",
    }
)
#: Suffixes of lower-cased parameter names whose values are credentials (``csrf_token``, ``db_password``).
CREDENTIAL_SUFFIXES: Final = ("token", "secret", "password", "passwd", "signature", "apikey", "api_key")

_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_REF_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HOST_RE: Final = re.compile(r"^[a-z0-9.:-]{1,253}$")
_SIG_RE: Final = re.compile(r"^[0-9a-f]{16}$")
_TOKEN_RE: Final = re.compile(r"^[a-z0-9_]{1,48}$")
#: A URL in free text. The scheme is bounded so that scanning stays linear on hostile input.
_URL_IN_TEXT_RE: Final = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,31}://\S+")
#: ``eyJ`` (base64url of ``{"``) followed by three dot-separated base64url segments (the last may be
#: empty), starting a base64url run (the lookbehind keeps scanning linear).
_JWT_RE: Final = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
#: URLs nested inside parameter values (a redirect target's own redirect) are scrubbed this deep;
#: a value nested deeper that still holds a URL is redacted whole.
_MAX_URL_NESTING: Final = 4
_SUFFIX_RE: Final = re.compile(r"[?#]")

#: Allowlisted ``args`` keys and how each value is checked; anything else is dropped.
_STR_ARG_LIMITS: Final[Mapping[str, int]] = {
    "field_kind": 32,
    "direction": 16,
    "tab_action": 32,
    "reason": 64,
    "tier": 32,
    "verdict": 32,
}
_INT_ARGS: Final = frozenset({"pixels", "count"})
_MAX_KEYS: Final = 8
_MAX_KEY_CHARS: Final = 32


class ContractError(ValueError):
    """A content-free refusal: ``code`` is the whole message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class EventRejected(ContractError):
    """``malformed`` | ``event_too_large`` | ``source_excluded``."""


class BatchRejected(ContractError):
    """``malformed`` | ``batch_too_large`` | ``unsupported_schema`` | ``sequence_regression``."""


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    seq: int
    episode_id: str
    attempt_id: str | None
    parent_attempt_id: str | None
    source: str
    actor: str
    observed_at: float
    phase: str
    op: str
    target: str | None
    site: str | None
    route: str | None
    args_json: str
    result_status: str
    result_method: str | None
    result_evidence: tuple[str, ...]
    coverage: str
    exclusions: tuple[str, ...]
    truncated: bool
    page_sig_before: str | None
    page_sig_after: str | None
    hermes_session_id: str | None
    turn_id: str | None
    run_id: str | None
    text: str | None
    #: Scrubbed ``?query#fragment`` of the route (starts with ``?`` or ``#``).
    query: str | None = None
    page_title: str | None = None
    page_text: str | None = None
    content_digest: str = ""


@dataclass(frozen=True)
class BatchEnvelope:
    schema_version: int
    producer_id: str
    producer_kind: str
    events: tuple[Mapping[str, Any], ...]


def canonical_json(value: Any, *, ascii_only: bool = True) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only, allow_nan=False)


#: Fields added after events were first stored: omitted from the canonical form while ``None``, so
#: the ``content_digest`` of an event stored before they existed still verifies.
_OPTIONAL_FIELDS: Final = ("query", "page_title", "page_text")


def _canonical_fields(event: NormalizedEvent) -> dict[str, Any]:
    fields = asdict(event)
    fields.pop("content_digest")
    for key in _OPTIONAL_FIELDS:
        if fields[key] is None:
            del fields[key]
    return fields


def canonical_digest(event: NormalizedEvent) -> str:
    """sha256 over the canonical JSON of every normalized field except the digest itself."""
    return hashlib.sha256(canonical_json(_canonical_fields(event)).encode("ascii")).hexdigest()


def site_excluded(site: str | None, excluded_sites: Iterable[str]) -> bool:
    """``site`` is an excluded host or one of its subdomains."""
    if site is None:
        return False
    return any(site == host or site.endswith("." + host) for host in excluded_sites)


# --- field helpers -------------------------------------------------------------------------------


def _malformed() -> EventRejected:
    return EventRejected("malformed")


def _group(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _malformed()
    return value


def _enum(value: Any, allowed: frozenset[str], default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or value not in allowed:
        raise _malformed()
    return value


def _ident(value: Any, *, pattern: re.Pattern[str] = _ID_RE, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _malformed()
    return value


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _malformed()
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise _malformed()
    return number


def _seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _malformed()
    return value


# --- secret scrubbing ----------------------------------------------------------------------------


def credential_param(name: str) -> bool:
    """A URL parameter name whose value is a credential (exact name or credential suffix)."""
    lowered = name.strip().lower()
    return lowered in CREDENTIAL_PARAMS or lowered.endswith(CREDENTIAL_SUFFIXES)


def _scrub_value(value: str, depth: int) -> tuple[str, bool]:
    """A non-credential parameter value: a JWT is redacted whole, a nested URL (a redirect target) scrubbed."""
    if _JWT_RE.search(value):
        return REDACTED, True
    if depth >= _MAX_URL_NESTING:
        return (REDACTED, True) if "://" in value else (value, False)
    return _scrub(value, depth + 1)


def _scrub_params(params: str, depth: int) -> tuple[str, bool]:
    """``a=1&token=x`` with credential values redacted, order kept; verbatim when nothing was redacted.

    ``;`` separates parameters like ``&`` (servers that honour it would otherwise see a hidden
    ``token``); a rebuilt list joins them with ``&``.
    """
    scrubbed: list[tuple[str, str]] = []
    redacted = False
    for name, value in parse_qsl(params.replace(";", "&"), keep_blank_values=True):
        if credential_param(name) and value:
            scrubbed.append((name, REDACTED))
            redacted = True
            continue
        clean, hit = _scrub_value(value, depth)
        scrubbed.append((name, clean))
        redacted = redacted or hit
    return (urlencode(scrubbed, doseq=True), True) if redacted else (params, False)


def _scrub_jwts(text: str) -> tuple[str, bool]:
    clean, count = _JWT_RE.subn(REDACTED, text)
    return clean, count > 0


def _scrub_fragment(fragment: str, depth: int) -> tuple[str, bool]:
    """A fragment that is a parameter list (``access_token=..``) or a hash route with one (``/cb?code=..``)."""
    route, mark, params = fragment.partition("?")
    if mark:
        clean_route, route_hit = _scrub_jwts(route)
        clean_params, params_hit = _scrub_params(params, depth)
        return clean_route + mark + clean_params, route_hit or params_hit
    if "=" in fragment:
        return _scrub_params(fragment, depth)
    return _scrub_jwts(fragment)


def _scrub_suffix(suffix: str, depth: int = 0) -> tuple[str, bool]:
    """``?query#fragment`` (either part optional) with every credential value redacted."""
    query, mark, fragment = suffix.partition("#")
    query_hit = fragment_hit = False
    if query:
        params, query_hit = _scrub_params(query[1:], depth)
        query = "?" + params
    if fragment:
        fragment, fragment_hit = _scrub_fragment(fragment, depth)
    return query + mark + fragment, query_hit or fragment_hit


def _split_suffix(url: str) -> tuple[str, str]:
    """``(scheme://authority/path, ?query#fragment)``; the suffix starts at the first ``?`` or ``#``."""
    cut = _SUFFIX_RE.search(url)
    return (url, "") if cut is None else (url[: cut.start()], url[cut.start() :])


def _scrub_userinfo(head: str) -> tuple[str, bool]:
    """``scheme://user:password@host/path`` (no suffix) with a non-empty password redacted.

    As in :func:`urllib.parse.urlsplit`, the authority ends at the first ``/`` and the userinfo at
    its LAST ``@``, and the password follows the userinfo's first ``:``; so a password holding ``@``
    or ``:`` is redacted whole. The username (possibly empty) and the host stay as sent.
    """
    scheme, sep, rest = head.partition("://")
    authority, slash, path = rest.partition("/")
    userinfo, at, host = authority.rpartition("@")
    username, colon, password = userinfo.partition(":")
    if not (sep and at and colon and password):
        return head, False
    return f"{scheme}{sep}{username}:{REDACTED}@{host}{slash}{path}", True


def _scrub_url(url: str, depth: int) -> tuple[str, bool]:
    head, suffix = _split_suffix(url)
    head, userinfo_hit = _scrub_userinfo(head)
    head, path_hit = _scrub_jwts(head)
    suffix, suffix_hit = _scrub_suffix(suffix, depth)
    return head + suffix, userinfo_hit or path_hit or suffix_hit


def _scrub(text: str, depth: int = 0) -> tuple[str, bool]:
    """``(text, anything redacted)`` — see :func:`scrub_urls`."""
    redacted = False

    def one(match: re.Match[str]) -> str:
        nonlocal redacted
        clean, hit = _scrub_url(match.group(0), depth)
        redacted = redacted or hit
        return clean

    return _URL_IN_TEXT_RE.sub(one, text), redacted


def scrub_urls(text: str) -> str:
    """Every URL inside ``text`` kept, with its secrets replaced by :data:`REDACTED`.

    Query and fragment parameters named like credentials (:func:`credential_param`), JWT-looking
    values anywhere in the URL and a userinfo password are redacted; every other parameter keeps its
    value and order. A query or fragment without anything to redact is left byte-for-byte unchanged.
    """
    return _scrub(text)[0]


class _Text(NamedTuple):
    """A bounded, scrubbed text field: ``(value, truncated, redacted)``."""

    value: str | None = None
    cut: bool = False
    redacted: bool = False


def _bounded(text: str, limit: int, scrub: Callable[[str], tuple[str, bool]] = _scrub) -> _Text:
    clean, redacted = scrub(text)
    return _Text(clean[:limit], True, redacted) if len(clean) > limit else _Text(clean, False, redacted)


def _bounded_text(value: Any, limit: int) -> _Text:
    if value is None:
        return _Text()
    if not isinstance(value, str):
        raise _malformed()
    return _bounded(value, limit)


def _page_field(value: Any, limit: int) -> _Text:
    """``page_title`` / ``page_text``: a string, whitespace runs collapsed, scrubbed and bounded."""
    if value is None:
        return _Text()
    if not isinstance(value, str):
        raise _malformed()
    collapsed = " ".join(value.split())
    return _bounded(collapsed, limit) if collapsed else _Text()


def _query_text(suffix: str) -> _Text:
    """A ``?query#fragment`` suffix, scrubbed and bounded; nothing when it is only delimiters."""
    if not suffix.strip("?#"):
        return _Text()
    return _bounded(suffix, MAX_QUERY_CHARS, scrub=_scrub_suffix)


def _query(value: Any, from_route: _Text) -> _Text:
    """A collector's top-level ``query`` wins over the one derived from its route."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return from_route
    if not isinstance(value, str):
        raise _malformed()
    suffix = value.strip()
    return _query_text(suffix if suffix.startswith(("?", "#")) else "?" + suffix)


def _host(value: str) -> str:
    try:
        host = urlsplit(value if "://" in value else "//" + value).hostname
    except ValueError as exc:
        raise _malformed() from exc
    if not host or not _HOST_RE.fullmatch(host):
        raise _malformed()
    return host


def _site(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise _malformed()
    return _host(value.strip())


class _Location(NamedTuple):
    """A route split into its path (``route``), the host of a full URL, and its scrubbed suffix."""

    route: str | None = None
    host: str | None = None
    query: _Text = _Text()
    truncated: bool = False
    redacted: bool = False


def _route(value: Any) -> _Location:
    if value is None or value == "":
        return _Location()
    if not isinstance(value, str):
        raise _malformed()
    head, suffix = _split_suffix(value)
    host = None
    path = head
    if "://" in head:
        host = _host(head)
        path = urlsplit(head).path
    path, redacted = _scrub_jwts("/" + re.sub(r"/{2,}", "/", path).lstrip("/"))
    cut = len(path) > MAX_ROUTE_CHARS
    return _Location(path[:MAX_ROUTE_CHARS], host, _query_text(suffix), cut, redacted)


def _arg_value(key: str, value: Any) -> Any:
    """The checked value of an allowlisted ``args`` key, or ``None`` to drop it."""
    if key in _STR_ARG_LIMITS:
        return value if isinstance(value, str) and len(value) <= _STR_ARG_LIMITS[key] else None
    if key in _INT_ARGS:
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if key == "duration_s":
        ok = isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)
        return value if ok else None
    if key == "keys":
        ok = (
            isinstance(value, list)
            and len(value) <= _MAX_KEYS
            and all(isinstance(k, str) and len(k) <= _MAX_KEY_CHARS for k in value)
        )
        return value if ok else None
    return None


def _args(raw: Any) -> tuple[str, tuple[str, ...]]:
    """``(canonical args JSON, exclusions)`` — allowlisted keys only (``text`` / ``value`` never are)."""
    if raw is None:
        return "{}", ()
    if not isinstance(raw, Mapping):
        raise _malformed()
    kept: dict[str, Any] = {}
    for key, value in raw.items():
        checked = _arg_value(key, value) if isinstance(key, str) else None
        if checked is not None:
            kept[key] = checked
    encoded = canonical_json(kept)
    if len(encoded.encode("utf-8")) > MAX_ARGS_BYTES:
        return "{}", (EXCLUSION_ARGS,)
    return encoded, ()


def _typed_args(raw: Mapping[str, Any] | None) -> tuple[str | None, str | None]:
    """``(field_kind, typed text)`` from checked ``args``; the text comes from ``text``, else ``value``."""
    if raw is None:
        return None, None
    kind = _arg_value("field_kind", raw.get("field_kind"))
    typed = next((raw[key] for key in ("text", "value") if isinstance(raw.get(key), str)), None)
    return kind, typed


def _signature(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SIG_RE.fullmatch(value):
        raise _malformed()
    return value


def _str_list(value: Any, pattern: re.Pattern[str], limit: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > limit:
        raise _malformed()
    if not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        raise _malformed()
    return tuple(value)


@dataclass(frozen=True)
class _Result:
    status: str
    method: str | None
    evidence: tuple[str, ...]
    exclusions: tuple[str, ...]


def _result(raw: Mapping[str, Any]) -> _Result:
    status = _enum(raw.get("status"), RESULT_STATUSES, default="unknown")
    method = None if raw.get("method") is None else _enum(raw.get("method"), RESULT_METHODS)
    evidence = _str_list(raw.get("evidence"), _ID_RE, MAX_EVIDENCE_REFS)
    # Only the receiver's own verifier may set verified_*; a collector's is a claim.
    if status.startswith("verified_"):
        return _Result(
            "claimed_" + status.removeprefix("verified_"), method, evidence, (EXCLUSION_VERIFICATION_DROPPED,)
        )
    return _Result(status, method, evidence, ())


def _dedupe(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


@dataclass(frozen=True)
class _Action:
    op: str
    target: _Text
    site: str | None
    location: _Location
    args_json: str
    exclusions: tuple[str, ...]
    field_kind: str | None
    #: A string ``args.text`` / ``args.value``; a candidate for ``text``, never stored as an argument.
    typed_arg: str | None


def _action(raw: Mapping[str, Any]) -> _Action:
    op = _enum(raw.get("op"), OPS)
    target = _bounded_text(raw.get("target"), MAX_TARGET_CHARS)
    location = _route(raw.get("route"))
    site = _site(raw.get("site")) or location.host
    args_json, exclusions = _args(raw.get("args"))
    field_kind, typed_arg = _typed_args(raw.get("args"))
    return _Action(op, target, site, location, args_json, exclusions, field_kind, typed_arg)


def _text(raw: Mapping[str, Any], phase: str, action: _Action, sensitive: bool) -> tuple[_Text, tuple[str, ...]]:
    """``(text, exclusions)`` under the free-text rules in the module docstring."""
    value = raw.get("text")
    if action.op not in TYPED_OPS:
        if value is None:
            return _Text(), ()
        if phase not in TEXT_PHASES:
            return _Text(), (EXCLUSION_TEXT,)
        return _bounded_text(value, MAX_TEXT_CHARS), ()
    if value is None:
        value = action.typed_arg
    if value is None:
        return _Text(), ()
    # What was typed into a secret field is never kept; an unclassified field only in a text phase.
    if sensitive or (action.field_kind is None and phase not in TEXT_PHASES):
        return _Text(), (EXCLUSION_TYPED_TEXT,)
    return _bounded_text(value, MAX_TEXT_CHARS), ()


def _sensitive(action: _Action, collector_exclusions: tuple[str, ...]) -> bool:
    kind = (action.field_kind or "").strip().lower()
    return kind == SENSITIVE_FIELD_KIND or COLLECTOR_SENSITIVE_MARK in collector_exclusions


def _identity(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": _ident(raw.get("event_id"), required=True),
        "seq": _seq(raw.get("seq")),
        "episode_id": _ident(raw.get("episode_id"), required=True),
        "attempt_id": _ident(raw.get("attempt_id")),
        "parent_attempt_id": _ident(raw.get("parent_attempt_id")),
        "source": _enum(raw.get("source"), SOURCES),
        "actor": _enum(raw.get("actor"), ACTORS, default="unknown"),
        "observed_at": _number(raw.get("observed_at")),
        "phase": _enum(raw.get("phase"), PHASES),
    }


def _quality(raw: Mapping[str, Any]) -> dict[str, Any]:
    truncated = raw.get("truncated", False)
    if not isinstance(truncated, bool):
        raise _malformed()
    return {
        # Without a coverage claim the receiver cannot assume the selected tab was fully seen.
        "coverage": _enum(raw.get("coverage"), COVERAGES, default="partial"),
        "exclusions": _str_list(raw.get("exclusions"), _TOKEN_RE, MAX_EXCLUSIONS),
        "truncated": truncated,
        "page_sig_before": _signature(raw.get("page_sig_before")),
        "page_sig_after": _signature(raw.get("page_sig_after")),
    }


def _session_ref(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _ident(raw.get(key), pattern=_REF_RE) for key in ("hermes_session_id", "turn_id", "run_id")}


def event_size(event: NormalizedEvent) -> int:
    """UTF-8 size of the normalized event (non-ASCII text is not inflated by escapes)."""
    return len(canonical_json(_canonical_fields(event), ascii_only=False).encode("utf-8"))


def normalize_event(
    raw: Mapping[str, Any], *, excluded_sites: frozenset[str], max_event_bytes: int = MAX_EVENT_BYTES
) -> NormalizedEvent:
    """Reduce one collector event to the stored contract, or raise :class:`EventRejected`."""
    if not isinstance(raw, Mapping):
        raise _malformed()
    identity = _identity(raw)
    action = _action(_group(raw, "action"))
    result = _result(_group(raw, "result"))
    quality = _quality(_group(raw, "quality"))
    text, text_exclusions = _text(raw, identity["phase"], action, _sensitive(action, quality["exclusions"]))
    query = _query(raw.get("query"), action.location.query)
    page_title = _page_field(raw.get("page_title"), MAX_PAGE_TITLE_CHARS)
    page_text = _page_field(raw.get("page_text"), MAX_PAGE_TEXT_CHARS)
    if site_excluded(action.site, excluded_sites):
        raise EventRejected("source_excluded")
    texts = (action.target, text, query, page_title, page_text)
    redacted = action.location.redacted or any(field.redacted for field in texts)
    event = NormalizedEvent(
        **identity,
        op=action.op,
        target=action.target.value,
        site=action.site,
        route=action.location.route,
        args_json=action.args_json,
        result_status=result.status,
        result_method=result.method,
        result_evidence=result.evidence,
        coverage=quality["coverage"],
        exclusions=_dedupe(
            (
                *quality["exclusions"],
                *result.exclusions,
                *action.exclusions,
                *text_exclusions,
                *((EXCLUSION_URL_PARAMS,) if redacted else ()),
            )
        ),
        truncated=quality["truncated"] or action.location.truncated or any(field.cut for field in texts),
        page_sig_before=quality["page_sig_before"],
        page_sig_after=quality["page_sig_after"],
        **_session_ref(_group(raw, "session_ref")),
        text=text.value,
        query=query.value,
        page_title=page_title.value,
        page_text=page_text.value,
    )
    if event_size(event) > max_event_bytes:
        raise EventRejected("event_too_large")
    return replace(event, content_digest=canonical_digest(event))


def check_batch_envelope(batch: Mapping[str, Any], *, max_events: int, max_bytes_raw: int) -> BatchEnvelope:
    """Validate the batch wrapper (not its events), or raise :class:`BatchRejected`."""
    if not isinstance(batch, Mapping):
        raise BatchRejected("malformed")
    version = batch.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise BatchRejected("malformed")
    if version != SCHEMA_VERSION:
        raise BatchRejected("unsupported_schema")
    producer_id = batch.get("producer_id")
    producer_kind = batch.get("producer_kind")
    events = batch.get("events")
    if not isinstance(producer_id, str) or not _ID_RE.fullmatch(producer_id):
        raise BatchRejected("malformed")
    if producer_kind not in PRODUCER_KINDS or not isinstance(events, list):
        raise BatchRejected("malformed")
    if not events or not all(isinstance(event, Mapping) for event in events):
        raise BatchRejected("malformed")
    if len(events) > max_events:
        raise BatchRejected("batch_too_large")
    try:
        size = len(canonical_json(batch, ascii_only=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise BatchRejected("malformed") from exc
    if size > max_bytes_raw:
        raise BatchRejected("batch_too_large")
    return BatchEnvelope(version, producer_id, str(producer_kind), tuple(events))


def check_sequence(events: Sequence[NormalizedEvent]) -> None:
    """Producer sequence numbers must strictly increase within one batch."""
    for previous, current in pairwise(events):
        if current.seq <= previous.seq:
            raise BatchRejected("sequence_regression")
