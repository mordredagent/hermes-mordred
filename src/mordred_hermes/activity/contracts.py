"""The activity event contract (``activity_batch_v1``): enums, limits and normalization.

Collectors are paired peers: their transport origin is authenticated, the
truth of what they report is not. The capture policy is *record everything a
collector reports except secrets*, so :func:`normalize_event` reduces every
raw event to bounded, allowlisted fields before anything is stored:

* URLs keep their query string and fragment wherever they appear (target
  labels, free text, page title and text, ``query``), but the value of every
  credential parameter (``token``, ``password``, ``*_secret``, ``*_key``, ...,
  :func:`credential_param`), every other value that looks like a secret
  (:func:`looks_like_secret`), every JWT-looking value, any userinfo password
  and a user name that is a credential becomes ``redacted`` (exclusion
  ``url_params_redacted``). ``site`` is a lower-case host and ``route`` the
  path only; a route's scrubbed ``?query#fragment`` (or a collector's own
  top-level ``query``) is kept separately in ``query``. An explicit ``site``
  naming another host than a full-URL ``route`` is ``malformed``.
* Free text other than typed text (task and correction text, target labels,
  page title and text) has its secrets replaced by ``redacted``
  (:func:`redact_text_secrets`: JWTs, key-prefixed tokens, PEM armour lines
  and the value named after or before a password-like keyword, also one of
  several words up to the end of its clause, as speech recognition writes a
  spoken password; exclusion ``text_secrets_redacted``), before it is bounded
  and before the content digest is computed.
* ``target`` / ``text`` / ``route`` / ``query`` / ``page_title`` /
  ``page_text`` are bounded (120 / 4000 / 200 / 1000 / 300 / 8000 chars) and
  ``args`` keeps only allowlisted keys as canonical JSON of at most 512 bytes.
* Free text is kept for ``correction`` and ``boundary`` phases. A ``type`` /
  ``search`` operation keeps what was typed (top-level ``text``, else a string
  ``args.text`` / ``args.value``) when ``args.field_kind`` classifies the field
  as non-sensitive; a ``sensitive`` field (or, outside those two phases, an
  unclassified one) keeps nothing (exclusion ``typed_text_dropped``), and so
  does a typed value that looks like a secret whatever the field kind
  (:func:`looks_like_secret`). Other operations drop free text outside those
  phases (``text_dropped``).
* Page title and page text are kept for every event (but see the page-host
  rule below), whitespace-normalized.
* A collector may claim, never verify: ``verified_*`` becomes ``claimed_*``
  with the exclusion ``verification_claim_dropped``.
* Unknown enum values are ``malformed``; an event naming a site excluded by
  configuration (nothing is excluded by default) is ``source_excluded``,
  whichever host names it (:func:`event_hosts`: the site, the route URL, URLs
  in the route's query, the top-level ``query`` and the target label); an
  event whose normalized form exceeds the per-event limit is
  ``event_too_large``. Each refuses the whole batch upstream.
* While any site is excluded, an event whose page host is unknown (no
  ``site`` and no full-URL ``route``: a task boundary, a correction, a gap
  marker, an action on a page the collector did not name) could be an
  excluded host's, which the receiver cannot check. It is kept without its
  site-controlled content: ``target``, ``query``, ``page_title``,
  ``page_text`` and ``text`` unless the text is the user's own words
  (:func:`speaks_for_user`); anything dropped adds the exclusion
  ``page_host_unknown``.

Rejections carry a code only. Nothing here logs or echoes event content.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from itertools import pairwise
from typing import Any, Final, NamedTuple
from urllib.parse import parse_qsl, urlsplit

from ._redaction import (
    _MAX_URL_NESTING,
    _URL_IN_TEXT_RE,
    _scrub,
    _scrub_jwts,
    _scrub_suffix,
    _split_suffix,
)

# Preserve the public redaction API for existing collectors and history readers.
from ._redaction import AMBIGUOUS_SECRET_KEYWORDS as AMBIGUOUS_SECRET_KEYWORDS
from ._redaction import CREDENTIAL_COMPOUNDS as CREDENTIAL_COMPOUNDS
from ._redaction import CREDENTIAL_PARAMS as CREDENTIAL_PARAMS
from ._redaction import CREDENTIAL_SUFFIXES as CREDENTIAL_SUFFIXES
from ._redaction import CREDENTIAL_WORDS as CREDENTIAL_WORDS
from ._redaction import JAPANESE_SECRET_KEYWORDS as JAPANESE_SECRET_KEYWORDS
from ._redaction import KEY_PREFIXES as KEY_PREFIXES
from ._redaction import MAX_SECRET_VALUE_CHARS as MAX_SECRET_VALUE_CHARS
from ._redaction import MAX_SECRET_VALUE_WORDS as MAX_SECRET_VALUE_WORDS
from ._redaction import MAX_SECRET_VALUES as MAX_SECRET_VALUES
from ._redaction import OPAQUE_USERNAME_CHARS as OPAQUE_USERNAME_CHARS
from ._redaction import ORDINARY_NAME_QUALIFIERS as ORDINARY_NAME_QUALIFIERS
from ._redaction import REDACTED as REDACTED
from ._redaction import SECRET_INNER_TOKEN_MIN_CHARS as SECRET_INNER_TOKEN_MIN_CHARS
from ._redaction import SECRET_TOKEN_MIN_CHARS as SECRET_TOKEN_MIN_CHARS
from ._redaction import SECRET_VALUE_STOP_WORDS as SECRET_VALUE_STOP_WORDS
from ._redaction import SecretValues as SecretValues
from ._redaction import contains_values as contains_values
from ._redaction import credential_param as credential_param
from ._redaction import looks_like_secret as looks_like_secret
from ._redaction import redact_secret_shaped_tokens as redact_secret_shaped_tokens
from ._redaction import redact_secret_tokens as redact_secret_tokens
from ._redaction import redact_text_secrets as redact_text_secrets
from ._redaction import redact_values as redact_values
from ._redaction import scrub_query as scrub_query
from ._redaction import scrub_urls as scrub_urls
from ._redaction import secret_values as secret_values

SCHEMA_VERSION: Final = 1


@dataclass(frozen=True)
class PeerPrincipal:
    """Authenticated submitter of activity batches.

    ``peer_id`` is ``operator:<12 hex>`` for an activity peer, ``extension``
    for the paired browser extension and ``hermes:<profile>`` for Hermes's own
    browser calls (:mod:`.capture_hermes`, an in-process principal with trust
    ``local``, never reachable over the network). ``trust`` and
    ``permitted_use`` come from the authentication path, never from a payload.
    """

    peer_id: str
    kind: str  # "operator" | "browser" | "hermes"
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
#: A batch's ``producer_kind`` must equal its principal's ``kind`` (the receiver refuses anything else as
#: ``malformed``), so a paired peer can never claim to be Hermes.
PRODUCER_KINDS: Final = frozenset({"operator", "browser", "hermes"})

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
#: A credential parameter, a secret-shaped parameter value, a JWT or secret userinfo inside a URL was
#: replaced with :data:`REDACTED`.
EXCLUSION_URL_PARAMS: Final = "url_params_redacted"
#: A secret inside free text (task or correction text, a target label, the page title or text) was
#: replaced with :data:`REDACTED` (:func:`redact_text_secrets`).
EXCLUSION_TEXT_SECRETS: Final = "text_secrets_redacted"
#: While sites are excluded, the site-controlled content of an event whose page host is unknown (no ``site``,
#: no full-URL ``route``) was dropped: it could be an excluded host's page (:func:`normalize_event`).
EXCLUSION_PAGE_HOST_UNKNOWN: Final = "page_host_unknown"
#: A collector's own quality exclusion marking a sensitive field; its typed text is withheld too.
COLLECTOR_SENSITIVE_MARK: Final = "sensitive_field"

_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_REF_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HOST_RE: Final = re.compile(r"^[a-z0-9.:-]{1,253}$")
_SIG_RE: Final = re.compile(r"^[0-9a-f]{16}$")
_TOKEN_RE: Final = re.compile(r"^[a-z0-9_]{1,48}$")

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
    """``site`` is an excluded host or one of its subdomains (case and a trailing dot ignored)."""
    if site is None:
        return False
    site = site.lower().rstrip(".")
    excluded_sites = [host.lower().rstrip(".") for host in excluded_sites]
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


class _Text(NamedTuple):
    """A bounded, scrubbed text field: ``(value, truncated, URL secrets redacted, text secrets redacted)``."""

    value: str | None = None
    cut: bool = False
    redacted: bool = False
    secrets: bool = False


def _bounded(
    text: str,
    limit: int,
    scrub: Callable[[str], tuple[str, bool]] = _scrub,
    *,
    free_text: bool = True,
    user: bool = False,
) -> _Text:
    """URL-scrubbed, then (``free_text``) secret-redacted (the user's own words, ``user``, also their
    secret-shaped tokens), then bounded: nothing is cut before it is checked."""
    clean, redacted = scrub(text)
    clean, secrets = redact_text_secrets(clean) if free_text else (clean, False)
    if user:
        clean, shaped = redact_secret_shaped_tokens(clean)
        secrets = secrets or shaped
    cut = len(clean) > limit
    return _Text(clean[:limit] if cut else clean, cut, redacted, secrets)


def _bounded_text(value: Any, limit: int, *, free_text: bool = True, user: bool = False) -> _Text:
    if value is None:
        return _Text()
    if not isinstance(value, str):
        raise _malformed()
    return _bounded(value, limit, free_text=free_text, user=user)


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
    return _bounded(suffix, MAX_QUERY_CHARS, scrub=_scrub_suffix, free_text=False)


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


def bare_host(host: str) -> str:
    """``host`` compared as a site: lower case, without a trailing dot or a leading ``www.``."""
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _url_hosts(text: str, depth: int = 0) -> Iterator[str]:
    """Hosts of the URLs in ``text`` and, nested up to :data:`_MAX_URL_NESTING` deep, in their parameters."""
    for match in _URL_IN_TEXT_RE.finditer(text):
        head, suffix = _split_suffix(match.group(0))
        try:
            host = urlsplit(head).hostname
        except ValueError:
            host = None
        if host:
            yield host
        if suffix and depth < _MAX_URL_NESTING:
            yield from _param_hosts(suffix, depth + 1)


def _param_hosts(params: str, depth: int) -> Iterator[str]:
    """Hosts of URLs inside the (decoded) parameter values of a ``?query#fragment`` or a parameter list."""
    for _name, value in parse_qsl(re.sub(r"[?#;]", "&", params), keep_blank_values=True):
        if "://" in value:
            yield from _url_hosts(value, depth)


def event_hosts(raw_action: Mapping[str, Any], raw_query: Any) -> set[str]:
    """Hosts of the URLs a raw event names besides its own site: URLs inside the ``site`` and ``route``
    strings, the route's query, the top-level ``query`` and the target label, redirect targets included
    (parameter values decoded up to :data:`_MAX_URL_NESTING` levels). :func:`normalize_event` checks these
    and the normalized site against ``excluded_sites``."""
    hosts: set[str] = set()
    for key in ("site", "route", "target"):
        value = raw_action.get(key)
        if isinstance(value, str):
            hosts.update(_url_hosts(value))
    route = raw_action.get("route")
    if isinstance(route, str):
        hosts.update(_param_hosts(_split_suffix(route)[1], 1))
    if isinstance(raw_query, str):
        hosts.update(_param_hosts(raw_query, 1))
    return hosts


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
    site = _site(raw.get("site"))
    if site and location.host and bare_host(site) != bare_host(location.host):
        raise _malformed()  # a site that contradicts its own URL could hide an excluded host
    site = site or location.host
    args_json, exclusions = _args(raw.get("args"))
    field_kind, typed_arg = _typed_args(raw.get("args"))
    return _Action(op, target, site, location, args_json, exclusions, field_kind, typed_arg)


def _text(
    raw: Mapping[str, Any], phase: str, action: _Action, sensitive: bool, *, user: bool = False
) -> tuple[_Text, tuple[str, ...]]:
    """``(text, exclusions)`` under the free-text rules in the module docstring; ``user``: the text is the user's
    own words (:func:`speaks_for_user`)."""
    value = raw.get("text")
    if action.op not in TYPED_OPS:
        if value is None:
            return _Text(), ()
        if phase not in TEXT_PHASES:
            return _Text(), (EXCLUSION_TEXT,)
        return _bounded_text(value, MAX_TEXT_CHARS, user=user), ()
    if value is None:
        value = action.typed_arg
    if value is None:
        return _Text(), ()
    # What was typed into a secret field is never kept; an unclassified field only in a text phase.
    if sensitive or (action.field_kind is None and phase not in TEXT_PHASES):
        return _Text(), (EXCLUSION_TYPED_TEXT,)
    # Whatever the field, a value shaped like a credential is withheld too.
    if isinstance(value, str) and looks_like_secret(value):
        return _Text(), (EXCLUSION_TYPED_TEXT,)
    # Typed text keeps its own withhold rule above instead of the free-text redaction.
    return _bounded_text(value, MAX_TEXT_CHARS, free_text=False), ()


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


def speaks_for_user(phase: str, op: str, source: str, actor: str) -> bool:
    """The event's text is the user's own words, by the collector's attribution: a task start whose ``actor`` is
    ``human``, or a correction whose ``source`` is ``user_correction`` and whose ``actor`` is ``human``. Text
    labelled ``agent`` or ``unknown`` never is. The SQL form is :data:`.history.USER_TEXT_SQL`."""
    if actor != "human":
        return False
    return (phase == "boundary" and op == "task_start") or (phase == "correction" and source == "user_correction")


class _Content(NamedTuple):
    """An event's site-controlled fields and its free text: what an event without a page host loses."""

    target: _Text
    text: _Text
    query: _Text
    page_title: _Text
    page_text: _Text


def _placed(content: _Content, *, unplaced: bool, user_words: bool) -> tuple[_Content, tuple[str, ...]]:
    """``(content kept, exclusions)``: an ``unplaced`` event (no page host while sites are excluded) keeps only
    the user's own words, with :data:`EXCLUSION_PAGE_HOST_UNKNOWN` when anything was dropped."""
    if not unplaced:
        return content, ()
    kept = _Content(_Text(), content.text if user_words else _Text(), _Text(), _Text(), _Text())
    dropped = any(old.value is not None and new.value is None for old, new in zip(content, kept, strict=True))
    return kept, ((EXCLUSION_PAGE_HOST_UNKNOWN,) if dropped else ())


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
    user = speaks_for_user(identity["phase"], action.op, identity["source"], identity["actor"])
    text, text_exclusions = _text(raw, identity["phase"], action, _sensitive(action, quality["exclusions"]), user=user)
    query = _query(raw.get("query"), action.location.query)
    page_title = _page_field(raw.get("page_title"), MAX_PAGE_TITLE_CHARS)
    page_text = _page_field(raw.get("page_text"), MAX_PAGE_TEXT_CHARS)
    if excluded_sites:
        hosts = {action.site, action.location.host, *event_hosts(_group(raw, "action"), raw.get("query"))}
        if any(site_excluded(host, excluded_sites) for host in hosts):
            raise EventRejected("source_excluded")
    content, unplaced_exclusions = _placed(
        _Content(action.target, text, query, page_title, page_text),
        # ``action.site`` is the explicit site or else the host of a full-URL route: the page's host.
        unplaced=bool(excluded_sites) and action.site is None,
        user_words=speaks_for_user(identity["phase"], action.op, identity["source"], identity["actor"]),
    )
    redacted = action.location.redacted or any(field.redacted for field in content)
    event = NormalizedEvent(
        **identity,
        op=action.op,
        target=content.target.value,
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
                *unplaced_exclusions,
                *((EXCLUSION_URL_PARAMS,) if redacted else ()),
                *((EXCLUSION_TEXT_SECRETS,) if any(field.secrets for field in content) else ()),
            )
        ),
        truncated=quality["truncated"] or action.location.truncated or any(field.cut for field in content),
        page_sig_before=quality["page_sig_before"],
        page_sig_after=quality["page_sig_after"],
        **_session_ref(_group(raw, "session_ref")),
        text=content.text.value,
        query=content.query.value,
        page_title=content.page_title.value,
        page_text=content.page_text.value,
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
