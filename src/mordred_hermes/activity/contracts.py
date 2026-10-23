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

import bisect
import hashlib
import importlib
import json
import math
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from itertools import groupby, pairwise
from typing import Any, Final, NamedTuple, cast
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

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
        "client_assertion",
        "samlresponse",
        "samlrequest",
        "relaystate",
    }
)
#: Suffixes of lower-cased parameter names whose values are credentials (``csrf_token``, ``db_password``,
#: ``code_verifier``, ``aws_credentials``).
CREDENTIAL_SUFFIXES: Final = (
    "token",
    "secret",
    "password",
    "passwd",
    "signature",
    "apikey",
    "api_key",
    "credential",
    "credentials",
    "verifier",
    "ticket",
)
#: Short words that make a parameter name a credential when they are its last word (``x_key``, ``apiKey``,
#: ``auth-code``, ``x.pass``, ``req_sig``, ``basicAuth``); ``monkey`` or ``barcode`` are words of their own.
CREDENTIAL_WORDS: Final = frozenset({"key", "code", "pass", "sig", "auth"})
#: One-word names that end in a credential word (``accesskey``, ``passkey``, ``authcode``, ``oauth``).
CREDENTIAL_COMPOUNDS: Final = frozenset(
    {
        "accesskey",
        "secretkey",
        "privatekey",
        "passkey",
        "authkey",
        "sessionkey",
        "signingkey",
        "licensekey",
        "authcode",
        "passcode",
        "otpcode",
        "smscode",
        "oauth",
        "xauth",
    }
)
#: Words before a final ``code`` or ``key`` that make an ordinary name (``country_code``, ``sortKey``).
ORDINARY_NAME_QUALIFIERS: Final = frozenset(
    {
        "country",
        "currency",
        "zip",
        "postal",
        "post",
        "lang",
        "language",
        "locale",
        "region",
        "error",
        "status",
        "http",
        "sort",
        "color",
        "colour",
    }
)
#: The words of a parameter name: an upper-case run, a capitalized or lower-case word, or digits.
_NAME_WORD_RE: Final = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
#: ``user[password]`` / ``tokens[0]``: the bracketed parts of an array-style parameter name.
_NAME_BRACKET_RE: Final = re.compile(r"\[([^\[\]]*)\]")
#: A userinfo name this long made only of key characters is an opaque credential, not a user name.
OPAQUE_USERNAME_CHARS: Final = 24
_OPAQUE_RE: Final = re.compile(r"[A-Za-z0-9_-]+")

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
#: Well-known credential prefixes starting a token, followed by at least 8 key characters: OpenAI-style
#: ``sk-``, Stripe ``sk_live_`` / ``sk_test_`` / ``rk_live_`` / ``rk_test_``, GitHub ``ghp_`` / ``gho_`` /
#: ``ghs_`` / ``ghu_`` / ``github_pat_``, GitLab ``glpat-``, AWS ``AKIA`` / ``ASIA``, Google ``AIza`` /
#: ``ya29.``, Slack ``xoxb-`` / ``xoxp-`` / ``xoxa-`` / ``xoxe-`` / ``xoxr-`` / ``xoxs-`` / ``xapp-``, npm
#: ``npm_`` and Hugging Face ``hf_``.
KEY_PREFIXES: Final = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxe-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "npm_",
    "hf_",
)
_KEY_PREFIX_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_-])(?:" + "|".join(re.escape(prefix) for prefix in KEY_PREFIXES) + r")[A-Za-z0-9_-]{8,}"
)
#: The armour line of a PEM private key or certificate request (``-----BEGIN RSA PRIVATE KEY-----``).
_PEM_RE: Final = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|KEY BLOCK)-----")
#: A labelled secret in free text: ``password: …``, ``pin=…``, ``api key: …``.
_LABELLED_SECRET_RE: Final = re.compile(
    r"(?i)\b(?:pass(?:word|wd|phrase|code)?|pwd|pin|secret|token|api(?:[^\S\r\n]{1,32}|[_-])?key)\s*[:=]\s*\S"
)
#: Keywords naming a secret in free text (case-insensitive). An ASCII keyword must not touch an ASCII letter
#: or digit on either side (``pinned``, ``tokens`` and ``password2`` are no keywords); ``pin code`` is tried
#: before ``pin``.
_KEYWORD_JOINER: Final = r"(?:[^\S\r\n]{1,32}|[_-])?"  # the words of a two-word keyword: same-line spaces, _ or -
_ASCII_SECRET_KEYWORDS: Final = (
    f"pin{_KEYWORD_JOINER}code|one{_KEYWORD_JOINER}time{_KEYWORD_JOINER}code|api{_KEYWORD_JOINER}(?:key|token)"
    f"|access{_KEYWORD_JOINER}token|pass(?:word|wd|phrase|code)|pwd|otp|pin|secret|token"
)
#: The Japanese words for one-time password, password, PIN, passcode and verification code; written without
#: spaces, so they need no word boundary.
JAPANESE_SECRET_KEYWORDS: Final = (
    "ワンタイムパスワード",
    "パスワード",
    "暗証番号",
    "パスコード",
    "認証コード",
)
_SECRET_KEYWORD_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:" + _ASCII_SECRET_KEYWORDS + r")(?![A-Za-z0-9])|" + "|".join(JAPANESE_SECRET_KEYWORDS)
)
#: Keywords that are ordinary English words too ("pin the tab", "the secret is out", "token count"): unless
#: labelled (``:`` / ``=``) or quoted, their value must be credential-shaped (:func:`_credential_shaped`).
AMBIGUOUS_SECRET_KEYWORDS: Final = frozenset({"pin", "secret", "token"})
#: Values after a keyword that are interface or function words, not secrets ("the password field",
#: "reset password page", "the password is incorrect"); compared without case.
SECRET_VALUE_STOP_WORDS: Final = frozenset(
    {
        # interface words
        *("field", "fields", "box", "boxes", "input", "inputs", "form", "forms", "reset", "manager", "managers"),
        *("page", "pages", "button", "buttons", "prompt", "prompts", "dialog", "dialogs", "hint", "hints"),
        *("policy", "policies", "strength", "requirement", "requirements", "rule", "rules", "length", "screen"),
        *("settings", "setting", "link", "menu", "entry", "label", "change", "changes", "changed", "recovery"),
        *("generator", "protected", "protection", "expired", "expires", "expiry", "incorrect", "invalid", "wrong"),
        *("mismatch", "error", "sent", "verification", "confirmation", "confirm", "required", "optional", "login"),
        *("sign", "show", "hide", "forgot", "remember", "cancel", "submit", "continue", "next", "back", "ok"),
        *("enter", "type", "create", "new", "current", "old", "repeat", "edit", "update", "updated", "save"),
        *("saved", "set", "use", "used", "here", "below", "above", "none", "empty", "weak", "strong", "valid"),
        # function words
        *("a", "an", "the", "and", "or", "but", "nor", "to", "for", "of", "in", "on", "at", "by", "with", "from"),
        *("into", "is", "was", "are", "were", "be", "been", "it", "its", "this", "that", "these", "those", "my"),
        *("your", "our", "their", "his", "her", "not", "no", "if", "as", "so", "too", "there", "then", "when"),
        *("will", "would", "can", "could", "should", "must", "may", "has", "have", "had", "do", "does", "did"),
        "please",
        # the Japanese words for field, input field, field (katakana), reset, change, screen, input, setting,
        # resetting and confirmation
        *("欄", "入力欄", "フィールド", "リセット"),
        *("変更", "画面", "入力", "設定", "再設定", "確認"),
        # and for manager (two spellings), page, form, hint, box, button, policy, rule, link, menu, list, error,
        # file, app, management, generation, saving, protection, required, display, reissue, strength,
        # requirement, condition, expiry, history, registration and update. They hold no ASCII letter or digit,
        # so only a value of several words could take one (:func:`_starts_a_value`).
        *("マネージャー", "マネージャ", "ページ", "フォーム", "ヒント", "ボックス", "ボタン", "ポリシー", "ルール"),
        *("リンク", "メニュー", "リスト", "エラー", "ファイル", "アプリ", "管理", "生成", "保存", "保護", "必須"),
        *("表示", "再発行", "強度", "要件", "条件", "期限", "有効期限", "履歴", "登録", "更新"),
    }
)
#: Words the newer forms (a value before its keyword, after ``to``, after a qualifier) never take as a value:
#: placeholders ("type something into the password field") and properties ("is case-sensitive"). The rule
#: after a keyword keeps :data:`SECRET_VALUE_STOP_WORDS` only, so it replaces no less than it did before.
_PLACEHOLDER_WORDS: Final = frozenset(
    {
        *("something", "anything", "nothing", "everything", "whatever", "same", "value", "values", "text"),
        *("case-sensitive", "case-insensitive"),
    }
)
#: Connectors between a keyword and its value: labels (``:``, ``=``, full-width too), the Japanese particles
#: of topic, object and subject, and the words ``is``, ``was`` and ``of`` after whitespace.
_LABEL_MARKS: Final = frozenset(":=\uff1a\uff1d")  # full-width colon and equals sign
_PARTICLES: Final = frozenset("はをが")
_WORD_CONNECTOR_RE: Final = re.compile(r"(?i)(?:is|was|of)(?=[\s:=\uff1a\uff1d\"'\u201c\u2018「『])")
_SPACE_RE: Final = re.compile(r"\s{1,32}")
_MAX_CONNECTORS: Final = 4
#: Quotes and brackets around a value (kept in the text) and the mark that closes each: straight, curly and
#: corner quotes, ASCII and full-width brackets. Inside quotes (not brackets) a value may hold spaces.
_VALUE_QUOTES: Final[Mapping[str, str]] = dict(
    zip("\"'\u201c\u2018「『([<\uff08【", "\"'\u201d\u2019」』)]>\uff09】", strict=True)
)
_SPACED_QUOTES: Final = frozenset("\"'\u201c\u2018「『")
#: Quotes that may follow a keyword directly (``password"x"``, the Japanese corner brackets).
_DIRECT_QUOTES: Final = frozenset('"\u201c「『')
#: Longest secret value inspected; a longer unquoted run is redacted to its end when it is accepted.
MAX_SECRET_VALUE_CHARS: Final = 256
#: An unquoted value: no whitespace, hiragana (a particle or verb ending), CJK punctuation or full-width
#: punctuation.
_NOT_VALUE_CHARS: Final = r"\s\u3040-\u309f\u3000-\u303f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65"
_VALUE_CHARS: Final = "[^" + _NOT_VALUE_CHARS + "]"
_NOT_VALUE_RE: Final = re.compile("[" + _NOT_VALUE_CHARS + "]")
_BARE_VALUE_RE: Final = re.compile(_VALUE_CHARS + f"{{1,{MAX_SECRET_VALUE_CHARS}}}")
#: Punctuation that ends a sentence or closes a bracket after an unquoted value; kept outside the replacement.
_TRAILING_MARKS: Final = frozenset(".,;:!?)]}>\"'\u201d\u2019")
#: A value named before its keyword (:func:`_value_before`). Between value and keyword stand at most
#: :data:`_MAX_BACKWARD_CONNECTORS` of these words, at least one of them a link: "Hunter2 as the password",
#: "use X for my PIN", "type X into the field for the password", "hunter 2 is the password" (a copula: the value is
#: the keyword's, not put in its place).
_COPULAS: Final = frozenset({"is", "was"})
_BACKWARD_LINKS: Final = frozenset({"as", "for", "in", "into", "to"}) | _COPULAS
_BACKWARD_CONNECTORS: Final = _BACKWARD_LINKS | frozenset(
    {"the", "a", "an", "my", "your", "our", "their", "his", "her", "this", "that", "field", "box", "input"}
)
_MAX_BACKWARD_CONNECTORS: Final = 5
#: A verb that puts a value somewhere, right before the value ("type swordfish as the password"); ``fill in``
#: and ``key in`` are two words (:data:`_IN_VERB_RE` before ``in``).
_VALUE_VERB_RE: Final = re.compile(
    r"(?i)(?:typ(?:e|es|ed|ing)|enter(?:s|ed|ing)?|us(?:e|es|ed|ing)|input(?:s|ted|ting)?|put(?:s|ting)?"
    r"|past(?:e|es|ed|ing)|insert(?:s|ed|ing)?)"
)
_IN_VERB_RE: Final = re.compile(r"(?i)(?:fill(?:s|ed|ing)?|key(?:s|ed|ing)?)")
#: A word after the keyword that makes the keyword a modifier, not the place of a value ("2FA in the password
#: settings", "v2 to the token list"); compared without case.
_KEYWORD_HEADS: Final = frozenset(
    {
        *("manager", "managers", "policy", "policies", "reset", "resets", "page", "pages", "button", "buttons"),
        *("prompt", "prompts", "dialog", "dialogs", "hint", "hints", "strength", "requirement", "requirements"),
        *("rule", "rules", "length", "screen", "screens", "settings", "setting", "link", "links", "menu"),
        *("label", "labels", "change", "changes", "recovery", "generator", "protection", "expiry", "history"),
        *("form", "forms", "count", "counts", "list", "lists", "limit", "limits", "type", "types", "format"),
        *("formats", "usage", "budget", "vault", "vaults", "store", "file", "files", "alternative", "alternatives"),
        *("sharing", "group", "groups", "reminder", "reminders"),
    }
)
#: The word after a keyword or a value on the same line (the next line starts another phrase).
_NEXT_WORD_RE: Final = re.compile(r"(?:[^\S\r\n]|-){1,32}([A-Za-z]{1,32})")
#: Japanese value-first forms: the value before the object particle (then the keyword, an optional field word
#: and the target or direction particle or the word for "as": :data:`_JA_SLOTS`), or before the word for
#: "called"; and the value between the target particle or the word for "as" after a keyword
#: (:data:`_JA_TARGETS`) and the object particle.
_JA_OBJECT: Final = "\u3092"
_JA_CALLED: Final = "\u3068\u3044\u3046"
_JA_TARGETS: Final = ("\u3068\u3057\u3066", "\u306b")
#: The Japanese words for input field, field and field (katakana), longest first.
_JA_FIELDS: Final = ("\u5165\u529b\u6b04", "\u6b04", "\u30d5\u30a3\u30fc\u30eb\u30c9")
_JA_SLOTS: Final = ("\u3068\u3057\u3066", "\u306b", "\u3078")
#: What may stand right before or after a keyword in the Japanese forms (whitespace too): a cheap first check.
_JA_BEFORE_KEYWORD: Final = frozenset({_JA_OBJECT, _JA_CALLED[-1]})
_JA_AFTER_KEYWORD: Final = frozenset(word[0] for word in (*_JA_FIELDS, *_JA_TARGETS))
#: Characters inside a value that let a keyword in it name something outside it (:func:`_closed_part`): an
#: opening quote or bracket, and the first characters of the Japanese forms after a keyword.
_REGION_BREAKERS_RE: Final = re.compile(
    "[" + "".join(re.escape(char) for char in sorted({*_VALUE_QUOTES, *_JA_AFTER_KEYWORD})) + "]"
)
#: Shorter values are not worth a check: a keyword with its connector does not fit in them.
_MIN_CLOSED_VALUE_CHARS: Final = 8
#: Characters that end a token, an ASCII run, a run of closing marks or of opening marks (:class:`_TextIndex`).
_WHITESPACE_RE: Final = re.compile(r"\s")
#: A run of ASCII (a Japanese sentence's unquoted value) is ASCII without whitespace, control characters too.
_NOT_ASCII_RUN_RE: Final = re.compile(r"[^\x00-\x7f]|\s")
_NOT_CLOSING_RE: Final = re.compile("[^" + "".join(re.escape(char) for char in sorted(_TRAILING_MARKS)) + "]")
_NOT_OPENING_RE: Final = re.compile("[^" + "".join(re.escape(char) for char in sorted(_VALUE_QUOTES)) + "]")
#: How far an index question looks before it builds its table.
_LOCAL_SCAN_CHARS: Final = 64
#: Longest token read as a connector or a verb.
_MAX_WORD_CHARS: Final = 16
#: The opening mark of each closing quote or bracket (:data:`_VALUE_QUOTES` reversed).
_OPENER_OF: Final[Mapping[str, str]] = {closer: opener for opener, closer in _VALUE_QUOTES.items()}
_ASCII_ALNUM_RE: Final = re.compile(r"[A-Za-z0-9]")
#: "set the password to X" (:func:`_value_after_to`): the keyword, ``to``, the value, and a verb that sets it at
#: most :data:`_MAX_SET_VERB_DISTANCE` words before the keyword.
_TO_RE: Final = re.compile(r"(?i)\s{1,32}to\s{1,32}")
_SET_VERB_RE: Final = re.compile(
    r"(?i)(?:set(?:s|ting)?|chang(?:e|es|ed|ing)|updat(?:e|es|ed|ing)|reset(?:s|ting)?|modif(?:y|ies|ied|ying))"
)
_MAX_SET_VERB_DISTANCE: Final = 3
#: "the password for the bank is X" (:func:`_qualified_value`): the keyword, one of these words, at most
#: :data:`_MAX_QUALIFIER_WORDS` words in all, then ``is`` / ``was`` or ``:`` / ``=``.
_QUALIFIER_LINKS: Final = frozenset({"for", "on", "at", "of", "in"})
_MAX_QUALIFIER_WORDS: Final = 4
#: A whitespace-separated word; a label mark ends it when whitespace (or the end) follows.
_WORD_AFTER_RE: Final = re.compile(r"\s{1,32}((?:[^\s:=\uff1a\uff1d]|[:=\uff1a\uff1d](?=\S))+)")
_IS_WAS_RE: Final = re.compile(r"(?i)(?:is|was)(?=[\s:=\uff1a\uff1d\"'\u201c\u2018「『])")
#: Words after a number that make it a length or a count, not a secret ("to 12 characters"); without case.
_VALUE_UNITS: Final = frozenset(
    {
        *("char", "chars", "character", "characters", "digit", "digits", "letter", "letters", "symbol", "symbols"),
        *("word", "words", "day", "days", "hour", "hours", "minute", "minutes", "week", "weeks", "month", "months"),
        *("year", "years", "time", "times"),
    }
)
_CLAUSE_MARKS: Final = frozenset(".,;:!?")
#: Most words a value of several words takes (:func:`_words_after`, :func:`_words_before`). Speech recognition writes
#: a spoken password as several words ("the password is hunter 2 fake pw"), and a passphrase has four to seven: eight
#: covers both, while a sentence without punctuation loses at most eight ordinary words to the replacement.
MAX_SECRET_VALUE_WORDS: Final = 8
#: The same-line whitespace between two words of a value (a line break starts another phrase).
_LINE_BREAKS: Final = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")
_WORD_GAP_RE: Final = re.compile(r"[^\S\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]{1,32}")
_HIRAGANA_RE: Final = re.compile("[\u3040-\u309f]")
#: Articles, possessives and demonstratives: a spoken passphrase may hold them ("my secret sauce 42", "hunter the
#: great 7"), so they never end a value of several words; one may start it after a strong frame
#: (:func:`_after_a_determiner`).
_DETERMINERS: Final = frozenset(
    {"a", "an", "the", "my", "your", "our", "their", "his", "her", "its", "this", "that", "these", "those"}
)
#: Words that start another part of the sentence, so a value of several words ends before them: the interface and
#: function words (:data:`SECRET_VALUE_STOP_WORDS`: "and", "then", "please", "with", "in", "as", "is", "expires" ...)
#: but the determiners, more connectives and words of time. A keyword that starts a frame of its own and a verb that
#: puts or sets a value end it too (:func:`_ends_value`).
_VALUE_END_WORDS: Final = (SECRET_VALUE_STOP_WORDS - _DETERMINERS) | frozenset(
    {
        *("also", "after", "before", "because", "while", "until", "once", "which", "where", "since", "unless"),
        *("yesterday", "today", "tomorrow", "tonight", "now", "soon", "later", "again", "instead", "okay", "thanks"),
    }
)
#: Words of :data:`_VALUE_END_WORDS` that may stand for a symbol or a digit inside a spoken value ("hunter at fake dot
#: pw"): they end it only before (reading on) or after (reading back) a word that starts another part, a typed word
#: or nothing (:func:`_link_ends`: "for the bank", "to log in", "use at least").
_SPOKEN_LINKS: Final = frozenset({"at", "to", "for"})
#: A word that only separates ("hunter / 2 fake pw", "blue | s3cr3t!"): a value of several words is read on (or back)
#: through it, and it is replaced only between two words of the value. It ends the value only after a field label
#: that starts another part ("user = demo", :data:`_FIELD_LABELS`).
_SEPARATOR_WORD_RE: Final = re.compile("[:=\uff1a\uff1d/|]+")
_FIELD_LABELS: Final = frozenset({"user", "username", "userid", "email", "e-mail", "mail", "id", "name", "account"})
_NEXT_PART_VERBS: Final = frozenset(
    {"log", "access", "unlock", "open", "get", "go", "start", "finish", "proceed", "complete", "visit", "click"}
)
#: The words after (or before) a spoken link that start another part, so the link ends the value (:func:`_link_ends`).
_NEXT_PART_WORDS: Final = SECRET_VALUE_STOP_WORDS | _VALUE_END_WORDS | _NEXT_PART_VERBS
#: Words a value of several words never starts with (:func:`_starts_a_value`): the interface and function words, the
#: heads that make a keyword a modifier, placeholders, units, and the pronouns and quantifiers that start a
#: description ("the password you received", "the password every 90 days"), and the login page's "keep me signed
#: in", "stay signed in" and "need help".
_NOT_VALUE_STARTS: Final = (
    SECRET_VALUE_STOP_WORDS
    | _KEYWORD_HEADS
    | _PLACEHOLDER_WORDS
    | _VALUE_UNITS
    | frozenset({"i", "you", "we", "they", "he", "she", "me", "us", "them", "him", "who", "what", "which"})
    | frozenset({"every", "each", "all", "any", "some", "keep", "stay", "need"})
)
#: Hiragana that may stand inside a value in a Japanese sentence, between two words (a space either side allowed): the
#: particles for "to", "of" and "and", and the readings of digits, which speech recognition writes for a spoken digit
#: ("ハンターにフェイクPW" for "hunter 2 fake pw"). Not followed or preceded by more hiragana
#: ("にして" is a particle and a verb). Longest first.
_JA_JOINTS: Final = (
    *("きゅう", "じゅう", "いち", "さん", "よん", "ろく", "なな", "はち", "ぜろ", "れい"),
    *("に", "の", "と", "ご"),
)
_JA_JOINT_RE: Final = re.compile("(?:" + "|".join(_JA_JOINTS) + ")(?![\u3040-\u309f])")
#: Words a value in a Japanese sentence ends before, after a joint or a space: the verbs that put, send or set a value
#: (log in, sign in, input, send, use, put in, type, press, set, change, register, authenticate, access, confirm,
#: specify, fill in, update, reset, paste, place) and the Japanese words of :data:`SECRET_VALUE_STOP_WORDS`; matched at
#: the start of a word ("に変更", "と入力"). A particle with no joint reading ("で", "を", "です") ends it anyway.
_JA_VALUE_END_WORDS: Final = (
    *("ログイン", "ログオン", "サインイン", "入力", "送信", "利用", "使", "入れ", "打", "押", "設定", "変更", "登録"),
    *("認証", "アクセス", "確認", "指定", "記入", "更新", "再設定", "貼", "置"),
    *(word for word in SECRET_VALUE_STOP_WORDS if not word.isascii()),
)
_JA_VALUE_END_RE: Final = re.compile(
    "|".join(re.escape(word) for word in sorted(set(_JA_VALUE_END_WORDS), key=lambda word: (-len(word), word)))
)
#: A word of katakana only (the long vowel mark and the middle dot, half-width forms too): how speech recognition
#: writes a spoken foreign word. Words of several such words are a spoken value; kanji words are a description.
_KATAKANA_WORD_RE: Final = re.compile("[\u30a1-\u30ff\uff66-\uff9f]+")
#: A run of ASCII without whitespace (a token of the user's own words, :func:`redact_secret_shaped_tokens`).
_ASCII_TOKEN_RE: Final = re.compile(r"[^\s\x80-\U0010ffff]+")
#: A run of 13-19 digits, optionally grouped by single spaces or dashes (a payment card number candidate).
_CARD_RE: Final = re.compile(r"(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])")
#: Minimum length of a whole-value token that counts as secret-shaped (rule 3 of :func:`looks_like_secret`).
SECRET_TOKEN_MIN_CHARS: Final = 16
#: Minimum length of one token inside a longer text that counts as secret-shaped.
SECRET_INNER_TOKEN_MIN_CHARS: Final = 20
#: Characters that join ordinary words (``part-number``, ``file_name``, ``v1.2``); not a "symbol" below.
_WORD_JOINERS: Final = frozenset("-_.")
#: Single tokens that are ordinary text even when long and mixed: a URL, a host with an optional path, an
#: e-mail address, a file path, an ISO date or date-time.
_ORDINARY_TOKEN_RES: Final = (
    re.compile(r"(?i)^[a-z][a-z0-9+.-]{0,31}://\S+$"),
    # Host names are typed in lower case; ``Password2024.Autumn`` is not a host.
    re.compile(r"^(?:www\.)?(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$"),
    re.compile(r"^[^@\s]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$"),
    re.compile(r"^(?:~|\.{1,2})?/\S*$"),
    re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"),
)
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


# --- secret scrubbing ----------------------------------------------------------------------------


def _credential_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in CREDENTIAL_PARAMS or lowered.endswith(CREDENTIAL_SUFFIXES):
        return True
    words = _NAME_WORD_RE.findall(name)
    if not words:
        return False
    last = words[-1].lower()
    if last in CREDENTIAL_COMPOUNDS:
        return True
    return last in CREDENTIAL_WORDS and not (len(words) > 1 and words[-2].lower() in ORDINARY_NAME_QUALIFIERS)


def credential_param(name: str) -> bool:
    """A URL parameter name whose value is a credential, compared without case.

    The name, or any bracketed part of an array-style name (``user[password]``, ``token[]``, ``keys[0]``), is
    one of :data:`CREDENTIAL_PARAMS`, ends in one of :data:`CREDENTIAL_SUFFIXES`, or ends in a word of
    :data:`CREDENTIAL_WORDS` (a camel-case or ``_`` / ``-`` / ``.`` separated last word, not preceded by one
    of :data:`ORDINARY_NAME_QUALIFIERS`) or :data:`CREDENTIAL_COMPOUNDS`.
    """
    stripped = name.strip()
    parts = [stripped.split("[", 1)[0], *_NAME_BRACKET_RE.findall(stripped)]
    return any(_credential_name(part.strip()) for part in parts if part.strip() and not part.strip().isdigit())


def _scrub_value(value: str, depth: int) -> tuple[str, bool]:
    """A non-credential parameter value: a JWT or any other secret-shaped value (:func:`looks_like_secret`)
    is redacted whole, a nested URL (a redirect target) scrubbed."""
    if _JWT_RE.search(value):
        return REDACTED, True
    if "://" not in value:
        return (REDACTED, True) if value and looks_like_secret(value) else (value, False)
    if depth >= _MAX_URL_NESTING:
        return REDACTED, True
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


def _secret_username(username: str) -> bool:
    """A userinfo name that is a credential: secret-shaped, or a long opaque key (``ghp_…@``, a DSN key)."""
    name = unquote(username)
    return looks_like_secret(name) or (len(name) >= OPAQUE_USERNAME_CHARS and _OPAQUE_RE.fullmatch(name) is not None)


def _scrub_userinfo(head: str) -> tuple[str, bool]:
    """``scheme://user:password@host/path`` (no suffix) with a non-empty password and a secret user name
    redacted.

    As in :func:`urllib.parse.urlsplit`, the authority ends at the first ``/`` and the userinfo at
    its LAST ``@``, and the password follows the userinfo's first ``:``; so a password holding ``@``
    or ``:`` is redacted whole. A user name that is a credential (:func:`_secret_username`, such as a
    token used as the user name) is redacted too; any other user name (possibly empty) and the host
    stay as sent.
    """
    scheme, sep, rest = head.partition("://")
    authority, slash, path = rest.partition("/")
    userinfo, at, host = authority.rpartition("@")
    username, colon, password = userinfo.partition(":")
    if not (sep and at):
        return head, False
    secret_user = bool(username) and _secret_username(username)
    secret_password = bool(colon and password)
    if not (secret_user or secret_password):
        return head, False
    username = REDACTED if secret_user else username
    password = REDACTED if secret_password else password
    return f"{scheme}{sep}{username}{colon}{password}@{host}{slash}{path}", True


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


def scrub_query(suffix: str) -> str:
    """A stored ``?query#fragment`` with its secrets replaced by :data:`REDACTED` again, by the rules of
    :func:`scrub_urls` (credential parameters, secret-shaped values, nested URLs with their userinfo).

    Readers apply it so that a suffix stored before a rule existed is shown as the receiver stores it now;
    a suffix with nothing to redact is returned unchanged.
    """
    text = suffix if suffix.startswith(("?", "#")) else "?" + suffix
    return _scrub_suffix(text)[0]


def _secret_shaped_token(token: str) -> bool:
    """One whitespace-free token of 16+ characters mixing letters with digits or symbols, not ordinary text."""
    if len(token) < SECRET_TOKEN_MIN_CHARS or not token.isascii():
        return False  # scripts written without spaces (Japanese, Chinese) are prose, not keys
    if any(pattern.match(token) for pattern in _ORDINARY_TOKEN_RES):
        return False
    if not any(char.isalpha() for char in token):
        return False
    return any(char.isdigit() or (not char.isalnum() and char not in _WORD_JOINERS) for char in token)


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _card_number(text: str) -> bool:
    """A 13-19 digit run (single spaces or dashes allowed) that passes the Luhn check."""
    return any(_luhn(re.sub(r"[ -]", "", match.group(0))) for match in _CARD_RE.finditer(text))


def redact_secret_tokens(text: str) -> str:
    """``text`` with JWTs, key-prefixed tokens and PEM armour lines replaced by :data:`REDACTED`."""
    return _PEM_RE.sub(REDACTED, _KEY_PREFIX_RE.sub(REDACTED, _JWT_RE.sub(REDACTED, text)))


# --- secrets in free text ------------------------------------------------------------------------


class _Connection(NamedTuple):
    """What joins a keyword to its value: where the value starts and which connectors were seen."""

    start: int
    joined: bool  # any connector, whitespace included
    labelled: bool  # ``:`` or ``=``
    linked: bool  # ``is`` / ``was`` / ``of`` or a Japanese particle
    japanese: bool  # a Japanese particle: the value is read as Japanese (:func:`_words_after`)
    strong: bool = False  # a label, ``is`` / ``was`` or a particle (not ``of``): the value is the keyword's


def _connection(text: str, pos: int) -> _Connection:
    """Up to :data:`_MAX_CONNECTORS` connectors after a keyword: whitespace, labels, particles and words."""
    joined = labelled = linked = particle = strong = False
    for _ in range(_MAX_CONNECTORS):
        space = _SPACE_RE.match(text, pos)
        if space:
            pos, joined = space.end(), True
        char = text[pos : pos + 1]
        word = _WORD_CONNECTOR_RE.match(text, pos) if space else None
        if char and char in _LABEL_MARKS:
            pos, joined, labelled, strong = pos + 1, True, True, True
        elif char and char in _PARTICLES:
            pos, joined, linked, particle, strong = pos + 1, True, True, True, True
        elif word:
            pos, linked, strong = word.end(), True, strong or word.group(0).lower() != "of"
        else:
            break
    return _Connection(pos, joined, labelled, linked, particle, strong)


def _quoted_value(text: str, pos: int) -> tuple[int, int] | None:
    """``(start, end)`` of a value inside the quote or bracket at ``pos``, without the marks."""
    closer = _VALUE_QUOTES.get(text[pos : pos + 1])
    if closer is None:
        return None
    close = text.find(closer, pos + 1, pos + 2 + MAX_SECRET_VALUE_CHARS)
    inner = text[pos + 1 : close] if close > pos + 1 else ""
    if not inner or inner != inner.strip() or "\n" in inner:
        return None  # a quote that closes the keyword's own quotation (``"password" or "pin"``)
    if text[pos] not in _SPACED_QUOTES and any(char.isspace() for char in inner):
        return None
    return pos + 1, close


def _without_closing_marks(text: str, start: int, end: int) -> int:
    while end > start and text[end - 1] in _TRAILING_MARKS:
        end -= 1
    return end


def _bare_value(text: str, pos: int) -> tuple[tuple[int, int] | None, bool]:
    """``((start, end) or None, capped)`` of an unquoted value: one token, closing punctuation left out;
    ``capped`` when the token runs past :data:`MAX_SECRET_VALUE_CHARS` (only that much was inspected)."""
    run = _BARE_VALUE_RE.match(text, pos)
    if run is None:
        return None, False
    end = _without_closing_marks(text, pos, run.end())
    capped = run.end() - pos == MAX_SECRET_VALUE_CHARS
    return ((pos, end) if end > pos else None), capped


def _credential_shaped(value: str) -> bool:
    """A digit, a non-alphanumeric character or an upper-case letter after the first one."""
    return any(char.isdigit() or not char.isalnum() for char in value) or any(char.isupper() for char in value[1:])


def _value_like(value: str) -> bool:
    """Not an interface or function word, a URL, a masked placeholder, ``redacted`` or a keyword."""
    if value == REDACTED or "://" in value or not _ASCII_ALNUM_RE.search(value):
        return False
    return value.lower() not in SECRET_VALUE_STOP_WORDS and not _SECRET_KEYWORD_RE.fullmatch(value)


def _named_value(value: str) -> bool:
    """:func:`_value_like` and not a placeholder (:data:`_PLACEHOLDER_WORDS`): a value of the newer forms."""
    return _value_like(value) and value.lower() not in _PLACEHOLDER_WORDS


def _plausible_value(value: str, keyword: str, connection: _Connection, quoted: bool) -> bool:
    """A value that may be a secret, not an interface word, a URL or a masked placeholder."""
    if not _value_like(value):
        return False
    if connection.labelled or quoted:
        return True
    if connection.linked and keyword.lower() not in AMBIGUOUS_SECRET_KEYWORDS:
        return True
    return _credential_shaped(value)


def _value_at(text: str, pos: int) -> tuple[tuple[int, int] | None, bool, bool]:
    """``(span, quoted, capped)`` of the value at ``pos``: inside a quote or bracket, else one bare token
    (:func:`_bare_value`)."""
    span = _quoted_value(text, pos)
    if span is not None:
        return span, True, False
    span, capped = _bare_value(text, pos + 1 if text[pos : pos + 1] in _VALUE_QUOTES else pos)
    return span, False, capped


class _TextIndex:
    """Where runs, tokens and runs of marks of one text end, for the redactor's per-keyword questions.

    Every keyword is read, so no question may rescan a stretch other keywords share (``pin:`` repeated before a
    long tail of dots). Each answer is first looked for within :data:`_LOCAL_SCAN_CHARS` characters; past that,
    the positions of the characters that end such a stretch are found once per text and bisected, and answers
    are remembered, so a text costs O(n log n) at worst and an ordinary one builds no table. The words of a value
    of several words (:func:`_words_after`, :func:`_words_before`) are remembered per position too (``runs``), so
    the keywords whose values end or start at one place read the words beyond it once."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._tables: dict[re.Pattern[str], list[int]] = {}
        self._answers: dict[tuple[re.Pattern[str], int], int] = {}
        self.runs: dict[tuple[bool, int, bool], tuple[tuple[int, int], ...]] = {}

    def _table(self, stop: re.Pattern[str]) -> list[int]:
        table = self._tables.get(stop)
        if table is None:
            table = self._tables[stop] = [match.start() for match in stop.finditer(self.text)]
        return table

    def forward(self, stop: re.Pattern[str], pos: int) -> int:
        """The first position at or after ``pos`` of a character ``stop`` matches (``len(text)`` without one)."""
        local = stop.search(self.text, pos, pos + _LOCAL_SCAN_CHARS)
        if local is not None:
            return local.start()
        if pos + _LOCAL_SCAN_CHARS >= len(self.text):
            return len(self.text)
        table = self._table(stop)
        index = bisect.bisect_left(table, pos)
        return table[index] if index < len(table) else len(self.text)

    def backward(self, stop: re.Pattern[str], keeps: Callable[[str], bool], end: int) -> int:
        """The last position before ``end`` of a character ``stop`` matches (``-1`` without one); ``keeps`` is
        the opposite test for one character, for the local look."""
        answer = self._answers.get((stop, end))
        if answer is None:
            text, pos = self.text, end - 1
            while pos >= 0 and end - pos <= _LOCAL_SCAN_CHARS and keeps(text[pos]):
                pos -= 1
            if pos >= 0 and keeps(text[pos]):  # nothing within the look: ask the table
                table = self._table(stop)
                index = bisect.bisect_left(table, end)
                pos = table[index - 1] if index else -1
            answer = self._answers[(stop, end)] = pos
        return answer

    def run_end(self, pos: int) -> int:
        """The end of the unquoted run (:data:`_VALUE_CHARS`) that goes on from ``pos``."""
        return self.forward(_NOT_VALUE_RE, pos)

    def run_start(self, end: int) -> int:
        """The start of the unquoted run (:data:`_VALUE_CHARS`) that ends at ``end``."""
        return self.backward(_NOT_VALUE_RE, _value_char, end) + 1

    def trimmed(self, start: int, end: int) -> int:
        """``end`` with the closing marks before it left out, never before ``start``
        (:func:`_without_closing_marks`)."""
        return max(start, self.backward(_NOT_CLOSING_RE, _TRAILING_MARKS.__contains__, end) + 1)

    def opened(self, start: int, end: int) -> int:
        """``start`` with the opening marks after it left out, never past ``end``."""
        return min(end, self.forward(_NOT_OPENING_RE, start))

    def token_start(self, end: int) -> int:
        """The start of the whitespace-free token that ends at ``end``."""
        return self.backward(_WHITESPACE_RE, _not_space, end) + 1

    def ascii_start(self, end: int) -> int:
        """The start of the run of ASCII without whitespace that ends at ``end``."""
        return self.backward(_NOT_ASCII_RUN_RE, _ascii_not_space, end) + 1

    def ascii_end(self, pos: int) -> int:
        """The end of the run of ASCII without whitespace that goes on from ``pos``."""
        return self.forward(_NOT_ASCII_RUN_RE, pos)

    def breaker(self, pos: int) -> int:
        """The first opening quote or bracket, or first character of a Japanese form after a keyword
        (:data:`_REGION_BREAKERS_RE`), at or after ``pos``."""
        return self.forward(_REGION_BREAKERS_RE, pos)


def _not_space(char: str) -> bool:
    return not char.isspace()


def _value_char(char: str) -> bool:
    return _NOT_VALUE_RE.match(char) is None


def _ascii_not_space(char: str) -> bool:
    return char.isascii() and not char.isspace()


def _closed_part(index: _TextIndex, span: tuple[int, int]) -> tuple[int, int] | None:
    """The part of the value ``span`` in which every keyword names nothing outside the value, so it need not be
    read; ``None`` when there is none.

    The value is one unquoted run (:data:`_VALUE_CHARS`: no whitespace, hiragana or CJK punctuation) with no
    opening quote or bracket and no first character of a Japanese form after a keyword
    (:data:`_REGION_BREAKERS_RE`), and only closing marks follow it before the run ends. A keyword inside it
    has no whitespace, particle or field word before or after it, so the only value it can name follows ``:``
    / ``=`` and ends where the run ends, inside ``span``. No more words follow such a value: the value found ends
    there too, and the words after a place are the same for every value that ends at it (:func:`_words_after`),
    except that a keyword read as Japanese may go on past a joint, so hiragana after the run (a space between
    allowed) leaves no part. The part leaves out the label marks the value ends in: a keyword before them could
    reach past the value."""
    start, end = span
    if end - start < _MIN_CLOSED_VALUE_CHARS or index.run_end(start) < end:
        return None
    if index.breaker(start) < end or index.trimmed(end, index.run_end(end)) != end:
        return None
    gap = _WORD_GAP_RE.match(index.text, end)
    if _HIRAGANA_RE.match(index.text, gap.end() if gap else end):
        return None  # a keyword inside, read as Japanese, could take the words after a joint (:func:`_joint_after`)
    labels = 0
    while labels <= _MAX_CONNECTORS and index.text[end - labels - 1] in _LABEL_MARKS:
        labels += 1
    return start, end - labels


def _to_its_end(index: _TextIndex, span: tuple[int, int], capped: bool) -> tuple[int, int]:
    """A long run is redacted to its end, never left half visible."""
    if not capped:
        return span
    return span[0], index.trimmed(span[0], max(index.run_end(span[0]), span[1]))


def _counted(text: str, end: int) -> bool:
    """The word after ``end`` makes the value a length or a count (:data:`_VALUE_UNITS`)."""
    unit = _NEXT_WORD_RE.match(text, end)
    return unit is not None and unit.group(1).lower() in _VALUE_UNITS


# --- values of several words (speech recognition writes a spoken password as words) ------------------------------


def _value_char_at(text: str, pos: int) -> bool:
    return pos < len(text) and _NOT_VALUE_RE.match(text, pos) is None


def _gap_before(text: str, pos: int) -> int:
    """Where the same-line whitespace (at most 32 characters) that ends at ``pos`` starts."""
    start = pos
    while start > 0 and pos - start < 32 and text[start - 1].isspace() and text[start - 1] not in _LINE_BREAKS:
        start -= 1
    return start


def _joint_after(text: str, pos: int) -> int | None:
    """Where the next word of a Japanese value starts after a joint at ``pos`` (:data:`_JA_JOINT_RE`, a space after
    it allowed), or ``None``: the word must not be a verb or an interface word (:data:`_JA_VALUE_END_RE`)."""
    joint = _JA_JOINT_RE.match(text, pos)
    if joint is None:
        return None
    gap = _WORD_GAP_RE.match(text, joint.end())
    start = gap.end() if gap else joint.end()
    return start if _value_char_at(text, start) and not _JA_VALUE_END_RE.match(text, start) else None


def _joint_before(text: str, pos: int, at: int) -> int | None:
    """Where the previous word of a Japanese value ends before a joint that ends at ``at`` (a space before it
    allowed), the word after it starting at ``pos``; ``None`` without one (:func:`_joint_after` backwards)."""
    if _JA_VALUE_END_RE.match(text, pos):
        return None
    for joint in _JA_JOINTS:
        start = at - len(joint)
        if start > 0 and text.startswith(joint, start) and not _HIRAGANA_RE.match(text, start - 1):
            end = _gap_before(text, start)
            return end if end > 0 and _value_char_at(text, end - 1) else None
    return None


def _is_end_word(text: str, span: tuple[int, int]) -> bool:
    """The word at ``span`` (closing marks left out) is in :data:`_VALUE_END_WORDS` or puts or sets a value."""
    word = _word(text, span)
    return word in _VALUE_END_WORDS or bool(_VALUE_VERB_RE.fullmatch(word) or _SET_VERB_RE.fullmatch(word))


def _starts_frame(index: _TextIndex, start: int, end: int) -> bool:
    """The word ``text[start:end]`` holds a keyword that starts a frame of its own: the keyword (at the word's start
    or inside it, "DB_PASSWORD=xyz") followed by a label, ``is`` / ``was``, a particle or a direct quote ("pin: 1234",
    "token=abc", "PIN is 4821"). A word that only contains or starts a keyword ("pin cushion", "spinach",
    "tokenize") does not: a passphrase may hold it."""
    text = index.text
    first = _SECRET_KEYWORD_RE.match(text, start)
    for keyword in [*([first] if first else []), *_SECRET_KEYWORD_RE.finditer(text, start + 1, end)]:
        connection = _connection(text, keyword.end())
        if connection.strong or text[connection.start : connection.start + 1] in _DIRECT_QUOTES:
            return True
    return False


def _link_ends(index: _TextIndex, start: int, end: int, *, forward: bool) -> bool:
    """A spoken link (:data:`_SPOKEN_LINKS`) at ``start:end`` ends the value when the word on its far side (after it
    reading on, before it reading back) starts another part (:data:`_NEXT_PART_WORDS`: "for the bank", "to log in",
    "use at least"), is typed (a symbol in it: "PIN=4821 to Hunter2-x"; speech writes letters and digits), is a
    keyword ("the password for the bank": the link is the keyword's qualifier) or starts a frame of its own, or is
    missing. The word on the value's own side never decides: when unsure, read on."""
    text = index.text
    if forward:
        gap = _WORD_GAP_RE.match(text, end)
        word = _BARE_VALUE_RE.match(text, gap.end()) if gap else None
        if word is None:
            return True
        span = (word.start(), _without_closing_marks(text, word.start(), word.end()))
    else:
        stop = _gap_before(text, start)
        begin = index.run_start(stop) if 0 < stop < start else stop
        if begin == stop or text[stop - 1] in _TRAILING_MARKS:
            return True
        span = (begin, stop)
    if not text[span[0] : span[1]].isalnum() or _SECRET_KEYWORD_RE.fullmatch(text, span[0], span[1]):
        return True
    if _starts_frame(index, span[0], span[1]):
        return True
    word_text = _word(text, span)
    return word_text in _NEXT_PART_WORDS or bool(
        _VALUE_VERB_RE.fullmatch(word_text) or _SET_VERB_RE.fullmatch(word_text)
    )


def _ends_value(index: _TextIndex, start: int, end: int, *, forward: bool) -> bool:
    """The word ``text[start:end]`` starts another part of the sentence, so a value of several words ends before it
    (reading on) or after it (reading back): a keyword that starts a frame of its own (:func:`_starts_frame`), a
    word of :data:`_VALUE_END_WORDS`, a verb that puts or sets a value, a Japanese verb or interface word
    (:data:`_JA_VALUE_END_RE`), a spoken link before a word that starts another part (:func:`_link_ends`) or,
    reading back, a URL (a value named before its keyword never starts inside one). Reading on, a URL is read
    through: when unsure, the rest of the clause is replaced."""
    text = index.text
    if _starts_frame(index, start, end) or _JA_VALUE_END_RE.match(text, start):
        return True
    if not forward and "://" in text[start:end]:
        return True
    core = _without_closing_marks(text, start, end)
    if _word(text, (start, core)) in _SPOKEN_LINKS:
        return core < end or _link_ends(index, start, core, forward=forward)
    return _is_end_word(text, (start, core))


def _field_label(text: str, span: tuple[int, int]) -> bool:
    return _word(text, span) in _FIELD_LABELS


def _next_word_start(text: str, pos: int, japanese: bool) -> int | None:
    """Where the next word of a value starts after ``pos``: after same-line whitespace, or (``japanese``) after a
    joint (:func:`_joint_after`); ``None`` before closing punctuation, a line break, hiragana, CJK punctuation or the
    end."""
    gap = _WORD_GAP_RE.match(text, pos)
    start = _joint_after(text, gap.end() if gap else pos) if japanese else None
    if start is None and gap is not None:
        start = gap.end()
    return start


def _word_after_ends(index: _TextIndex, start: int, end: int) -> bool:
    """Reading on, the word at ``start:end`` ends the value: an opening quote or bracket, a field label that starts
    another part ("hunter2 user: demo") or a word that starts another part (:func:`_ends_value`)."""
    text = index.text
    core = _without_closing_marks(text, start, end)
    if text[start] in _VALUE_QUOTES or (text[core : core + 1] in _LABEL_MARKS and _field_label(text, (start, core))):
        return True
    return _ends_value(index, start, end, forward=True)


def _scan_after(index: _TextIndex, end: int, japanese: bool) -> tuple[tuple[int, int], ...]:
    text = index.text
    words: list[tuple[int, int]] = []
    pos = end
    for _ in range(2 * MAX_SECRET_VALUE_WORDS):  # separators are read through but not counted
        start = _next_word_start(text, pos, japanese) if len(words) < MAX_SECRET_VALUE_WORDS - 1 else None
        word = _BARE_VALUE_RE.match(text, start) if start is not None else None
        if word is None:
            break
        if _SEPARATOR_WORD_RE.fullmatch(text, word.start(), word.end()):
            if words and _field_label(text, words[-1]):
                words.pop()  # "hunter2 user = demo": the label starts another part
                break
            pos = word.end()  # replaced only if a word of the value follows it
            continue
        if _word_after_ends(index, word.start(), word.end()):
            break
        capped = word.end() - word.start() == MAX_SECRET_VALUE_CHARS
        stop = _without_closing_marks(text, word.start(), word.end())
        if capped:  # a long run is redacted to its end, never left half visible
            stop = index.trimmed(word.start(), max(index.run_end(word.start()), word.end()))
        if stop == word.start():
            break
        words.append((word.start(), stop))
        if capped or stop < word.end():
            break  # closing punctuation ends the clause
        pos = stop
    return tuple(words)


def _words_after(index: _TextIndex, end: int, japanese: bool) -> tuple[tuple[int, int], ...]:
    """The further words of a value whose first word ends at ``end``, as ``(start, end)`` spans: a value of several
    words, as speech recognition writes a spoken password ("the password is hunter 2 fake pw").

    Each word is an unquoted run (:data:`_VALUE_CHARS`) after same-line whitespace; ``japanese`` (a Japanese
    keyword or particle) also lets a joint stand between two words (:data:`_JA_JOINT_RE`: "ハンターにフェイクPW").
    The value ends at its clause's end: closing punctuation (kept outside it), a line break, an opening quote or
    bracket, hiragana that is no joint (a particle or a verb ending), CJK punctuation, or a word that starts
    another part (:func:`_ends_value`: "and", "then", "please", "for the", a keyword ...). At most
    :data:`MAX_SECRET_VALUE_WORDS` words in all, each read for at most :data:`MAX_SECRET_VALUE_CHARS` characters
    (a longer one is taken to its end and ends the value); remembered per position (:class:`_TextIndex`)."""
    key = (True, end, japanese)
    found = index.runs.get(key)
    if found is None:
        found = index.runs[key] = _scan_after(index, end, japanese)
    return found


def _previous_word(index: _TextIndex, pos: int, japanese: bool) -> tuple[int, int] | None:
    """The run of value characters that ends before ``pos`` behind same-line whitespace, or (``japanese``) behind a
    joint (:func:`_joint_before`); ``None`` without one, or when it is longer than :data:`MAX_SECRET_VALUE_CHARS`."""
    text = index.text
    gap = _gap_before(text, pos)
    end = _joint_before(text, pos, gap) if japanese else None
    if end is None:
        end = gap if gap < pos else 0
    begin = index.run_start(end) if end else end
    return (begin, end) if begin < end and end - begin <= MAX_SECRET_VALUE_CHARS else None


def _scan_before(index: _TextIndex, start: int, japanese: bool) -> tuple[tuple[int, int], ...]:
    text = index.text
    words: list[tuple[int, int]] = []
    pos = start
    separated = False
    for _ in range(2 * MAX_SECRET_VALUE_WORDS):  # separators are read through but not counted
        word = _previous_word(index, pos, japanese) if len(words) < MAX_SECRET_VALUE_WORDS - 1 else None
        if word is None:
            break
        begin, end = word
        if _SEPARATOR_WORD_RE.fullmatch(text, begin, end):
            pos, separated = begin, True  # replaced only if a word of the value precedes it
            continue
        opened = index.opened(begin, end)
        if text[end - 1] in _TRAILING_MARKS or opened == end:
            break  # the word before ends a clause ("user, hunter 2 as the password")
        if (separated and _field_label(text, (opened, end))) or _ends_value(index, opened, end, forward=False):
            break  # "user = demo hunter 2 as the password": the label starts the part before
        separated = False
        words.append((opened, end))
        if opened > begin:
            break  # an opening quote or bracket starts the value
        pos = begin
    return tuple(words)


def _words_before(index: _TextIndex, start: int, japanese: bool) -> tuple[tuple[int, int], ...]:
    """The further words of a value named before its keyword, whose last word starts at ``start``, nearest first:
    :func:`_words_after` read backwards. The value starts after the previous clause's end: a word ending in
    closing punctuation, a line break, an opening quote or bracket (the value starts after it), hiragana that is no
    joint, or a word that starts another part ("and hunter 2 fake pw as the password")."""
    key = (False, start, japanese)
    found = index.runs.get(key)
    if found is None:
        found = index.runs[key] = _scan_before(index, start, japanese)
    return found


def _starts_a_value(word: str) -> bool:
    """The word next to the keyword's frame may start a value of several words: it holds a letter or a digit and is
    no word of :data:`_NOT_VALUE_STARTS`, no URL and not ``redacted`` (a keyword may: "my secret sauce 42")."""
    return (
        word != REDACTED
        and "://" not in word
        and any(char.isalnum() for char in word)
        and word.lower() not in _NOT_VALUE_STARTS
    )


def _after_a_determiner(
    index: _TextIndex, span: tuple[int, int], japanese: bool, plausible: Callable[[list[str]], bool]
) -> tuple[int, int] | None:
    """A value of several words that starts with a determiner (:data:`_DETERMINERS`) after a strong frame ("the
    password is my secret sauce 42"): the words after the determiner are a value of several words
    (:func:`_several_words`) and ``plausible``."""
    text = index.text
    if text[span[0] : span[1]].lower() not in _DETERMINERS:
        return None
    more = _words_after(index, span[1], japanese)
    words = _texts(text, more)
    if words and _several_words(words[0], words, needs_credential=False) and plausible(words):
        return span[0], more[-1][1]
    return None


def _several_words(first: str, words: Sequence[str], *, needs_credential: bool) -> bool:
    """``words`` (``first`` the one next to the keyword's frame) are a value of several words: at least two,
    ``first`` may start one (:func:`_starts_a_value`), some word holds an ASCII letter or digit or every word is
    katakana (a spoken foreign word; Japanese words of kanji describe, "安全に管理"), and, with
    ``needs_credential``, some word is credential-shaped."""
    if len(words) < 2 or not _starts_a_value(first):
        return False
    if not any(_ASCII_ALNUM_RE.search(word) for word in words) and not all(
        _KATAKANA_WORD_RE.fullmatch(word) for word in words
    ):
        return False
    return not needs_credential or any(_credential_shaped(word) for word in words)


def _whole_keyword(text: str, keyword: re.Match[str]) -> bool:
    """``keyword`` is the longest keyword at its place, not the first word of a two-word one ("pin" of "pin code",
    whose "code 0000" is no value of several words)."""
    longest = _SECRET_KEYWORD_RE.match(text, keyword.start())
    return longest is not None and longest.end() == keyword.end()


def _texts(text: str, spans: Iterable[tuple[int, int]]) -> list[str]:
    return [text[start:end] for start, end in spans]


def _secret_value(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of the secret value following ``keyword``, or ``None``."""
    text = index.text
    connection = _connection(text, keyword.end())
    pos = connection.start
    direct = text[pos : pos + 1] in _DIRECT_QUOTES
    if not (connection.joined or direct or not keyword.group(0).isascii()):
        return None  # ``password_reset``, ``password?``
    span, quoted, capped = _value_at(text, pos)
    if span is None:
        return None
    value = text[span[0] : span[1]]
    if quoted or capped:
        plausible = _plausible_value(value, keyword.group(0), connection, quoted)
        return _to_its_end(index, span, capped) if plausible else None
    more = _words_after(index, span[1], connection.japanese or not keyword.group(0).isascii())
    end = more[-1][1] if more else span[1]
    if _plausible_value(value, keyword.group(0), connection, False):
        return span[0], end
    # "password hunter 2 fake pw", "パスワード は ハンター ツー フェイク です": the first word alone says too little
    ambiguous = keyword.group(0).lower() in AMBIGUOUS_SECRET_KEYWORDS and not connection.labelled
    if not _whole_keyword(text, keyword):
        return None
    if connection.strong:  # "the password is my secret sauce 42", not "the passcode of my work account"
        led = _after_a_determiner(
            index, span, connection.japanese, lambda words: not ambiguous or any(map(_credential_shaped, words))
        )
        if led is not None:
            return led
    words = [value, *_texts(text, more)]
    return (span[0], end) if _several_words(value, words, needs_credential=ambiguous) else None


def _set_verb_before(index: _TextIndex, start: int) -> bool:
    """A verb that sets a value (``set``, ``change``, ``update``, ``reset``, ``modify``) at most
    :data:`_MAX_SET_VERB_DISTANCE` words before ``start``, with no sentence punctuation between."""
    for _ in range(_MAX_SET_VERB_DISTANCE):
        token = _token_before(index, start)
        if token is None or index.text[token[1] - 1] in _CLAUSE_MARKS:
            return False
        if _SET_VERB_RE.fullmatch(_word(index.text, token)):
            return True
        start = token[0]
    return False


def _to_end(text: str, pos: int) -> int | None:
    """The end of `` to `` at ``pos``."""
    to = _TO_RE.match(text, pos)
    return to.end() if to else None


def _qualified(text: str, pos: int, link: Callable[[str, int], int | None]) -> int | None:
    """After a keyword ending at ``pos``: one of :data:`_QUALIFIER_LINKS` and one to three more words (none
    ending in ``.,;!?``), then ``link``; where the link ends, or ``None``. (A word is walked by at most the four
    keywords before it, the last of their words each, so the walks stay linear.)"""
    first = _WORD_AFTER_RE.match(text, pos)
    if first is None or first.group(1).lower() not in _QUALIFIER_LINKS:
        return None
    pos = first.end()
    for _ in range(_MAX_QUALIFIER_WORDS - 1):
        word = _WORD_AFTER_RE.match(text, pos)
        if word is None or word.group(1)[-1] in _CLAUSE_MARKS:
            return None
        pos = word.end()
        end = link(text, pos)
        if end is not None:
            return end
    return None


def _value_after_to(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of the value in "set the password (for the bank) to X" (:func:`redact_text_secrets`)."""
    text = index.text
    to = _to_end(text, keyword.end())
    if to is None:
        to = _qualified(text, keyword.end(), _to_end)
    if to is None or not _set_verb_before(index, keyword.start()):
        return None
    span, quoted, capped = _value_at(text, to)
    name = keyword.group(0).lower()
    if span is not None and not (quoted or capped) and _whole_keyword(text, keyword):  # "set it to my dog rex 7"
        ambiguous = name in AMBIGUOUS_SECRET_KEYWORDS
        led = _after_a_determiner(index, span, False, lambda words: not ambiguous or _set_value(name, "".join(words)))
        if led is not None:
            return led
    if span is None or not _named_value(value := text[span[0] : span[1]]) or (not quoted and _counted(text, span[1])):
        return None
    if quoted or capped:
        return _to_its_end(index, span, capped) if quoted or _set_value(name, value) else None
    more = _words_after(index, span[1], False)
    end = more[-1][1] if more else span[1]
    if _set_value(name, value):
        return span[0], end
    words = [value, *_texts(text, more)]
    if not (_whole_keyword(text, keyword) and _several_words(value, words, needs_credential=False)):
        return None
    # "update the PIN to 4 8 2 1": a PIN or a token of several words is judged as one
    plausible = _set_value(name, "".join(words)) if name in AMBIGUOUS_SECRET_KEYWORDS else True
    return (span[0], end) if plausible else None


def _set_value(name: str, value: str) -> bool:
    """An unquoted value after "set the ``name`` to" may be a secret: after ``pin`` 4-12 digits, after ``token`` and
    ``secret`` credential-shaped and at least 8 characters ("update the token to v2" is a version), else
    credential-shaped."""
    if name == "pin":
        return value.isdigit() and 4 <= len(value) <= 12
    if name in AMBIGUOUS_SECRET_KEYWORDS:
        return _credential_shaped(value) and len(value) >= 8
    return _credential_shaped(value)


def _link_end(text: str, pos: int) -> int | None:
    """The end of ``is`` / ``was`` after whitespace, or of ``:`` / ``=`` (full-width too), at ``pos``."""
    space = _SPACE_RE.match(text, pos)
    after = space.end() if space else pos
    if text[after : after + 1] in _LABEL_MARKS:
        return after + 1
    word = _IS_WAS_RE.match(text, after) if space else None
    return word.end() if word else None


def _qualified_value(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of the value in "the password for the bank is X" (:func:`redact_text_secrets`)."""
    text = index.text
    link = _qualified(text, keyword.end(), _link_end)
    if link is None:
        return None
    span, quoted, capped = _value_at(text, _connection(text, link).start)
    ambiguous = keyword.group(0).lower() in AMBIGUOUS_SECRET_KEYWORDS
    if span is not None and not (quoted or capped) and _whole_keyword(text, keyword):  # "... is my dog rex 7"
        led = _after_a_determiner(
            index, span, False, lambda words: not ambiguous or _qualified_secret(True, "".join(words))
        )
        if led is not None:
            return led
    if span is None or not _named_value(value := text[span[0] : span[1]]) or (not quoted and _counted(text, span[1])):
        return None
    if quoted or capped:
        return _to_its_end(index, span, capped) if quoted or _qualified_secret(ambiguous, value) else None
    more = _words_after(index, span[1], False)
    end = more[-1][1] if more else span[1]
    if _qualified_secret(ambiguous, value):
        return span[0], end
    words = [value, *_texts(text, more)]
    if not (_whole_keyword(text, keyword) and _several_words(value, words, needs_credential=False)):
        return None
    plausible = _qualified_secret(ambiguous, "".join(words)) if ambiguous else True  # "the PIN for it is 4 8 2 1"
    return (span[0], end) if plausible else None


def _qualified_secret(ambiguous: bool, value: str) -> bool:
    """An unquoted value after a qualifier may be a secret: after :data:`AMBIGUOUS_SECRET_KEYWORDS` at least 4
    characters holding a digit ("the PIN for the map is A1" is a place), else credential-shaped."""
    if ambiguous:
        return any(char.isdigit() for char in value) and len(value) >= 4
    return _credential_shaped(value)


def _space_before(text: str, end: int) -> int:
    """Where the whitespace run (at most 32 characters) that ends at ``end`` starts."""
    pos = end
    while pos > 0 and end - pos < 32 and text[pos - 1].isspace():
        pos -= 1
    return pos


def _space_after(text: str, pos: int) -> int:
    space = _SPACE_RE.match(text, pos)
    return space.end() if space else pos


def _token_before(index: _TextIndex, end: int) -> tuple[int, int] | None:
    """``(start, end)`` of the whitespace-free token before the whitespace that ends at ``end``, or ``None``."""
    text = index.text
    stop = _space_before(text, end)
    if stop in (end, 0) or text[stop - 1].isspace():
        return None
    return index.token_start(stop), stop


def _word(text: str, span: tuple[int, int] | None) -> str:
    """The token at ``span`` without case; empty when it is too long to be a connector or a verb."""
    if span is None or span[1] - span[0] > _MAX_WORD_CHARS:
        return ""
    return text[span[0] : span[1]].lower()


def _quoted_before(text: str, end: int, *, word_start: bool) -> tuple[int, int] | None:
    """``(start, end)`` of a value inside the quote or bracket that closes at ``end - 1``, without the marks;
    with ``word_start`` the opening mark must start a word."""
    opener = _OPENER_OF.get(text[end - 1 : end])
    if opener is None:
        return None
    start = text.rfind(opener, max(0, end - 2 - MAX_SECRET_VALUE_CHARS), end - 1)
    if start < 0 or (word_start and start > 0 and not text[start - 1].isspace()):
        return None
    inner = text[start + 1 : end - 1]
    if not inner or inner != inner.strip() or "\n" in inner:
        return None
    if opener not in _SPACED_QUOTES and any(char.isspace() for char in inner):
        return None
    return start + 1, end - 1


def _unquoted_value(index: _TextIndex, start: int, end: int) -> tuple[int, int] | None:
    """``(start, end)`` of the unquoted value in ``text[start:end]``: opening and closing marks left out."""
    start = index.opened(start, end)
    end = index.trimmed(start, end)
    return (start, end) if end > start else None


def _after_a_verb(index: _TextIndex, start: int) -> bool:
    """The word before ``start`` puts a value somewhere: ``type``, ``enter``, ``use`` ..., ``fill in``."""
    previous = _token_before(index, start)
    word = _word(index.text, previous)
    if _VALUE_VERB_RE.fullmatch(word):
        return True
    return (
        word == "in"
        and previous is not None
        and bool(_IN_VERB_RE.fullmatch(_word(index.text, _token_before(index, previous[0]))))
    )


def _english_value_before(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of a value before an ASCII ``keyword`` (:func:`redact_text_secrets`, value first)."""
    text = index.text
    if not text[keyword.start() - 1 : keyword.start()].isspace():
        return None  # a connector word always stands before the keyword
    head = _NEXT_WORD_RE.match(text, keyword.end())
    if head and head.group(1).lower() in _KEYWORD_HEADS:
        return None
    linked = copula = False
    token = _token_before(index, keyword.start())
    for _ in range(_MAX_BACKWARD_CONNECTORS):
        word = _word(text, token)
        if token is None or word not in _BACKWARD_CONNECTORS:
            break
        linked = linked or word in _BACKWARD_LINKS
        copula = copula or word in _COPULAS
        token = _token_before(index, token[0])
    if token is None or not linked:
        return None
    last = text[token[1] - 1]
    if last in _OPENER_OF:
        span, quoted = _quoted_before(text, token[1], word_start=True), True
    elif last in _CLAUSE_MARKS:
        return None  # "After you log in, as the password ...": the value ends a clause, not this phrase
    else:
        span, quoted = _unquoted_value(index, token[0], token[1]), False
    if span is None or not _named_value(value := text[span[0] : span[1]]):
        return None
    # "and hunter 2 fake pw as the password": the words before the one next to the frame, back to the clause's start
    more = _words_before(index, token[0], False) if not quoted and span[0] == token[0] else ()
    start = more[-1][0] if more else span[0]
    words = [*_texts(text, reversed(more)), value]
    verb = _after_a_verb(index, index.token_start(start) if more else (span[0] - 1 if quoted else token[0]))
    several = _several_words(value, words, needs_credential=False)
    credential = _credential_shaped(value) or (several and any(_credential_shaped(word) for word in words))
    if keyword.group(0).lower() in AMBIGUOUS_SECRET_KEYWORDS:  # "4821 is the PIN" needs no verb
        plausible = (verb or copula) and (quoted or credential)
    else:
        plausible = quoted or verb or credential or several
    return (start, span[1]) if plausible else None


def _japanese_slot_follows(text: str, pos: int) -> bool:
    """An optional Japanese field word, then the target or direction particle or the word for "as"."""
    pos += next((len(word) for word in _JA_FIELDS if text.startswith(word, pos)), 0)
    return text.startswith(_JA_SLOTS, _space_after(text, pos))


def _japanese_value(text: str, span: tuple[int, int] | None, keyword: re.Match[str], quoted: bool) -> bool:
    """A value in a Japanese sentence: after :data:`AMBIGUOUS_SECRET_KEYWORDS` (``PIN`` in Japanese text) it must
    also be quoted or credential-shaped."""
    if span is None or not _named_value(value := text[span[0] : span[1]]):
        return False
    return quoted or keyword.group(0).lower() not in AMBIGUOUS_SECRET_KEYWORDS or _credential_shaped(value)


def _japanese_value_before(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of a quoted or ASCII value before the object particle (the keyword then followed by
    :func:`_japanese_slot_follows`) or before the word for "called"."""
    text = index.text
    before = text[keyword.start() - 1 : keyword.start()]
    if not (before in _JA_BEFORE_KEYWORD or before.isspace()):
        return None
    pos = _space_before(text, keyword.start())
    if text.endswith(_JA_CALLED, 0, pos):
        pos -= len(_JA_CALLED)
    elif text.endswith(_JA_OBJECT, 0, pos) and _japanese_slot_follows(text, keyword.end()):
        pos -= len(_JA_OBJECT)
    else:
        return None
    end = _space_before(text, pos)
    if text[end - 1 : end] in _OPENER_OF:
        span = _quoted_before(text, end, word_start=False)
        return span if _japanese_value(text, span, keyword, True) else None
    span = _unquoted_value(index, index.ascii_start(end), end)
    named = _japanese_value(text, span, keyword, False)
    # the whole word before the particle and the words before it: "ハンターにフェイクPWをパスワードに"
    begin = index.run_start(end)
    last = _unquoted_value(index, begin, end) if end - begin <= MAX_SECRET_VALUE_CHARS else None
    if last is None:
        return span if named else None
    more = _words_before(index, begin, True) if last[0] == begin else ()
    start = more[-1][0] if more else last[0]
    if named and span is not None:
        return min(start, span[0]), span[1]
    words = [*_texts(text, reversed(more)), text[last[0] : last[1]]]
    ambiguous = keyword.group(0).lower() in AMBIGUOUS_SECRET_KEYWORDS
    return (start, last[1]) if _several_words(words[-1], words, needs_credential=ambiguous) else None


def _japanese_value_after(index: _TextIndex, keyword: re.Match[str]) -> tuple[int, int] | None:
    """``(start, end)`` of a quoted or ASCII value between the target particle or the word for "as" after a
    ``keyword`` in a Japanese sentence (an optional field word between) and the object particle."""
    text = index.text
    pos = keyword.end()
    after = text[pos : pos + 1]
    if not (after in _JA_AFTER_KEYWORD or after.isspace()):
        return None
    pos = _space_after(text, pos + next((len(word) for word in _JA_FIELDS if text.startswith(word, pos)), 0))
    target = next((word for word in _JA_TARGETS if text.startswith(word, pos)), None)
    if target is None:
        return None
    pos = _space_after(text, pos + len(target))
    span = _quoted_value(text, pos)
    if span is not None:
        followed = text.startswith(_JA_OBJECT, _space_after(text, span[1] + 1))
        return span if followed and _japanese_value(text, span, keyword, True) else None
    end = index.ascii_end(pos)
    span = _unquoted_value(index, pos, end) if end > pos else None
    if span is not None and text.startswith(_JA_OBJECT, _space_after(text, end)):
        return span if _japanese_value(text, span, keyword, False) else None
    # a value of several words, or one with Japanese in it, up to the object particle: "パスワードにハンター ツーを"
    first, _quoted, capped = _value_at(text, pos)
    if first is None or capped:
        return None
    more = _words_after(index, first[1], True)
    end = more[-1][1] if more else first[1]
    if not text.startswith(_JA_OBJECT, _space_after(text, end)):
        return None
    words = [text[first[0] : first[1]], *_texts(text, more)]
    ambiguous = keyword.group(0).lower() in AMBIGUOUS_SECRET_KEYWORDS
    if _japanese_value(text, first, keyword, False) or _several_words(words[0], words, needs_credential=ambiguous):
        return first[0], end
    return None


def _values_before(index: _TextIndex, keyword: re.Match[str]) -> list[tuple[int, int]]:
    """Every secret value a form names before ``keyword``; the Japanese forms also hold for an ASCII keyword in a
    Japanese sentence ("1234 as PIN" in Japanese word order)."""
    found = [_english_value_before(index, keyword)] if keyword.group(0).isascii() else []
    found.append(_japanese_value_before(index, keyword))
    return [span for span in found if span is not None]


def _values_after(index: _TextIndex, keyword: re.Match[str]) -> list[tuple[int, int]]:
    """Every secret value a form names after ``keyword``: each form is read, none stops another."""
    found = [_secret_value(index, keyword), _japanese_value_after(index, keyword)]
    if index.text[keyword.end() : keyword.end() + 1].isspace():  # "to" and qualifiers follow a space
        found += [_value_after_to(index, keyword), _qualified_value(index, keyword)]
    return [span for span in found if span is not None]


def _readings(text: str, keyword: re.Match[str]) -> list[re.Match[str]]:
    """``keyword`` and, for a two-word keyword whose first word is a keyword too ("pin  code"), that word on
    its own: "pin  code=1234" names "code=1234" after "pin" as well, so neither reading hides the other."""
    space = _WHITESPACE_RE.search(keyword.group(0))
    if space is None:
        return [keyword]
    first = _SECRET_KEYWORD_RE.match(text, keyword.start(), keyword.start() + space.start())
    return [keyword, first] if first is not None else [keyword]


def _merged(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """``spans`` in order, overlapping or touching ones joined."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _secret_spans(text: str) -> list[tuple[int, int]]:
    """The secret values the keywords of ``text`` name (:func:`redact_text_secrets`), merged (:func:`_found_spans`)."""
    return _merged(_found_spans(text))


def _found_spans(text: str, *, every_keyword: bool = False) -> Iterator[tuple[int, int]]:
    """Every value span any form finds for any reading of any keyword, before merging, as it is found (so
    :func:`secret_values` can stop reading where its bound is passed).

    With ``every_keyword`` also the keywords inside a closed value (:func:`_closed_part`), whose values lie
    inside it and change nothing in the redaction, but are each a value of their own (:func:`secret_values`).

    Every keyword outside a URL is read on its own, also one inside another keyword's value or qualifier, and
    every form is read for each keyword, so no match hides another ("password for account PIN=4821 is
    Hunter2-x" loses both values)."""
    # A keyword inside a URL is a parameter name or a path word: the URL scrubber's business.
    urls = [match.span() for match in _URL_IN_TEXT_RE.finditer(text)]
    index = _TextIndex(text)
    closed = (0, 0)  # the furthest part of a value whose keywords name nothing outside it (_closed_part)
    pos = url = 0
    while (keyword := _SECRET_KEYWORD_RE.search(text, pos)) is not None:
        pos = keyword.end()
        while url < len(urls) and urls[url][1] <= keyword.start():
            url += 1
        if url < len(urls) and urls[url][0] <= keyword.start():
            pos = urls[url][1]
            continue
        if not every_keyword and closed[0] < keyword.start() and keyword.end() < closed[1]:
            continue
        for reading in _readings(text, keyword):
            # A value named before the keyword is never inside a URL.
            yield from [span for span in _values_before(index, reading) if not (url and urls[url - 1][1] > span[0])]
            for span in _values_after(index, reading):
                yield span
                part = _closed_part(index, span) if span[1] > closed[1] else None
                if part is not None and part[1] > closed[1]:
                    closed = part


def _redact_keyword_values(text: str) -> tuple[str, bool]:
    spans = _secret_spans(text)
    if not spans:
        return text, False
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts += [text[cursor:start], REDACTED]
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), True


def redact_text_secrets(text: str) -> tuple[str, bool]:
    """``(text with its secrets replaced by`` :data:`REDACTED` ``, anything replaced)``.

    The exact rule. Replaced are JWTs, key-prefixed tokens and PEM armour lines (as
    :func:`redact_secret_tokens`), and the value named after or before a secret keyword. Keywords, without
    case: ``password``, ``passwd``, ``passphrase``, ``passcode``, ``pwd``, ``pin``, ``pin code``, ``otp``,
    ``one-time code``, ``secret``, ``api key``, ``api token``, ``access token``, ``token`` (an ASCII keyword
    must not touch an ASCII letter or digit; the words of a two-word keyword are joined by up to 32 same-line
    whitespace characters, ``_`` or ``-``, and its first word, when a keyword itself, is read on its own too) and
    :data:`JAPANESE_SECRET_KEYWORDS`. A keyword inside a URL is
    left to URL scrubbing. Every other keyword is read on its own, also one inside another keyword's value
    or qualifier, every form below is read for it, and all the values found are merged before they are
    replaced, so no form hides another ("password for account PIN=4821 is Hunter2-x" and "change the
    password for bank is Hunter2-x to OtherPw-3" lose both values; :func:`_secret_spans`). A keyword inside
    a found value that can name nothing outside it is not read again (:func:`_closed_part`). Every question
    a keyword asks about the text is a bisection over positions found once (:class:`_TextIndex`), so a text
    costs O(n log n) at worst.

    The value after a keyword:

    * after connectors (at least one, except after a Japanese keyword or before a double or CJK quote):
      whitespace, ``:`` / ``=`` (full-width too), the Japanese topic, object and subject particles, and
      ``is`` / ``was`` / ``of`` after whitespace;
    * the value: the text inside a quote or bracket (marks kept; spaces allowed inside quotes), else one
      token that ends at whitespace, hiragana, CJK or full-width punctuation, with closing punctuation
      (``.,;:!?)]}>`` and quotes) kept outside the replacement;
    * after a Japanese keyword (and an optional field word) also the target particle or the word for "as",
      then the value (quoted, or one run of ASCII characters), then the object particle
      (:func:`_japanese_value_after`);
    * "set the password (for the bank) to X" (:func:`_value_after_to`): the keyword, optionally a qualifier
      (as in the next form), ``to``, the value, with a verb that sets it (``set``, ``change``, ``update``,
      ``reset``, ``modify`` and their inflections) at most :data:`_MAX_SET_VERB_DISTANCE` words before the
      keyword and no sentence punctuation between. The value
      is quoted or credential-shaped; after ``pin`` an unquoted value is 4-12 digits, after ``token`` and
      ``secret`` it is credential-shaped and at least 8 characters long;
    * "the password for the bank is X" (:func:`_qualified_value`): the keyword, one of ``for``, ``on``,
      ``at``, ``of``, ``in`` and one to three more words (none ending in ``.,;!?``), then ``is`` / ``was``
      or ``:`` / ``=`` (full-width too), then the value: quoted or credential-shaped; after
      :data:`AMBIGUOUS_SECRET_KEYWORDS` quoted, or at least 4 characters holding a digit.

    In the last two forms an unquoted value followed by a unit word (:data:`_VALUE_UNITS`: "to 12
    characters") is a length, not a secret.

    A value of several words (speech recognition writes a spoken password as words: "the password is hunter 2 fake
    pw"). Wherever a form takes an unquoted value, the value runs on over the words after it, or (value first) back
    over the words before it, to the end of its clause (:func:`_words_after`, :func:`_words_before`): closing
    punctuation, a line break, a quote or bracket, CJK punctuation, hiragana that is no joint, or a word that starts
    another part (:func:`_ends_value`: the words of :data:`_VALUE_END_WORDS` such as "and", "then", "please",
    "with", "in", "as", "is", "expires", not the determiners; a verb that puts or sets a value; a keyword that
    starts a frame of its own, :func:`_starts_frame`; reading back, a URL; "at", "to" and "for" only before a word
    that starts another part, as they may be a spoken symbol or digit). When unsure the rest of the clause goes: a
    word that only holds a keyword, a separator word (``/``, ``|``, ``:``, ``=``; but after a field label,
    :data:`_FIELD_LABELS`) and, reading on, a URL are read through. After a strong frame a value may start with a
    determiner (:func:`_after_a_determiner`). In a Japanese reading (a
    Japanese keyword or particle) a joint may stand between two words (:data:`_JA_JOINT_RE`: "ハンターにフェイクPW"),
    and a verb or interface word after it ends the value (:data:`_JA_VALUE_END_RE`). At most
    :data:`MAX_SECRET_VALUE_WORDS` words, each read for at most :data:`MAX_SECRET_VALUE_CHARS` characters. When
    the word next to the frame is accepted by the rules here, its further words are replaced with it; when it is
    not (it alone says too little: "password hunter 2 fake pw", "hunter 2 fake pw as the password", "パスワード は
    ハンター ツー フェイク です"), the words are taken as one value when there are at least two, the one next to the
    frame may start a value (:func:`_starts_a_value`: no stop word, head, placeholder, unit, pronoun, keyword or
    URL), some word holds an ASCII letter or digit or every word is katakana, and, after
    :data:`AMBIGUOUS_SECRET_KEYWORDS`, some word is credential-shaped (after "set the PIN to" the words are 4-12
    digits in all, after a qualified ``pin`` / ``secret`` / ``token`` at least 4 characters holding a digit), and
    never for the first word of a two-word keyword read on its own ("code 0000" of "pin code 0000"). Before an
    English keyword the links also take ``is`` / ``was`` ("hunter 2 fake pw is the password"); there
    :data:`AMBIGUOUS_SECRET_KEYWORDS` need no verb ("4821 is the PIN").

    The value before a keyword (value first):

    * English: the value, then at most :data:`_MAX_BACKWARD_CONNECTORS` words from ``as``, ``for``, ``in``,
      ``into``, ``to`` (at least one of these), ``the``, ``a``, ``an``, the possessives, ``this``, ``that``,
      ``field``, ``box``, ``input``, then the keyword: "Hunter2-x as the password", "use X for my PIN",
      "type X into the password field". The value is quoted (the opening mark starting a word) or one
      whitespace-free token not ending in ``.,;:!?``. Nothing is replaced when the word after the keyword
      makes it a modifier (:data:`_KEYWORD_HEADS`: "2FA in the password settings", "the token list").
    * Japanese: the value, then the object particle, then the keyword followed by an optional field word and
      the target or direction particle or the word for "as" (:data:`_JA_SLOTS`); or the value, then the word
      for "called", then the keyword. The value is quoted or one run of ASCII characters. The Japanese forms
      (also the one after a keyword above) hold for an ASCII keyword too ("PIN" in a Japanese sentence);
      before or after :data:`AMBIGUOUS_SECRET_KEYWORDS` the value must then be quoted or credential-shaped.

    Nothing is replaced when the value (of one word) holds no ASCII letter or digit (masked dots, Japanese words), is a
    URL, ``redacted`` or a keyword, or is in :data:`SECRET_VALUE_STOP_WORDS` ("the password field"); the forms
    other than the first one after a keyword also never take :data:`_PLACEHOLDER_WORDS`. After a
    keyword, after only whitespace, and after :data:`AMBIGUOUS_SECRET_KEYWORDS` unless labelled or quoted,
    the value must also be credential-shaped (a digit, a symbol or an inner capital): "password Hunter2-x"
    is replaced, "pin the tab" and "the token count" are not. Before an English keyword the value must be
    quoted, credential-shaped or follow a verb that puts a value somewhere (``type``, ``enter``, ``use``,
    ``input``, ``put``, ``paste``, ``insert`` and their inflections, ``fill in``, ``key in``); before
    :data:`AMBIGUOUS_SECRET_KEYWORDS` it must follow such a verb and be quoted or credential-shaped:
    "use swordfish as the password" is replaced, "same as the password" and "use swordfish as the token"
    are not.
    """
    clean, jwts = _JWT_RE.subn(REDACTED, text)
    clean, keys = _KEY_PREFIX_RE.subn(REDACTED, clean)
    clean, pems = _PEM_RE.subn(REDACTED, clean)
    clean, values = _redact_keyword_values(clean)
    return clean, bool(jwts or keys or pems or values)


def redact_secret_shaped_tokens(text: str) -> tuple[str, bool]:
    """``(text with its secret-shaped tokens replaced by`` :data:`REDACTED` ``, anything replaced)``; for the
    user's own words (:func:`speaks_for_user`), where a password often has no keyword ("my login is demo-user /
    ...").

    The exact rule: each run of ASCII without whitespace, its opening and closing marks left out, that is a
    secret-shaped token of at least :data:`SECRET_INNER_TOKEN_MIN_CHARS` characters (rule 5 of
    :func:`looks_like_secret` inside a longer text: a letter and a digit or a symbol other than ``-``, ``_``
    and ``.``; not a URL, host, e-mail address, file path or date) is replaced; the marks stay. Usernames such
    as ``demo-user``, URLs, dates and ordinary words are kept; a long identifier that mixes letters and digits
    (``order-2026-000123-final``) is replaced too, as typed text is withheld."""
    replaced = False

    def one(match: re.Match[str]) -> str:
        nonlocal replaced
        token = match.group(0)
        start, end = 0, len(token)
        while start < end and token[start] in _VALUE_QUOTES:
            start += 1
        while end > start and token[end - 1] in _TRAILING_MARKS:
            end -= 1
        core = token[start:end]
        if len(core) < SECRET_INNER_TOKEN_MIN_CHARS or not _secret_shaped_token(core):
            return token
        replaced = True
        return token[:start] + REDACTED + token[end:]

    return _ASCII_TOKEN_RE.sub(one, text), replaced


#: Most distinct values :func:`secret_values` lists for one text. Each keyword's value is listed on its own, and the
#: values of the keywords of one unquoted run overlap: every ``pin:`` of ``"pin:" * 9999 + "1234"`` names the rest
#: of the run (Codex review of 7a1084bee).
MAX_SECRET_VALUES: Final = 64


@dataclass(frozen=True, slots=True)
class SecretValues:
    """The values a text names as secrets (:func:`secret_values`). Memory only: never logged or stored."""

    values: tuple[str, ...]
    #: False when the text names more than is listed (:func:`secret_values`): a caller that withholds what matches
    #: these values must then withhold everything it would have compared with them (fail closed).
    complete: bool


def secret_values(text: str) -> SecretValues:
    """The values :func:`redact_text_secrets` replaces in ``text`` (JWTs, key-prefixed tokens, PEM armour lines,
    the values its keywords name), once each, in order; for a caller that must withhold the same values
    elsewhere (Hermes's typed text). Each value any form finds for any keyword is listed on its own, besides
    the merged span the redaction replaces ("PIN code=1234": ``code=1234`` and ``1234``). A value of several words
    is listed whole ("hunter 2 fake pw") and also without its whitespace ("hunter2fakepw"), as a spoken password is
    likely typed.

    Bounded: at most :data:`MAX_SECRET_VALUES` distinct values, each at most :data:`MAX_SECRET_VALUE_CHARS`
    characters long. Values are found as spans and only those within the bound are copied out; reading stops at
    the first value past it (one more distinct value, or a longer one: a long unquoted run is redacted to its end,
    and every keyword inside it names a suffix of it). The values found until then are listed and ``complete`` is
    false, so a caller fails closed instead of comparing with a partial list. Ordinary text stays within the bound
    (the phrase corpus of ``tests/test_activity_redaction_properties.py``); the cost is that of the redaction."""
    found = _NamedValues()
    for pattern in (_JWT_RE, _KEY_PREFIX_RE, _PEM_RE):
        if not all(found.listed(0, text, match.span()) for match in pattern.finditer(text)):
            return found.result(False)
    clean = redact_secret_tokens(text)
    spans: list[tuple[int, int]] = []
    for span in _found_spans(clean, every_keyword=True):
        if not found.listed(1, clean, span):
            return found.result(False)
        spans.append(span)
    return found.result(all(found.listed(1, clean, span) for span in _merged(spans)))


class _NamedValues:
    """The distinct values :func:`secret_values` lists, each with the place it was first found (source, start, end,
    form), at most :data:`MAX_SECRET_VALUES`."""

    def __init__(self) -> None:
        self._found: dict[str, tuple[int, int, int, int]] = {}

    def _added(self, value: str, place: tuple[int, int, int, int]) -> bool:
        if value and value != REDACTED and value not in self._found:
            if len(self._found) == MAX_SECRET_VALUES:
                return False
            self._found[value] = place
        return True

    def listed(self, source: int, within: str, span: tuple[int, int]) -> bool:
        """List the value at ``span`` of ``within`` (and, when it holds whitespace, the value without it); ``False``
        once it passes the bound."""
        start, end = span
        if end - start > MAX_SECRET_VALUE_CHARS:
            return False
        value = within[start:end]
        joined = "".join(value.split())
        first = self._added(value, (source, start, end, 0))
        return first and (joined == value or self._added(joined, (source, start, end, 1)))

    def result(self, complete: bool) -> SecretValues:
        return SecretValues(tuple(sorted(self._found, key=self._found.__getitem__)), complete)


#: An ASCII letter or digit, the characters a whole word of :func:`redact_values` must not touch.
_ASCII_ALNUM: Final = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
#: Characters :mod:`re` compares without case although neither one's upper case gives the other's lower case.
_CASE_KEY_FIXES: Final[Mapping[str, str]] = {"\u1fd3": "\u0390", "\u1fe3": "\u03b0", "\ufb05": "\ufb06"}
#: Keys :class:`_CaseKeys` remembers; past this many distinct characters a key is worked out each time.
_MAX_CASE_KEYS: Final = 4096


def _case_key(char: str) -> str:
    """One character that stands for ``char`` without case: two characters get the same key exactly when
    ``re.IGNORECASE`` compares them equal, and a key is an ASCII letter or digit exactly when ``(?i)[A-Za-z0-9]``
    matches ``char`` (checked for every code point by the tests). The lower case of the upper case (the long s,
    the Kelvin sign and the dotless i become ``s``, ``k`` and ``i``); where either changes the length (``ß``, the
    dotted capital I), the first character of the lower case."""
    upper = char.upper()
    lower = upper.lower() if len(upper) == 1 else ""
    if len(lower) != 1:
        lower = char.lower()[:1]
    return _CASE_KEY_FIXES.get(lower, lower)


class _CaseKeys(dict[int, str]):
    """A :meth:`str.translate` table of :func:`_case_key`, filled as characters are met (at most
    :data:`_MAX_CASE_KEYS` remembered)."""

    def __missing__(self, code: int) -> str:
        key = _case_key(chr(code))
        if len(self) < _MAX_CASE_KEYS:
            self[code] = key
        return key


_CASE_KEYS: Final = _CaseKeys()


def _without_case(text: str) -> str:
    """``text`` with each character replaced by its :func:`_case_key`: as long as ``text``, so positions agree."""
    return text.lower() if text.isascii() else text.translate(_CASE_KEYS)


#: Compiled value patterns :data:`_VALUE_PATTERNS` keeps (a session's withheld values, a turn's named ones), and the
#: characters of their patterns and values it keeps in all (a few MiB once compiled); a larger set is compiled for
#: each call and never kept.
_MAX_VALUE_PATTERNS: Final = 8
_MAX_VALUE_PATTERN_CHARS: Final = 1 << 18


def _shared_end(first: str, last: str, depth: int) -> int:
    """Where ``first`` and ``last`` part, from ``depth`` on (they agree before it)."""
    pos, end = depth, min(len(first), len(last))
    while pos < end and first[pos] == last[pos]:
        pos += 1
    return pos


def _rest_pattern(keys: Sequence[str], depth: int) -> str:
    """The pattern of ``keys`` (sorted, distinct, agreeing on their first ``depth`` characters) from ``depth`` on:
    the stretch a group of them shares is written once, a group per next character (so at most one alternative
    goes on at any character), and where a key ends the rest is optional and tried first (the longest key first).
    One level per place keys part or end, so at most two per key."""
    ends = len(keys[0]) == depth
    alternatives = []
    for _char, members in groupby(keys[1:] if ends else keys, key=lambda key: key[depth]):
        group = list(members)
        shared = _shared_end(group[0], group[-1], depth)
        alternatives.append(re.escape(group[0][depth:shared]) + _rest_pattern(group, shared))
    if not alternatives:
        return ""
    body = alternatives[0] if len(alternatives) == 1 else "(?:" + "|".join(alternatives) + ")"
    return f"(?:{body})?" if ends else body


def _uncached_compiler() -> Callable[[str, int], re.Pattern[str]] | None:
    """``re._compiler.compile`` (CPython 3.11 and later): what ``re.compile`` runs, without the module's own cache,
    which would keep each value set's pattern alive after :data:`_VALUE_PATTERNS` dropped it (Codex review of
    29c6be5c0: 96 patterns, about 98 MiB). Private API, pinned by a test; ``None`` where it is missing."""
    try:
        module = importlib.import_module("re._compiler")
    except ImportError:
        return None
    compiler = getattr(module, "compile", None)
    return cast("Callable[[str, int], re.Pattern[str]]", compiler) if callable(compiler) else None


_COMPILE_UNCACHED: Final = _uncached_compiler()


def _compile_uncached(source: str) -> re.Pattern[str]:
    """``source`` compiled, never kept by the :mod:`re` module's cache: without :func:`_uncached_compiler` the
    module's cache is emptied after compiling (a correct, slower fallback for the other patterns it held)."""
    if _COMPILE_UNCACHED is not None:
        return _COMPILE_UNCACHED(source, 0)
    pattern = re.compile(source)
    re.purge()
    return pattern


class _ValuePatterns:
    """The compiled patterns of the value sets used last (:func:`_rest_pattern`), at most
    :data:`_MAX_VALUE_PATTERNS` and :data:`_MAX_VALUE_PATTERN_CHARS` characters of pattern and values in all, the
    least recently used dropped first. Each is compiled outside the :mod:`re` module's cache
    (:func:`_compile_uncached`), so what this drops is freed. Memory only."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._patterns: OrderedDict[frozenset[str], tuple[re.Pattern[str], int]] = OrderedDict()
        self.chars = 0

    def get(self, keys: frozenset[str]) -> re.Pattern[str]:
        """The pattern of ``keys`` (values without case, :func:`_without_case`) between the whole-word boundaries:
        at each place it follows one path of at most the longest key's length and matches the longest key that
        stands there as a whole word."""
        with self._lock:
            kept = self._patterns.get(keys)
            if kept is not None:
                self._patterns.move_to_end(keys)
                return kept[0]
        source = r"(?<![A-Za-z0-9])" + _rest_pattern(sorted(keys), 0) + r"(?![A-Za-z0-9])"
        pattern = _compile_uncached(source)
        chars = len(source) + sum(map(len, keys))
        with self._lock:
            if keys not in self._patterns and chars <= _MAX_VALUE_PATTERN_CHARS:
                self._patterns[keys] = (pattern, chars)
                self.chars += chars
                while len(self._patterns) > _MAX_VALUE_PATTERNS or self.chars > _MAX_VALUE_PATTERN_CHARS:
                    self.chars -= self._patterns.popitem(last=False)[1][1]
        return pattern

    def clear(self) -> None:
        with self._lock:
            self._patterns.clear()
            self.chars = 0


_VALUE_PATTERNS: Final = _ValuePatterns()


def _value_keys(values: Iterable[str]) -> frozenset[str]:
    return frozenset(_without_case(value) for value in values if value)


def contains_values(text: str, values: Iterable[str]) -> bool:
    """Whether :func:`redact_values` would replace anything in ``text``: it stops at the first whole word found
    (Hermes's typed text against the values the turn's message names, :func:`secret_values`)."""
    keys = _value_keys(values)
    return bool(keys) and _VALUE_PATTERNS.get(keys).search(_without_case(text)) is not None


def redact_values(text: str, values: Iterable[str]) -> tuple[str, bool]:
    """``(text with every occurrence of`` ``values`` ``replaced by`` :data:`REDACTED` ``, anything replaced)``.

    Compared without case, the longest value first, only as a whole word (no ASCII letter or digit right before
    or after it), also inside a URL (its userinfo, host or path: no part is exempt); independent of any
    phrasing (Hermes's own capture: the values it typed into fields that may be secret). Exactly what one
    ``re.IGNORECASE`` alternation of every value, the longest first, between those boundaries replaces: from left
    to right, the leftmost place a value stands as a whole word, by the longest value there, then on after it. The
    text is compared without case (:func:`_without_case`) against one pattern that shares the values' common
    characters (:class:`_ValuePatterns`), so each place costs at most the longest value's length, whatever the
    number of values or how often they overlap."""
    keys = _value_keys(values)
    if not keys:
        return text, False
    parts: list[str] = []
    cursor = 0
    for match in _VALUE_PATTERNS.get(keys).finditer(_without_case(text)):
        parts += [text[cursor : match.start()], REDACTED]
        cursor = match.end()
    if not parts:
        return text, False
    parts.append(text[cursor:])
    return "".join(parts), True


def looks_like_secret(text: str) -> bool:
    """Typed text that must not be stored, whatever field it was typed into.

    The exact rule (a safety net, not a guarantee: a short password is not caught). The text is a secret
    when any of these holds:

    1. a JWT anywhere (``eyJ`` + three dot-separated base64url segments);
    2. a token anywhere that starts with one of :data:`KEY_PREFIXES` followed by at least 8 characters of
       ``[A-Za-z0-9_-]``, or a PEM private-key armour line;
    3. a labelled secret anywhere: ``password``, ``passwd``, ``passphrase``, ``passcode``, ``pwd``,
       ``pin``, ``secret``, ``token`` or ``api key`` followed by ``:`` or ``=`` and a value, or any keyword
       and value that :func:`redact_text_secrets` would replace ("my password is Hunter2-x", "Hunter2-x as
       the password", the Japanese "password is" followed by a value);
    4. a payment card number anywhere: 13-19 digits (single spaces or dashes between them allowed) that
       pass the Luhn check;
    5. a secret-shaped token: an ASCII token without whitespace that contains a letter and a digit or a
       symbol (any non-alphanumeric character except the word joiners ``-``, ``_`` and ``.``), and is not
       a URL (``scheme://...``), a lower-case host with optional port and path (``www.example.com/a?b=1``),
       a lower-case e-mail address, a file path (``/``, ``~/``, ``./``, ``../``) or an ISO date or
       date-time; it counts when it is the whole value (surrounding whitespace ignored) and at least
       :data:`SECRET_TOKEN_MIN_CHARS` characters long, or one token of a longer text and at least
       :data:`SECRET_INNER_TOKEN_MIN_CHARS` characters long.

    Sentences of ordinary words, non-ASCII prose written without spaces (Japanese), short words, numbers
    that fail the Luhn check, dates, URLs and hyphenated words are kept. Identifiers that mix letters and
    digits (``order-2026-000123-final``) are withheld.
    """
    if _JWT_RE.search(text) or _KEY_PREFIX_RE.search(text) or _PEM_RE.search(text):
        return True
    if _LABELLED_SECRET_RE.search(text) or _card_number(text) or _redact_keyword_values(text)[1]:
        return True
    tokens = text.split()
    if len(tokens) == 1:
        return _secret_shaped_token(tokens[0])
    return any(len(token) >= SECRET_INNER_TOKEN_MIN_CHARS and _secret_shaped_token(token) for token in tokens)


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
