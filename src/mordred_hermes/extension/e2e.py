"""Shared Mordred E2E transport hooks for chat platform adapters.

Slack / Discord / Teams adapters call into this module so each platform acts
as a pure encrypted transport for the Mordred browser extension:

  * inbound gateway commands must use context-bound ``🔒ENC:v3``;
  * replies into a conversation that received an encrypted message are
    re-encrypted with the channel key (reply-in-kind, §4);
  * ``🔑REQ/GRANT`` key-exchange control messages (§5) are peer-to-peer
    between extensions and must be dropped before the agent reacts to them.

The legacy v1/v2 token-replacement helpers remain fail-open for stored history
and non-gateway callers.
The gateway uses :func:`decrypt_gateway_envelope`, which authenticates the
entire wire grammar before releasing any plaintext and fails closed.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

# A `🔒ENC:v1/v2:…` token anywhere in the text. Extensions keep a leading
# @mention plaintext, so the ciphertext is NOT necessarily at the start; the
# 🔒 may also be dropped by the platform's renderer. v2 first — it's longer.
ENC_TOKEN_RE = re.compile(
    r"🔒?ENC:v2:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
    r"|🔒?ENC:v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
)

# A claim that a wire message is encrypted, including unsupported/truncated
# forms. The lock emoji can survive the platform render or be stripped. Once a
# message makes this claim, the gateway must parse it as a complete authenticated
# envelope; it must never fall back to treating an invalid claim as plaintext.
ENC_CLAIM_RE = re.compile(r"🔒\ufe0f?ENC|(?<![A-Za-z0-9_])ENC:")

_CANONICAL_V1_TOKEN_RE = re.compile(r"🔒?ENC:v1:(?P<nonce>[A-Za-z0-9_-]+):(?P<ciphertext>[A-Za-z0-9_-]+)")
_CANONICAL_V2_TOKEN_RE = re.compile(
    r"🔒?ENC:v2:(?P<key_id>[A-Za-z0-9_-]{8}):"
    r"(?P<nonce>[A-Za-z0-9_-]+):(?P<ciphertext>[A-Za-z0-9_-]+)"
)
_CANONICAL_V3_TOKEN_RE = re.compile(
    r"(?:(?:🔒|:lock:))?ENC:v3:(?P<key_id>[A-Za-z0-9_-]{8}):"
    r"(?P<message_id>[A-Za-z0-9_-]{22}):(?P<sequence>0|[1-9][0-9]{0,4}):"
    r"(?P<total>[1-9][0-9]{0,4}):(?P<nonce>[A-Za-z0-9_-]+):"
    r"(?P<ciphertext>[A-Za-z0-9_-]+)"
)
_NON_WHITESPACE_RE = re.compile(r"\S+")
_WHITESPACE_RE = re.compile(r"\s+")

# Key-exchange control tokens (SPEC-v2 §5). v1 = X25519-only (legacy),
# v2 = hybrid X25519+ML-KEM-768 (post-quantum).
KEYEXCH_RE = re.compile(r"🔑?(?:REQ|GRANT):v[12]:\S+")

# Leading mention/control tokens kept PLAINTEXT so pings still work, per
# platform wire format:
#   Slack:   <@U123>, <!here>, <!subteam^S1|…>, <#C1|…>
#   Discord: <@123>, <@!123> (nick), <@&456> (role), @everyone/@here
#   Teams:   <at>Name</at> (Graph/Bot Framework mention markup)
SLACK_MENTION_PREFIX_RE = re.compile(
    r"^((?:<@[A-Z0-9]+>|<!(?:here|channel|everyone)>"
    r"|<!subteam\^[A-Z0-9]+(?:\|[^>]*)?>|<#[A-Z0-9]+(?:\|[^>]*)?>|\s)+)"
)
DISCORD_MENTION_PREFIX_RE = re.compile(r"^((?:<@[!&]?\d+>|<#\d+>|@everyone|@here|\s)+)")
TEAMS_MENTION_PREFIX_RE = re.compile(r"^((?:<at>[^<]*</at>|\s)+)", re.IGNORECASE)
_SLACK_FREE_TEXT_LABEL_RE = re.compile(r"(<!(?:subteam)\^[A-Z0-9]+|<#[A-Z0-9]+)\|[^>]*(>)")
_TEAMS_FREE_TEXT_MENTION_RE = re.compile(r"<at>[^<]*</at>", re.IGNORECASE)

_MENTION_PREFIXES = {
    "slack": SLACK_MENTION_PREFIX_RE,
    "discord": DISCORD_MENTION_PREFIX_RE,
    "teams": TEAMS_MENTION_PREFIX_RE,
}


class InvalidEncryptedEnvelope(ValueError):
    """The inbound wire claimed E2E encryption but was not wholly authentic."""


@dataclass(frozen=True, slots=True)
class ReplayClaim:
    """Opaque, authenticated identities committed immediately before release."""

    identities: tuple[str, str]


def is_key_exchange(text: str) -> bool:
    """True when `text` carries a 🔑REQ/GRANT token — drop it before the agent."""
    return bool(text) and KEYEXCH_RE.search(text) is not None


def key_index() -> dict[str, bytes]:
    """keyId → raw key for every key Hermes holds (per-channel + master/v1)."""
    from mordred_hermes.extension.crypto import key_id
    from mordred_hermes.extension.pairing import load_channel_keys, load_pairing

    idx: dict[str, bytes] = {}
    for raw in load_channel_keys().values():
        idx[key_id(raw)] = raw
    p = load_pairing()
    if p is not None:
        idx.setdefault(key_id(p.aes_key), p.aes_key)  # master (v1 legacy)
    return idx


def decrypt_inbound(text: str) -> str | None:
    """Replace EVERY `🔒ENC:v1/v2:` token in `text` with its plaintext,
    selecting the key per token (v2: by keyId from the channel keyring;
    v1: master). Returns None when there is nothing to decrypt. Fail-open;
    a per-token failure leaves that token as-is.
    """
    return decrypt_inbound_keyed(text)[0]


def decrypt_inbound_keyed(text: str) -> tuple[str | None, str | None]:
    """Like :func:`decrypt_inbound`, but also returns the keyId of the key that
    decrypted (the first successful token). Callers store that keyId on the
    conversation so the reply can be re-encrypted with the SAME key regardless
    of how the platform/extension formats channel ids (SPEC-v2)."""
    try:
        if not text or not ENC_TOKEN_RE.search(text):
            return None, None
        from mordred_hermes.extension.crypto import (
            DecryptError,
            decrypt_message,
            key_id,
            parse_token,
        )
        from mordred_hermes.extension.pairing import load_pairing

        pairing = load_pairing()
        if pairing is None:
            return None, None
        by_id = key_index()
        used: dict[str, str | None] = {"kid": None}

        def _sub(m: re.Match[str]) -> str:
            token = m.group(0)
            core = token[1:] if token.startswith("🔒") else token
            full = "🔒" + core
            try:
                ver, kid, _n, _c = parse_token(full)
                key = (by_id.get(kid) if kid is not None else None) if ver == 2 else pairing.aes_key
                if key is None:
                    return token  # missing channel key — leave locked
                out = decrypt_message(key, full)
                if used["kid"] is None:
                    used["kid"] = kid if ver == 2 else key_id(key)
                return out
            except (DecryptError, Exception):
                return token

        return ENC_TOKEN_RE.sub(_sub, text), used["kid"]
    except Exception:
        return None, None


def _gateway_prefix_end(text: str, platform: str) -> int:
    """Return the end of the only plaintext prefix allowed on this platform."""
    prefix_re = _MENTION_PREFIXES.get(platform)
    if prefix_re is not None:
        match = prefix_re.match(text)
        if match is not None:
            return match.end()
    # Unknown platforms may still surround a ciphertext token with whitespace,
    # but do not get to smuggle another platform's mention syntax through.
    match = _WHITESPACE_RE.match(text)
    return match.end() if match is not None else 0


def _normalize_v3_token(token: str) -> str:
    if token.startswith(":lock:"):
        return "🔒" + token[len(":lock:") :]
    return token if token.startswith("🔒") else "🔒" + token


def _canonical_v3_parts(token: str) -> tuple[str, str, int, int, bytes, bytes, str, ReplayClaim]:
    """Parse one exact v3 token, accepting Slack's canonical ``:lock:`` alias."""
    import hashlib

    from mordred_hermes.extension.crypto import b64u_encode, parse_token_v3

    match = _CANONICAL_V3_TOKEN_RE.fullmatch(token)
    if match is None:
        raise InvalidEncryptedEnvelope("legacy_or_malformed_token")
    normalized = _normalize_v3_token(token)
    try:
        kid, message_id, sequence, total, nonce, ciphertext = parse_token_v3(normalized)
    except Exception as exc:
        raise InvalidEncryptedEnvelope("malformed_token") from exc
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise InvalidEncryptedEnvelope("malformed_token")
    if (
        b64u_encode(nonce) != match.group("nonce")
        or b64u_encode(ciphertext) != match.group("ciphertext")
        or kid != match.group("key_id")
        or message_id != match.group("message_id")
        or str(sequence) != match.group("sequence")
        or str(total) != match.group("total")
    ):
        raise InvalidEncryptedEnvelope("noncanonical_token")
    # One platform message is one authenticated command. Keeping sequence and
    # total in v3 makes a future assembly protocol explicit without accepting
    # today's spliceable multi-token grammar.
    if sequence != 0 or total != 1:
        raise InvalidEncryptedEnvelope("multi_token_not_supported")
    message_identity = hashlib.sha256(
        b"mordred-e2e-v3-message\0" + kid.encode("ascii") + b"\0" + message_id.encode("ascii")
    ).hexdigest()
    nonce_identity = hashlib.sha256(b"mordred-e2e-v3-nonce\0" + kid.encode("ascii") + b"\0" + nonce).hexdigest()
    return (
        kid,
        message_id,
        sequence,
        total,
        nonce,
        ciphertext,
        normalized,
        ReplayClaim((message_identity, nonce_identity)),
    )


def _context_channel_key(
    kid: str,
    *,
    chat_id: str,
    parent_chat_id: str | None,
) -> bytes:
    """Resolve a key only from the authenticated event's channel context."""
    from mordred_hermes.extension.crypto import key_id
    from mordred_hermes.extension.pairing import load_channel_keys

    channel_keys = load_channel_keys()
    candidates = [chat_id]
    if parent_chat_id and parent_chat_id not in candidates:
        candidates.append(parent_chat_id)
    for channel_id in candidates:
        raw_key = channel_keys.get(channel_id)
        if raw_key is not None and key_id(raw_key) == kid:
            return raw_key
    raise InvalidEncryptedEnvelope("key_not_bound_to_channel")


def _decrypt_gateway_claim(
    text: str,
    platform: str,
    *,
    chat_id: str,
    thread_root: str | None,
    parent_chat_id: str | None,
) -> tuple[str, str, ReplayClaim]:
    """Parse and authenticate one context-bound v3 platform message."""
    from mordred_hermes.extension.crypto import DecryptError, decrypt_message_v3

    prefix_end = _gateway_prefix_end(text, platform)
    # Mentions are unauthenticated transport routing metadata. In particular,
    # Slack channel/subteam labels and Teams display names contain free text;
    # accepting their syntax must not release that text into the agent prompt.
    position = prefix_end
    whitespace = _WHITESPACE_RE.match(text, position)
    if whitespace is not None:
        position = whitespace.end()
    token_match = _NON_WHITESPACE_RE.match(text, position)
    if token_match is None:
        raise InvalidEncryptedEnvelope("missing_token")
    token = token_match.group(0)
    position = token_match.end()
    if text[position:].strip():
        raise InvalidEncryptedEnvelope("mixed_or_multiple_content")

    kid, _message_id, _sequence, _total, _nonce, _ciphertext, normalized, replay = _canonical_v3_parts(token)
    raw_key = _context_channel_key(kid, chat_id=chat_id, parent_chat_id=parent_chat_id)
    try:
        plaintext = decrypt_message_v3(
            raw_key,
            normalized,
            direction="command",
            platform=platform,
            chat_id=chat_id,
            thread_root=thread_root,
        )
    except (DecryptError, UnicodeError, ValueError) as exc:
        raise InvalidEncryptedEnvelope("authentication_failed") from exc
    return plaintext, kid, replay


def decrypt_gateway_envelope(
    text: str,
    platform: str,
    *,
    chat_id: str,
    thread_root: str | None,
    parent_chat_id: str | None = None,
) -> tuple[str | None, str | None, ReplayClaim | None]:
    """Authenticate and decrypt a complete gateway wire envelope.

    The accepted grammar is::

        [platform mention prefix] one context-bound ENC:v3 token [whitespace]

    The prefix may contain only the existing Slack/Discord/Teams mention
    syntax for ``platform`` and whitespace. It is accepted as transport routing
    metadata but discarded rather than released into the agent prompt.
    Legacy v1/v2 gateway commands are rejected; their helpers remain available
    only for stored/history compatibility. The returned replay claim must be
    committed after outbound reply-path verification and immediately before
    plaintext release. ``(None, None, None)`` means no encrypted claim.
    """
    if not text or ENC_CLAIM_RE.search(text) is None:
        return None, None, None

    try:
        if not platform or not chat_id:
            raise InvalidEncryptedEnvelope("missing_context")
        return _decrypt_gateway_claim(
            text,
            platform.lower(),
            chat_id=chat_id,
            thread_root=thread_root,
            parent_chat_id=parent_chat_id,
        )
    except InvalidEncryptedEnvelope:
        raise
    except Exception as exc:
        # Pairing/keyring I/O and parser drift are security failures here, not
        # invitations to hand the claimed ciphertext wire to the agent.
        raise InvalidEncryptedEnvelope("internal_error") from exc


def claim_gateway_replay(replay: ReplayClaim) -> bool:
    """Persist an authenticated replay claim atomically across restarts."""
    from mordred_hermes.extension.pairing import claim_e2e_replay_identities

    return claim_e2e_replay_identities(replay.identities)


# Conversations that received an encrypted message → reply-in-kind. Value is
# (expiry, key_id) so replies re-encrypt with exactly the inbound key. Keyed by
# (platform, channel_id, thread_root) so ids never collide across platforms.
_ENC_THREADS: dict[tuple[str, str, str | None], tuple[float, str | None]] = {}
_ENC_TTL = 24 * 3600  # seconds


def mark_encrypted_thread(
    platform: str,
    channel_id: str,
    thread_root: str | None,
    key_id: str | None = None,
) -> bool:
    """Record reply-in-kind context, returning whether it was stored."""
    if not channel_id:
        return False
    _ENC_THREADS[(platform, channel_id, thread_root)] = (time.time() + _ENC_TTL, key_id)
    return True


def _prune(now: float) -> None:
    for k, (exp, _kid) in list(_ENC_THREADS.items()):
        if exp < now:
            _ENC_THREADS.pop(k, None)


def is_encrypted_thread(platform: str, channel_id: str, thread_root: str | None) -> bool:
    """Is this conversation known-encrypted? Falls back to the channel-level mark.

    The fallback must apply even when ``thread_root`` is set: a user who
    @-mentions the agent at channel top level is recorded under
    ``thread_root=None`` (the inbound event has no thread), but the agent
    answers *in a thread* rooted at that mention, so the outbound lookup carries
    a thread_ts. Without the fallback the reply is judged unencrypted and goes
    out in CLEARTEXT. Mirrors :func:`thread_key_id`, which already scans
    ``(thread_root, None)`` — the two must agree or the reply path leaks.
    """
    now = time.time()
    _prune(now)
    return any(_ENC_THREADS.get((platform, channel_id, tr), (0, None))[0] > now for tr in (thread_root, None))


def thread_key_id(platform: str, channel_id: str, thread_root: str | None) -> str | None:
    """The keyId last seen encrypting this conversation, if still fresh."""
    now = time.time()
    _prune(now)
    for tr in (thread_root, None):
        exp, kid = _ENC_THREADS.get((platform, channel_id, tr), (0, None))
        if exp > now and kid:
            return kid
    return None


def reply_key(key_id_hint: str | None) -> bytes | None:
    """Raw key to encrypt a reply with: the remembered inbound key, by keyId.
    Id-format-agnostic — no channel-id matching needed.

    Fail-closed: when the hint is missing or unknown this returns ``None``
    instead of falling back to the master/pairing key. The master is NOT a
    channel key any extension holds, so encrypting a reply with it emits
    ciphertext nobody in the channel can read — strictly worse than refusing,
    because the failure is silent (it looks encrypted). Callers turn ``None``
    into a visible "could not encrypt" notice.

    v1/legacy conversations are unaffected: their remembered keyId IS the
    master's, and ``key_index()`` contains the master, so the lookup still hits.
    """
    try:
        if not key_id_hint:
            return None
        return key_index().get(key_id_hint)
    except Exception:
        return None


def channel_key(channel_id: str) -> bytes | None:
    """The K_chan for a channel (SPEC-v2), falling back to the master key for
    channels that only have a v1/legacy key. Retained for callers that key by a
    native channel id; the reply path prefers reply_key(keyId)."""
    try:
        from mordred_hermes.extension.pairing import load_channel_keys, load_pairing

        ck = load_channel_keys().get(channel_id)
        if ck is not None:
            return ck
        p = load_pairing()
        return p.aes_key if p is not None else None
    except Exception:
        return None


def _unpadded_b64_length(raw_length: int) -> int:
    """Return the exact unpadded base64url length for ``raw_length`` bytes."""
    return (4 * raw_length + 2) // 3


def _v3_plaintext_budget(max_len: int, prefix: str = "") -> int:
    """Maximum UTF-8 plaintext bytes whose complete v3 wire fits ``max_len``."""
    from mordred_hermes.extension.crypto import ENC_PREFIX_V3

    # Key id (8), message id (22), sequence/total (one digit each), nonce
    # (12 bytes -> 16 base64url chars), their separators, and an optional
    # plaintext routing prefix. AES-GCM adds a 16-byte tag to the plaintext.
    fixed = len(prefix) + (1 if prefix else 0) + len(ENC_PREFIX_V3) + 8 + 1 + 22 + 1 + 1 + 1 + 1 + 1 + 16 + 1
    if fixed + _unpadded_b64_length(16) > max_len:
        return -1

    low, high = 0, max_len
    while low < high:
        candidate = (low + high + 1) // 2
        wire_length = fixed + _unpadded_b64_length(candidate + 16)
        if wire_length <= max_len:
            low = candidate
        else:
            high = candidate - 1
    return low


def _split_utf8(body: str, first_budget: int, later_budget: int) -> list[str]:
    """Split at Unicode boundaries without exceeding per-chunk byte budgets."""
    if first_budget < 0 or later_budget < 0:
        raise ValueError("platform message limit is too small for an encrypted reply")
    if not body:
        return [""]

    pieces: list[str] = []
    current: list[str] = []
    used = 0
    budget = first_budget
    for character in body:
        size = len(character.encode("utf-8"))
        if used + size > budget:
            # A long plaintext mention prefix can leave no room for the first
            # body character. Emit an authenticated empty first message, then
            # continue with the normal no-prefix budget.
            pieces.append("".join(current))
            current = []
            used = 0
            budget = later_budget
        if size > budget:
            raise ValueError("platform message limit cannot fit one encrypted character")
        current.append(character)
        used += size
    if current:
        pieces.append("".join(current))
    return pieces


def encrypt_reply(
    raw_key: bytes,
    content: str,
    max_len: int,
    mention_prefix_re: re.Pattern[str] | None = None,
    *,
    platform: str,
    chat_id: str,
    thread_root: str | None,
) -> list[str]:
    """Encrypt reply platform messages as context-bound v3 tokens.

    Slack channel/subteam display labels and Teams mention display names are
    free text, not authenticated routing identifiers, so they are normalized
    away. Even an empty/all-mention reply carries an authenticated empty token;
    a known-encrypted send never degrades to a wholly plaintext chunk.
    """
    from mordred_hermes.extension.crypto import encrypt_message_v3, key_id

    kid = key_id(raw_key)
    m = mention_prefix_re.match(content) if mention_prefix_re else None
    prefix = m.group(1).strip() if m else ""
    prefix = _SLACK_FREE_TEXT_LABEL_RE.sub(r"\1\2", prefix)
    prefix = _TEAMS_FREE_TEXT_MENTION_RE.sub("", prefix).strip()
    body = content[m.end() :] if m else content
    first_budget = _v3_plaintext_budget(max_len, prefix)
    later_budget = _v3_plaintext_budget(max_len)
    pieces = _split_utf8(body, first_budget, later_budget)
    out: list[str] = []
    for i, piece in enumerate(pieces):
        enc = encrypt_message_v3(
            raw_key,
            piece,
            kid,
            direction="reply",
            platform=platform,
            chat_id=chat_id,
            thread_root=thread_root,
        )
        wire = f"{prefix} {enc}" if (i == 0 and prefix) else enc
        if len(wire) > max_len:  # Defensive assertion against wire-format drift.
            raise ValueError("encrypted reply exceeds the platform message limit")
        out.append(wire)
    return out
