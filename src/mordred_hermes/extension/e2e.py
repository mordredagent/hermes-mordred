"""Shared Mordred E2E transport hooks for chat platform adapters.

Slack / Discord / Teams adapters call into this module so each platform acts
as a pure encrypted transport for the Mordred browser extension:

  * inbound ``🔒ENC:v1/v2`` tokens are decrypted before the agent sees them
    (per-token key selection by keyId; SPEC-v2 §1);
  * replies into a conversation that received an encrypted message are
    re-encrypted with the channel key (reply-in-kind, §4);
  * ``🔑REQ/GRANT`` key-exchange control messages (§5) are peer-to-peer
    between extensions and must be dropped before the agent reacts to them.

All functions are fail-open on unexpected errors (never block message flow)
except the encrypt path, which the callers treat fail-closed.
"""

from __future__ import annotations

import re
import time

# A `🔒ENC:v1/v2:…` token anywhere in the text. Extensions keep a leading
# @mention plaintext, so the ciphertext is NOT necessarily at the start; the
# 🔒 may also be dropped by the platform's renderer. v2 first — it's longer.
ENC_TOKEN_RE = re.compile(
    r"🔒?ENC:v2:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
    r"|🔒?ENC:v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+"
)

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


# Conversations that received an encrypted message → reply-in-kind. Value is
# (expiry, key_id) so replies re-encrypt with exactly the inbound key. Keyed by
# (platform, channel_id, thread_root) so ids never collide across platforms.
_ENC_THREADS: dict[tuple[str, str, str | None], tuple[float, str | None]] = {}
_ENC_TTL = 24 * 3600  # seconds


def mark_encrypted_thread(platform: str, channel_id: str, thread_root: str | None, key_id: str | None = None) -> None:
    if not channel_id:
        return
    _ENC_THREADS[(platform, channel_id, thread_root)] = (time.time() + _ENC_TTL, key_id)


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
    return any(
        _ENC_THREADS.get((platform, channel_id, tr), (0, None))[0] > now for tr in (thread_root, None)
    )


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


def encrypt_reply(
    raw_key: bytes,
    content: str,
    max_len: int,
    mention_prefix_re: re.Pattern[str] | None = None,
) -> list[str]:
    """Encrypt a reply body-only (v2), keeping leading mentions plaintext."""
    from mordred_hermes.extension.crypto import encrypt_message_v2, key_id

    kid = key_id(raw_key)
    m = mention_prefix_re.match(content) if mention_prefix_re else None
    prefix = m.group(1).strip() if m else ""
    body = content[m.end() :] if m else content
    if not body.strip():
        return [content]
    safe = max(512, int(max_len * 0.6))
    pieces = [body[i : i + safe] for i in range(0, len(body), safe)]
    out: list[str] = []
    for i, piece in enumerate(pieces):
        enc = encrypt_message_v2(raw_key, piece, kid)
        out.append(f"{prefix} {enc}" if (i == 0 and prefix) else enc)
    return out
