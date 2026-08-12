<a id="hermes--gateway-e2e-&#x6697;&#x53f7;&#x5316;"></a>

# Hermes ⇄ gateway E2E encryption

This document defines how Hermes receives and replies to agent commands when
the Mordred browser extension uses Slack or Discord only as a ciphertext
transport. Gateway agent commands accept `ENC:v3` only. The WebSocket API,
history, and the v1/v2 `K_extchat` helpers are separate protocols and remain
available for compatibility.

> **Migration note:** v3 is an intentional breaking wire change. Deploying this
> gateway before the external Mordred extension implements the v3 AAD and
> direction fields disables both gateway commands and replies for v1/v2
> clients. Update Hermes and the extension together. There is no implicit
> downgrade path for older commands.

## 1. v3 wire

A platform post contains only an allowed leading mention, one v3 token, and
trailing whitespace:

```text
[mention-prefix] 🔒ENC:v3:{kid}:{message_id}:{seq}:{total}:{nonce}:{ciphertext}
```

- `kid`: `base64url(SHA-256(K_chan)[0:6])` (8 characters)
- `message_id`: a random 128-bit value generated before posting (22-character
  base64url), not the platform message ID assigned later by Slack or Discord
- The current profile always uses `seq=0,total=1`.
- `nonce`: a 96-bit AES-GCM nonce
- `ciphertext`: AES-256-GCM ciphertext for the UTF-8 body plus its 16-byte tag
- All base64url values use canonical, unpadded encoding.

When Slack normalizes the Unicode lock emoji to `:lock:`,
`:lock:ENC:v3:…` is accepted as the same canonical alias. A token without the
lock is also accepted for compatibility with existing renderers. An unknown
version, multiple tokens, a plaintext prefix or suffix, non-canonical
encoding, or tampering rejects the entire post.

<a id="2-aad&#x3068;&#x5b9b;&#x5148;&#x675f;&#x7e1b;"></a>

## 2. AAD and destination binding

AES-GCM AAD joins the following fields in order. Each string is encoded as
UTF-8 and framed as `uint32_be(length) || bytes`; the final fields are encoded
as `uint16_be(seq) || uint16_be(total)`.

```text
"mordred-e2e-v3"
direction          # "command" or "reply"
platform.lower()   # "slack" / "discord"
chat_id
thread_root        # None is the empty string
message_id
seq
total
```

Hermes fixes inbound messages to `direction="command"` and replies to
`direction="reply"`, so a reply ciphertext cannot be reflected into an agent
command. Cross-channel and cross-thread replays also fail authentication when
`platform`, `chat_id`, or `thread_root` changes.

For a Discord auto-thread, the new thread ID does not exist when the extension
encrypts the command. Its command AAD therefore uses the canonical
`(parent_chat_id, thread_root=None)` destination. Hermes performs this
conversion only after correlating the Hermes 0.19 `auto_thread_created` marker
with the `raw_message.channel.id` retained by Hermes 0.13 and 0.19. The reply
registry and reply AAD use `(thread_id, thread_id)` after creation. Hermes
rejects the message instead of guessing if the marker, parent, and raw channel
conflict, or if an older event cannot distinguish an auto-thread from an
existing thread.

Slack top-level channel messages have a mirrored issue. For session keying,
the default Slack adapter (`reply_in_thread`) synthesizes the message's own
`ts` as `thread_id` (`thread_ts == ts`). The extension cannot know this
server-assigned value while encrypting, so command AAD uses
`thread_root=None` only when the routed thread root equals the command's own
message ID. A real thread reply arrives with `thread_ts != ts` and is
authenticated against the real root, so replaying a top-level token into an
existing thread still fails. Reply routing continues to use the synthesized
thread.

Keys are never selected from a global `kid` index. Hermes considers only the
`K_chan` registered for the event's `chat_id`, or for an authenticated Discord
thread's `parent_chat_id`, and decrypts only when that key's fingerprint
matches `kid`.

<a id="3-replay&#x9632;&#x6b62;&#x3068;plaintext-release"></a>

## 3. Replay protection and plaintext release

After authentication, domain-separated SHA-256 produces two identities:

- `(kid, message_id)`
- `(kid, nonce)`

Raw IDs and nonces are not stored. The identities are saved atomically in the
private `~/.hermes/extension/state.json` file with a 30-day TTL and a fixed
capacity. Restarting the gateway therefore does not make a command fresh.
Hermes rejects both message-ID reuse and AES-GCM nonce reuse.

The commit order is:

1. Authenticate the wire grammar and AES-GCM payload.
2. Confirm that the target profile's live outbound adapter has a fail-closed
   wrapper.
3. Record `(platform, chat_id, thread_root, kid)` in the reply-in-kind
   registry.
4. Atomically check and store the replay identities.
5. Release plaintext to the agent for the first time.

A valid post that fails step 2 or 3, such as during an adapter outage, does not
consume its replay entry. Replay-store read or write failures are fail-closed.

<a id="4-&#x8fd4;&#x4fe1;"></a>

## 4. Replies

A conversation that supplies an encrypted command is recorded in an in-memory
registry for 24 hours. Reply bodies are encrypted with the same channel key as
v3 tokens using `direction="reply"`. Long replies are split by platform post;
each post is an independent `seq=0,total=1` message with a fresh message ID and
nonce.

Slack and Discord routing mentions may remain as a plaintext prefix, but Slack
channel or subteam display labels and Teams display names are not added to the
agent prompt, and free-form text is removed. If encryption classification,
thread resolution, key lookup, or encryption fails, the wrapper never delegates
to the original plaintext sender. Slack may emit a minimal locked notice, but
never the reply body.

In a multiplexed Hermes gateway, the wrapper, verification, and notice path use
`gateway._profile_adapters[profile]` selected by `event.source.profile`. A
wrapped default-profile adapter is never substituted for an unprotected
secondary-profile adapter on the same platform. The legacy
`gateway.adapters` path remains supported for older Hermes versions.

## 5. Mandatory E2E

Hermes never sends an unencrypted Slack or Discord message to the agent. It
attempts to send setup guidance and skips dispatch. Other platforms such as
Teams may still accept plaintext, but any payload claiming the `ENC` wire
format fails closed unless it passes the same v3 validation.

The needs-key notice is rate-limited per conversation (platform × profile ×
channel, 60-second window). The notice is emitted before host authorization;
without a cooldown, any channel member could amplify a message flood into an
equal flood of bot posts. Suppression affects only the notice: every refused
message still receives the `skip` verdict.

**An empty `text` value is also rejected as unencrypted input.** The Slack
adapter strips bot mentions (`text.replace(f"<@{bot_uid}>", "").strip()`) and
stores attachments in `media_urls`, so `@Hermes` plus an image, audio clip, or
mention alone reaches the hook with `text == ""`. An empty value cannot contain
a v3 token. Mandatory platforms therefore skip it and send setup guidance just
like any other plaintext input. Other platforms continue normal dispatch. A
2026-08-02 security review found that this path could otherwise bypass the gate
and leak an agent reply in plaintext.

<a id="6-&#x30c6;&#x30b9;&#x30c8;&#x8981;&#x4ef6;"></a>

## 6. Test requirements

- Canonical v3 with the Unicode lock, no lock, and Slack's `:lock:` alias
- AAD failure after independently changing platform, chat, thread, or direction
- Rejection when a matching key exists only in a different channel
- Rejection of v1/v2 gateway commands, multiple tokens, mixed plaintext, and
  tampering
- Rejection of replayed messages, reused message IDs, and reused nonces across
  simulated restarts with persistent state
- Replay commit occurring only after outbound protection is confirmed
- No confusion between default- and secondary-profile adapters
- No plaintext `orig_send` call when encryption classification raises
- Rejection of empty or missing `text` on mandatory platforms for image/audio
  attachments and mention-only posts, while other platforms still dispatch
  normally
