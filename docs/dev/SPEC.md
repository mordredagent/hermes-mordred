# Mordred — Specification (Hermes-base)

This document defines the behavior shipped by `hermes-mordred`. It describes
the current contract, not the sequence of pull requests that produced it.
Implementation details may evolve, but security boundaries, persistent wire
formats, and public behavior must stay consistent with this specification or
change here in the same patch.

## Vision

Mordred adds privacy-oriented policy, route selection, local-LLM enforcement,
hardware-backed key handling, at-rest protection, and an end-to-end browser
extension gateway to an ordinary Hermes installation. It is a cooperative
control layer inside the Hermes process, not an operating-system sandbox and
not a claim that every program run by the same user is contained.

The default experience remains usable: an operator can install the package,
run `hermes-mordred setup`, inspect the resulting state, and opt into
stricter controls. When a strict boundary cannot establish the evidence it
needs, it refuses rather than silently claiming protection.

## Project Identity

### Relationship to Hermes

`hermes-mordred` is a standalone MIT-licensed package that depends on
`hermes-agent`. It is not a fork or a copy of the upstream repository. It
ships one `hermes_agent.plugins` entry point, `mordred`
(`mordred_hermes.plugin`), which registers the components listed under
[What Mordred Adds](#what-mordred-adds-one-plugin-six-components). Releases up
to 0.1.0a20 shipped each component as its own entry point (`mordred_network`,
`mordred_privacy_check`, `mordred_llm_guard`, `mordred_keyvault`,
`mordred_wizard`, `mordred_e2e`); config writers migrate those names in
`plugins.enabled` / `plugins.disabled` to `mordred`.

Hermes core stays unmodified and Mordred does not submit upstream pull
requests. [`UPSTREAM.md`](./UPSTREAM.md) owns that relationship and the
compatibility policy.

### Platform Support (v1)

- Python 3.11 or newer is required. CI exercises Python 3.11 through 3.13.
- macOS and Linux support the policy, network, CLI, and extension layers.
- On macOS, the preferred native key backend is the installed Secure Enclave
  helper. An entitled in-process Security-framework backend and a
  login-Keychain software P-256 namespace remain ordered compatibility
  fallbacks.
- On Linux, the keyvault requires the installed TPM 2.0 helper and fails
  closed if it is absent or unusable. There is no Linux software-key fallback.
- Transparent `.env` injection, `config.yaml` materialize/reseal, agent-memory
  at-rest encryption, and the encrypted workspace integration are active only
  on macOS. Off macOS they may be enrolled, but status reports them inactive
  and plaintext remains the runtime source.
- Arming those macOS seals is fail-closed on the runtime: before removing a
  plaintext, the CLI probes the interpreter that should run `hermes` and also
  the interpreter of each `hermes gateway run` process it can identify in the
  process table, refusing when either cannot run the startup shim. Identifiable
  means: this user's process whose argv is `<python> -m hermes_cli… gateway
  run`, `<python> <launcher> gateway run`, `<launcher> gateway run`, or
  `<shell> <launcher> gateway run`, with an absolute launcher path. Gateways
  running under another account, or argv shapes outside that set, are not
  probed. A scan that finds nothing is not a refusal, and
  `--force-runtime-unverified` seals without either check.
- The `config` target protects `config.yaml` between managed process runs, not
  throughout a run. Its startup hook materializes a mode-`0600` plaintext file
  for the managed process lifetime and reseals it on clean exit; an unclean
  exit can leave that working copy until the next managed start and exit.
- File-vault `vault recover` is supported only on macOS. The Linux TPM helper
  implements native wrapping, but the file vault has no Linux device-anchor
  store and must not claim a working recovery hot path there.
- Windows product support is in development under the completion contract
  below; it is not yet a supported end-to-end workflow. Mobile support remains
  deferred. Injected-backend tests alone do not establish platform support.

### License Note

This repository is MIT licensed. Dependencies and optional native tooling keep
their own licenses; release review must preserve attribution and avoid copying
Hermes source into this package.

## Threat Model & Accepted Limitations

Mordred is designed for a cooperative Hermes process on a host whose operator
controls the account. It protects policy decisions and stored material against
common misconfiguration, accidental clearnet use through integrated routes,
and loss of plaintext files at rest. It does not create a hostile-code
security boundary.

Current defenses include:

- policy-gated skill installation through `hermes-mordred install`;
- generic strict runtime blocking for known network tools on clearnet;
- Tor/VPN route lifecycle and provider-transport compatibility checks;
- strict LLM identity and endpoint checks immediately before primary egress,
  plus dedicated guards for Hermes auxiliary LLM clients;
- strict startup refusal when a required Mordred sibling plugin is disabled;
- purpose-bound envelope encryption and native-key authorization;
- encrypted audit records when a keyvault-backed writer is available; and
- loopback-only, paired, encrypted browser-extension transport; and
- a read-only Telegram importer (see [Telegram import](#telegram-import)); and
- tool-egress levels (`lockdown` / `search` / `ask` default / `blocklist` / `off`)
  enforced in `privacy_check`'s `pre_tool_call`: free-form code tools are
  refused below `blocklist` except exact first-party read-only commands,
  unknown tools count as internet-capable, and a session that read private
  data is locked down (taint).

Accepted limitations include:

- tool-egress control acts on tool calls, not sockets: under `blocklist` a
  `terminal` command can still reach any host not named in the blocklist, and
  a Hermes feature that sends data without a tool call (cron `no_agent`
  scripts, platform delivery, external ACP delegates) is outside the hook;

- a skill can open a direct socket or invoke an unwrapped executable;
- Hermes does not provide trusted `origin_skill` provenance to
  `pre_tool_call`, so runtime policy is tool-based rather than per-skill;
- provider or transport metadata supplied by an untrusted component can lie;
- same-UID malware can inspect process memory, modify local files, or remove
  audit history;
- plaintext necessarily exists while a secret is in use, and screen-capture
  detection cannot defeat a physical camera;
- traffic emitted by a parent harness such as Codex CLI, Claude CLI, Cursor,
  or an ACP client bypasses Hermes plugin hooks;
- if the Mordred plugin and the packaged interpreter-startup guard are
  removed, plugin-only enforcement no longer runs;
- helper discovery through writable PATH locations is not equivalent to
  signed-distribution attestation; and
- wallet signing and payment authorization are not isolated into a separate
  privilege domain; and
- the Telegram session is a full MTProto account credential (Telegram has no
  scoped or read-only token). Read-only behavior is enforced by the client,
  not by Telegram, and same-UID malware that can open the vault hot path can
  use the session.

### Telegram import

Linux enablement is proposed in the
[Linux private Telegram design](#linux-private-telegram-design).
That draft does not change the current macOS-only agent-memory requirement;
the TPM credential backend alone is not full Linux Telegram support.

The optional `telegram` extra lets the operator import their **own** Telegram
account (MTProto user session via Telethon) and ask questions over it from the
browser extension, using a Venice.ai private model.

- **Custody (TEE).** API credentials, the Telethon `StringSession`, the
  archive key and the LLM API key are sealed in `credentials.sealed` under a
  data key wrapped (keyvault ECIES, `wrap.wrap_dek`) by a P-256 key inside the
  Secure Enclave (Linux: TPM). The backend is the signed hardware helper only
  — no software-key namespace, no legacy fallback — so without
  `keyvault enable-se` every read and write fails with `tee_unavailable`.
  Every unseal is a fresh Enclave ECDH (nothing decrypted is cached); the key
  requires Touch ID / passcode per use unless created with `--no-touch-id`.
  The sealed file is not the vault `.env`, so nothing is ever injected into a
  Hermes process environment. The 2FA password is never stored.
- **Plaintext in memory only.** Messages are AES-256-GCM encrypted on disk;
  processes that unseal credentials disable core dumps, deny debugger attach
  (`PT_DENY_ATTACH`), and cap Telethon logging at WARNING. Status polls use a
  non-secret flags file and never unseal.
- **Destinations.** Imported text goes only to Venice (fixed
  `https://api.venice.ai/api/v1`, `private` models) or to a loopback model
  (`telegram local-llm`, literal `127.0.0.1`/`::1`, no proxy). Redirects are
  never followed. No other endpoint is configurable.
- **Read-only.** Every request is checked against an allowlist of reads before
  Telethon resolves or queues it, both at `TelegramClient._call` and at the
  MTProto sender's `send`. Sending, editing, deleting, reacting,
  `messages.ReadHistory`, `account.UpdateStatus`, media download (`upload.*`)
  and cross-DC exported senders are refused. Auth requests are unlocked only
  inside the interactive `telegram login`; `auth.LogOut` only inside
  `telegram logout`. Telethon's update machinery is disabled (`_on_login`
  seeds state from `updates.GetState` only; no update loop), so no
  `updates.GetDifference` traffic is needed. A second `telegram login` is
  refused while a session exists, and a login that fails after Telegram
  accepted it revokes the new authorization.
- **At rest.** `<home>/mordred/telegram/` holds an index plus AES-256-GCM
  segment files of up to 2000 messages per chat (a sync rewrites only the last
  segment). Separate HKDF subkeys of `store_key` encrypt and name files; the
  AAD binds each blob to its logical name and file names are an HMAC of chat id
  and segment number. File counts and sizes remain observable.
- **Egress.** Telegram and Venice resolve one explicit route through
  `extension.egress` (shared with Discord): Tor requires a loopback SOCKS proxy
  with remote DNS; VPN without a live runtime is refused.
- **Questions.** Only Venice models whose live catalog entry has
  `model_spec.privacy == "private"` are used; `anonymized` models, unknown
  models and an unreadable catalog fail closed. The request carries no tools,
  disables web search and Venice's system prompt, and runs the llm_guard
  `check_runtime_provider(active_provider="venice")` gate first. Only a
  bounded selection is sent, pseudonymized by default (sender names, chat
  titles, e-mail addresses, phone numbers become aliases mapped back locally;
  alias brackets in message text are neutralized so text cannot forge one),
  inside a delimiter message text cannot close. Names mentioned inside message
  text and the question itself are sent as written.
- **Wire.** Account label, chat titles and answer chunks are sealed with
  `K_extchat`; the question must arrive sealed. Numeric chat ids, counts and
  dates travel unsealed over the loopback socket. Each question runs as its
  own task (at most two per socket) and `telegram_ask_cancel` or a closed
  socket stops it. Page sessions cannot reach the Telegram handlers.
- **Hermes tools.** The `mordred` plugin's e2e component registers `telegram_chats` / `telegram_ask`
  (toolset `mordred_telegram`). `check_fn` offers them only when the
  configured Hermes model is Venice or loopback; each call re-checks the
  running agent's `model`/`base_url` and, for Venice, requires
  `model_spec.privacy == "private"` from the public catalog before unsealing
  anything. Results carry an untrusted-content note.
- **Not covered.** Secret chats (device-bound E2EE), media contents, and
  sending messages. Venice E2EE (TEE-attested) models are a planned follow-up.

The remaining hardening work is tracked as release gates in
[`ROADMAP.md`](./ROADMAP.md), especially OS1 and P1. Documentation must not
describe those gates as current protection.

### Newly defended via Hermes plugin hooks (no core seam needed)

Hermes hooks provide useful cooperative boundaries:

- `on_session_start` checks plugin integrity, declared harness state,
  persisted provider state, auxiliary-guard installation, and route startup;
- `pre_tool_call` receives `tool_name` and applies the generic clearnet guard;
- `pre_api_request` receives the resolved `provider` and `base_url` for the
  primary request, allowing endpoint-bound LLM and transport checks;
- `on_session_end` performs best-effort route teardown and secret resealing;
  and
- `pre_gateway_dispatch` receives `event` and `gateway` for the E2E gateway.

[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) and
`tools/hook_payload_contract.json` own the exact consumed fields.

### Defended via plugin-side strict-mode startup refusal (zero-PR strategy)

Each runtime sibling registers the shared integrity check. In strict mode, a
known Mordred plugin recorded as disabled causes
`MordredIntegrityRefused`, a `BaseException` subclass, at the next session
start. This deliberately escapes Hermes's ordinary hook error wrapper.

The check is a startup boundary, not a live lock on configuration edits.
Changing disable state during an already-running session takes effect on the
next startup. Hard prevention of the disable operation itself is not shipped.

### Plugin-only fallback for missing seams

Where Hermes supplies no trusted skill origin, Mordred records
`mordred.degraded.no_origin_skill` and uses the generic strict tool-name rule.
Where provider identity cannot be resolved, strict mode blocks/refuses and
records the relevant degraded and policy reasons. Mordred never treats missing
evidence as permission and does not claim that these fallbacks contain direct
network access.

## Plugin-Only Architecture (zero Hermes core modifications, zero-PR strategy)

All integration occurs through installed entry points, the standalone
`hermes-mordred` console script, supported Hermes hooks, narrowly targeted
runtime guards, and the packaged `.pth` startup files. The `.pth` guards engage
only for Hermes invocations (or their explicit opt-in environment variables)
and do not turn Mordred into a replacement Python runtime.

`hermes-mordred` is the canonical CLI spelling. The registered Hermes-host
subcommand is a compatibility alias on versions that discover plugin CLI
commands; it is not available before the `mordred` plugin is loaded on older
supported hosts.

### What Mordred Adds (one plugin, six components)

The distribution is `hermes-mordred`; imports remain under `mordred_hermes`.
Hermes sees one plugin, `mordred`. Its `register()` first installs the shared
integrity gate on `on_session_start`, then registers the components in this
order (the table order):

| Component | Module | Current responsibility |
|---|---|---|
| `keyvault` | `mordred_hermes.keyvault` | native-key envelopes, recovery primitives, audit encryption, macOS runtime secret lifecycle |
| `llm_guard` | `mordred_hermes.llm_guard` | `mordred-local` registration, strict provider/endpoint refusal, harness and auxiliary-client guards |
| `network` | `mordred_hermes.network` | Tor/VPN/clearnet route lifecycle, proxy evidence, health checks, transport gating |
| `privacy_check` | `mordred_hermes.privacy_check` | install policy, generic runtime tool policy, audit writer, plugin integrity |
| `e2e` | `mordred_hermes.extension.gateway_plugin` | gateway-side encrypted extension dispatch, signing integration, read-only Telegram tools |
| `wizard` | `mordred_hermes.wizard` | configuration, migration, status, policy, network, keyvault, vault, encryption, and plugin CLI |

A component whose `register()` raises an ordinary exception is contained: its
registrations are disposed, the others still register, and the integrity gate
reports it as `mordred/<component>` (strict: refuse the session; lenient/off:
warn), exactly as a failed separate plugin was reported before. Deliberate
fail-closed refusals (`BaseException`) propagate and stop startup. Settings
stay in the `plugins.mordred_network`, `plugins.mordred_privacy_check`, and
`plugins.mordred_llm_guard` sections of `config.yaml`.

### Conventions (not plugins)

`<home>` means the active profile-aware Hermes home, normally `~/.hermes`.
Policy values, audit reason strings, filesystem ownership, and hook payloads
are shared contracts rather than independent plugins. Their canonical maps
are [`POLICY.md`](./POLICY.md), [`PATHS.md`](./PATHS.md), and
[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md).

### What Mordred Inherits from Hermes (never modified)

Mordred uses Hermes's agent loop, provider registry, skills, tools, memory,
gateway framework, configuration home, plugin manager, and hook dispatcher.
Compatibility code may read those surfaces and refuse when they drift, but it
does not patch the upstream repository or redistribute a modified Hermes.

### Conditionally inherited (lenient mode only)

Lenient mode permits operation when metadata or protection evidence is
incomplete, while warning and auditing the downgrade. It may therefore inherit
Hermes's ordinary provider, skill, and clearnet behavior. Strict mode must not
be described as providing the same permissive fallback.

### Naming Convention

The canonical distribution name is `hermes-mordred`; `mordred-hermes` is a
metadata-only compatibility shim. Python imports use `mordred_hermes`, the one
Hermes entry point is `mordred`, config sections keep the pre-0.2.0a0
per-component names (`plugins.mordred_network`, ...), and audit reasons use
stable dotted names. The `### Plugin: mordred_*` sections below describe the
components by those historical names. The browser-facing gateway component
(formerly the `mordred_e2e` entry point) lives under `mordred_hermes.extension`.

## Target User (v1)

The primary user runs Hermes locally, accepts that plugins are cooperative
controls, and wants explicit choices for network paths, cloud LLM use, local
secret storage, and browser-extension access. Strict mode is intended for an
operator willing to resolve missing evidence instead of accepting automatic
fallback.

## User Stories (v1)

### Story 1: Adding the privacy layer for existing Hermes users

An existing Hermes user installs the appropriate extras, runs
`hermes-mordred setup`, reviews `hermes-mordred status`, and continues to run
the upstream agent. Setup is re-runnable and skips completed steps.
Configuration writes preserve unrelated Hermes keys and install Mordred's
six-plugin set without modifying upstream source.

### Story 1.5: Migration from OpenClaw + Mordred-OpenClaw

`hermes-mordred upgrade` detects a legacy `~/.openclaw` tree, applies explicit
row-level conflict policies, and remains idempotent. It never overwrites an
existing conflicting Mordred configuration silently. The exact source,
destination, and conflict ownership are in [`PATHS.md`](./PATHS.md).

### Story 2: New user setup

A new user installs Hermes plus this distribution and runs the Mordred wizard.
The wizard defaults to lenient policy, writes `config.yaml` and the derived
`policy.json` transactionally, and explains which optional backend or route
setup is still required.

### Story 3: Skill execution and automatic path selection

Installation through `hermes-mordred install` evaluates the skill's
`metadata.mordred` declaration before delegating to Hermes. At runtime,
configured Tor/VPN routes are selected before provider-client construction and
kept stable for the session. This story does not imply per-skill runtime
provenance or direct-socket containment.

### Story 4: Local LLM enforcement (strict-mode override)

The heading is retained as a stable documentation anchor; current behavior is
refusal, not override. In strict mode, `mordred-local` is allowed only when its
runtime endpoint exactly matches the pinned loopback endpoint and resolves
only to loopback addresses. A cloud provider is allowed only when cloud use is
enabled, the provider is allowlisted (or interactively granted by
`prompt-once`), and the actual HTTPS endpoint matches that provider's accepted
shape. Otherwise Mordred stops the request before egress.

The primary boundary is `pre_api_request`. Hermes auxiliary clients that do
not emit that hook are guarded at their resolver/client-construction seams.
Mordred does not rewrite an already resolved provider to `mordred-local`.

### Story 5: Key management

The user initializes one profile-scoped keyvault, verifies a digest through an
offline workflow, and stores secret material only in purpose-bound envelopes.
macOS prefers the Secure Enclave helper with compatibility fallbacks; Linux
requires the TPM helper. Seed display is short-lived and capture-aware where
the OS exposes the signal.

The Python API can export and import a recoverable encrypted manifest. The
operator CLI exposes `keyvault export --output` and `recover --blob` for the
corresponding portable snapshot workflow. Exported snapshots are point-in-time
artifacts and must be recreated after Keyvault contents change.

### Story 6: Coexistence with Hermes's existing features

Mordred preserves unrelated Hermes configuration and uses profile-aware paths.
Mordred owns agent-memory at-rest encryption as a runtime wrapper around the
memory tool's read/write seam in `tools/memory_tool.py`: no Hermes release
encrypts memories, and the zero-PR commitment means upstream cannot be asked
to. Hermes still owns the entry format inside the plaintext and the memory
tool itself. Extension state uses Hermes's established `<home>/extension/`
directory rather than the private keyvault tree.

## Scope (In) — what we build in v1

### Plugin: `mordred_network`

The network plugin provides:

- `tor`, `vpn`, and `clearnet` route selection with one process-wide runtime;
- Tor child-process ownership, a profile-scoped data directory, SOCKS5h proxy
  environment, and optional ControlPort liveness through `stem`;
- VPN provider support, including Mullvad account indirection through
  `<home>/.env` and configurable external commands;
- strict-vs-lenient route bring-up behavior and repeated health checks;
- provider transport classification before client construction;
- conservative handling of unknown transport facts, DNS behavior, IPv6, QUIC,
  UDP, gRPC, and WebSocket limitations; and
- audit events for use, failure, drop, bring-up failure, and incompatibility.

Mordred's `disable_ipv6` option configures its Tor client; it does not disable
host IPv6 or prevent an unwrapped process from opening a socket. A transport
refusal does not tear down a shared route merely to fall back another session
to clearnet. [`POLICY.md`](./POLICY.md) owns the matrices and provider evidence.

### Plugin: `mordred_privacy_check`

The privacy plugin parses `SKILL.md` frontmatter for
`metadata.mordred.network_requirements`, `requires_keyvault`, and advisory
`outbound_endpoints`. Its install decision is authoritative only when the user
goes through `hermes-mordred install`; an ordinary Hermes install command does
not traverse this wrapper.

At runtime it checks plugin integrity, writes the one-shot missing-origin
degradation marker, and blocks the default network-tool set on clearnet under
strict policy. Audit records are bounded and must never contain secrets or raw
untrusted documents.

### Plugin: `mordred_llm_guard`

The LLM plugin registers the synthetic `mordred-local` provider, establishes a
loopback proxy bypass, detects declared/known harness primaries, guards Hermes
auxiliary clients, checks persisted provider state at session start, and
checks the resolved primary request at `pre_api_request`.

Strict enforcement is fail-closed and exception-based. `prompt-once` is
process-local, keyed by normalized provider/route, and available only with an
interactive terminal. A missing TTY denies without caching that denial.

### Plugin: `mordred_keyvault`

The keyvault plugin owns native wrapping-key integration, verification
digests, encrypted secret envelopes, recovery manifests, encrypted audit
writers, Ethereum key envelopes, and the macOS startup/reseal integration for
the at-rest vault. Public calls accept an injected backend for deterministic
testing; production entry points resolve a platform backend centrally.

#### Key hierarchy

Each logical key ID identifies a native non-exportable P-256 wrapping key. A
random 32-byte data-encryption key (DEK) encrypts each secret with AES-256-GCM;
the native public key wraps that DEK through P-256 ECDH, HKDF-SHA-256, and
RFC 3394 AES Key Wrap. Only wrapped keys and ciphertext are persisted.

Logical key IDs and purposes are hashed before use as path components. The
profile-scoped native ID binds the logical identity to the keyvault root so
different Hermes homes cannot accidentally share a same-named native key.

The separate at-rest file vault uses a random master key with two recovery
paths: a device-wrapped master and an Argon2id passphrase-wrapped master. It
lives at `<home>/mordred/vault/`, not inside the keyvault envelope tree.

#### Key generation and verification digest

Let `H` be 32-byte BLAKE3, and let `top4` return the first four PoW bytes:

```text
seed_hash      = H(normalized_seed UTF-8)
pass_hash      = H(normalized_passphrase UTF-8)
masked_pass    = (pass_hash[0:4] XOR top4(pow_bytes)) || pass_hash[4:32]
digest         = H(seed_hash || masked_pass)
```

The expected value is exactly 32 bytes and comparison is timing-safe. Recovery
parses the backup header and verifies this digest before running Argon2id or
decrypting ciphertext. The offline tool shipped in the wheel implements the
same algorithm without importing the live keyvault state.

#### Proof-of-Work (PoW) algorithm (Phase 4 PR10 step-0 freeze, 2026-05-16)

The historical heading is retained because tests and external notes cite it.
The current PoW contract is:

```text
prefix     = b"MRPOW\x01"
preimage   = prefix || normalized_seed UTF-8 || nonce.uint64_little_endian
condition  = BLAKE3(preimage) has at least 20 leading zero bits
result     = the digest for the smallest nonce satisfying condition
```

Only the first four result bytes mask the verification digest. Difficulty,
prefix, byte order, and smallest-nonce rule are part of the compatibility
contract.

#### `keyvault init` flow (Phase 4 PR10)

Initialization is an explicit ceremony:

1. Probe the selected native backend and required crypto dependencies.
2. Generate a BIP39 seed and collect a recovery passphrase without placing
   either secret on a command line.
3. Normalize the inputs, compute PoW and the expected digest, and prepare an
   opaque, expiring seed-display handle without mutating durable state.
4. Display the seed through the protected display flow and direct the user to
   reproduce the digest on an offline device.
5. Require the typed digest to match exactly.
6. Only after confirmation, create the native wrapping key, commit metadata
   and the digest, optionally store the seed for HD derivation, and emit the
   completion event.

Any mismatch emits `keyvault.init_denied` and leaves no committed keyvault.
Interrupted native-key creation is reconciled through the lifecycle journal.

#### Seed phrase display security

The display handle has a 60-second monotonic deadline, redacted
representation, no equality/hash/copy/pickle/state export, one-shot consume,
and an in-place wipeable byte buffer. Display attempts a network blackout and,
on macOS, aborts if screen capture is detected. These controls reduce
accidental disclosure; they cannot defeat a physical camera, privileged
capture, terminal scrollback outside the controlled flow, or memory inspection
by the same user.

#### Protection-tier hierarchy (fallback)

Production backend selection is ordered and platform-specific:

1. macOS installed `mordred-hermes-sekey` helper (Secure Enclave);
2. macOS legacy in-process Security-framework namespace when usable;
3. macOS login-Keychain software P-256 namespace for compatibility when the
   interpreter lacks the entitlement needed to persist an Enclave key;
4. Linux installed `mordred-hermes-tpmkey` helper (TPM 2.0), with no software
   fallback.

Installing a helper does not migrate an existing key between namespaces.
Committed metadata keeps enough backend identity to continue finding an older
key. `enable-se` and `enable-tpm` build/install/probe helpers; they do not
convert current key material.

#### Implementation interface

`NativeBackend` exposes generate, public-key lookup, delete, and ECDH
operations. The public `keyvault.api` exposes two-phase generation, digest
verification, `encrypt`, `decrypt`, `export_backup`, and `import_backup`.
Secret encryption requires a non-empty purpose, and decryption requires the
same logical key ID, envelope ID, and purpose.

Exceptions distinguish structural corruption, missing keys, duplicate keys,
native unavailability, authorization cancellation, and verification mismatch.
Callers must not collapse an authorization denial into a corruption message.

#### Backup wire format versioning (Phase 4 PR2 freeze, 2026-05-14)

`MRKV` v1 is a self-describing passphrase-wrapped blob:

```text
magic(4)="MRKV" | version(1)=1 | kdf_id(1)=Argon2id |
m_cost(4 BE)=47104 KiB | t_cost(4 BE)=1 | p_cost(4 BE)=1 |
salt(16) | verification_digest(32) | aes_blob_len(4 BE) |
nonce(12) | ciphertext(N) | tag(16)
```

The first 66 bytes are AES-GCM AAD. Version 1 accepts only the canonical KDF
profile and rejects malformed lengths and unsafe cost values before KDF work.
A breaking layout or KDF-profile change requires a new version and compatible
reader dispatch.

#### Wrap wire format & algorithm (Phase 4 PR3 freeze, 2026-05-14)

`MRKW` v1 is exactly 127 bytes:

```text
"MRKW"(4) | version(1) | suite(1) | key_id_hash(16) |
ephemeral P-256 public key(65) | AES-KW wrapped DEK(40)
```

Wrapping uses the cached native public key and a fresh software ephemeral
P-256 key, derives a 32-byte KEK with HKDF-SHA-256 bound to the non-secret
header fields, and applies RFC 3394 AES Key Wrap to a 32-byte DEK. It requires
no private-key authorization and emits no successful unwrap event.

Unwrapping invokes native ECDH and emits exactly one of
`keyvault.unwrap_authorized` or `keyvault.unwrap_denied`. AES-KW has no
separate IV field; its fixed integrity value is part of the 40-byte result.

#### PR4 API contract & MREN envelope wire format (Phase 4 PR4 step-0 freeze, 2026-05-15)

The historical heading remains the stable anchor for the public keyvault API
and `MREN` v1. Current behavior is defined by the following subsections.

##### Mordred normalization (split: seed phrase vs passphrase, codex HIGH #1)

Seed phrases use Unicode NFKD, remove Unicode format (`Cf`) characters,
case-fold, split on whitespace, and rejoin with one ASCII space. This matches
the tolerance expected for BIP39 words.

Passphrases use Unicode NFKD only. Case, whitespace, and format characters are
significant entropy and are not trimmed, folded, or removed. The two
normalizers must not be merged.

##### Two-phase generate (codex BLOCKER #2)

`prepare_generate(seed, passphrase, pow_bytes)` computes the digest and
returns `(SeedDisplayHandle, expected_digest)` without disk, backend, or audit
mutation. `confirm_generate(...)` consumes the confirmed state and performs
the native/persistent transaction only after a timing-safe digest match.
`generate(...)` is the composed public convenience entry point and preserves
the same fail-before-mutation guarantee.

The default logical key ID is `default`. A successful result reports the
logical key ID, its hashed storage identity, and the committed UTC timestamp.

##### SeedDisplayHandle (opaque, codex BLOCKER #3)

`SeedDisplayHandle` is intentionally not a dataclass or serializable secret
container. Its observable representation is always redacted. It is unhashable,
rejects equality/copy/deepcopy/pickle/state access, serializes consumption with
a lock, and releases the normalized seed at most once. Expiry wipes before
raising `SeedDisplayExpired`.

The non-secret expected digest remains readable after a successful display so
a slow confirmation does not resurrect or retain the seed.

##### MREN envelope (managed storage, decrypt requires purpose)

`MREN` v1 layout is:

```text
"MREN"(4) | version(1) | key_id_hash(16) | purpose_hash(16) |
wrapped_dek/MRKW(127) | aes_blob_len(4 BE) |
nonce(12) | ciphertext(N) | tag(16)
```

The first 164 bytes are AES-GCM AAD; the fixed header including the length is
168 bytes. The parser verifies magic, version, framing, key hash, and purpose
hash before native unwrap. Envelopes are stored beneath hashed key and purpose
directories; clear purpose strings are not recoverable from their path.

##### export_backup / import_backup (ciphertext-rewrap manifest, codex BLOCKER #1)

`keyvault.api.export_backup()` unwraps each stored DEK through the authorized
native boundary, rewraps the manifest under an `MRKV` recovery blob, returns
the bytes in memory, and emits `keyvault.backup_exported`. It does not choose a
destination path or persist a temporary plaintext/export file.

`keyvault.api.import_backup()` accepts an `MRKV` blob, verifies the embedded
digest before KDF/decryption, provisions a fresh native key in an empty target
keyvault, and reconstructs purpose-bound `MREN` envelopes for that device.
Import refuses overwrite/merge conflicts and rolls back provisional state on
failure.

The CLI exposes export through `keyvault export --output <path>`. It selects
the single initialized logical key, collects the init passphrase and any
required paper Seed Phrase through masked prompts, and delegates MRKV creation
to `keyvault.api.export_backup()`. The wizard publishes a complete mode-`0600`
file atomically without replacement. The parent must already be a real
directory, the final path must not exist, and failures leave no partial final
file. Import remains `keyvault recover --blob <path>` into an empty profile.

##### File-safety semantics (step-B foundation, codex HIGH #4)

Security-sensitive state uses profile-scoped validated roots, mode `0700`
directories, mode `0600` regular files, atomic replacement, directory flushes,
and stable lock files. Reads and writes reject unsafe symlinks and special-file
endpoints. Lifecycle lock ordering prevents reset, import, generation, and
envelope mutation from crossing one another.

The exact persistent inventory and journal names are owned by
[`PATHS.md`](./PATHS.md).

##### Audit emissions for PR4 (4 new reason codes #21-24)

The heading is historical; the complete current enum is in
[`POLICY.md`](./POLICY.md). The four format-era events remain:

- `keyvault.recovery_digest_mismatch`
- `keyvault.seed_display_aborted_screenshot`
- `keyvault.unwrap_authorized`
- `keyvault.unwrap_denied`

Initialization and backup export add their own later stable reasons. An event
contains bounded identifiers only, never seed words, passphrases, raw key IDs,
DEKs, or backup bytes.

##### Capability-probe fail-on-skip (codex HIGH #5)

Live backend tests are allowed to skip only when their entire suite was not
requested. Once `MORDRED_KEYVAULT_LIVE=1` requests the live path, missing
hardware capability, helper installation, or authorization is a failure, not
a green skip. CI cannot provide the device interaction; maintainers record the
manual result as required by [`CI.md`](./CI.md).

#### Agent-memory at-rest encryption (sealed memory file format v1)

No Hermes release encrypts `<home>/memories/*.md`, and the `memory`
encryption target previously only provisioned a key without protecting
anything on disk. This runtime makes that protection real, on the same
precedent as the `.env` write guard and the config `.pth` hook: a defensive
wrapper Mordred installs around a private upstream seam, fail-closed on the
read path.

The sealed memory file format is a two-line text container:

```text
line 0: HERMES-MEMORY-ENC-v1
line 1: base64url(nonce[12] || AES-256-GCM(plaintext, aad))
```

The key is `HERMES_MEMORY_KEY`: URL-safe base64 of exactly 32 bytes, with an
optional `base64:` or `hex:` prefix. AAD binds each ciphertext to its file's
basename (`hermes-memory-v1:<file basename>`) so `MEMORY.md` and `USER.md`
ciphertexts cannot be swapped for each other. The format is text-safe on
purpose — an upstream `read_text()` of a sealed file yields a recognisable
magic line instead of a `UnicodeDecodeError`. Every write uses a fresh nonce,
and the plaintext is always the whole file body: Mordred encrypts bytes and
leaves entry parsing to Hermes.

Arming is evaluated per call, from a marker file and the current key, never
cached:

| marker | key | behavior |
|---|---|---|
| absent | any | not armed — plaintext as today |
| present | valid | armed — writes seal; reads unseal sealed files and pass plaintext files through (migration on write) |
| present | missing or invalid | armed, fails closed for memory I/O — every write refuses, and reading a *sealed* file refuses; plaintext files still read |
| present | valid, but ciphertext fails to authenticate | refuses loudly — the read raises, so the affected load or mutation aborts and nothing is overwritten |

`HERMES_SAFE_MODE` disarms the hook outright. An undecryptable sealed file
always refuses loudly rather than reporting an empty memory. The hook never
blocks interpreter start-up; when sealed files exist and the key is missing,
the first memory load fails with the remedy in the message (so agent start-up
stops there) instead of presenting an empty memory, and every memory write
refuses — Mordred never silently writes plaintext while armed.

Seam coverage depends on which shape of the upstream memory tool is
installed. Mordred wraps three call sites per seam shape shipped by
hermes-agent 0.13–0.15, 0.16–0.19, and current main: the read chokepoint, the
write chokepoint, and the drift-backup write. An unrecognised seam is
unsupported: when armed, the process refuses to start (`sys.stderr` plus exit
1, recoverable with `HERMES_SAFE_MODE=1`); when not armed, nothing is wrapped
and memory stays plaintext.

Known out-of-band paths are documented limitations, not silent gaps: `hermes
agent-import` is best-effort patched; raw readers (`hermes doctor` size
reporting, the Desktop learning graph, the Honcho migration upload) see
sealed text and degrade gracefully rather than leak plaintext; an
out-of-process writer produces plaintext that is sealed on its next write and
shown as `exposed` in the meantime; and `memory.write_approval` pending JSON
stays plaintext (`encryption enable memory` warns about it).

`encryption enable memory` requires the runtime probe to pass and the env
target to already be enrolled and not opted out — the key rides on the env
shim. It performs one Touch ID authorization through `set_memory_key`, writes
the marker, eagerly migrates existing plaintext files to sealed, and warns
when a running gateway needs a restart to pick up the change. `encryption
disable memory` decrypts every sealed file back to plaintext, removes the
marker and sets the opt-out marker (paused by operator), and keeps the key.
`encryption purge memory` disables and then strips the key. `encryption
status` reports `on`, `paused`, `off`, or `exposed`. `setup` runs a
`memory-encryption` step right after `env-encryption`: it runs without a
dedicated prompt, exactly like the env step (the opt-out marker is how an
operator declines), resolves `manual` under `--non-interactive`, and honours
the operator opt-out.

The capability probe `runtime_memory_encryption_available` joins the env and
config probes in the same family and appears in `encryption status`'s gateway
lines. A CI canary test runs the round trip against the installed upstream
memory tool so an upstream refactor of the seam trips a red build rather than
a silent regression.

#### Explicitly out of v1

- exporting private native wrapping keys;
- silently downgrading Linux TPM protection to a software key;
- automatic migration of an existing key when `enable-se` or `enable-tpm`
  installs a helper;
- unattended claims for keys created with attended authorization policy;
- same-UID tamper-proof storage; and
- cross-purpose decryption or recovery into a non-empty keyvault.

### Plugin: `mordred_wizard` (CLI Extension)

The standalone CLI exposes these top-level commands:

```text
status
setup
configure
upgrade
install
network     use | status | init
policy      show | explain | dry-run | reload
audit       tail | grep | decrypt | purge
keyvault    init | list | verify-digest | export | recover | reset |
            enable-se | enable-tpm | enable-winkey | native | eth
vault       init | change-passphrase | recover | add | status | cat |
            migrate | set-memory-key | enable-config-decrypt |
            disable-config-decrypt
encryption  status | enable | disable | purge | change-passphrase
plugins     list | migrate
extension   pair | serve
desktop     install | uninstall | status
egress      status | set | block | unblock | block-tool | unblock-tool |
            taint
telegram    setup | doctor | login | sync | status | logout | venice |
            local-llm | migrate-tee
uninstall
```

`status`, `policy show`, keyvault listing, vault status, and encryption status
are non-mutating. `configure`, `keyvault init/reset`, `network init`, vault
mutations, encryption toggles, audit purge, pairing, serving, and `uninstall`
(restores plaintext, edits `config.yaml` / `.env`, removes the package; `--dry-run`
is non-mutating) can touch real profile or external state; tests and local experiments must isolate
`HERMES_HOME` as described in [`setup.md`](./setup.md).

The wizard is the sole writer of the canonical Mordred policy transaction and
preserves unrelated Hermes configuration. It never accepts the Mullvad account,
seed phrase, or recovery passphrase as a normal command-line flag.

`setup` is a re-runnable first-run orchestrator. It probes upstream Hermes,
configuration, the selected network route, the platform helper, keyvault, and
macOS env and agent-memory encryption, then runs only incomplete steps and
prints status. It never resets or overwrites a blocked/corrupt keyvault.
Non-interactive mode runs only the automatable subset and reports the
interactive commands still needed.

## Operational Guarantees & Caveats

### Audit log policy

Audit entries are bounded records with `ts`, `event`, `decision`, and
`reason`. Current decisions include `allow`, `block`, `override`, `warn`,
`raise`, and `fallback`. `reason` is one of the 31 stable values in
[`POLICY.md`](./POLICY.md), or `null` where no policy reason applies.

The active log rotates daily or at 10 MiB, retains dated files for 30 days,
and serializes cooperating writers through a stable sidecar lock. Plaintext
NDJSON is the baseline before a keyvault audit key exists. When encrypted
logging was expected but cannot be constructed, the factory falls back to
plaintext and emits `mordred.degraded.audit_encryption_unavailable` when it can
do so safely.

Native Windows has no such catch-all fallback: its factory selects the
encrypted, explicitly degraded plaintext or refused outcome from the
independent audit custody role, as defined in
[Windows privacy audit writer routing (C7b)](#windows-privacy-audit-writer-routing-c7b).

Encryption protects record confidentiality and per-entry integrity at rest.
It does not make the log append-only or prevent a same-UID process from
deleting, truncating, or replacing history.

#### Encrypted audit-log wire format (`MRAL` v1, Phase 4 PR6 freeze)

`MRAL` is line-oriented:

```text
line 0: {"fmt":"MRAL","ver":1,"key_id":...,"wdek":...}
line N: base64(nonce(12) || AES-GCM-ciphertext || tag(16))
```

`wdek` is a base64 `MRKW` blob. The in-memory 32-byte log DEK is wiped when the
writer closes. Every entry is encrypted independently and bound by AAD to its
file header. Cooperating append/rotate/rollback operations share the audit lock
and detect inode/header ownership changes before reusing a cached DEK.

Historical plaintext logs are not rewritten in place. The audit CLI can tail,
search, decrypt dated encrypted files, and purge confirmed old rotations.

### Plugin-disable protection (plugin-side only, zero-PR strategy)

The required sibling set is a fixed six-entry constant, not dynamically
expanded from manifests. Strict startup aborts when any sibling is recorded as
disabled. Lenient/off operation may continue with a degradation record.

The packaged interpreter-startup integrity guard provides an earlier
defense-in-depth check for normal Hermes console starts, but it remains local
code under the same user account. Neither layer prevents an operator or
same-UID attacker from uninstalling the package or launching a different
interpreter.

### Policy file caching

Readers cache a validated policy snapshot within a process. `policy reload`
clears that in-process cache; there is no filesystem watcher. The wizard uses a
lock and pending marker across `config.yaml` plus `policy.json`, and readers
that observe an incomplete transaction fail closed instead of combining two
generations.

### Plugin Versioning & Compatibility

The `mordred` plugin and all its components ship in the `hermes-mordred`
distribution and share one version.
The package version in `src/mordred_hermes/__about__.py` is the release source
of truth and is updated through `tools/bump_version.py`. The minimum supported
Hermes version is declared in `pyproject.toml`; CI checks both the floor and a
current release. Private upstream seams used by compatibility guards must be
validated in tests and cause an explicit refusal or diagnostic on drift.

Persistent `MRKV`, `MRKW`, `MREN`, and `MRAL` layouts require versioned readers.
Stable audit reason strings and documented policy fields are compatibility
surfaces and are not renamed casually.

### Observability

Operators use `hermes-mordred status`, focused `network`/`policy`/`keyvault`/
`vault`/`encryption` status commands, and the audit CLI. Status output must
distinguish configured, initialized, protected, exposed, paused/inactive, and
unavailable states instead of reducing them to one boolean.

Sensitive values are redacted. JSON output is available where documented for
automation, while destructive or secret-bearing ceremonies remain explicit
and interactive unless a narrowly scoped confirmation flag exists.

## Scope (Out) — explicitly deferred

- modifying or submitting pull requests to Hermes upstream;
- a general sandbox for arbitrary Python, shell, or direct socket activity;
- automatic rerouting of a resolved cloud LLM request to a local provider;
- trusted per-skill runtime provenance without a new host seam;
- hard prevention of plugin disable/uninstall by the local user;
- mobile product support (Windows completion is tracked below);
- transparent env/config/workspace lifecycle outside macOS (the Windows
  memory lifecycle is required by the completion contract below);
- audit hash chains, external anchoring, or same-UID tamper resistance;
- isolated signer/payment authorization;
- automatic migration of native-key protection tiers.

Future candidates and their release gates live in
[`ROADMAP.md`](./ROADMAP.md); actionable unfinished work lives in
[`TODO.md`](./TODO.md).

## Windows product completion contract

This section defines the remaining native Windows work after the helper,
private-filesystem and wallet slices (PRs #189–#194). It supplements their
contracts; it does not turn their successful checks into product acceptance.
The port retains the Linux-equivalent scope of the Windows native support
proposal: Windows memory and Private Telegram custody are required; new
macOS-equivalent env/config/workspace seals, Windows Hello, per-use presence,
ARM64 and TPM-key recovery remain excluded. Completing every component means
completing that native port, not silently broadening those security promises.
The initial target is Windows 11 x64 with local NTFS and an ordinary user.
Windows Server 2025 is a development and hardware-validation environment.
Virtual machines are acceptable: record the OS, architecture, token and TPM
provider, and qualify evidence from a virtual TPM accordingly. A physical PC
is not an acceptance prerequisite. Server or hosted-CI results do not establish
Windows 11 compatibility.

### Shared storage and coordination

- Preserve the checked filesystem boundary: no reparse traversal, hard-linked
  sensitive files, ACL repair on reads, unbounded reads or implicit adoption of
  unsafe existing state. Preserve classified failures and uncertain commit
  outcomes through every caller. Only a checked, pre-mutation missing result
  can select a fresh-state path. Permission errors are not absence.
- Add checked metadata, bounded enumeration, prefix reads, deletion, append
  and no-replace sibling rename before migrating consumers that need them.
  Files remain bound to validated identities throughout mutations. A delete
  removes a namespace entry, not the underlying media securely. Mutations
  cannot promise power-loss atomicity; post-mutation cleanup errors remain
  uncertain and must not cause automatic retry, rollback or key recreation.
- Append holds the stable directory transaction across size capture, write,
  flush and any rollback. A failed rollback is uncertain. Rotation publishes
  without replacing existing history; compression retains the raw source
  until its replacement is verified. Retention deletes only validated files.
- Keep the permanent directory lock while the directory is a live shared
  namespace. Recursive deletion requires an outer lifecycle lock and checked
  traversal; never delete a live lock to make a busy operation succeed.
- Existing Hermes home directories are shared upstream state. Define a
  separate trusted-parent boundary for canonical config and dotenv files;
  do not silently relax the private-directory contract or rewrite the home's
  ACL. New sensitive files receive a private ACL before content is written.
  Existing unsafe files require an explicit migration with verified recovery.
- Canonical policy writes serialize the complete config/policy pair, including
  nested writer calls. Use one caller coordinator and documented lock order;
  do not recursively acquire the non-reentrant foundation lock. Retain a
  pending marker after interrupted or uncertain publication. Readers reject
  pending/unsafe state, including cache hits. Windows caches must revalidate
  security metadata or remain disabled.

### Component acceptance boundaries

| Component | Required Windows behavior |
| --- | --- |
| keyvault | CNG-backed memory and Private Telegram custody, checked state/markers/plaintext capture, generation leases, reset/export, runtime probes, retained encrypted audit keys and truthful file-vault capability gates |
| wizard | Native installer, actual Hermes interpreter discovery, helper installation/probe, configure/setup/status, lifecycle commands, upgrade and uninstall with verified backups |
| network | Native executable discovery and safe process lifecycle, Tor private state and quoted paths, explicit VPN capabilities, enforced no-clearnet fallback in strict mode |
| llm_guard | Checked policy/config reads and fail-closed pending-state checks on every decision, including previously cached provider decisions |
| privacy_check | Checked plaintext/encrypted audit publication, process serialization, rotation/compression/retention and recoverable failures |
| extension | Pairing, attestation, replay and revocation serialization; encrypted history and Telegram custody; process-safe archive lifecycle; gateway shutdown and runtime discovery |
| Desktop integration | Native installation/removal, truthful Windows capability/status output, CNG-backed memory flow, local-model checks and restart behavior |

These are separate implementation PR boundaries, not permission to combine
plugins in one PR. Shared contracts land in documentation first; shared
primitives get their own implementation PR. Dependencies may be stacked, but
each PR identifies the incremental component changes and targets `dev`.

Do not infer CNG key absence from an inaccessible keyset, regenerate keys after
unwrap failure, or claim that a vTPM provides biometric/per-operation presence.
Windows reset journals preserve ambiguous native deletion outcomes. Enabling
memory encryption must prove that the actual installed Hermes runtime consumes
it before removing any plaintext. Unknown process discovery is not an empty
process list. File-vault recovery and excluded env/config seals remain explicitly
unavailable on Windows and must refuse before changing retained state; safe
unsupported refusal satisfies the gate for these excluded capabilities only.

APFS workspace images and Secure Enclave/Touch ID remain explicitly
macOS-specific. A Windows setup may skip that optional target with a concrete
explanation; it may not skip every encryption target or report an ordinary
directory as an encrypted workspace. External route/account/model dependencies
are reported per capability, not hidden behind a general Windows-ready flag.

### Product completion evidence

Acceptance requires a wheel built from the sdist, installed outside the source
tree through the native installer, with a disposable `HERMES_HOME`. Record the
actual Python/module/helper paths. Exercise install, registration with Hermes,
configure, setup, status, gateway/extension use, memory sealing and reopening,
applicable export, excluded recovery refusal, upgrade, uninstall and reinstall.
Include separate users,
concurrent processes, spaces/non-ASCII paths, restart, reboot, unavailable TPM,
corruption and unsafe filesystem objects. Verify no plaintext fallback or lost
retained ciphertext on failures. Real network routes and externally authenticated
flows need their own explicit acceptance evidence; synthetic fixtures are
regression tests, not substitutes for those claims.

Publish a matrix distinguishing implemented, unit-tested, native-server-tested,
Windows-11-tested and externally unverified. Until the applicable Windows 11
installation-to-use and security gates pass, Windows product support remains
incomplete even if every component PR has been created.

### Canonical Windows configuration boundary

`open_confidential_directory(path, create=False)` is a separate internal
capability for shared Hermes home files and installer-owned profile executables.
It does not relax `open_private_directory`: Mordred state directories and their
files keep the exact private DACL requirement. The confidential capability
pins every local NTFS ancestor and validates the endpoint as a trusted parent,
including refusal of untrusted add-file/add-directory/delete-child, ownership,
ACL or reparse-relevant mutation rights. Directory read/traverse rights alone
are acceptable. Existing parent descriptors are never repaired.

An existing confidential file must be regular, non-reparse, single-linked and
owned by the current token user. Its DACL may be inherited, but every effective
allow must grant only the current user, SYSTEM or Administrators. Recognize
only supported ordinary allow/deny ACEs, inheritance flags and permission bits;
unknown descriptors fail closed. Denies do not excuse unsafe allows. Safe
duplicate or restricted grants are acceptable; a null DACL is not. Actual access
failure remains a failure. New/staged/backup/lock files always receive the exact
private DACL before content. Replacing a validated inherited-safe file creates
a private replacement; a no-op preserves its bytes and descriptor. Broad or
foreign-owned existing files cannot be adopted by silently replacing them.

The capability exposes checked `stat`, bounded `read_bytes`, and transactions
with `stat`, `read_bytes`, `create_bytes`, `replace_bytes` and identity-bound
`delete_file`. Missing final-leaf observations must be distinguished from
missing/uncheckable ancestors and cleanup uncertainty. Creation is limited to
the checked missing final directory. No generic public `strict=False` switch,
raw fallback or second installer-specific ACL validator is permitted.

Canonical Windows configuration sessions acquire the home transaction before
the private `home/mordred` transaction. Nested same-home calls reuse live
capabilities bound to process, thread and directory identity; nested different
homes refuse. Policy scope can extend an existing home scope in that order and
retains both until outer exit. Never call a home operation while holding only a
lower-level Mordred lock. Runtime readers take the same locks nonblocking and
fail closed on contention. A decision reading both config and policy uses one
checked snapshot; separate before/after marker checks cannot exclude a complete
intervening write. Windows decision caches must not bypass this boundary.

Policy updates stage complete intended changes before an explicit commit.
Parse and validate existing documents first; neither unreadable nor malformed
state becomes an empty config. Publish/verify the pending marker before either
member, publish the changed members, then read and verify the complete intended
pair. Only that verification permits identity-bound marker deletion. An
interrupted or uncertain pair publication retains the marker. Failure during
or after final marker deletion is uncertain and requires reconciliation; it
may leave an already verified consistent pair marker-free. Do not promise to
recreate an already deleted marker, automatically retry, or provide two-file
power-loss atomicity. Full configure may explicitly reconcile a stale safe
marker; generic readers, dotenv operations and uninstall cannot clear it.
Reading through a pending marker requires the active owning canonical session
for full recovery; a public boolean bypass is insufficient. Ordinary snapshots
fail closed on marker presence or inability to validate it.

Canonical config, policy and dotenv reads are initially bounded to 8 MiB each;
marker diagnostics to 4 KiB. Checked absence alone selects fresh-install state.
Config-only edits and deletion use the pair protocol, even when policy remains
unchanged. Dotenv RMW uses home scope. Cleanup first creates and verifies a
private no-replace backup under the same locks. Existing POSIX lock/adoption
behavior remains unchanged; Windows legacy mode-based writers must all be
stopped during migration. Unsafe upstream-created Windows defaults remain
unchanged/refused and require a separately reviewed explicit migration.

Bounded in-process wait (ruling R-C2b-1). A `blocking=False` canonical
session waits only for the process-wide in-process guard: when another thread
of the same process holds an outermost canonical session, the reader waits at
most `IN_PROCESS_WAIT_SECONDS` (2.0 s, a documented `_config_io` module
constant, applied as one timed acquire with no spinning) and then refuses with
the same `busy` / `canonical_lock` error. That holder is one of Mordred's own
short sessions, so two gateway threads reading policy at the same moment no
longer refuse each other. The cross-process home and Mordred file locks stay
strictly nonblocking for `blocking=False` and refuse `busy` immediately;
nested sessions on the same thread reuse live capabilities without waiting;
`blocking=True` sessions still wait without bound. Long-held in-process
writers (the wizard memory lifecycle) require stopped gateways, so they do not
coexist with gateway readers; the accepted cost is that a nonblocking reader
meeting a slow in-process writer can take up to the bound before refusing.
Where this specification says runtime readers or capability predicates take
locks nonblocking, fail closed on contention or never wait for a lock, read it
as never waiting for a cross-process lock and waiting at most this bound for an
in-process holder; contention outlasting the bound still fails closed.

### Windows network checked decisions (C8)

Every Windows network decision reads one checked canonical generation of the
config/policy pair: registration and pre-client activation, the session-start
wrapper and gate, `pre_api_request`, `pre_tool_call`, the activation-config
comparison and the strict default-path reader. A decision never combines
values from two reads and never reuses an earlier generation. Unsafe, pending,
contended, unreadable, malformed or mistyped consumed state refuses in every
mode with the existing non-catchable route refusal; no clearnet fallback is
derived from a refused read. Only checked absence yields `off` / `clearnet`.
Refusals expose no document bytes or parser diagnostics. Handles and locks are
closed before route activation, Tor/VPN process calls or network calls. POSIX
readers are unchanged. The detailed contract is in POLICY.md §Native Windows
network policy decisions; native Tor/VPN routes remain C9. A null
`model.provider` is unset for the network gate (it only selects the provider
that refuse-only gate evaluates) but refused by the LLM reader, which validates
the main model route it authorizes.

### Windows extension checked state (C10a)

On Windows, `<home>/extension/` is an exact-private `_private_fs` directory.
`pending.json`, `state.json`, `attest_key.pem`, `webauthn.json` and
`history.enc` are read and written only inside its checked transaction on the
permanent `.mordred-fs.lock`, the lock the wallet selection already uses in
that directory; `.lock` is not created. Reads are bounded (pending 1 MiB,
state 8 MiB, WebAuthn 64 KiB, attestation key 16 KiB, history 64 MiB) and bound
to the checked identity observed before and after the read. Writes refuse an
oversized document before touching storage, create a checked absence without
replacement and replace only the identity the operation observed; new files
are private before content. Deletes are identity-bound. One-use codes, replay
identities, revocation and pairing commits keep their POSIX read-modify-write
order under that one transaction; nested same-thread calls reuse it because
the foundation lock is not reentrant.

Only a checked missing directory or file is absence. Reads never create the
directory or state files; an admitted directory without `.mordred-fs.lock`
receives the private lock file. Unsafe, inaccessible, oversized, hard-linked, reparse or
otherwise unadmitted state refuses with a content-free `ExtensionStorageError`
(`storage_unavailable`), without chmod, ACL repair or adoption. A refusal or
cleanup failure after any mutation in the same operation, or an uncertain
primitive outcome, is `ExtensionStorageUncertain` (`storage_uncertain`) and is
never retried. Corrupt or truncated JSON keeps the POSIX `RuntimeError` refusal
and is never reset. `pair_init` answers `pair_fail` with the storage code;
authentication, the auth challenge (with fail-closed `webauthn_required`) and
other requests surface the code instead of empty state. Unpair, WebAuthn
removal and history clear refuse instead of silently leaving state. Only the
records POSIX already tolerates (the pairing outcome annotation and stale
WebAuthn removal after a committed re-pair) are logged rather than raised.

The attestation key is created once, exclusively, under the lock. A checked
absence while `state.json` holds an active pairing refuses instead of minting a
new identity, with the dedicated reason `attestation_key_missing` reported by
`pair_fail` and `pair_outcome`. Recovery is explicit: remove the pairing, then
pair again; the new pairing presents a new attestation identity that the
extension must trust anew. No operator unpair command exists yet; until one
does, call `mordred_hermes.extension.pairing.clear_pairing()` from the Hermes
environment's Python with the same `HERMES_HOME`. The `state.json` parse cache keys on directory and file identity,
size and mtime and performs a checked stat for every read, so security drift
refuses and a replaced identity is re-parsed. The extension wallet snapshot
fingerprint is a checked stat under the same lock; wallet persistence remains
the keyvault's checked storage. History keeps its pairing-key envelope and
`undecryptable` status, while storage refusals reach the chat/history caller.
POSIX behavior is unchanged. Telegram custody/archive (C10b), gateway/Desktop
lifecycle (C11), native validation and Windows 11 acceptance remain open.

### Windows network routes and VPN capability (C9)

Product limitation (controller ruling for this slice): Tor is the only
supported private route on native Windows. `vpn_providers.provider_capability`
returns an explicit `(supported, available, reason)` per provider and never
starts a process. `mullvad` and `wireguard` are `supported=False` with reason
`not-ported-on-windows`, because their tunnel services need administrative
installation and a separately validated route; every Mullvad and WireGuard
entry point refuses with that reason before any subprocess, and their health
probes report unhealthy. `custom` is supported only when every configured up,
down and health executable resolves to a validated `.exe` (see below). A
strict VPN default path on Windows therefore refuses bring-up with the
classified reason (a validated custom route still fails the existing strict
kill-switch gate) and never falls back to clearnet; lenient/off log a warning
and record the existing audited clearnet fallback. The cost: Windows users who
need Mullvad or WireGuard cannot route through them with Mordred until a later
slice ports and validates those routes natively. Until then they must use Tor,
or a custom VPN command under lenient/off without Mordred's kill-switch
guarantee.

Executables. `tor_binary` and each `custom_*_cmd` executable are resolved to
one absolute `.exe`; `.cmd`, `.bat`, `.com`, scripts and extensionless absolute
paths are refused. A path with a directory must be absolute with a drive;
relative, drive-relative, UNC and device-namespace paths are refused. A bare
name gains `.exe` and is looked up only in absolute, non-UNC `PATH` entries;
the current directory, relative `PATH` entries and the App Paths registry are
never consulted. The resolved image is admitted as `managed` by
`inspect_managed_installation_image`, or as `user-private` when it is owned by
the current user inside a checked confidential or private directory; anything
else is `untrusted`. Strict refuses an untrusted image before any state or
process is touched; lenient/off warn and continue. No ACL is repaired.
Processes start from an argument list with the resolved image as the explicit
executable, never through a shell; a lock test rejects `shell=True` and string
commands anywhere in the network package. Refusals name only a sanitized
basename.

Tor private state. `<home>/mordred/tor-data` is opened through the checked
private-directory contract: created with the private ACL before any content,
and an existing unsafe directory, reparse point or unsafe member refuses
bring-up without repair. Under its exclusive transaction (taken without
waiting), Mordred publishes `torrc` and an empty pinned `torrc-defaults`
through checked no-replace staging and rename, then records the launched
daemon in `daemon.json` (at most 4 KiB, strict schema: Tor PID, creation time,
image and user, the launching process PID and creation time, and the torrc
path). Tor starts as `tor.exe -f <torrc> --defaults-torrc <defaults>`, so
neither stdin nor a per-user default torrc configures it. The rendered torrc
binds SOCKS and control ports to `127.0.0.1` only, quotes the DataDirectory as
a Tor C string (control characters refused) and adds
`__OwningControllerProcess <launching pid>`. Tor creates its control cookie
with its token's default DACL; before authentication Mordred reads it through
the checked bounded reader (trusted owner, no untrusted mutation grant, no
reparse point, exactly 32 bytes) and treats an unsafe cookie as unhealthy.

Process lifecycle. Tor starts with `CREATE_NO_WINDOW`, stdin from `NUL` and the
image directory as working directory, and is assigned to a kill-on-close job
object (standard library `ctypes`) whose membership is verified before its
identity is recorded; when the launching process exits for any reason the
kernel ends the job's members. Teardown revalidates the recorded PID and
creation time through psutil, terminates through the creation handle, closes
the job (exact membership) and forgets only its own record; nothing is ever
selected by image name. Startup cleanup forgets a record whose process is gone
or whose PID now has another creation time; terminates a recorded Tor only
after its live PID, creation time, image and user match the record and its
recorded launching process is gone; and refuses as uncertain on malformed
state, an identity mismatch, a live launching process, denied inspection or a
failed termination. A current-user process whose command line names this
profile's torrc but is not recorded is refused, never stopped and never
reused. Residuals: a crash between process creation and job assignment leaves
an unrecorded Tor that Tor's own owning-controller poll ends; until then the
command-line inventory refuses it, and Tor's DataDirectory lock refuses a
second daemon on the same state. An elevated same-user process can hide its
command line from that inventory; the DataDirectory lock remains the backstop.
psutil's own creation-time check immediately precedes a stale termination,
leaving only that call's PID-reuse interval.

Liveness and proxies. The liveness worker keeps the existing strict contract:
a dropped Tor latches the route, the next strict tool or provider request
raises the existing non-catchable refusal, and nothing switches the process
to clearnet. The bootstrap reader bounds each line to 8,192 characters and
buffered lines to 1,024 on every platform; exceeding either is a classified
bring-up failure while the pump keeps draining the pipe. The proxy environment
is written to the current process environment only, with the same variables
as POSIX; the network package never writes the registry, WinINET, WinHTTP or
system proxy settings (lock-tested). Child-process counting uses psutil
instead of `pgrep`. POSIX behavior and the wizard presentation are unchanged;
wizard capability presentation is C6, and real route evidence and Windows 11
acceptance remain separate gates.

Executable admission scope (controller ruling R-C9-2). The `untrusted` class
means an image in a directory that other principals can change, for example
`C:\tools` created under `C:\` (which inherits the Authenticated Users modify
grant), `C:\Users\Public`, or a directory with an Everyone grant. Images
under default per-user ACL directories such as `%TEMP%` or `Downloads` are
user-private and are admitted in strict mode, because the threat model is
other principals. The cost: strict mode does not stop a Tor or custom VPN
image that the current user, or code running as that user, placed in its own
temporary or download directory.

Control cookie residual (controller ruling R-C9-3). The checked cookie read
proves integrity, not confidentiality. It refuses an untrusted owner, an
untrusted mutation grant, a reparse point, a changed file and a wrong size,
but it does not refuse read grants on the cookie itself. Confidentiality rests
on the private `tor-data` directory ACL. Other principals cannot list, create
or replace its members. Because the private ACL has no inheritable entries,
the cookie that Tor creates there receives the Tor token's default DACL, which
grants no other user. No further check is made. Windows bypass-traverse
checking lets a principal open a file by its full path through a directory it
cannot list, so a read grant that the owner or an administrator later adds to
the cookie itself would expose it, and Mordred would not detect that.

Cookie path pinning. stem's `Controller.authenticate()` re-reads the cookie
with a raw `open()`. It uses the `COOKIEFILE` path that Tor reports in
PROTOCOLINFO, and it does so after Mordred's checked precheck has read the
private path. On native Windows the deep liveness probe therefore requests
PROTOCOLINFO itself. The reported path must equal
`<home>/mordred/tor-data/control_auth_cookie`, compared case-insensitively
after Windows path normalization. The probe passes that same response to
`authenticate(protocolinfo_response=...)`, so stem sends no second
PROTOCOLINFO and opens only the checked private cookie. A missing reported
path makes the probe unhealthy with the classified reason
`control-cookie-path-unreported`; a different one gives
`control-cookie-path-outside-tor-data`. The reason is logged as a warning, and
the reported path is never echoed. In strict mode the existing liveness
threshold then drops the route without any clearnet fallback. One residual
remains: stem's raw `open()` of the pinned path follows reparse points and is
not the checked read. A member swapped between the precheck and
authentication would therefore be read, but only principals that can change
the private directory (the current user, SYSTEM and Administrators) can swap
it. POSIX keeps stem's own discovery unchanged.

Nested jobs. The kill-on-close job relies on nested job objects (Windows 8 and
Windows Server 2012 or later). The launching process may already run inside a
job, for example under a terminal, a task scheduler, a service host or a CI
runner. Tor's assignment to Mordred's empty job then succeeds only because
Windows nests the new job under the inherited one. On a system without nested
jobs that assignment fails: the child is terminated and bring-up refuses with
the classified job failure, so Tor never runs outside the job. Windows 10,
Windows 11 and Windows Server 2016 or later all provide nested jobs.

Daemon state refusals. A malformed or oversized `daemon.json` refusal names
the file and the private `mordred/tor-data` directory. It never echoes the
full path or the contents. It tells the operator to confirm that no Tor from
this profile is still running, then remove that file. If a Tor does survive,
the command-line inventory and Tor's DataDirectory lock still refuse it at
the next start. The inventory refusal says "an unrecorded process", because it
matches any current-user process whose command line names this profile's
torrc, not only Tor images (TODO.md records that gap).

## MVP Phasing

The original phase headings and pull-request notes have been removed from the
current specification. All six entry points, the policy/network/LLM layers,
keyvault formats, CLI, at-rest vault, and extension surface described above are
shipped behavior. A feature is current only when implementation, tests, and
the canonical documents agree; a roadmap item is not part of the MVP merely
because code scaffolding exists.

## Operational Setup (one-time)

Use [`setup.md`](./setup.md) for the development environment and
[`../user/QUICKSTART.md`](../user/QUICKSTART.md) for operator setup. Always run
repository commands through `uv run` or `.venv/bin/...`, and isolate
`HERMES_HOME` before testing a mutating ceremony. On macOS, build/probe the
Secure Enclave helper before relying on that protection tier; on Linux,
build/probe the TPM helper before keyvault initialization. Reserve extension
port 7788 for the production gateway and use another port for local tests.

Operators should start with `hermes-mordred setup`; developers should follow
[`setup.md`](./setup.md). Before a release, run the automated quality gates in
[`CI.md`](./CI.md) and record the applicable manual live-device validations.
Do not substitute version strings for checking which environment/import path
is actually under test.

## Linux Private Telegram Design

Status: dedicated-key implementation completed on 2026-10-07; acceptance results
are recorded below and in the validation log.
Implementation and EC2 acceptance are recorded in PLAN.md and CI.md; live-account
acceptance remains separate from synthetic hardware validation.

### Intent and success criteria

Enable Mordred's read-only private Telegram integration on Linux, including
headless EC2 and Hermes Desktop. Preserve encrypted credentials, encrypted
archives, mandatory encrypted agent memory, read-only MTProto, and Venice/local
model restrictions. Validate on EC2 throughout implementation, including a
packaged Desktop check. The user requested planning before implementation.

Success requires the actual Linux Hermes interpreter to read and write sealed
memory across process restarts, the Telegram setup to complete with a usable
TPM, and failures to refuse without exposing plaintext or losing keys. A
mocked platform check or successful helper compilation is insufficient.

### Current evidence

The following describes the unchanged pre-feature baseline `f3211c6fb`; the
implementation now supplies the dedicated provider, lifecycle, and Linux UI
described below. See CI.md for feature acceptance and the pending live-account gate.

- `extension/telegram/tee.py:hardware_backend` already selects the Linux TPM
  helper and excludes software and legacy fallbacks.
- `_memory_hook.py` wraps the memory tool independently of the OS, but obtains
  its key exclusively from `HERMES_MEMORY_KEY`.
- `wizard/memory_cli.py` requires the macOS `.env` vault injection path;
  `wizard/encryption_cli.py:memory_status` explicitly requires Darwin.
- `keyvault/_identity.py:resolve_store` uses the Keychain anchor store. The
  file vault has no production Linux freshness anchor. Enabling the existing
  `.env` path on Linux would therefore be incomplete and unsafe.
- `wizard/_runtime_gate.py` skips checks outside macOS. The memory runtime
  probe currently proves only that the upstream memory seam is compatible.
- Desktop rejects non-macOS setup; the CLI setup and diagnostic text assume
  Secure Enclave, Touch ID, Xcode, and a Mac-local model.
- The previous EC2 validation covered Linux API behavior and packaged Desktop,
  but explicitly excluded hardware keys and live Telegram login.
- The current baseline's Ubuntu CI TPM job passed 64 native tests against
  swtpm with the live-test gate enabled. A separately requested EC2 baseline
  run then passed the same 64 native tests on actual NitroTPM, 172 focused
  Python tests, production wrap/unwrap and Telegram credential-store round
  trips, cross-instance key-blob rejection, and stop/start persistence.
  See [the validation log](CI.md#manual-live-device-validation-log).
  This established the existing custody path before the Linux memory and
  Telegram integration work.

### Options and recommendation

1. **Recommended: a dedicated TPM-wrapped Linux memory key.** Reuse the existing
   hardware backend, wrap format, memory cipher, and memory hook. The Linux
   memory lifecycle does not enroll `.env` or open the file vault. This delivers
   private Telegram without redesigning the vault's freshness guarantees.
2. **Port the complete file vault to Linux first.** Add a genuine device-bound
   freshness anchor, recovery, runtime `.env` injection, and lifecycle support.
   This offers broader feature parity but requires a separate security design
   and substantially more work. A disk file pretending to be a Keychain anchor
   is not an acceptable implementation.

This proposal selects option 1. Existing macOS key custody and wire formats
remain compatible. General Linux `.env`/config/workspace encryption and vault
recovery are outside this feature.

### Security and persistence contract

- Python 3.11 remains the minimum; no Hermes upstream changes or PRs.
- Linux requires a working TPM 2.0 helper; no software-key fallback.
- TPM protection is machine-bound, without a per-use Touch ID/PIN guarantee.
  UI, CLI, and documentation must describe that distinction explicitly.
- Memory remains AES-256-GCM in the existing `memory_crypto` format.
- A new 32-byte memory key is wrapped with `wrap.wrap_dek`; its existing
  127-byte format is stored at `<home>/mordred/memory-key.wrapped`, mode `0600`.
  The parent is private (`0700`); explicit provisioning tightens an existing
  safe non-private parent to this mode. Reject symlinks and non-regular files.
- The logical wrapping key ID is `mordred-hermes.memory.v1.` followed by the
  first 16 hex characters of SHA-256 over the canonical absolute Hermes home.
  Native storage uses that home's `mordred/keyvault` root. Another profile may
  not read, overwrite, or delete this profile's memory key.
- First provisioning is locked, atomic, and never replaces an existing key.
  An orphaned hardware key may be reused if no wrapped key or sealed memories
  exist. Corrupt/missing material with an armed marker or sealed memories is a
  refusal, not an instruction to generate a new key.
- A managed Linux profile reads its wrapped key directly through the memory
  hook. No plaintext key is written to `.env`, config, logs, responses, command
  arguments, or a new environment variable. No process-global key cache is
  introduced in the first version: each key resolution follows the live home
  and revalidates the stored material.
- A valid ambient memory key may be adopted only by explicit enable-time
  migration, after it authenticates every existing sealed memory. Re-enable
  with an existing wrapped key ignores ambient values, including malformed ones. Runtime use
  of a managed profile never falls back to ambient keys after TPM failure.
- This is memory-key custody, not a new file-vault anchor. It does not add
  rollback protection to memory snapshots or authenticate a whole-disk state;
  public-key wrapping alone is not a freshness or writer-identity guarantee.
  Existing vault verification remains unchanged.
- The first version has no portable recovery/export for the Linux memory key.
  Losing the TPM state loses access to sealed memory and Telegram credentials.
  Disabling memory encryption while the TPM is usable restores plaintext;
  setup must explain the recovery limitation before provisioning.

### Runtime and lifecycle

The new keyvault module owns hardware selection, key identity, secure storage,
and runtime key resolution. It must not import Telegram or wizard modules.
The memory hook resolves keys per profile before decrypting or sealing data,
including when imported before plugin registration. Missing hardware or an
invalid key must never cause a plaintext write or truncate a sealed file.
Safe mode retains the existing protection against overwriting sealed memory.

Linux `encryption enable memory` checks the local seam and installed Hermes
runtime before provisioning. After provisioning, a subprocess of the actual
runtime must unwrap the key and round-trip a synthetic memory payload in RAM;
only then may the CLI arm the marker and migrate real files. Probe identifiable
gateway interpreters as well. Check install-time capability separately from a
running process: an older live gateway must be stopped/restarted before use.
Probe failures leave existing files and markers unchanged; an inert provisioned
key may remain for retry. No probe prints key bytes or real memory contents.

The generic runtime gate gains a supported-platform parameter whose default
remains Darwin-only; only memory opts into Linux. Existing force semantics may
skip interpreter verification, but never hardware, key-integrity, or migration
checks. Guided Telegram setup does not use the force option.

Linux hook operations pin the active home, refuse paths from another profile,
and hold the profile lifecycle lock through managed reads, every write and
drift-backup publication. Unmanaged reads create no files and require no
writable Mordred directory; if they observe a seal, it is still authenticated.
The non-secret lock accepts safe existing non-private directories without
changing their mode. Disable and purge take the same lock; even disarmed writes
join it so concurrent enable cannot be followed by a stale plaintext write.
Re-enable authenticates all existing seals and backups before arming.
Linux adoption, migration, disable, purge and readiness checks enumerate memory
files explicitly and refuse traversal/read failures; an inaccessible directory
is never evidence that no encrypted files remain.

Disable decrypts existing files before disarming, retaining the Linux key for
re-enable. Purge deletes the Linux key only after successful disable and a
rescan proving no sealed memory remains. Keep the current refusal on concurrent
gateway resealing. Uninstall restores memory before removing the runtime hook;
Telegram logout/forget never deletes the separate memory key. Keyvault reset
takes the memory lifecycle lock before its own lock and refuses to remove the
native store while independent memory custody remains. Uninstall with data
purge restores or explicitly erases memory, then purges its key before resetting
the native keyvault store.

Read-only status uses local capability, marker, key-artifact, and plaintext-drift
checks; it does not unwrap keys. It must distinguish configured protection from
a verified live TPM operation. Actual access and enable-time probes are the
authority when hardware disappears or loses permissions after a status check.

### Telegram setup and interface compatibility

- CLI selects `keyvault enable-tpm` on Linux and `enable-se` on macOS.
- Linux setup enables memory directly, skipping `.env` enrollment and the
  Keychain-backed vault. macOS retains its existing shared FlowSession.
- Desktop adds `POST /hardware/build` with OS-aware dispatch. Retain
  `/enclave/build` as the macOS-only compatibility endpoint.
- Desktop `/status?client_version=2` retains `platform` and `telegram_supported`
  (implementation support for a compatible client, not setup readiness), and adds
  `hardware_kind` (`secure_enclave`, `tpm`, or `null`) and
  `user_presence_supported` and `telegram_platform_supported`. Legacy status
  requests keep Linux unsupported so old assets cannot promise Secure Enclave
  or Touch ID behavior. Linux `/memory/enable` requires the new client
  acknowledgment `acknowledge_tpm_no_recovery: true`, sent only from the button
  below the displayed recovery limitation. Unready Linux shows TPM prerequisites and failed
  checks; unsupported operating systems still refuse before any mutation.
- Preserve the existing `secure_enclave` diagnostic field for older clients;
  add a hardware-neutral `hardware` check for new clients and use explicit
  metadata rather than parsing English sentences for readiness.
- `/memory/enable` on Linux provisions only the dedicated key and never
  generates a vault recovery passphrase. It preserves `ok`, `already`, and
  `restart_required` response behavior. macOS responses remain compatible.
- No Linux screen or error remediation prescribes Xcode or Touch ID. Local
  model guidance says this host, not this Mac. Legacy client/server combinations
  must retain a safe unsupported/setup-incomplete state.

### EC2 validation contract

The previous environment was found in local session
`01a11385-d499-7af1-a128-6394c5b250aa` and the local artifact directory
`~/.codex/artifacts/mordred-ubuntu-validation-20261007/`. Its AWS state was read
on 2026-10-07: stopped, Ubuntu 24.04 x86_64, `t3.medium`, UEFI boot, no
`TpmSupport`. The subsequent, explicitly requested TPM baseline test cloned
that stopped disk into a private NitroTPM-enabled AMI and used two isolated
instances. The original instance remained stopped. Results are in
[CI.md](CI.md#manual-live-device-validation-log).

1. Use the NitroTPM test environment for the required EC2 checks. Preserve the
   earlier Desktop environment and use separate test homes, checkouts, and key
   stores. Hermetic swtpm tests remain useful in CI but never replace the
   user-requested actual-device acceptance gate.
2. Use a NitroTPM-enabled Linux AMI and supported instance type for actual TPM
   success tests. Reusing the old non-TPM machine unchanged cannot provide this proof.
   Inspect P-256/ECDH support, device permissions, helper probe, and actual wrap
   round trips before accepting that instance as a suitable test target.
3. Use fresh processes, a Hermes gateway, and the packaged Desktop against the
   new build. Confirm that the imported Mordred path is the intended checkout
   or wheel in each interpreter. Use port 7799 and loopback-only SSH tunnels.
4. Use synthetic Telegram messages for repeatable tests. A real account login,
   small read-only sync, query, cancellation, and logout form a separate live
   acceptance gate; the operator supplies API credentials, OTP/2FA and any
   model credentials interactively, without putting them in test artifacts.
5. Record exact commits, OS/Python/Hermes versions, commands, counts, failures,
   screenshots, and limitations. Emulator, NitroTPM, and live Telegram results
   must be reported separately. Stop task-owned compute after testing.

AWS requires an enabled AMI and UEFI for NitroTPM. NitroTPM state is not part
of EBS snapshots; restoring a disk is not key recovery. See the
[AWS NitroTPM requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html).

### Delivery boundaries

Follow the repository's docs-first, one-component-per-PR convention: contract
documentation, keyvault runtime, wizard lifecycle/setup, then Desktop/extension
integration. All PRs target `dev`. Do not advertise Linux support before the
dependent slices and acceptance gates pass. This change contains planning and
the separately requested unchanged-code TPM baseline evidence, not the feature
implementation or published PRs.

Review decisions: approve the dedicated-key scope and its recovery limitation;
choose in-session execution or subagent-driven execution. Recommended execution
is in-session because the small sequence has tightly coupled interfaces.
## Windows keyvault wallet configuration (2026-10-08)

This is the first bounded keyvault caller migration after the private filesystem
foundation in PR #192 (contract PR #191). It covers only the keyvault-owned
`<home>/extension/wallet.json` selection document. Native Windows product support,
key custody, signing, memory, reset/purge, audit and Desktop remain incomplete.
The component contract must precede its implementation PR; both target `dev`.

On Windows, `extension_sign.set_wallet` and `_load_wallet_cfg` use checked
private directories, bounded reads and transactions from `_private_fs`.
Keep the POSIX implementation and `.wallet.lock` protocol unchanged. On Windows
use the permanent `<home>/extension/.mordred-fs.lock` for the entire file
existence/read/create-or-replace operation; retain the in-process wallet mutex.
All Windows wallet writers/readers in this version use that same lock. Older
Windows writers do not participate: stop them before using this version. No
mixed-version Windows writer compatibility or automatic ACL migration is claimed.

Writes create only the final `extension` directory under an existing trusted
profile path. Existing directories/files must satisfy the foundation's private
ACL contract; never chmod, repair or adopt them automatically. Reject junctions,
unsafe ancestors, hard-linked files and unsafe lock objects. A missing checked
directory or wallet alone permits the existing absent-wallet discovery behavior;
access, ACL, lock, cleanup, size and other I/O failures must never become absence.
The scope of a missing-error handler must distinguish the open/read operation
from transaction/directory cleanup errors, even when those errors say `missing`.

Preserve the existing JSON schema, duplicate-member rejection and UTF-8 checks.
Both existing-file reads and serialized writes are bounded at 1 MiB. Validate
the proposed document before creating a directory. Under the transaction, read
and validate the existing file's storage posture before choosing exclusive
creation for absence or checked replacement for presence. Oversized existing
files are refused without replacement. This operation is not a multi-file or
native-key lifecycle transaction and needs no delete/append primitive.

Map filesystem failures to a `WalletConfigError` subclass, retaining non-secret
reason, native status and `commit_state`. Its message must distinguish an
uncertain save and tell the caller to inspect before retrying. Never retry,
delete, regenerate keys, return a default wallet or roll back after an uncertain
publication, including errors during context cleanup. Do not include document
contents, key IDs, RPC credentials or paths in the public error text.

Acceptance covers public set/load behavior on Windows Server 2022 hosted CI
(Python 3.11–3.13) and retained Server 2025 ordinary-user source/wheel checks,
including a fresh process, other-user denial and retained selection. No TPM
operation is needed for this selection-document slice. Windows 11, interactive
installation and whole-product flows remain later acceptance gates.



## Windows native support proposal (2026-10-07)

Status: proposed implementation contract following the approved Windows
feasibility investigation. Windows product support remains deferred until the
component and acceptance gates below pass. This section does not change the
currently shipped Platform Support (v1) claims.

### Intended outcome and scope

Run the single Mordred plugin natively on Windows, with the same policy and
privacy decisions as the supported Linux tier, including TPM-protected Private
Telegram credentials and agent memory. Validate progressively on AWS Windows
Server with actual NitroTPM. Preserve public Hermes integration and the
zero-upstream-PR commitment. WSL results are not native Windows results.

Initial implementation targets x86_64, Python 3.11–3.13, and a pinned,
Windows-capable released Hermes version. Server 2025 is the actual-device
engineering target; Server 2022 is a compatibility target. Windows 11 Desktop
installation and its bundled runtime need a distinct acceptance run. Neither
Server tests nor source-built Desktop prove MSIX installation/update behavior.

No new macOS-equivalent `.env`, configuration/workspace seal, Windows Hello,
per-use presence, ARM64, or TPM-key recovery claim is part of this port.

### Windows hardware custody

Implement a separate `mordred-hermes-winkey.exe` helper using Windows CNG and
`Microsoft Platform Crypto Provider`. Preserve the existing helper commands,
neutral error taxonomy, SEC1 P-256 public-key representation and 127-byte MRKW
version-1 format. No changes to P-256 ECDH, HKDF-SHA256 or AES-256-KW are required
by the successful initial AWS wire-format experiment.

- Open the explicit Platform Crypto Provider and verify its implementation
  reports hardware, with no software-provider substitution.
- Create user-scoped persisted `ECDH_P256` keys. Do not set the Key Usage property
  to KeyAgreement: the actual provider refused that setting with `0x80090029`,
  while its default key successfully performed ECDH. Probe actual operations,
  not just advertised algorithms or a property's label.
- Keep export policy non-exportable. Public-key export is permitted; a private
  export must fail. Handle conversion validates magic, curve size and lengths.
- Import a valid public peer into the same provider, call `NCryptSecretAgreement`
  and `NCryptDeriveKey(TRUNCATE)`, reverse the returned little-endian secret and
  return exactly 32 bytes, preserving leading zeroes. Test against independent
  Python/OpenSSL ECDH and the production wrapping functions.
- Key names use `mordred-hermes:` followed by the lowercase SHA-256 hex digest
  of the decoded application tag, keeping CNG names bounded and case-stable.
  Reject empty, odd-length, non-hex tags and tags larger than 256 decoded bytes
  before calling CNG; a
  4 KiB UTF-8 request limit bounds the new helper. Generation must not overwrite
  an existing key. Deletion must respect lifecycle guards. A successful Windows
  deletion requires opening and deleting the exact key. An unopenable keyset
  returns `UNAVAILABLE` with the original native status, even on a repeated
  delete after successful removal. Actual PCP testing could not distinguish
  absence from retained but inaccessible keys: both returned `NTE_BAD_KEYSET`,
  and enumeration omitted the inaccessible retained key. Thus the Windows
  helper does not promise success-on-missing idempotency; it must never falsely
  confirm removal from a successful probe of a different key.
- Do not store Windows passwords or impersonate users in the product helper.
  It runs under the application's existing user token. Diagnostics test this
  actual token's key access. The probe observed public-key-only SSH refusal and
  password-authenticated ordinary-user success; desktop, terminal, scheduled
  gateway and service contexts must be tested separately. Preserve native
  error status in diagnostics: `NTE_BAD_KEYSET` is documented as key-not-found,
  but the probe also observed it for an existing key under an incapable token.
  Missing access must never be treated as permission to replace retained keys.
  See [NCryptOpenKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenkey).
- Runtime lookup/open/unwrap failures never generate replacement keys, downgrade
  to software, adopt an ambient plaintext key or erase valid ciphertext.
- Describe the tier as machine-bound, without per-use presence or automatic
  recovery. A copied disk is not a TPM backup; deletion/termination warnings
  apply before irreversible custody actions.

### Windows private storage and lifecycle

Replace POSIX-specific security properties with tested Windows equivalents;
never make Windows support a collection of skipped mode/lock checks.

Private files and directories must have protected DACLs granting only the
current user, SYSTEM and Administrators the necessary access. Validate ownership,
parent-directory trust, unexpected inherited/broad grants, file type and stable
handle identity. Deny reparse points and directory junctions on protected paths.
Do not claim protection from administrators or arbitrary same-user hostile code.

Use `CreateFileW` with a security descriptor at creation, handle-based metadata,
`LockFileEx` for cooperating processes, and a checked replacement/flush strategy.
Creation must not have an initial broad-permission window. Sharing violations,
interrupted writes, concurrent writers and antivirus-held handles must preserve
the prior valid data and return an actionable refusal. Network shares are not
an initial supported secret-store location; validate local filesystem behavior.

Keep the POSIX implementation intact behind an OS-dispatch boundary. Migrate
caller components in separate PRs after the shared primitive contract is landed.

Use upstream home resolution and explicit `HERMES_HOME`, Windows `Scripts`
interpreter paths, `.exe` discovery, Unicode paths and PowerShell-compatible
setup. Install native executables through a verified temporary file and atomic
replacement; an in-use executable must not produce a partial installation.

### Feature integration and truthful capabilities

Windows memory custody follows the Linux wrapped-DEK lifecycle and retains its
concurrent provision/reset/purge guards. Setup, doctor and status inspect the
actual application interpreter and token before enabling encryption. Preserve
existing data and report why custody is unavailable when that check fails.

Desktop capability responses expose Windows TPM readiness, no per-use presence,
setup prerequisites and restart requirements. Hide unsupported setup paths;
never offer Xcode/Secure Enclave remediation on Windows. Old clients must not
silently enable an unsupported setup flow.

Each network path must verify Windows executable discovery, service ownership,
process-tree termination, local/remote DNS, explicit proxy use, route liveness
and failure behavior. Until verified, an unavailable route must refuse a strict
operation rather than fall through to clearnet. Keep component-specific policy,
LLM guard, privacy audit and extension changes separate.

### Acceptance and delivery boundaries

The first delivery is a docs-only contract PR targeting `dev`, then a keyvault
helper PR, shared Windows primitives, keyvault runtime, wizard setup, separate
network/policy/privacy caller migrations, Desktop/extension and CI integration.
Do not advertise broad Windows support before all dependent slices pass.

Actual-device gates cover ordinary-user generation/reopen/ECDH, independent
cryptographic parity, non-exportability, malformed/corrupt inputs, process and
OS restart, EC2 stop/start, unavailable provider/helper, deletion and device
binding. A second instance must reject copied custody data after controlling for
account/SID/DPAPI differences; an account-access denial alone is not that proof.

Run unchanged-code baseline failures before porting, focused regression tests
on Windows after each slice, reduced-extras typing, Windows wheel smoke and full
macOS/Linux regressions. Standard hosted Windows CI does not establish TPM
hardware support. Record emulator, actual NitroTPM, synthetic Telegram, real
account/model and Desktop UI results separately in the CI validation log.

The execution environment must contain only synthetic fixtures until a separate
live-account test is requested. Stop task-owned compute, retain only explicitly
identified development resources, and record residual storage costs.


## Checked private file lifecycle (C1a)

The opt-in `_private_fs` API retains checked private directories, single-link
regular files, platform ACL validation and its permanent cooperative transaction
lock. No component callers migrate in this slice. `FileMetadata` is a frozen
record of `identity: FileIdentity`, `size: int`, and Unix-epoch `mtime_ns: int`.
Both directory and transaction expose `stat(name)`, `read_prefix(name,
max_bytes=...)`, and `list_names(max_entries=...)`. Stat always opens and validates
the object; missing is an error. Prefix reads return up to the positive integer
limit, including from longer files. Full reads still refuse oversized files.
Enumeration returns sorted names as a bounded tuple, omitting only the reserved
permanent lock and staging names. At most max_entries names are returned; at
most max_entries + 1 non-dot entries fit the scan budget (one permanent-lock
allowance); one additional entry may be fetched to detect overflow.
Abandoned staging entries consume this scan budget. It never follows links or recurses, applies
the filename contract, and refuses overflow. Names remain untrusted until
opened. The transaction protects the snapshot from cooperating writers;
ordinary directory enumeration has no snapshot atomicity promise.

Transactions additionally expose `delete_file(name, expected_identity=None)`,
`rename_file(name, destination, expected_identity=None)` and
`append_bytes(name, data)`. They require existing checked regular files. Optional
identity comparison precedes mutation. Rename is sibling-only and never
replaces a destination, including an unsafe object. Windows uses an exclusive
DELETE-capable checked handle and native no-replace rename/FileDispositionInfo;
no checked-open/path-delete sequence is allowed. Deletion returns successfully
only after close and checked absence. Any error after native deletion is
attempted is uncertain. A rename error is retry-safe only after confirming the
original checked identity and source name are retained. POSIX uses descriptor-
relative unlink or no-replace link followed by unlink and directory flush;
partial rename retains the recoverable duplicate and reports uncertain.

Append holds the transaction, remembers original length, writes all bytes and
flushes. On write/flush failure it truncates and flushes only the still-validated
same file. Confirmed rollback reports not_committed; failed rollback reports
uncertain. Cleanup after successful mutation is uncertain, including unlock
and enclosing-directory close failures. Preserve original exceptions when
cleanup also fails, promoting classified failures rather than replacing them.
Never retry uncertain operations automatically. There is no secure-erasure,
power-loss atomic append, or protection from hostile same-user code claim.
All new operations reject invalid positive limits, reserved/path filenames and
invalid closed/thread/fork lifetimes before touching filesystem state.

### Confidential Windows directory capabilities

Windows-only `open_confidential_directory(path, *, create=False)` admits a
trusted shared parent while preserving exact-private `open_private_directory`.
`ConfidentialDirectory` provides `stat`, bounded `read_bytes`, bounded
`list_names(max_entries=...)`, and `transaction`;
`ConfidentialTransaction` exposes the same bounded `list_names` and adds
`create_bytes`, `replace_bytes`, and
`delete_file(name, *, expected_identity=None)`. Existing files must be owned by
the current user, regular, non-reparse and single-linked. Ordinary allow/deny
ACEs with known inheritance flags and masks are accepted only if every
effective allow targets that user, SYSTEM or Administrators; OWNER_RIGHTS maps
to the verified owner. Denies never excuse an outside grant. Inherited,
duplicate and restricted safe grants need not match the private descriptor.
New locks, staging files, backups and replacements are exact-private before
content. Existing parent descriptors and no-op file descriptors stay unchanged.

`open_optional_confidential_directory(path)` and
`open_optional_private_directory(path)` are Windows-only, noncreating contexts
yielding the corresponding capability or `None`. Only a checked missing final
leaf yields `None`; missing intermediate ancestors and unsafe/inaccessible
objects fail. All checked ancestor handles stay pinned through context exit;
cleanup errors propagate, including after an absence observation. No missing
sentinel crosses cleanup. The endpoint is checked as a trusted parent with
`creating_child=True`; create permits only a missing final leaf and verifies its
new exact-private descriptor. Each operation
rechecks the directory security/identity and successful observations recheck
the file binding and security. Failed lock creation never permits unlocked IO.


Both `PrivateDirectory` and `ConfidentialDirectory` expose
`directory_identity() -> FileIdentity` for coordinator identity binding. It
validates active context, originating process/thread, pinned directory and
ancestor security, identity and path binding before returning the checked
handle identity. There is no path-only or raw-stat fallback. POSIX private
directories revalidate descriptor-relative names throughout the pinned chain.


`PrivateTransaction` and `ConfidentialTransaction` also expose
`directory_identity() -> FileIdentity`. A borrowed transaction must be active
and belong to the current thread/process, then revalidate its owning directory
with the same checked identity contract. This method never reacquires a lock.




The confidential inventory uses the same handle-bound checked enumeration,
namespace validation and entry budget as private inventory. It filters only
foundation-reserved entries and does not admit listed children as safe files;
callers must use checked file operations for each selected name. Enumeration
rechecks directory binding/security before returning and respects directory and
transaction process/thread/lifetime boundaries.

`current_principal_id() -> bytes` returns the effective Windows token's validated
canonical binary SID through the existing token capability. It has no account-name,
path or environment fallback; token and cleanup failures propagate. Other platforms
raise classified `unsupported`. This is identity data, not a secret or a key.

### Checked Windows audit sessions

Shared audit operations use one exact-private directory transaction across
format probes, append, rotation, compression and retention. Borrowing an existing
transaction requires a checked `assert_private_admission()` capability as well
as matching checked directory identity; confidential admission is rejected even
when its parent is exact-private. No independent global mutex may be held while
waiting for this filesystem lock. Nested sessions reuse an explicitly owned
same-directory transaction; different-directory nesting refuses.

Snapshots and gzip decoding have explicit finite limits: initial defaults are
16 MiB per file/decompressed output, 64 MiB aggregate, 4,096 entries and 4,096
first-line bytes. Compression may retain an oversize raw file; readers never
silently truncate. Rotation uses no-replace publication and recognizes only
valid dated rotation names, with optional numeric suffix and gzip extension.
Automatic retention uses checked mtime and excludes the current operation's
new raw/gzip artifacts from that immediate sweep. It never selects unrelated
prefix-matching files or permanent locks.

Compression may report a degraded raw-retained result only for a local
compression failure before publication, or a known not-committed I/O/access/busy
publication failure, after verifying the original raw identity remains intact. Unsafe, identity, unsupported and uncertain errors
propagate. Published gzip is verified before identity-bound raw deletion;
failed deletion may leave both copies. Fatal compound failures after prior
persistent mutation are reported uncertain, preserving underlying diagnostics.
No automatic retry, guessed rollback, secure-erasure or power-loss claim is
made. Consumers own encryption formats, generation leases and key authorization;
uncertain writes invalidate their cached active identity/header/DEK and require
explicit reconciliation. Shared audit operations do not enable those consumers.


### Windows custody coordination capabilities

`CanonicalSession.borrow_mordred_transaction()` lends a lifetime-bound protected
`PrivateTransaction` proxy under home-before-mordred coordination. It requires
exact-private admission and matching checked directory identity, extends scope
without reacquiring the home lock, honors nonblocking mode, and creates only
when the owning outer session authorized creation. Pending policy state refuses
borrowing. Configured/canonical policy leaves, pending/legacy locks, their
legacy temporary files and foundation-reserved names cannot be read or mutated;
both rename operands are checked and bounded enumeration filters protected names.
The proxy never exposes or releases the underlying transaction. Successful
mutations join outer publication tracking and classified uncertainty is sticky,
even when caught by a caller. No unrelated policy marker is manufactured.

`CanonicalSession.publication_receipt()` lends no filesystem authority. Its
`mark_published()` and `mark_uncertain(error: PrivateFSError)` methods validate
process/thread/owner/receipt lifetime, then monotonically record child outcome
before any parent filesystem revalidation. A child writer must report each
successful mutation and each uncertain primitive/cleanup outcome. Escaping
errors after reported publication also poison the owner. Original uncertainty
survives later outer cleanup; reports cannot reset state. See
[the coordinator API](WINDOWS_CONFIG_IO.md#future-audit-integration) for the exact
caller obligations. These capabilities do not activate production custody.

### Native Windows installation and helper (C4)

The native PowerShell installer selects the actual Hermes virtualenv/conda
interpreter, verifies Hermes distribution/CLI registration there, installs a
pinned release or explicitly supplied source/wheel with keyvault and extension
extras, and verifies the single `mordred` entry point. It scrubs Python/uv
redirects and checks every native exit status. `-InstallOnly` finishes package
validation without claiming configure/setup; otherwise it delegates the existing
install dispatch and canonical writers (C3 dependency). No Bash or WSL is used.

Windows wizard interpreter discovery has one reusable Python resolver, honoring
an authoritative explicit override, `Scripts/python.exe`, conda roots and
Desktop managed environments. System Python and mismatched Hermes launchers
refuse. Public launchers and native helpers require verifiable content-bound
ownership; unknown files and reparse destinations are retained/refused.

`keyvault enable-winkey [--install-dir PATH]` builds only packaged or validated
checkout sources with PowerShell array arguments and the running interpreter.
Rust MSVC/Visual C++ tools are prerequisites. The exact freshly installed helper
is probed under the current token, including custom destinations; build/probe
errors remain failures. A successful probe establishes TPM machine binding,
not presence, active memory encryption or Windows product completion. Windows
setup/status use this command/finder without broadening encryption capabilities.

Native PowerShell 5.1/pwsh and ordinary-user Windows installation, upgrade,
uninstall and CNG evidence remain controller-run acceptance gates.

C4 native executable/receipt publication depends on C1b's
`open_confidential_directory` transactions, including trusted-parent ACL checks
and identity-bound deletion. Missing C1b refuses; no weak native fallback is
permitted. C4 cannot be finalized or advertised as native installation-ready
until that dependency and its native acceptance pass.
### Public Windows build-source reads

Windows-only `read_public_build_output(path, *, max_bytes) -> bytes` reads public
build output under the shared trusted-ancestor policy. The positive integer
bound is at most 64 MiB. The source must be a regular, non-reparse file on the
same local NTFS volume as its pinned parent, with a trusted owner and no foreign
mutation rights. Read-only outside grants are allowed. Cargo output may have
multiple hardlinks; the capability neither changes nor adopts the source.

A single source handle excludes concurrent write/delete access through every
alias until reading and security, identity, size and path postchecks finish.
The named source is rechecked under that handle. Bytes are returned only after
source and ancestor cleanup succeeds. There is no staging, guessed rollback or
retry. Installed confidential/private files, receipts and destination admission
still require a single link and retain their existing ownership/ACL rules.

The wizard checks the PE header and any supplied build-script SHA256 against
these bytes before publishing. Executable and receipt remain separate checked
publications; failure may leave an unowned artifact requiring inspection, and
never constitutes a successful installation.


C3 may create a verified, create-no-replace `env-removed-[safe stamp].env`
backup directly in the already-held exact-private policy directory through
`CanonicalSession.create_policy_backup`. It rejects canonical policy and pending
marker names before matching backup names, including custom canonical leaves.
The method uses existing coordinator bounds, marker guards and classified
publication/failure tracking. Explicit backup child directories retain their
checked private capabilities and lock order; a successful child publication
followed by outer coordination cleanup failure remains uncertain.

### Windows dedicated custody and memory lifecycle

C5 implements the Linux-equivalent Windows tier: CNG-backed memory custody,
independent encrypted audit-key custody, and shared role identity/lifecycle
services for Private Telegram. Preserve MRKW, memory AES-GCM and MRAL wire
formats and existing Linux/macOS identifiers. This does not require a port of
all `_storage` file-vault layouts. Windows file-vault freshness anchors,
env/config/workspace seals, TPM recovery and per-use presence remain excluded.
Their public APIs and runtime bootstrap paths must refuse before state mutation,
anchor substitution or plaintext deletion. Ordinary configuration editing is
supported independently of configuration encryption.

#### Custody coordinator interfaces

`CanonicalSession.borrow_mordred_transaction()` is a context-managed,
lifetime-bound proxy over the already-owned exact-private Mordred transaction;
it is not a raw transaction accessor. It validates process/thread/lifetime,
checked directory identity and `assert_private_admission()`. Acquiring or
extending scope follows home before mordred; borrowers never release the
underlying lock. Reject another home, an unauthorized absent directory or a
confidential-admission transaction.

The proxy rejects canonical `policy.json`, the configured policy leaf,
`.policy-write.pending`, permanent foundation lock/staging names and legacy
coordinator lock names on every operation. Rename checks both operands;
enumeration excludes these protected names. Thus callers cannot bypass the
pair protocol, read through its marker or clear coordination state. A closed
loan or outer session invalidates the proxy. C3 keeps its narrower
`create_policy_backup` interface.

The coordinator records successful proxy mutations and uncertain failures
before returning to the borrower. Uncertainty poisons the owning session even
if the borrower catches the exception; it cannot subsequently report success
or clear a pending policy marker. Known unchanged collisions may be handled
without erasing earlier publication tracking. Outer cleanup failure after a
recorded mutation is a compound uncertain result, without automatic rollback.

`CanonicalSession.publication_receipt()` supplies a lifetime-bound receipt
with monotonic `mark_published()` and `mark_uncertain(exc)` methods for an
independently locked memories child transaction. It provides no filesystem
authority and no method to clear recorded state. The memory adapter reports
each successful mutation and uncertain primitive/child-cleanup failure before
leaving that child scope; escaping classified uncertainty is also recorded.
The outer coordinator retains this outcome after a caller catches the error.
No independent child publication may evade the owner's cleanup accounting.

C5 lifecycle order is home, mordred, then memories; every Windows memory write,
including a disarmed plaintext write, joins it. C7a audit operations receive
the protected loan when their directory is mordred. A custom audit directory
is acquired after custody locks. Audit providers resolve ownership first and
must not recursively acquire home under an audit/mordred lock. Synchronous
audit sinks reuse an explicitly lent transaction or emit after the scope;
there is no cross-module implicit transaction lookup.

The confidential capability is narrowly extended to canonical
`<home>/memories`, including bounded `list_names(max_entries=...)` on both its
directory and transaction. Existing inherited-safe files retain current-user
ownership and confidential admission; broad grants, hardlinks, reparse points
and inaccessible state refuse without ACL repair. New ciphertext, restored
plaintext and backups are exact-private before content. The foundation exposes
Windows `current_principal_id() -> bytes`, returning the validated current
token's canonical binary SID; callers do not duplicate token/ACL code or use
localized account names for identity.

#### Physical profile binding and flat ownership

New Windows native selectors are versioned and fully domain-separated by role.
They bind the checked physical home `FileIdentity`, current binary SID and a
persisted random profile nonce, plus an independent role-generation nonce.
Derive a full SHA-256 identifier from validated, unambiguous field encodings;
never authorize native use/deletion through a path string's casefold or an
arbitrary persisted tag. The helper retains its bounded hashed CNG key naming.

Aliases reaching the same checked physical home use the same ownership state.
A safe rename/relocation preserving its FileIdentity, current SID and nonce is
allowed. A copied, restored or recreated home with a different identity refuses
without generating a key or automatically adopting retained material. Cost:
movement to a new physical directory requires decrypt-before-move or explicit
future migration; transparent encrypted portability is not promised. Existing
Linux/macOS IDs and preliminary Windows artifacts are not silently reinterpreted.

`<home>/mordred/windows-custody.json` is a flat, exact-private ownership
manifest, bounded to 64 KiB and at most 64 retained role generations across
roles. Roles are fixed to memory, audit and Telegram; current and retained
records, version, profile binding and lifecycle epoch use an exact validated
schema frozen by C5a before implementation. Role-specific pending journals
record enrollment or deletion intent before the native operation. These are
custody journals, not a new vault freshness anchor or whole-disk rollback
protection. Memory purge does not delete independent audit or Telegram roles;
retained audit generations remain owned while their history is retained.

##### Dedicated Windows custody v1 schema

The manifest has exactly `version: 1`, `home: {volume, file_id}`, `sid`,
`profile_nonce`, `epoch`, and `roles`. Volume is an unsigned 64-bit integer;
file ID is 16 bytes encoded as lowercase hex; SID is canonical revision-1
binary SID encoded as lowercase hex. Nonces are independent random 32-byte
lowercase hex values. Epoch is an integer from 0 through 2^53-1, never a
boolean. `roles` contains exactly `memory`, `audit`, and `telegram`, each with
`current` (null or record) and `retained` (record array). A record has exactly
`generation`, `epoch`, `key_id`, `native_key_id`, and `public_sha256`.
Logical IDs are respectively `mordred.memory`, `mordred.audit-log`, and
`mordred-hermes.telegram.credentials.v1`. Public fingerprints are full SHA-256
over validated uncompressed P-256 public bytes. Generation nonces are unique across all
records. A current record's epoch does not change when another role changes.
Duplicate JSON keys, unknown fields, invalid UTF-8, noncanonical hex, malformed
SID/identity, record mismatch, overflow, and more than 64 retained generations
refuse. Encoded manifests and journals are each bounded to 64 KiB.

`windows-{role}.pending.json` has exactly `version`, `profile_nonce`, `role`,
`operation`, `phase`, and `record`. Operation is `create` or `delete`; create
phases are `intent` and `verified`, delete phases `intent` and `deleted`.
Only create intent permits a null public fingerprint. Journal identity and
generation are checked against the bound manifest. Create intent is durable
before native creation, verified fingerprint before memory-wrapper publication,
current ownership before final journal deletion. Delete intent precedes native
deletion, and positive deletion is durably recorded before artifact cleanup.
An interrupted native delete with only intent remains ambiguous even if the
key subsequently cannot be opened. Explicit reconciliation never generates.
Retained audit/Telegram records can be selected only by a validated generation
lease; a new current role may retain its predecessor without deleting it.

The native selector is `mordred-hermes.windows.v1.` plus full lowercase SHA-256
of the domain `mordred-hermes.windows-custody.v1\0` followed by length-prefixed
binary fields: big-endian 64-bit volume, 16-byte file ID, SID, profile nonce,
ASCII role, and generation nonce. Each length is unsigned big-endian 32-bit.
No pathname participates in native authority.

`windows_custody_session(home, create=False, canonical=None, backend=None)`
owns home then mordred, or joins an explicit C2 session after checking the
physical home identity without reacquiring its lock. `WindowsCustodySession`
provides immutable `GenerationLease` values (profile nonce, role, generation,
epoch, logical/native IDs and fingerprint), current/retained `lease()` selection,
`validate_lease()` and `backend_for()` exact-public verification. Leases are
observations, not perpetual authority: consumers validate them inside a fresh
custody scope before mutation. The session's checked `canonical` coordinator
supports subsequent memory/audit adapters; use ends when either scope closes.

`enroll_memory(adopted_key=None)` provisions inert memory custody;
`enroll_role(role, retain_current=False)` explicitly provisions audit/Telegram.
Runtime `resolve_windows_memory_key` is load-only. A valid manifest containing
only other roles is not broken memory custody; no memory role/journal/blob,
marker/opt-out or seal evidence means an unmanaged result without creation.
Helper discovery happens before enrollment intent, but native creation failures
retain the intent journal. `reconcile_pending()` never creates a native key.

`delete_role(lease, erase_authorized=False)` validates ownership and journals
irreversible deletion. Memory requires explicit opt-out, no opt-in/seals and a
known stopped Windows gateway inventory. Audit/Telegram require a future caller
ceremony proving history removal or explicitly authorizing erasure. Only a
positively recorded `deleted` phase permits checked wrapper/opt-out removal,
role cleanup and journal removal last; recovery may encounter already-removed
cleanup members, but still refuses opt-in, seals or unsafe objects. Independent
roles and permanent directory locks survive. Successful memory purge returns
to unmanaged state; a later explicit enrollment obtains a fresh generation.
An intent with an ambiguous native deletion result remains unresolved. Native
create/delete scopes mark the owning publication receipt before the call, so
later ledger failures remain sticky even if a borrower catches them; classified
filesystem failures retain their identity and are promoted to uncertain.

#### Enrollment, loading and lifecycle failures

Separate explicit create-only enrollment from load-only key resolution.
Enrollment first validates checked fresh state or an explicit in-memory
adoption request, then persists its role journal, invokes native generation
without overwrite, verifies the exact public key and wrap/unwrap roundtrip,
publishes the wrapped memory key without replacement, and commits checked
ownership. The arm marker is a later step. A generation collision or any
uncertain step retains evidence and requires explicit reconciliation.

`NTE_BAD_KEYSET`, `WrapKeyNotFound`, failed lookup or enumeration omission never
proves hardware-key absence. Neither runtime loading nor enrollment recovery
may generate a replacement after such a result. Wrapped keys, markers,
opt-outs, pending ownership and any existing/broken memory seal preclude a
fresh-state inference. Explicit pending recovery can reuse only the journaled
key after positive exact-key verification; a probe of another key is no proof.
No ambient plaintext key or software backend is a runtime fallback.

Checked flat memory inventory includes `.md` files and `.md.bak.*` backups;
initial limits are 4,096 entries, 8 MiB per file and 64 MiB aggregate. Errors
and overflow are not an empty inventory. Explicit adoption authenticates every
seal before native creation. Windows hook reads, writes, journey checks and
drift backups use the shared checked adapter, not upstream raw publication.
Preserve basename-bound AEAD, broken-seal refusal and sticky sealing while
disarmed/in safe mode. Unreadable sealed state cannot become an empty successful
memory read. No process-global plaintext key cache is introduced.

Disable decrypts and verifies all selected memories before final disarm;
partial failure preserves custody, remaining ciphertext and armed state.
Purge requires a complete rescan proving no seal or broken seal remains and a
positive exact-key native deletion under a persisted deletion journal. Failure
after deletion but before recording success remains ambiguous; a later failed
open cannot turn it into confirmed absence or permission to recreate the key.
Classified uncertainty survives wrapper exceptions and outer cleanup.

#### Runtime proof and audit enrollment

The first Windows release requires installed-runtime proof; there is no
force-runtime-unverified override. Reuse C4's `_windows_runtime` resolver,
validator and scrubbed environment rather than copying launcher logic.
An authoritative interpreter/launcher failure does not fall through to another
runtime. Check the actual installed memory hook and perform a synthetic
in-memory roundtrip through its CNG-backed provider under the application token.
Release custody locks before launching that subprocess, then reacquire and
revalidate the same profile/generation/wrapped key before arming. A failed proof
preserves real files and markers; an inert enrolled key may remain for retry.

Windows gateway discovery returns explicit known/unknown state and observed
runtimes. Use viable native/psutil process inspection, preserving AccessDenied,
process-exit and PID-reuse distinctions. An inaccessible plausible gateway or
failed inventory is unknown, never an empty list proving safety. The observed
ordinary-user CIM denial must not become an empty-success fallback. Unknown
or running relevant gateways refuse destructive lifecycle transitions; a new
subprocess cannot prove which hook an existing process loaded. Process discovery
supplements lifecycle locks and does not guarantee that a new process cannot
start after the scan.

Audit enrollment is an explicit native-custody initialization ceremony. Memory
enable may call that ceremony explicitly; an audit callback never provisions
a key. Audit load/writer construction uses a checked independent role lease,
without a full file-vault/main-key metadata dependency. C7a supplies checked
append, rotation and bounded snapshots. Uncertain outcomes invalidate cached
active identity/header/DEK and require reconciliation. Existing audit downgrade
policy remains a separate consumer decision; unsafe/uncertain storage never
permits overwriting retained ciphertext or silently creating replacement keys.

The opt-in C5d API is `keyvault.windows_audit.WindowsAuditProvider(home,
backend=None)`. `lease(custody=None)` resolves the current independent audit
role and verifies its native public fingerprint. `writer(path,
rotate_bytes=10485760, retention_days=30, custody=None)` returns a
`WindowsEncryptedWriter` containing an immutable lease and backend, never a
live custody session. Construction is load-only; missing ownership, helper or
native key never causes enrollment. `enroll_role("audit")` remains an explicit
ceremony. Product factory/CLI routing belongs to C7b.

`WindowsEncryptedWriter.append(entry)` owns a fresh custody scope. A synchronous
nested callback uses `append_in_custody(entry, custody=session,
transaction=None)`; an optional transaction must be a live, matching protected
Mordred loan. Lock order is home, mordred, writer mutex, then audit. The default
physical Mordred directory borrows its C2 transaction even through safe path
aliases. A custom exact-private directory must already exist and obtains a
nonblocking lock after custody, so cross-profile custom paths cannot form a
waiting lock cycle. A custom path equal to the physical home is refused.
Every successful or uncertain mutation and child-exit failure is immediately
reported through the owning monotonic publication receipt. After publication,
ordinary failures become classified uncertainty; interrupts keep their type and
are recorded as uncertain. Caught errors cannot acknowledge success at the
outer exit. A new generation's DEK is wrapped, its complete header built and the
entry sealed before rotation, so only checked filesystem primitives follow the
first mutation: a definite native wrap failure publishes nothing, poisons no
writer and leaves the outer exit definite. Uncertain outcomes and a missing
previously owned active file permanently poison that writer. Definite failures
and close wipe the DEK but keep poison and the owned active-file identity, which
only the writer's own rotation clears. Header/identity changes wipe the prior
DEK before validating and rotating only checked recognized plaintext or owned
MRAL history; any other active header is a classified write refusal.

`decrypt_windows_log_file(path, home=..., audit_sink=..., backend=None,
custody=None, max_file_bytes=16842752, max_output_bytes=16777216)` takes a bounded
immutable C7a snapshot and releases its audit context/custom lock before native
unwrap or its synchronous audit callback. The retained custody scope excludes
reset through entry authentication. The default borrowed Mordred lock belongs
to that lifecycle, not to an additional audit sidecar. Nested sinks explicitly
borrow the caller's custody; they must never recursively resolve a fresh
provider/home. Raw caller snapshots are not accepted. Gzip output, exact MRAL
schema and MRKW structure are checked before native I/O. Shared MRAL header/AAD,
entry encoding and crypto remain byte-for-byte unchanged; Windows requires the
scoped native field. `WindowsCustodySession.lease_for_native(role,
native_key_id)` resolves only exact owned current/retained records in the checked
physical profile, then uses normal lease/journal validation. An arbitrary tag,
another role/profile, or a legacy global native selector grants no lookup
permission. Memory purge/re-enrollment does not invalidate retained audit roles.
Destructive audit-key/history purge remains a later explicit caller ceremony.

Flat memory/audit lifecycle needs no recursive filesystem API. Keep its
permanent directory lock after purge. Recursive uninstall of Telegram/archive
or legacy vault trees remains a later shared-foundation prerequisite requiring
checked traversal, an outer lifecycle lock and quiescent directory removal;
raw recursive deletion does not satisfy this contract.

C5 profile binding uses `CanonicalSession.home_directory_identity()` to obtain
`FileIdentity | None` for its checked, currently owned home. The method validates
session process/thread/lifetime and existing home identity without reacquiring
locks; `None` means only the already checked absent home. It grants no raw
handle or transaction access. A supplied custody home must resolve through a
checked directory capability to that same identity before borrowing custody
state; string spelling and private coordinator attributes are not authority.

Managed-memory evidence is role-specific after validating the complete physical
profile manifest. Valid audit/Telegram ownership alone does not imply a missing
memory wrapper. Confirmed memory deletion first records its durable deleted
phase, then removes the checked wrapper and opt-out, clears only the memory
role, and removes its journal last. Recovery of that recorded phase may finish
already-partial cleanup, but still refuses unexpected opt-in, seals or unsafe
objects. Successful purge leaves an unmanaged memory role while preserving
independent audit/Telegram roles. A missing wrapper with retained memory-role,
marker, opt-out, seal or ambiguous pending evidence remains broken, never fresh.

#### Windows privacy audit writer routing (C7b)

On Windows, `privacy_check.audit.make_audit_writer(audit_path, keyvault_home,
backend)` never consults `keyvault_initialized` or file-vault metadata; that
probe returns `False` on Windows without reading `_storage`. Inside one
load-only custody session (home, then mordred) the factory observes the
independent audit role through C5e `WindowsCustodySession.role_status("audit")`,
without native I/O, applies the C5d directory rules to the audit path, then
decides:

| Observed state | Result |
| --- | --- |
| Committed current audit generation | C5d `WindowsEncryptedWriter` from `WindowsAuditProvider.writer(...)` in a nested same-home custody session, reported as `mode == "encrypted"` |
| Checked clean absence: no manifest or an empty audit role, no pending or orphan journal, and no MRAL or unrecognized active or dated history in the audit namespace | Checked plaintext writer reported as `mode == "plaintext-degraded"`, with a logged downgrade warning |
| Pending or orphan journal, retained generations without a current one, copied or malformed manifest, missing native key or helper, pending policy, unsafe or uncertain storage, retained MRAL or unrecognized history, a missing custom audit directory or the home itself as audit directory | `AuditWriterRefused` with a closed `reason`; no writer |

The POSIX catch-all plaintext fallback does not apply: no MRAL log is rotated
aside and plaintext is never written over retained ciphertext. The factory never
enrolls, creates or probes native keys beyond C5d's load-only lease (exactly one
native public-key lookup for a managed role, none otherwise). Construction
creates no audit file or directory; its checked transactions may create only
the foundation's permanent directory lock sidecar. The directory rules are the
same whether or not `<home>/mordred` exists: only the checked-absent default
`<home>/mordred` counts as empty history, while a missing custom directory or
the home itself refuses. The plaintext writer publishes only through C7a
sessions in the C5d audit scope. Each append reenters custody and refuses once
the audit role has been enrolled, before taking the writer mutex; it then
refuses an MRAL or unrecognized active file, and appends, rotates, compresses
and applies retention through the checked session. A missing `<home>/mordred`
is created exact-private at the first append; a custom directory must already be
exact-private. The mutex is released only after custody exits, so a late
outcome settles before another thread appends.

`AuditWriterRefused` is an ordinary exception, so existing Windows guards
convert it: privacy hooks block tools or raise `MordredIntegrityRefused`.
Exactly these reasons are recoverable: `audit-unavailable` (definite busy, I/O,
`access_denied` or missing-directory storage failures), `policy-pending`,
`native-unavailable` (missing helper or transient native failure),
`custody-nesting` (nested canonical-session misuse) and `entry-rejected`
(oversized or unserializable entry). They refuse only the current operation and
never poison: an unrecordable session-start entry refuses the turn that fired
the session hook and releases the one-shot marker claim so the next session
start retries it (CLI/TUI hosts re-gate only when the system prompt is rebuilt,
gateway hosts per turn; strict mode still poisons for disabled or incomplete
plugins), an unrecordable egress approval becomes a block, an unrecordable
Windows `pre_install` entry raises `InstallBlocked`, and a recoverable
construction refusal is retried by the next hook. Everything else is sticky,
including `audit-uncertain`, `audit-unsafe`, `audit-invalid` (for example a
relative or `..`-aliased home), `custody-broken`, `custody-pending`,
`custody-retained`, `native-key-missing`, `retained-ciphertext`,
`history-unrecognized`, `audit-role-enrolled` and `interrupted`: a constructed
writer's `refusal` stays set, a refused construction is remembered for the
process without rescanning history, every privacy hook refuses until
reconciliation and restart, and a refused session start also poisons the
process, as for an unreadable policy. A checked-absent Hermes home on the
default path selects the plaintext writer, whose first append creates `<home>`
and `<home>/mordred` exact-private. Privacy hooks append outside any held
canonical session, so a plain `append` never nests the home lock;
`append_in_custody` serves callers that already own custody. The wizard audit
CLI (C7b part 2) is separate.

#### Windows capability predicates and flat role reset (C5e)

`keyvault._windows_capability` exposes pure predicates. A frozen
`WindowsCapability(name, supported, available, reason)` is returned by
`windows_capabilities(home) -> tuple[WindowsCapability, ...]` in the fixed
order `memory_custody`, `native_audit`, `telegram_hardware`, `file_vault`,
`env_config_workspace_seals`, `recovery`, `presence`, `secret_store`.
`windows_capability(home, name) -> WindowsCapability` returns one entry and
rejects unknown names with `ValueError`. Off Windows both raise
`PrivateFSError("unsupported", ...)`. There is no aggregate readiness flag,
and installed-runtime proof (C5c) is not reported here.

The first three names are supported on Windows. The next four always report
`supported=False, available=False, reason="excluded-on-windows"`;
`secret_store` (the generic `_storage` keyvault: meta, ciphertexts, digests)
is not an excluded capability but has no checked Windows port yet and reports
`supported=False, available=False, reason="not-ported-on-windows"`. All of
these are answered without custody reads. For a supported name, `available` is true only
with reason `enrolled`. It derives from C4 helper presence (the same
`find_winkey_helper` selection custody uses, never a probe), the current
interpreter's structural C4 admission for memory
(`windows_memory_runtime_admitted`, no subprocess) and one load-only
`windows_custody_session(home)` reading `role_status(role)`, `memory_state()`
and `validate_lease(...)`. That session joins a `canonical_session(...,
scope="policy", blocking=False)`: predicates never wait for a lock. A home,
Mordred or in-process canonical lock held by another thread or process yields
`busy`, reported as `custody-uncertain`. No native backend is constructed and
nothing is generated, unwrapped or deleted; the checked lock protocol may
create its permanent lock files as other checked readers do. Reasons are evaluated in
this order: custody failures (`custody-unsafe` for unsafe, access-denied or
unsupported admission; `custody-uncertain` for an unresolved role journal,
uncertain/io/busy outcomes or a pending policy publication; `custody-broken`
for retained evidence that does not validate for this physical profile and
token, such as a copied or malformed manifest, lost wrapper or orphan
marker/journal), then `helper-missing` / `helper-uncertain`, then
`runtime-not-admitted` or `runtime-uncertain` (memory only; an `OSError` while
checking structural admission is uncertain, still unavailable), then
`not-enrolled`. Any other exception
propagates; no failure is reported as available or treated as empty.

Excluded public entry points first call
`refuse_excluded_on_windows(capability, operation)`, which raises
`KeyvaultUnsupportedOnWindows(capability, operation)` on Windows. It is a
`VaultError` subclass with `reason == "excluded-on-windows"` and is raised
before `_storage`, anchor/backend resolution, lock acquisition, native use or
plaintext capture/deletion. Guarded: `vault.init_vault`, `vault.open_vault`,
`OpenVault.enroll_file` and `OpenVault.unenroll_file` (`file_vault`);
`vault.recover_vault`, `vault.recover_to_device`, `vault.change_passphrase`,
`api.export_backup` and `api.import_backup` (`recovery`: file-vault master
and keyvault cross-device recovery; memory plaintext capture/export is a
separate C5b/C6 surface);
`_runtime_env.inject_vault_env`, `_config_bootstrap.materialize_config`,
`_config_bootstrap.reseal_config` and `_env_reseal.reseal_env`
(`env_config_workspace_seals`). The unported secret store refuses through
`refuse_unported_on_windows("secret_store", operation)` with the same
exception and `reason == "not-ported-on-windows"`: `api.generate`,
`api.confirm_generate`, `api.encrypt` and `api.decrypt` refuse before any
`_storage` call or mkdir, and `_storage.ensure_layout` and
`_storage.keyvault_lifecycle_lock` (hence `keyvault_lock`) refuse on Windows
as defence in depth, so no `<home>/mordred` directory or lock file is created
with an unchecked ACL; the wizard's secret-store reset therefore refuses at its
first `_storage` lifecycle step, before any journal, native deletion or tree
removal. `prepare_generate` stays a pure in-memory step. The guards are no-ops
on POSIX. The startup
and session hooks `install_vault_env_decrypt`, `install_config_decrypt`,
`install_env_write_guard` and `reseal_stray_env_if_present` keep their existing
inert non-macOS behavior and never-raise contracts: they return before any
path, vault or plaintext operation, so ordinary Windows startup is unaffected
and off-macOS plaintext stays the live copy. Low-level crypto (MRKW wrap,
memory AEAD, file containers) and injected test backends remain usable.
`_identity.resolve_store` is unchanged; C6 must route Windows wizard
vault/encryption commands to this refusal before any native key generation.

`excluded_artifacts(home) -> tuple[ExcludedArtifactReport, ...]` lists
retained `<home>/mordred` entries through a non-blocking checked canonical
Mordred loan (a held lock raises `PrivateFSError` `busy`):
`vault` (`file_vault`), `env-vault.optout` (`env_seal_optout`) and
`config-vault.marker` (`config_seal_marker`), each reported as
`ExcludedArtifactReport(kind, path, present=True)`. A checked absent home or
Mordred directory reports nothing; every other failure propagates. Reported
artifacts are preserved and unsupported, never adopted, erased or
reinitialized.

`WindowsCustodySession.role_status(role) -> RoleStatus(role, current,
retained, pending)` observes one role from the complete checked manifest and
refuses orphan journals; its leases are observations that still require
normal revalidation. `reset_role(role, *, erase_authorized=False) ->
RoleReset(role, deleted)` deletes every owned generation of exactly that role.
Before the first journal it validates the complete manifest and the syntax of
every role journal, then refuses absent ownership, an unresolved journal for
that role and a role with no owned generation. Audit and Telegram reset
require `erase_authorized`. Memory reset ignores `erase_authorized` and
refuses, pointing to the C6 ceremony, any retained memory generation, any
memory marker and any seal or broken seal; a lost wrapper fails closed through
`memory_state()`. It then deletes one generation at a time through
`delete_role`, retained first and current last, reusing its intent/deleted
journals and memory guards (explicit opt-out, known-stopped gateways).
`RoleReset.deleted` records the confirmed generations. A failure propagates
with its original type and commit state plus a note naming the confirmed
count. If the failed generation's intent journal was written it is retained,
so an ambiguous native result or a crash between native deletion and the
deleted-phase commit refuses the next reset until explicit reconciliation; a
failure before that journal (for example an unknown gateway inventory) writes
no journal and leaves the generation owned. Audit and Telegram reset do not
consult the gateway inventory; C6 and C7b callers must gate them on their own
consumers. Predicates are non-blocking; reset keeps blocking custody locks.
Memory reset preserves audit and Telegram roles; audit or Telegram reset
preserves the other roles. Reset never decrypts or deletes memory files,
performs no recursive deletion and keeps the permanent directory and its lock.

### Windows supported gateway inventory boundary

Ordinary Windows tokens cannot necessarily open foreign process tokens, even
with minimum query rights. WTS NULL SIDs, access denial, service accounts,
process-object owners and image publishers do not prove foreign ownership.
The lifecycle gate therefore describes the supported Windows runtime inventory,
not universal absence of arbitrary interpreters embedded in native applications.

C4-admitted Python/pythonw environments, recognizable Python and Hermes/Desktop
launchers, generic execution hosts and every hinted PID remain plausible.
Denied or unstable plausible records remain unknown. Every positively
current-owned process still receives the full argv/identity scan, regardless of
its image name; custom scripts executed by supported Python are included.
Unknown images in user-writable or untrusted locations remain unknown.

A denied noncandidate image may be outside this supported set only after a
shared foundation capability positively validates its file and ancestor
namespace as administrator/OS-managed and not mutable by the current ordinary
user or other untrusted principals. This is a support-boundary exclusion, not
foreign-owner proof. Stable native PID, creation time and image revalidation
remain required. No vendor basename list, environment-derived trusted root,
signed-file shortcut, missing SID or failed query grants this exclusion.

The new read-only Windows foundation operation
`inspect_managed_installation_image(path) -> FileMetadata` pins and checks the
local NTFS image and ancestor identities, rejects reparse points and unsafe
ownership/ACLs, and returns only after revalidation and successful cleanup.
It grants no mutation authority and changes no permissions. Current-user-owned
or writable installation namespaces cannot qualify. OS/administrative writers
remain trusted under the existing threat model; service ownership such as
TrustedInstaller requires explicit native SID validation. Source hardlinks may
be admitted because this operation only observes a protected executable; stored
private/confidential-file single-link rules remain unchanged. Implement this
separate policy through shared native descriptor/handle primitives, never by
weakening existing confidential or public-build admission.

An opaque renamed or embedded interpreter inside such an admitted managed
namespace is outside the supported set and can be omitted. Its operator must
stop it before lifecycle migration or use a supported launcher. Windows managed
memory hooks and installed-runtime proof must require the supported C4 runtime
boundary; no universal quiescence claim or force-proof bypass is introduced.

Image inspection applies a role-based mutation policy that is separate from
storage admission. The inspected image and its immediate parent directory
refuse every untrusted data, append, extended-attribute, attribute, delete,
delete-child, DACL and owner grant; the immediate parent additionally refuses
untrusted subdirectory creation because the application directory leads the
DLL search order. Directories strictly above the immediate parent refuse only
untrusted DELETE, FILE_DELETE_CHILD, WRITE_DAC and WRITE_OWNER: adding new
entries, extended attributes or attributes cannot rename, delete or replace an
existing child component or change its security, and every component is
verified to be a non-reparse NTFS directory on pinned handles and named
reopens. This admits the Windows default `ProgramData` ACL
(`BUILTIN\Users` container-inherit ADD_FILE, ADD_SUBDIRECTORY, WRITE_EA,
WRITE_ATTRIBUTES) above vendor-protected subtrees such as the Defender
platform directory. Private, confidential and public-build storage admission
keeps refusing untrusted ADD_FILE on ancestors; the relaxation applies to
read-only image inspection only.

Accepted residual: a directory-bit reparse tag set by an untrusted principal
on such an upper ancestor outside the inspection window, combined with a
filter that shadows existing on-disk children, could cause a denied process to
be omitted from the supported inventory. Such an omission never admits a
plausible interpreter, generic execution host, hinted PID or positively
current-owned process, and the inventory only gates destructive memory
migration. No vendor list, service-manager query, session classification or
privileged broker is introduced.

The inventory classifies a denied, non-hinted record in this order: literal
kernel pseudo images (`Registry`, `MemCompression`) are outside the supported
set; plausible basenames (`python*`, `pythonw*`, `py`, `pyw`, any basename
containing `hermes` or `mordred`, and the generic hosts `cmd`, `powershell`,
`powershell_ise`, `pwsh`, `rundll32`, `mshta`, `wscript`, `cscript`) remain
unknown; every other image is submitted to
`inspect_managed_installation_image` and is outside the supported set only
when admitted and after fresh PID, creation-time, name and image
revalidation. Any refusal, unsupported result or query failure keeps the
record unknown. The fixed OS-image list and `GetSystemDirectoryW` lookup are
removed; `System32` images are admitted by the same capability.
##### Windows checked memory operations (C5b)

`windows_memory_session(home, path=None, create=False, custody=None, lease=None,
safe_mode=False)` owns or explicitly joins custody and yields a lifetime-bound
`WindowsMemorySession`. It resolves the native memory key before opening the
memories child transaction, pins an immutable `WindowsMemoryState` (memory lease
or absence, bounded opt-in/opt-out bytes and wrapper SHA-256), and validates the
same state on every operation. `memory_state()` is the narrow public custody
read API; marker mutation and destructive migration are deferred until C5c
provides the approved installed-runtime proof contract. An injected custody
owner must match the checked physical home. A supplied lease must be current
and memory-specific. No ambient key or implicit transaction context is used.

The session exposes checked `read_text`, `read_plaintext`, `write_entries`,
`create_backup` and `inventory`. Reads distinguish checked absence from denial;
plaintext parsing preserves upstream delimiter/whitespace/newline semantics.
All Windows publishers use confidential transactions and immediately report
every successful or uncertain mutation to the canonical publication receipt.
Backups are sealed before create-no-replace publication and are included in the
flat bounded inventory. Timestamp collisions refuse without overwriting.
Physical directory identity pins every supplied target to active memories;
unsafe leaves, aliases to another home, stale leases and closed scopes refuse.

Managed Windows memory requires a structurally admitted current C4 Python
environment (`python.exe`, or `pythonw.exe` with its admitted Python sibling).
Admission runs before custody locks and performs no subprocess proof. Unmanaged
checked plaintext remains usable in other interpreters. Structural admission
does not establish installed-runtime proof or authorize enable/disable/purge.
C5b arming and destructive migration helpers remain unavailable until the C5c
proof contract is implemented and reviewed; this slice is storage and hooks.

Hook installation on Windows has one continue rule: upstream's raw memory seam
may run only on a checked fresh unmanaged profile, meaning a cleanly closed
custody owner observed no memory ownership, marker, opt-out, wrapper or pending
journal and a complete bounded inventory with no seal or broken seal. Every
other outcome with an unsupported or partially wrapped seam (managed custody,
retained seals or markers without ownership, lost wrappers, unreadable or
inadmissible custody, ACL/identity failures or an unresolvable home) stops the
process: stderr diagnostic, then `SystemExit` on the main thread or `os._exit`
off it, never a catchable exception that plugin or post-import containment
could swallow. Safe mode does not bypass this. Only Mordred's own
classification import reports instead of stopping. On a fresh unmanaged
profile, plaintext stays plaintext under upstream's raw seam, which is the
documented unmanaged behavior.

Windows journey mutations follow the same rule. A supported journey signature
is wrapped and memory nodes refuse with upstream's `{"ok": False, ...}`
contract, keyed on the computed memory path as well as the `memory:` prefix.
With an unsupported signature, a fresh unmanaged profile leaves upstream
untouched. Otherwise `delete_node`/`edit_node` are replaced by refusal stubs
that validate nothing, reach no I/O and log once; skill nodes are refused too.
If the stubs cannot be installed, the process stops. Keyless unmanaged drift
returns upstream's `BACKUP FAILED — file unchanged on disk` contract: no
plaintext backup is published and no key is enrolled.
A `KeyboardInterrupt` or `SystemExit` during a Windows memory publication is
recorded as uncertain and surfaces at the hook boundary as
`MemoryEncryptionUnavailable`, trading interrupt responsiveness for retained
uncertainty (fail-closed).

##### Windows installed-runtime memory proof (C5c phase 2)

`keyvault._windows_proof.prove_windows_memory_runtime(home, *, python=None,
timeout=20.0) -> WindowsRuntimeProof` runs outside every custody and memory
lock; a canonical session live in the calling thread refuses (`locks-held`).
It is the only way to obtain a proof. `WindowsRuntimeProof` is a frozen
dataclass with exactly `python: Path`, `module_path: str`, `helper_path: str`,
`seam: str`, `home_identity: FileIdentity`, `principal_sid: bytes`,
`profile_nonce: bytes`, `memory_generation: str`, `wrapped_digest: bytes`,
`challenge: bytes`, `epoch: int` and `proved_at: float` (monotonic). Direct
construction and `dataclasses.replace()` raise `TypeError`, and consumers
accept only the exact issued object, so copies and pickles refuse. Refusals
raise `WindowsRuntimeProofError` with a stable sanitized `reason`;
`GatewayDiscoveryUnavailable`, `CustodyError` and classified `PrivateFSError`
propagate unchanged. There is no force, bool or callback substitute.

1. Capture, load-only: a `windows_custody_session(home)` closed before any
   launch must show committed memory ownership with a wrapper
   (`custody-not-enrolled`) and no unresolved journal for any role
   (`custody-pending`). The read-only
   `WindowsCustodySession.profile_binding() -> ProfileBinding(home, sid,
   profile_nonce, epoch, pending)` returns the bound manifest identity, SID,
   nonce, existing v1 manifest `epoch` and roles with journals, without
   inventory or native calls. No schema change is needed.
2. Interpreter: `python`, else `MORDRED_HERMES_PYTHON`, is an authoritative
   override for C4 `resolve_windows_python`; failure refuses
   (`interpreter-invalid`) without fallback. An override naming `pythonw.exe`
   must exist and maps to its `python.exe` sibling. Without an override the C4
   home-venv candidates apply; launcher selection belongs to C6 routing.
3. `require_stopped_windows_gateways(home)` runs before the child starts.
4. Child: C4 `scrubbed_environment`, then every `PYTHON*` variable, every
   `MORDRED_*` variable except the runtime's own `MORDRED_WINKEY_HELPER`
   selector, `HERMES_MEMORY_KEY` and the inherited `HERMES_HOME` are removed;
   the child receives `HERMES_HOME=<home>`, `MORDRED_CONFIG_DECRYPT=0`,
   `PYTHONUTF8=1`, `PYTHONIOENCODING=utf-8`, `PYTHONNOUSERSITE=1` and
   `PYTHONDONTWRITEBYTECODE=1`. The probe is a C1 create-no-replace file in a
   new exact-private `mordred-proof-<random>` directory under the user temp
   directory, named `hermes` so the installed runtime `.pth` engages its real
   startup bootstrap, and is removed afterwards; that cleanup also covers a
   failed or uncertain probe write. The 32-byte challenge is one hex line on
   stdin; at most 4 KiB of stdout and 2 KiB of stderr are kept; the timeout
   kills the child. A launch `OSError` refuses as `launch-failed`, and an
   output stream still open after the child exits refuses as
   `output-unterminated`. The child moves its stdout descriptor to stderr,
   then requires `mordred_hermes.__file__` physically under its C4
   environment root, `memory_hook_installed()` after the installed bootstrap
   wrapped every seam of a supported shape, a resolved winkey helper,
   committed custody, `load_memory_key()` and an in-RAM `seal`/`unseal` of the
   challenge as `MEMORY.md`. It writes nothing and prints one JSON line with
   exactly `module`, `helper`, `seam`, `generation`, `wrapped_sha256` and
   `challenge_sha256 = SHA-256(challenge || "proof")`. Failures print only
   `mordred-proof:<code>:<exception type>`; no key bytes are ever printed.
5. Verification: exit status 0; exactly one newline-terminated strict JSON
   object with no duplicate or extra keys and non-empty string values; a
   constant-time challenge digest match; the captured generation and wrapped
   digest; seam `A`, `B` or `C`; a module path physically under the validated
   environment root, so an editable source checkout cannot prove; and an
   existing absolute helper equal to `MORDRED_WINKEY_HELPER` when that is set.
   A fresh load-only capture must equal the first (`proof-stale`).

`validate_windows_runtime_proof(custody, proof)` is the consumption check under
caller-held locks: the issued, unexpired proof (age 0 to 600 monotonic seconds)
must match the live identity, SID, nonce, manifest epoch, memory generation and
wrapper digest, with no pending journal (`proof-stale`, `proof-expired`,
`proof-not-issued`). `require_issued_proof(proof)` is its lock-free issued/TTL
part. Test-only `MORDRED_TEST_INJECT_BACKEND` survives the child scrub only
while pytest runs (`PYTEST_CURRENT_TEST`), the package runs from a source
checkout (`src/mordred_hermes` beside `pyproject.toml` and `tests/__init__.py`),
and the value is an absolute, non-symlink, non-traversing `.py` file resolving
under that `tests/` directory. Every other case drops it.

##### Windows proof-bound memory lifecycle (C5b-2)

`keyvault._memory_storage` adds `enable_memory_encryption(home, proof) ->
EnableReport(sealed, already_sealed, reconciled, armed)`,
`disable_memory_encryption(home, proof, *, keep_key=True) ->
DisableReport(decrypted, already_plaintext, reconciled, opted_out)`,
`verify_memory_purge_candidates(home) -> PurgeReport(managed, armed,
opted_out, sealed, broken, plaintext, backups, pending, reasons, may_purge)`
and `MemoryLifecycleError(MemoryStorageError)` with `operation`, `completed`,
`remaining` and `uncertain`. Reports carry counts or file names only.

Enable and disable check the issued proof and its TTL before any lock, own
`windows_custody_session(home)` and join it with
`windows_memory_session(home, custody=...)` (home -> mordred -> memories),
then revalidate the proof with `validate_windows_runtime_proof` and run
`require_stopped_windows_gateways` before any mutation. No installed-runtime
or Python subprocess runs under lifecycle locks; native CNG helper operations
remain under lifecycle locks as c5-design allows. Before the first mutation they refuse unrecognized lifecycle
siblings or siblings without a target, authenticate every existing seal under
its basename, refuse broken seals, non-UTF-8 files, decrypted text starting with
the seal magic, per-file or aggregate bound overflow and a directory with no
room for a staging entry, and prepare every replacement in RAM. Enable seals
the text the Windows hook reads, normalizing newlines of UTF-8 plaintext before
sealing; disable publishes the unsealed text as-is.

Each file is converted by a C1 create-no-replace staging sibling
`.mordred-memory-{seal|open}-<hex of the UTF-8 name>` (never a memory leaf),
read-back verification, a recheck of the target's identity, size and mtime,
an atomic checked `replace_bytes` of the target with the same verified bytes,
read-back verification that authenticates seals, and identity-bound sibling
deletion. The confidential transaction contract has no rename and a no-replace
rename cannot replace an existing file, so the target is never absent: it
holds its old form or the verified new form, and plaintext is never removed
before its sealed replacement authenticates. Each mutation reports to the
canonical publication receipt; post-publication failures are uncertain. The
next transition removes leftover siblings whose target exists, because the
target is authoritative. A final rescan requires every file converted and no
staging entry left.

With the memories lock released and home and mordred still held, the proof and
gateway gate are checked again and the markers transition. These are the only
Windows writers of `memory-vault.marker` (`memory-encryption enabled\n`) and
`memory-vault.optout` (`opt-out\n`): the opposite marker is deleted by expected
identity first, then the requested marker is created no-replace and verified
(an existing marker of at most 4 KiB is kept), so both never coexist. Enable
removes the opt-out and creates the marker; disable removes the marker and
creates the opt-out. After the first mutation any failure raises
`MemoryLifecycleError`: every file stays plaintext or an authenticated seal,
enable failures leave the profile unarmed, and disable file failures keep
custody, remaining ciphertext and the armed marker. Reruns validate every
seal and finish the transition.

`keep_key=False` refuses before any lock; disable never deletes the key.
`verify_memory_purge_candidates` takes no proof and performs no native call or
mutation: it reads custody state and a complete bounded checked scan of the
memories directory. `may_purge` requires managed custody, no opt-in marker,
an opt-out marker and no sealed, broken or staging entry. The purge itself stays
C5e `reset_role` plus C5a `delete_role`, invoked by C6 after this report and a
fresh stopped-gateway gate.

`pending_lifecycle_siblings(home) -> tuple[str, ...]` is a read-only status
helper returning only the names of lifecycle staging entries in the checked
memories directory (an empty tuple when it is absent). An interrupted disable
can leave a plaintext `open` sibling beside a still sealed target, and an
interrupted enable a `seal` sibling beside its plaintext target; status must
report them. Only the next `enable_memory_encryption` or
`disable_memory_encryption` removes them, and purge verification reports them
as blockers.
### Windows Telegram credential custody and checked archive (C10b)

Windows Private Telegram mirrors the Linux security and persistence contract
above with the independent C5a custody `telegram` role in place of the
Enclave/TPM helper key. `extension.telegram.tee.default_secret_store()` is the
selection seam: `win32` returns
`extension.telegram.windows_secrets.WindowsCustodySecretStore(home=None,
backend=None, audit_sink=None)`; macOS/Linux return the unchanged
`TeeSecretStore()`. `TelegramService` and the Hermes tool status use the seam;
wizard and Desktop callers adopt it in their own slices (C6-telegram, C11).

The store keeps the `TeeSecretStore` duck-typed contract (`load(fresh=)`,
`load_snapshot`, `update(mutate)`, `update_from_snapshot`, `store`, `flags`,
`sync_scope`, `save_sync_scope`, `ensure_key`, `invalidate`), the
`secrets.encode` payload and the file layout:
`<home>/mordred/telegram/credentials.sealed` is
`MTC1 || u16 len || wrap_blob || nonce(12) || AES-256-GCM` with the existing
AAD, and `credentials.meta.json` holds the same non-secret flags and sync
scope. `wrap_blob` is the 127-byte MRKW wrap of a fresh data key under the
logical id `mordred-hermes.telegram.credentials.v1` and the current telegram
generation's profile-scoped native selector. Every operation opens a load-only
`windows_custody_session(home)`, refuses an unresolved telegram journal
(`custody_uncertain`) or absent role (`telegram_not_enrolled`), validates the
lease and the exact native public fingerprint, and never generates a key; the
explicit enrollment ceremony (`enroll_role("telegram")`) is the wizard's. A
failed native lookup or missing helper is `tee_unavailable`, never absence.
Copied homes, another token SID or malformed ownership are `custody_broken`;
a seal wrapped to another profile or role is `secrets_corrupt`. Nothing
decrypted is cached and unwrap audit entries are emitted only after the
custody scope exits. Retained telegram generations are not consulted for
unsealing; credentials are bound to the current generation.

Per-use presence is excluded: `ensure_key()` (default `require_presence=True`)
refuses `presence_unsupported`, caused by `KeyvaultUnsupportedOnWindows`
(`presence`), before any native call; `ensure_key(require_presence=False)`
only verifies the enrolled role. The Windows store has no `delete_key`.

Credential files are read bounded and identity-checked and published inside
the checked exact-private Telegram directory transaction through staged
create-no-replace (new) or checked replacement (existing), then verified;
every publication is reported to the owning custody receipt. Lock order is the
archive sync lock (non-blocking), canonical home, mordred, telegram, dialogs.
Unsafe state refuses (`custody_unsafe`) without ACL repair; an unexpected
concurrent change refuses rather than being overwritten.

The archive (`index.enc`, `dialogs/<hmac>.enc`) keeps its MTG1 crypto, AAD and
naming. On Windows `ArchiveStore` admits `telegram` and `dialogs` as checked
private directories (with their `.gitignore`), reads at most 64 MiB per file
with an unchanged-identity check, and publishes the same way. A missing file
or directory is absence only for a definite uncommitted open/stat/read miss;
corrupt, truncated or swapped ciphertext is `store_undecryptable`, never an
empty index. Classified refusals map to `store_path_unsafe`,
`store_write_uncertain` or `store_unavailable`. The one-sync-at-a-time lock
is the permanent `.mordred-fs.lock` of the private `telegram/sync-lock`
directory, taken non-blocking with an in-process registry: contention in any
thread or process is `sync_in_progress` and `archive_busy` is true. Data
transactions use other directory locks, so status, questions and credential
updates never wait for a sync. `archive_updated(root)` replaces the raw
`index.enc` stat used by the Hermes tool coverage.

`store.wipe_archive(root=None, *, forget=False, backend=None)` on Windows
takes the sync lock and holds the telegram then dialogs transactions while it
enumerates (bounded to 65,536 entries per directory) and validates every leaf
before the first checked deletion: segments, then `index.enc`. Unknown names,
`.gitignore`, locks and directories stay; there is no recursive removal.
`forget=True` requires the profile's `<home>/mordred/telegram`, validates the
custody manifest and refuses an unresolved telegram journal before deleting
anything, adds `credentials.sealed` and `credentials.meta.json` to the same
validated plan, and only then calls `reset_role("telegram",
erase_authorized=True)` when the role owns a generation. Nothing is unsealed;
memory and audit roles are untouched. An ambiguous native deletion keeps its
intent journal and refuses the next forget until explicit reconciliation.
Without `forget` the credentials and role are kept. On macOS/Linux
`forget=True` is refused (`forget_unsupported`); their existing
`update(None)`/`delete_key` path is unchanged.

On Windows the raw POSIX helpers fail closed: `store._ensure_private_dir`
raises `store_path_unsafe` (so a directly constructed `TeeSecretStore` refuses
before any filesystem use) and `VaultSecretStore` refuses `vault_unavailable`
(caused by the excluded `file_vault` capability) before any path use. The
Telethon session never appears in logs, exceptions or metadata. Wizard
telegram ceremonies, a live Telegram account gate and Windows 11 acceptance
remain separate gates.

Forget preflight and labels (C10b round 2): before deleting anything,
`wipe_archive(forget=True)` validates the complete manifest and every role's
journal, refuses an unresolved telegram journal, discovers the helper,
verifies each owned telegram generation's native fingerprint and checks epoch
headroom for one deletion per generation, so a missing helper or native key,
a malformed memory/audit journal or exhausted epochs refuse with the archive
and credentials intact. Any failure once `reset_role` has started is
`custody_uncertain` (its journal is kept), never `tee_unavailable`. A checked
absent `telegram/` directory creates no directory, `.gitignore` or
`sync-lock/`; an owned role is still reset. A sync-lock release failure is a
classified store error and `TelegramService` records it as `last_error`
while still setting `finished_at`. Definite uncommitted `missing`/`io`/`busy`
storage failures are `store_missing`/`store_io`/`store_busy` for both the
archive and the credential store; a changed custody session identity during
helper discovery is `custody_broken`. A telegram role rotation
(`enroll_role("telegram", retain_current=True)`) leaves the credentials sealed
to the retained generation, so they and the archive (whose `store_key` they
hold) become unreadable (`secrets_corrupt`): C6 must re-seal the credentials
under the new generation before retiring the old one, or not offer rotation.

#### Windows wizard routing, ceremonies and uninstall (C6)

C6 is the wizard consumer of C5. It adds no keyvault API: every Windows
keyvault or memory decision goes through `windows_capabilities` /
`windows_capability`, the load-only `memory_state()` and
`verify_memory_purge_candidates`, `require_stopped_windows_gateways`,
`prove_windows_memory_runtime`, `enable_memory_encryption`,
`disable_memory_encryption` and `reset_role`. macOS and Linux behavior is
unchanged.

Frozen command name: the explicit native custody initialization ceremony is
`hermes-mordred keyvault native init [--role memory|audit ...]` (repeatable,
default `memory`; Telegram custody stays with the Telegram setup ceremony). It
lives under `keyvault` because it creates hardware custody keys, and in its own
`native` group because `keyvault init` is the unported secret-store ceremony
and `keyvault enable-winkey` only builds and probes the helper. The ceremony
reads the capabilities first and refuses `custody-unsafe`, `custody-broken`,
`custody-uncertain`, `helper-missing` and `helper-uncertain` with the
classified remedy before any custody write; `runtime-*` does not block inert
enrollment. Each requested role is enrolled in its own custody scope through
C5a `enroll_memory()` / `enroll_role("audit")` only when it is absent; an
enrolled role is reported unchanged and never re-created. A missing Hermes home
refuses instead of being created. C5a still refuses any retained evidence
without ownership before native generation. Output is metadata only (role,
generation, public-key SHA-256) plus the no-presence/no-portable-recovery
notice and the excluded/unported capability lines. `encryption enable memory`
(and therefore `setup`) prints the same notice whenever its ceremony step
creates the memory key, even if a later step refuses. Enrollment writes no
marker and changes no memory file. An audit writer or callback never enrolls.

Windows routing per entry point (each refusal names its step and reason, and
says what is unchanged):

| Entry point | Order |
| --- | --- |
| `encryption enable memory` | capabilities (`windows_capability(home, "memory_custody")`; custody/helper failures refuse, `runtime-*` warns) -> gate (`runtime_gate` on `win32`: `--force-runtime-unverified` refuses, then `require_stopped_windows_gateways`) -> ceremony (inert memory enrollment if absent) -> proof (`prove_windows_memory_runtime`, outside every lock) -> lifecycle (`enable_memory_encryption`) |
| `encryption disable memory` | capabilities plus the load-only purge scan (an unmanaged clean profile is a no-op; sealed files without custody refuse as `custody-broken`; an already disabled clean profile is a no-op) -> helper check -> gate -> proof -> `disable_memory_encryption(keep_key=True)` |
| `encryption purge memory --yes` | capabilities -> gate -> `verify_memory_purge_candidates` (any reason refuses with the remedy: disable first, finish interrupted staging, or restore broken seals by hand) -> `reset_role("memory", erase_authorized=False)` in a fresh custody scope |
| `encryption status`, `status`, `setup` | `windows_capabilities` (non-blocking) and the purge scan joined to a non-blocking canonical session; no unwrap, backend, subprocess or lock wait |
| `uninstall` | restore = the `disable` row (with `--purge-data` also for enrolled custody never explicitly disabled); `--purge-data` runs the `purge` row right after it, before any Hermes file, launcher or package step; `--erase-encrypted` refuses |
| `vault init`/open/change-passphrase/recover, env/config seal verbs, `keyvault init`, `keyvault reset` | `refuse_excluded_on_windows` / `refuse_unported_on_windows` as the first statement, before any backend/store resolution, lock (including the Linux memory-key lock and the keyvault lifecycle lock), prompt, `_storage` read or key generation |

Interpreter routing for the proof: `MORDRED_HERMES_PYTHON` remains
authoritative inside the proof. Otherwise a Hermes launcher (`hermes.exe` on
`PATH` or Hermes's managed launcher) is authoritative: its C4-validated
interpreter is passed as `python=`, and a launcher without one refuses as
`interpreter-invalid` rather than falling back. Without a launcher the proof
uses the C4 home-venv candidates. Desktop launcher routing remains C11.

`runtime_gate(..., supported_platforms=...)` lists `win32` only for the memory
caller. On `win32` it never accepts a bypass: `force_runtime_unverified`
refuses for every caller before any inventory, and a caller listing `win32`
gets only the stopped-gateway gate, where an unknown, running or failed
inventory refuses. The installed-runtime check is the separate proof.

Lifecycle failures keep the keyvault guarantees: a refusal before mutation
leaves files, markers and custody unchanged (after the ceremony step, the inert
key is kept for a retry); a `MemoryLifecycleError` reports completed and
remaining files, whether the last outcome is uncertain, that every file is
plaintext or an authenticated seal and that enable left the profile unarmed
(disable keeps custody, remaining seals and the armed marker), and asks for a
rerun with a fresh proof. The wizard never writes memory files or markers
itself. `erase_authorized` stays `False` for memory: no flag authorizes
deleting memory custody while seals remain, and purge never deletes memory
files. A reset failure after its intent journal keeps the journal, which blocks
the next purge until explicit reconciliation (not yet exposed by the wizard).

Status output on Windows: the `keyvault` line reports the secret store as
`not-ported-on-windows` (a retained store is reported as preserved, never
read), followed by one line per capability in the fixed C5e order with its own
supported/available/reason and remedy; there is no aggregate readiness line.
`encryption status` reports `env`, `config` and `workspace` as
`excluded on Windows (excluded-on-windows)`, naming retained file-vault,
`.env` opt-out and config-marker artifacts as preserved. The memory target is
`off` (not enabled, or inert enrollment), `on` (armed, no plaintext, broken
seal, staging or helper problem), `exposed` (armed with plaintext on disk),
`paused` (opted out) or an `UNAVAILABLE (<reason>)` detail for unsafe, broken,
uncertain or busy custody. The current interpreter's `runtime-*` reason is
shown but does not make an armed profile inactive: the installed runtime is
proven by enable, not by status.

`setup` on Windows skips the keyvault step (secret store not ported) and the
env step (excluded) without stopping; the memory step is `done` when armed and
clean or opted out, `manual` without the helper or under `--non-interactive`,
`blocked` (stopping the run) for unreadable/unsafe/broken custody, and
otherwise runs `encryption enable memory`. `encryption enable all` skips the
excluded env/config targets and runs the Windows memory flow.

Uninstall on Windows restores memory only (the env/config seals are excluded;
retained artifacts are reported). A refusing gate, proof or custody state stops
it before anything is removed. `--purge-data` deletes only the memory custody
key after the verified restore; audit and Telegram custody and history, a
retained secret store or file vault, and the `<home>\mordred` and
`<home>\extension` trees are kept and reported, because Windows has no checked
recursive removal yet. The plan lists exactly that. `--erase-encrypted`
refuses on Windows, including `--dry-run`.

Purge ordering on Windows uninstall: purge requires an explicit disable (the
opt-out marker) and no seal, broken seal or staging entry. With `--purge-data`
the restore is therefore planned whenever memory custody is managed and not
opted out, including inert enrollment (`keyvault native init`, or an enable
that refused at the proof); without `--purge-data` inert custody needs no
restore and no proof. The memory purge (stopped-gateway gate, purge
verification, `reset_role`) runs as part of step a, immediately after the
restore and before the Desktop page, `config.yaml`/`.env` cleanup, launcher
removal, helper removal or package uninstall, so a refusing gate, proof
(including a proof child that cannot start), verification or reset leaves
Hermes's files, launchers and the package installed. Its custody read waits for
the lock like the other lifecycle commands; the plan reads without waiting and,
when custody is unreadable, says the purge will re-check and refuse. The
typed-confirmation warning names the memory key only when step 5 lists its
deletion. Recorded C6 gaps: an armed profile with a broken seal, staging
entries or a missing helper renders `paused` in `encryption status` rather
than `on` (the fix changes setup's rerun decision and is deferred), and
`--purge-data` removes the owned CNG helper while kept audit/Telegram custody
still needs it.

### Windows Desktop integration and extension server shutdown (C11)

C11 is the Desktop and extension-server consumer of C4-C6 and C10. It adds no
keyvault, wizard or Telegram API: `desktop/api.py` routes `win32` to
`desktop/_windows.py` (API) and `desktop/_windows_assets.py` (placement), and
macOS/Linux never reach either module. Their behavior is unchanged.

Status. `/status?client_version=3` on Windows returns `hardware_kind: "cng"`,
`user_presence_supported: false` with `presence_reason` (the `presence`
capability's reason, `excluded-on-windows`) and `capabilities`: one
`{name, supported, available, reason}` row per `windows_capabilities(home)`
entry in the C5e order, or `[]` with `capabilities_error` set to the
classified reason. There is no aggregate readiness boolean.
`telegram_platform_supported` and `telegram_supported` are true only when
`default_secret_store()` selected the C10b store and `telegram_hardware` is
supported. The response also carries `helper` (below), `memory` (the load-only
C6 observation: `off`, `enrolled`, `on`, `exposed`, `degraded`, `paused` or
`unavailable` with its reason; `active` only when armed, clean and readable),
`telegram_custody` (`enrolled`, `reason`, `ceremony_available: false`,
`ceremony_command: null`), the required `acknowledgements`, the frozen
`custody_notice`, `uninstall` metadata (`erase_supported: false`,
`purge_scope: "memory_custody_key"`), per-step `checks` and the existing model
check (Venice private or a loopback local model). Older clients
(`client_version < 3`) keep the unsupported shape and reach no capability,
memory, credential or provider code. Status reads only the non-blocking
predicates, the non-blocking memory scan, the helper selection with its
installer receipt and Telegram `flags()`. It never unwraps, generates,
deletes or launches a subprocess.

Helper. `/hardware/build` on Windows never builds or installs. It returns
`built: false` and `helper = {state, path, install_command}`. `state` is
`validated` (the default `<home>\bin` executable with a verified C4 installer
receipt), `installed` (a helper selected by the override, `PATH` or without a
receipt), `missing` or `uncertain`. The documented command is
`hermes-mordred keyvault enable-winkey`, or the native installer.

Memory. `/memory/enable` requires `acknowledge_cng_no_recovery: true` and
`acknowledge_no_presence: true`; otherwise it answers
`telegram_platform_unsupported` before any custody read. It then runs in a
worker thread, one transition per process (`memory_operation_in_progress`),
in the C6 order:

1. capabilities: `windows_capability(home, "memory_custody")`; custody and
   helper failures refuse;
2. gate: the C5c typed inventory; `unknown` refuses as `gateways-unknown` and
   any runtime as `gateways-running`, and no force flag is read;
3. ceremony: `enroll_roles(home, ("memory",))`; `custody_notice` is returned
   whenever the key is created, even if a later step refuses;
4. proof: `prove_windows_memory_runtime`;
5. lifecycle: `enable_memory_encryption`.

A refusal is `{ok: false, error: "memory_encryption_refused", step, reason,
remedy, detail?}` plus `gateways` at the gate, `enrolled`/`custody_notice`
after the ceremony, and `completed`/`remaining`/`uncertain`/`armed` for a
partial lifecycle failure (`lifecycle-partial`). Success returns
`restart_required: true`, the counts and the proven interpreter.
`/memory/disable` is symmetric: load-only scan, helper, gate, proof, then
`disable_memory_encryption(keep_key=True)`, with error
`memory_disable_refused`. Purge stays the CLI ceremony. `GET /memory/status`
returns the memory state and the typed gateway inventory
`{state, running, found, pids, reasons}`; `running` is `null`, never zero,
whenever the inventory is `unknown`.

Desktop proof routing (deferred from C6): `MORDRED_HERMES_PYTHON` stays
authoritative. Otherwise the interpreter serving the Desktop API (the
Desktop-managed Hermes runtime) is passed as `python=` and validated by the
proof, with no fallback to a `PATH` launcher or the home venv; an empty
interpreter path refuses as `interpreter-invalid`. The wizard exposes no
structured (step, reason) result, so the Desktop composes the same order from
the wizard's and keyvault's public parts.

Telegram. The Desktop uses `default_secret_store()` everywhere
(`TeeSecretStore` on macOS/Linux, as before). On Windows, login start and the
question-model routes (`/llm/venice`, `/llm/local`) refuse until
`telegram_hardware` is `enrolled` (`telegram_not_enrolled` with
`ceremony_available: false`, `custody_unsafe`, `custody_uncertain`,
`custody_broken` or `tee_unavailable`), then until the request carries
`acknowledge_no_presence: true` (`presence_acknowledgement_required`). Only
then does the `NoPresenceStore` wrapper call
`ensure_key(require_presence=False)`; its `ensure_key()` takes no argument, so
no caller can request presence and receive an unattended check. Login also
requires the load-only Windows memory state (`memory_encryption_required`)
and the private model, and the import service receives the same memory guard.
`POST /telegram/logout` (Windows only) revokes the session at Telegram on a
best-effort basis. It then either drops the session and keeps the archive,
or with `forget: true` runs `store.wipe_archive(forget=True)`: the archive,
the sealed credentials, then only the `telegram` role. `delete_key` is never
called, and a credential read refusal deletes nothing. No wizard verb enrolls
the `telegram` role yet, so Windows Telegram setup stops at the custody step.

Placement. `desktop install` and the plugin's `ensure_page` place
`<home>\desktop-plugins\mordred\plugin.js` and
`<home>\plugins\mordred\dashboard\{manifest.json,plugin_api.py}` under the
shared home resolver (no second root). The Hermes-owned `desktop-plugins`
and `plugins` folders are admitted through `open_confidential_directory(...,
create=True)`. `plugins\mordred`, its `dashboard` and
`desktop-plugins\mordred` are checked private directories, created one level
at a time. A file is written with `create_bytes`/`replace_bytes` only when it
changed, then read back. Unsafe existing state refuses with the exact quoted
path and classified reason; no ACL is repaired. Removal (`desktop uninstall`
and `hermes-mordred uninstall` step b) deletes, by checked identity, only the
three enumerated files and the legacy `plugins\mordred\desktop\plugin.js`.
Directories, their permanent `.mordred-fs.lock` and unknown files are kept and
reported, and a refused folder is reported without stopping later steps.

Page. `plugin.js` requests `client_version=3` and selects the Windows page by
`hardware_kind === "cng"`. It renders each capability row through explicit
label tables, shows the custody notice and both acknowledgements before the
enable button, and renders the refusing step, reason and remedy from the
refusal metadata. It labels the custody, Telegram store and shared pairing
codes (`storage_unavailable`, `storage_uncertain`, `storage_error`,
`attestation_key_missing`) and hides erase-without-decrypt on Windows. A login
expiry resets by code, never by matching message text.

Extension server. `extension serve` stops with exit 0 on Ctrl-C
(`KeyboardInterrupt`), on SIGTERM (POSIX `add_signal_handler`) and, on
Windows, on `CTRL_BREAK_EVENT`. The proactor loop has no
`add_signal_handler`, so `SIGBREAK` goes through `signal.signal` and
`loop.call_soon_threadsafe`. The previous handlers are restored and
`server.stop()` closes the listener, so the same port can be bound again
immediately. A bind failure is classified and exits 1 without trying another
port: `port-in-use` (EADDRINUSE/WSAEADDRINUSE, with an `lsof` or
`Get-NetTCPConnection` hint), `port-forbidden` (EACCES/WSAEACCES, including
Windows excluded port ranges) or `bind-failed`. The gateway plugin has no
runtime-discovery hook; `GET /memory/status` is the only Desktop surface that
reports running gateways.
