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
- Windows and mobile support are deferred. Pure cryptographic and storage
  modules remain testable with injected backends on other platforms.

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
            enable-se | enable-tpm | eth
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
- Windows/mobile product support and a supported Windows helper workflow;
- transparent env/config/memory/workspace lifecycle outside macOS;
- audit hash chains, external anchoring, or same-UID tamper resistance;
- isolated signer/payment authorization;
- automatic migration of native-key protection tiers.

Future candidates and their release gates live in
[`ROADMAP.md`](./ROADMAP.md); actionable unfinished work lives in
[`TODO.md`](./TODO.md).

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
`ConfidentialDirectory` provides `stat`, bounded `read_bytes`, and `transaction`;
`ConfidentialTransaction` adds `create_bytes`, `replace_bytes`, and
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
