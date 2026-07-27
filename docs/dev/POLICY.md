# Mordred — Policy Schema Reference

Canonical reference for:

- The frozen audit-log `reason` enum (Phase 1.1 step 0 freeze, 2026-05-10)
- The `metadata.mordred.*` SKILL.md extension and its agentskills.io spec deviation
- The `~/.hermes/config.yaml plugins.mordred_privacy_check` config schema

Companion to `SPEC.md §Audit log policy` and `src/mordred_hermes/privacy_check/_audit_reasons.py` (the typed source of truth).

---

## Audit log `reason` enum (frozen)

The set is closed at the type level via `Literal` in `_audit_reasons.py:ReasonCode`. Any drift between this list and the writer surfaces as a mypy error at PR time.

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 1 | `policy.strict.clearnet` | 1.1 | Strict policy; skill declares `network_requirements: clearnet` (install) OR strict + clearnet path + tool ∈ default blocklist (`pre_tool_call`). |
| 2 | `policy.strict.unknown_metadata` | 1.1 | Strict policy; skill missing `metadata.mordred.network_requirements`. |
| 3 | `policy.lenient.unknown_metadata_warning` | 1.1 | Lenient policy; skill missing metadata — install proceeds, audit `decision=warn`. |
| 4 | `mordred.degraded.disable_unprotected` | 1.1 | Sibling Mordred plugin disabled (deny-list or opt-in allowlist). Strict aborts (`decision=block`); lenient/off warns. |
| 5 | `mordred.degraded.no_origin_skill` | 1.1 | One-shot per process. Emitted at `on_session_start` to record that `pre_tool_call` payload lacks `origin_skill` (HOOK_PAYLOADS §4). |
| 6 | `mordred.degraded.no_resolved_provider` | 2 | One-shot per process. Phase 2 emits when `pre_llm_call` lacks `provider_id`/`model_id` (HOOK_PAYLOADS §5). Frozen now to avoid v1→v2 churn. |
| 7 | `policy.strict.cloud_allowlisted` | 2 | **Action**. Strict + provider in `cloud_provider_allowlist` + `allow_cloud_llm: true`, or strict + `mordred-local` with a validated loopback endpoint → passthrough (`decision=allow`). |
| 8 | `policy.strict.cloud_not_allowlisted` | 2 | **Classification only** (Codex N1, 2026-05-13). Recorded **alongside** the action reason (#10 or #11) so audit consumers can filter on either axis. Emitted as a separate audit entry with `decision=block` (or `override` if #11 applies); the final action is in the immediately-following entry. v1 default ships only #10 (refuse). |
| 9 | `policy.strict.unconditional_override` | 2 | **Action** (PR2 degraded path). Cloud → local override applied unconditionally because `pre_llm_call` payload lacked provider info. |
| 10 | `policy.strict.session_refused` | 2 | **Action** (PR2 v1 default). Strict + cloud provider not allowlisted, unreachable local endpoint, or invalid/non-loopback `mordred-local` endpoint → session refused via `MordredSessionRefused(BaseException)`. |
| 11 | `policy.strict.provider_override_at_session_start` | 2 | **Action — v2 deferred** (Codex B2). Alternative auto-swap path: provider swapped to `mordred-local` at session start. Hermes resolves the active provider before `on_session_start` fires, so the config patch only takes effect next session. Will be reintroduced when (a) Hermes adds a pre-resolve hook upstream, or (b) Mordred ships a vendored fork (`[hard-lock]` extra, Tier B). |
| 12 | `policy.strict.local_stream_interrupted` | 2 | **Action — v2 deferred** (Codex H1). Frozen in the enum so consumers can prepare, but **no raise site exists in v1**: Hermes core owns the streaming pipeline (`agent/error_classifier.py` handles `httpx.RemoteProtocolError`), so a plugin-side `transport.py` cannot reliably emit this. The corresponding `MordredLocalStreamInterrupted` exception class is intentionally absent from `src/mordred_hermes/llm_guard/_exceptions.py` to prevent silent half-implementations. |

Under `strict`, `mordred-local` means loopback-only: both the configured
`local_llm_endpoint` and the resolved runtime `base_url` must be HTTP(S), must
not contain userinfo, and must use either the exact loopback IP literal
`127.0.0.1` / `::1` or `localhost`. Every current DNS result for `localhost`
must itself be loopback. When a process proxy is active, both `NO_PROXY`
spellings are populated with those exact hosts before the probe/model client
runs; the health probe independently disables ambient proxies. Validation
failure emits #10 with `decision=block` and raises
`MordredSessionRefused`. Lenient/off and other non-strict compatibility modes
do not apply this boundary.

### Phase 3 step-0 freeze (added 2026-05-13, PR1)

`network.*` codes appended to `ReasonCode`. Total freeze becomes 16 (12 Phase 1 + 4 Phase 3):

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 13 | `network.use` | 3.1 | **Action**. Successful initial/unfrozen route activation via `api.use(path)`. Decision `override`. Fields: `prev_path`, `new_path`, `live_subprocess_count` (M3 transitive-failure visibility — `> 0` signals env updates would not reach already-running children). Registration freezes the route after activation; same-route reuse is a silent no-op and a conflicting live route raises `PathSwitchRequiresRestart`. |
| 14 | `network.use_failed` | 3.1 | **Action**. `api.use(path)` raised `MordredNetworkError`. Decision `raise`. Fields: `requested_path`, `error_type`, `prev_path`. |
| 15 | `network.bringup_failed` | 3.1 | Lenient-mode path bring-up failure with clearnet fallback. Decision `warn`. Fields: `path`, `error_type`. Strict mode pairs this entry with a `MordredPathBringupFailed` raise from the hook. |
| 16 | `network.path_dropped` | 3.1 | M9 liveness probe detected 2 consecutive failures on active path. Decision `block` in strict (paired with `MordredPathDropped(BaseException)` raise on next `pre_tool_call`); `warn` in lenient. Fields: `path`, `consecutive_failures`, `last_health_at`. |

Naming deviation from `TODO.md` L331: the source used `network_use` (underscore form); PR1 normalized to `network.use` to match the existing `policy.*` / `mordred.*` dotted convention. Future Phase 4 codes will follow the same dotted form.

### Phase 4 step-0 freeze (added 2026-05-14, PR2)

`keyvault.*` codes appended to `ReasonCode`. Phase 4 PR2 contribution (2 codes):

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 17 | `keyvault.recovery_digest_mismatch` | 4 | **Action**. `recovery.import_backup` recomputed the verification digest and it disagrees with the digest embedded in the backup blob. Decision `block` (paired with `RecoveryDigestMismatch(VerificationDigestMismatch)` raise). Fields: `blob_version` (`0` = pre-parse rejection, the recomputed_digest length guard fired before `parse_header` ran and the blob's actual version is unknown; `1` = parsed version-1 blob), `event="keyvault.import_backup"`. Emitted **before** AES-GCM decryption runs — the secret is never materialized on mismatch (Codex review #4). If the audit sink itself raises (e.g. disk-full audit log), the sink exception is chained as `__context__` on the surface `RecoveryDigestMismatch` so callers' digest-mismatch handlers stay correct (code-reviewer HIGH-1, 2026-05-14). |
| 18 | `keyvault.seed_display_aborted_screenshot` | 4 | **Action — PR4 emit site**. `seed_display.py` detects `CGScreenIsBeingCaptured` or `CGDisplayRegisterReconfigurationCallback` firing during the 60s display window. Decision `block`. Fields: `event="keyvault.seed_display"`, `detector` (one of `cg_screen_is_being_captured` / `cg_display_reconfiguration`). SPEC §Seed phrase display security L352 references this; the emit site lands in Phase 4 PR4 alongside `seed_display.py`. |

### Phase 4 PR3 step-0 freeze (added 2026-05-14, PR3)

PR3 contribution (2 codes). Total implementation freeze stays at 20 after PR3 (12 Phase 1 + 4 Phase 3 + 2 Phase 4 PR2 + 2 Phase 4 PR3); PR4 step-0 (below) **documents** 4 additional codes whose `ReasonCode` Literal extension lands with the step-D emit sites in a follow-up PR. Codex review on the PR3 plan (BLOCKER-1 / HIGH-3) corrected the authorization boundary: wrap uses the Enclave **public** key + a software ephemeral private and is unauthorized public-key crypto; only unwrap — `SecKeyCopyKeyExchangeResult` on the Enclave private key — can prompt the user, so PR3 emits decision entries only on unwrap:

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 19 | `keyvault.unwrap_authorized` | 4 | **Action**. `wrap.unwrap_dek` — Enclave returned a valid ECDH shared secret after the user satisfied the access-control gate (Touch ID / Optic ID / passcode). Decision `allow`. Fields: `event="keyvault.unwrap_dek"`, `key_id_hash` (16-char hex prefix of `SHA-256(key_id)` — never the full `key_id`). Emitted exactly once per successful `unwrap_dek` call so audit consumers can rate-limit by `key_id_hash` without leaking the cleartext id. |
| 20 | `keyvault.unwrap_denied` | 4 | **Action**. `wrap.unwrap_dek` — Enclave returned `errSecUserCancelled` / `errSecAuthFailed` / equivalent (cancelled, biometry change locked out, passcode missing). Decision `block` (paired with `WrapAuthCancelled(WrapError)` raise; the cause chain preserves the native `NSError`). Fields: `event="keyvault.unwrap_dek"`, `key_id_hash`, `native_error_code` (translated string — one of `user_cancelled` / `auth_failed` / `biometry_lockout` / `passcode_not_set`; never the raw `OSStatus` integer, which would leak biometric-attempt state across the audit boundary). `key_not_found` is in the closed `NativeErrorCode` set (so backends can signal "missing Keychain item" through `NativeBackendError`) but never reaches this audit emit: `unwrap_dek` branches on it and raises `WrapKeyNotFound` as a pre-authorization failure with no audit entry (review-fix-1 HIGH-1, codex review-fix-2 LOW-1). Enforcement: `NativeBackendError.__init__` validates `code` against the frozen `_NATIVE_ERROR_CODES` set at construction time, so a buggy backend cannot stringify a raw `OSStatus` int and slip it past the audit boundary (codex review-fix-2 MEDIUM-1). |

Scope policy unchanged from PR2 (Codex review #8, 2026-05-14): Phase 4 step-0 freezes ONLY codes that either (a) have a same-PR emit site, or (b) are already referenced by frozen SPEC text. The PR4 reason codes below land in step-0 of PR4 (this section), paired with same-PR emit sites in `api.confirm_generate` and `api.export_backup`. The "frozen but never raised" footgun (Phase 2 entry #12 caveat) is avoided.

### Phase 4 PR4 step-0 freeze (added 2026-05-15, PR4)

PR4 contribution (4 codes; **documented in step-0, `ReasonCode` Literal extension lands with step-D emit sites**). PR4 splits into steps 0/A/B/C/D/E/F/G; step-0 + step-A is a partial-PR slice that lands the docs freeze + split normalization + `verify_digest` only. The audit emit sites for these 4 codes live in `api.confirm_generate` (step-D) and `api.export_backup` (step-D). To honor the PR2 scope policy (Codex review #8, 2026-05-14) — "freeze ONLY codes that either (a) have a same-PR emit site, or (b) are already referenced by frozen SPEC text" — the codes were **documented in step-0 under condition (b)** (SPEC.md §"PR4 API contract" references them by name in the audit table), with the `ReasonCode` Literal extension deferred until each emit site lands. **Step-D update (PR4c-2, 2026-05-15)**: `api.confirm_generate` lands, so codes #21–23 (`keyvault.init_started` / `init_completed` / `init_denied`) are now extended into the `ReasonCode` Literal under condition (a) — the total freeze count in code is **23**. **Step-E update (2026-05-16)**: `api.export_backup` lands, so code #24 (`keyvault.backup_exported`) is now extended into the `ReasonCode` Literal under condition (a) — the total freeze count in code is **24**. `encrypt` / `decrypt` are intentionally NOT audited at the api layer (codex review OD-3): `encrypt` has no authorization gate (wrap is offline), and `decrypt` inherits #19/#20 transitively via the wrap layer. Codex pre-implementation review (3 BLOCKER + 5 HIGH) drove the two-phase `generate` design — see SPEC.md §"PR4 API contract" — which is what creates the four lifecycle moments below:

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 21 | `keyvault.init_started` | 4 | **Lifecycle**. `api.confirm_generate` enters the durable phase (Enclave create + meta.json write). Decision `allow`. Fields: `event="keyvault.init"`, `key_id_hash` (16-char hex prefix of `SHA-256(key_id)` — never the cleartext id). Emitted exactly once per `confirm_generate` invocation, **before** any Keychain or filesystem state mutation. Sink-failure policy: if the audit sink raises during this emit, the entire init operation aborts and no Keychain item / `meta.json` row is created. Rationale: `init_started` is the durability barrier — failing-open here would diverge audit from observable state (no audit, but key exists), which violates the audit-as-evidence contract. Pattern differs from #22/#23/#24 below (success-path emits use `contextlib.suppress`). |
| 22 | `keyvault.init_completed` | 4 | **Lifecycle**. `api.confirm_generate` finished successfully: Enclave key created, `meta.json` row persisted, `digests/<kid>.commit` written. Decision `allow`. Fields: `event="keyvault.init"`, `key_id_hash`, `verification_digest_hex_prefix` (16-char hex prefix of the verification digest — full digest reachable only via `verify_digest` API). Sink-failure policy: init has already succeeded by this point, so a sink exception is suppressed via `contextlib.suppress(Exception)` (mirrors PR3 `wrap.py:555` success-path pattern). A single line is written to stderr so the operator can investigate; the durable state is correct. |
| 23 | `keyvault.init_denied` | 4 | **Action**. `api.confirm_generate` rejected the user-supplied `expected_digest` (recomputed digest does NOT match the prepared digest via `hmac.compare_digest`). Decision `block` (paired with `VerificationDigestMismatch` raise). Fields: `event="keyvault.init"`, `key_id_hash` (16-char hex prefix of the *intended* `key_id` — derived from the prepared digest, NOT from any user input). Emitted **before** the exception propagates and **before** any Keychain or filesystem state is touched (no rollback needed because no mutation occurred). Distinct from #17 (`keyvault.recovery_digest_mismatch`) which is import-backup-specific; the `event` field disambiguates audit consumers. If the audit sink itself raises, the sink exception is chained as `__context__` on the `VerificationDigestMismatch` (mirrors PR2 recovery `_emit_mismatch` failure-path pattern). |
| 24 | `keyvault.backup_exported` | 4 | **Lifecycle**. `api.export_backup` finished — the MRKV blob is materialized in the caller's hand (file persistence is the caller's responsibility; wizard PR lands `hermes mordred keyvault export`). Decision `allow`. Fields: `event="keyvault.backup_export"`, `key_id_hash`, `blob_version=1`, `kdf_id=1` (Argon2id, m=46 MiB / t=1 / p=1), `envelope_count` (number of ciphertext envelopes packed into the manifest). Sink-failure policy: success-path emit, suppressed via `contextlib.suppress(Exception)`; blob is already returned to the caller. The bytes are not persisted by keyvault; the caller (wizard) writes them to a path the user specifies. |

`encrypt` / `decrypt` audit observability comes only from `keyvault.unwrap_authorized` / `keyvault.unwrap_denied` (#19/#20) which the PR3 wrap layer emits when `unwrap_dek` runs. There is no per-encrypt audit (no auth gate to record).

### Phase 4 §4.1 freeze (added 2026-05-16)

`metadata.mordred.requires_keyvault` opt-in enforcement. 2 install-time `policy.*` codes appended to `ReasonCode`; total freeze becomes 26 (12 Phase 1 + 4 Phase 3 + 8 Phase 4 PR2–step-E + 2 Phase 4 §4.1). Both have a same-PR emit site in `install_wrapper.run` (`pre_install` event):

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 25 | `policy.strict.keyvault_uninitialized` | 4.1 | **Action**. Strict policy; the skill declares `metadata.mordred.requires_keyvault: true` but the Mordred keyvault holds no keys. Decision `block` (paired with an `InstallBlocked` raise; audit entry written first). The keyvault-initialized check is backend-free — it reads `meta.json` only (no Secure-Enclave `NativeBackend`, no `cryptography` stack), via `privacy_check/_keyvault_probe.py` — so the decision is reproducible on every platform. A network-level block (`policy.strict.clearnet` / `policy.strict.unknown_metadata`) short-circuits before this check. Fields: `event="pre_install"`, `skill_id`. |
| 26 | `policy.lenient.keyvault_uninitialized_warning` | 4.1 | Lenient policy; same precondition as #25. Decision `warn` — install proceeds, the operator is informed through the audit log (mirrors `policy.lenient.unknown_metadata_warning`). Fields: `event="pre_install"`, `skill_id`. |

### PR #39 review follow-up freeze (added 2026-05-17)

Found in the post-merge review of PR #39 (Phase 4 PR10): the encrypted-audit factory `audit.make_audit_writer` falls open from `EncryptedWriter` to plaintext `NDJSONWriter` when the keyvault is initialized but the encrypted writer cannot be built, and that downgrade was visible only in Python logging. 1 `mordred.degraded.*` code appended to `ReasonCode`; total freeze becomes 27 (12 Phase 1 + 4 Phase 3 + 8 Phase 4 PR2–step-E + 2 Phase 4 §4.1 + 1 PR #39 follow-up). Same-PR emit site in `audit.make_audit_writer`:

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 27 | `mordred.degraded.audit_encryption_unavailable` | 4 | **Degraded**. The keyvault is initialized (or its state could not be read) so an AES-GCM-encrypted audit log was *expected*, but the `EncryptedWriter` could not be built — missing audit-log wrapping key, corrupt keyvault, or an unavailable native backend — so privacy_check falls open to plaintext `NDJSONWriter`. Decision `warn`. The entry is written into that fallback NDJSON writer (best-effort; a sink failure is suppressed so `_runtime._load_state` cannot crash on a degraded path). The clean "keyvault never initialized" path is intentionally silent — it is the pre-keyvault baseline, not a downgrade. Fields: `event="mordred.audit_writer"`, `detail` (the fallback-triggering exception's type + message; never key material). |

### prompt-once freeze (added 2026-06-24)

`cloud_attempt_action: prompt-once` was previously a reserved wizard value with no enforcement (refuse-only, behaving like `always-block`). It now has a live emit site in `mordred_hermes.llm_guard.enforce._resolve_cloud_attempt` (the `pre_api_request` authoritative path): under strict mode, when a non-allowlisted cloud provider is reached, the operator is asked once per provider at an interactive terminal whether to allow that provider for the remainder of the current Hermes process. 2 `policy.strict.cloud_prompted_*` codes appended to `ReasonCode`; the freeze at this historical step became 29 (12 Phase 1 + 4 Phase 3 + 8 Phase 4 PR2–step-E + 2 Phase 4 §4.1 + 1 PR #39 follow-up + 2 prompt-once), before the network follow-up below raised the current total to 30. Same-PR emit site per the scope rule condition (a):

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 28 | `policy.strict.cloud_prompted_allow` | 2 | **Action**. `cloud_attempt_action: prompt-once`; operator approved a non-allowlisted cloud provider for the remainder of the current Hermes process at an interactive terminal (`sys.stdin` and `sys.stdout` both TTY). Decision `allow`. Fields: `event="pre_api_request"`, `provider_id`. Emitted once per provider — the verdict is cached for the process, so cached re-allows stay silent (mirrors the `check_runtime_provider` allow-is-silent rule). |
| 29 | `policy.strict.cloud_prompted_deny` | 2 | **Classification**. Same precondition as #28 but the operator declined, OR no interactive terminal was available (fail-closed). Decision `block`, recorded **before** the existing action pair (#8 `cloud_not_allowlisted` → #10 `session_refused`). Fields: `event="pre_api_request"`, `provider_id`, and `prompt_unavailable: true` when the deny was the no-terminal fallback rather than an explicit decline. An explicit decline is cached (no re-prompt); a no-terminal deny is **not** cached so a later interactive call can still ask. |

### Network transport-gate freeze (added 2026-07-27)

The process-scoped route hardening adds one live `network.*` emit site, bringing
the total freeze to 30. The route is activated and frozen during
`mordred_network.register()` before provider clients are constructed. Session
and request transport refusals preserve that shared route; they never tear down
Tor/VPN and expose another gateway session to clearnet.

| # | Code | Phase | Notes |
| --- | --- | --- | --- |
| 30 | `network.transport_incompatible` | 3.1 | **Action/classification**. Emitted when a provider is incompatible, unverified, unknown, or unresolved on strict + Tor; when configured Tor/VPN does not match the active ready route; or when the transport gate itself fails. Decision `block` for strict protected-route refusal and `warn` for downgraded diagnostics. Fields: `event` (`on_session_start` or `pre_api_request`), `active_path`, `provider`, `severity`, `detail`, `policy_mode`, and `stage` for internal-gate failures. A blocking entry is paired with `MordredPathBringupFailed`; the process route remains active. |

### Audit entry shape

Synthetic example:

```json
{"ts":"2026-04-29T12:34:56.789Z","event":"pre_install","decision":"block","reason":"policy.strict.clearnet","skill_id":"clearnet-skill"}
```

| Field | Type | Notes |
| --- | --- | --- |
| `ts` | string | ISO-8601 UTC with 3-digit millisecond precision, literally `"%Y-%m-%dT%H:%M:%S." + "{ms:03d}" + "Z"` (Python's `%f` is microseconds, so the helper builds the string manually). Auto-added if caller omits. |
| `event` | string | Hook or lifecycle name (`network.register`, `on_session_start`, `pre_tool_call`, ...) or `pre_install`. |
| `decision` | `"allow"` \| `"block"` \| `"override"` \| `"warn"` | |
| `reason` | one of the 30 codes currently in `ReasonCode`, or `null` | `null` only for off-mode allows. The PR4 set (#21–24) is fully frozen as of step-E; the §4.1 set (#25–26) is frozen as of `requires_keyvault` enforcement; #27 is frozen as of the PR #39 review follow-up; #28–29 are frozen as of prompt-once enforcement; #30 is frozen as of the process-scoped network transport gate. |
| `skill_id` / `tool_name` / `provider_id` | string (event-conditional) | Skill name from frontmatter; tool name from payload; provider id (Phase 2). |
| event-specific extras | various | e.g. `disabled_siblings: list[str]` on `mordred.degraded.disable_unprotected`. |

---

## SKILL.md `metadata.mordred.*` extension

Mordred reads three optional fields from SKILL.md frontmatter:

| Field | Type | Phase | Default |
| --- | --- | --- | --- |
| `metadata.mordred.network_requirements` | `"tor"` \| `"vpn"` \| `"clearnet"` \| `"local-only"` | 1.1 | absent (= unknown) |
| `metadata.mordred.requires_keyvault` | bool | 4 (enforced at install — §4.1) | `false` |
| `metadata.mordred.outbound_endpoints` | `list[str]` | 1.1 (read, not yet wired) | `()` |

### agentskills.io deviation

The agentskills.io v1 spec defines `metadata` as a flat `string -> string` map. Mordred deviates by:

- Using a **nested object** (`metadata.mordred.*` rather than `metadata.mordred-*`)
- Using **non-string types** (bool, list[str]) inside the nested object

The agentskills spec explicitly endorses vendor-namespaced keys ("We recommend making your key names reasonably unique to avoid accidental conflicts"). It does not forbid nested structures, but `skills-ref validate` may reject Mordred-flavoured skills due to the type-strictness rule.

**Acceptable for v1** because Mordred users go through `hermes mordred install` (the privacy-check wrapper). Pure-spec consumers reading `metadata` flatly will simply see Mordred's nested block as opaque.

---

## `plugins.mordred_privacy_check` config schema

Read from `~/.hermes/config.yaml` at first hook invocation. Schema:

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `policy` | `"strict"` \| `"lenient"` \| `"off"` | `"lenient"` | Invalid values fall back to `"lenient"` (logged warning). |
| `allow_cloud_llm` | bool | `false` | Phase 2 hookpoint — loaded but not yet enforced. |
| `cloud_provider_allowlist` | list\[str] | `[]` | Phase 2 hookpoint. |
| `audit_log_path` | str | `~/.hermes/mordred/audit.log` | Tilde expansion supported. |

The `mordred_wizard` plugin (Phase 1.3) writes this section via `ruamel.yaml` round-trip to preserve user comments and key order.

---

## Decision matrix (Phase 1)

### Install-time (`hermes mordred install <skill>`)

| `policy` | `network_requirements` | Decision | Reason |
| --- | --- | --- | --- |
| `off` | * | allow | `null` |
| `strict` | absent | block | `policy.strict.unknown_metadata` |
| `strict` | `"clearnet"` | block | `policy.strict.clearnet` |
| `strict` | `"tor"` \| `"vpn"` \| `"local-only"` | allow | `null` |
| `lenient` | absent | warn (still installs) | `policy.lenient.unknown_metadata_warning` |
| `lenient` | * | allow | `null` |

### Runtime (`pre_tool_call`)

| `policy` | active path | tool | Decision | Reason |
| --- | --- | --- | --- | --- |
| `off` / `lenient` | * | * | allow | — |
| `strict` | `"clearnet"` (or `None` until Phase 3 wires it) | ∈ default blocklist `{web_fetch, web_search}` | block | `policy.strict.clearnet` |
| `strict` | `"tor"` \| `"vpn"` | * | allow | — |
| `strict` | `"clearnet"` | not in blocklist | allow | — |

The default blocklist is overridable via `policy.evaluate_pre_tool_call(blocklist=...)`; the wizard will expose this in Phase 1.3 via `policy.json`.

---

## `policy.json` Phase 3 fields (Task #2 / #7)

Added 2026-05-14 alongside the Phase 3 PR3a network slice.

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `disable_ipv6` | bool | strict → `true`, lenient/off → `false` | Advisory Tor-client preference. Reader: `mordred_hermes.network._resolve_disable_ipv6`. Writer: `PolicySnapshot.disable_ipv6` (wizard computes from policy mode and writes explicitly). User pin always wins over the mode default. Non-bool values fall back to the mode default with a WARN log. |
| `provider_overrides` | object keyed by provider id | `{}` | Additive transport facts for internal providers. Baseline provider ids are immutable and cannot be replaced. Reader: `mordred_hermes.network.hooks._read_provider_overrides`. |

When `disable_ipv6=true`, the runtime renders Tor's `ClientUseIPv6 0` option. This affects Tor's own outbound client connections; it does **not** disable host IPv6, filter resolver AAAA answers, or constrain sockets opened directly by a provider SDK. Therefore `provider_transport_flagger._flag_for_ipv6` is never suppressed by this setting: strict + Tor aborts for `respects_ipv6_proxy=False`, while lenient warns. Host-level enforcement is **v2-N2 deferred**.

`provider_overrides` entries accept `transport` (non-empty string),
`respects_proxy` (boolean or `"partial"`), `respects_socks5h`,
`localhost_only`, `dns_quirk`, `unverified_baseline`, and
`respects_ipv6_proxy` (booleans), plus `transport_class` (`"http"`, `"tcp"`,
`"udp"`, `"quic"`, `"grpc"`, or `"websocket"`). A verified internal HTTP
provider can be declared as:

```json
{
  "provider_overrides": {
    "my-internal": {
      "transport": "httpx",
      "respects_proxy": true,
      "respects_socks5h": true,
      "respects_ipv6_proxy": true,
      "unverified_baseline": false,
      "transport_class": "http"
    }
  }
}
```

Omitted safety fields use conservative defaults (`respects_socks5h=false`,
`respects_ipv6_proxy=false`, `unverified_baseline=true`). Unknown fields,
invalid types, and attempts to replace a baseline entry are rejected by the
transport gate. Under strict + Tor, malformed overrides and any internal gate
error are audited as `network.transport_incompatible` and refused with
`MordredPathBringupFailed`; lenient/off audit a warning and continue. A
startup or request-time refusal keeps the process-scoped route active so a
long-lived gateway or another concurrent session cannot fall through to
clearnet; every later request is re-evaluated. The startup gate checks
the provider persisted in `config.yaml model.provider` or
`auth.json active_provider`; the `pre_api_request` gate repeats the check
against Hermes's request-resolved `provider`, so CLI, environment, one-shot,
and gateway overrides cannot bypass it. Missing runtime provider evidence is
treated as unknown and aborts under strict + Tor.

`provider_overrides` is the one operator-managed extension carried verbatim
through `configure`, `upgrade`, and OpenClaw migration rewrites. The wizard
does not validate, discard unknown nested fields, or coerce a non-object value
to `{}`; preserving malformed evidence is intentional so the transport gate
continues to reject it. Other unknown top-level `policy.json` keys remain
outside the snapshot schema and are scrubbed on rewrite.

---

## SOCKS5h library compatibility allowlist (Task #4)

Static allowlist in `mordred_hermes.network.proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS`. Per HTTP client, the minimum version that grew `socks5h://` URL-scheme support; older releases silently coerce to `socks5://` and leak DNS via the system resolver.

| Library | Min version | Notes |
| --- | --- | --- |
| `httpx` | 0.27.0 | Used by anthropic / openai / mordred-local SDKs. |
| `urllib3` | 2.0.0 | Via `requests[socks]`; 1.26.x branch only knows `socks5://`. |
| `requests` | 2.32.0 | Needs PySocks + urllib3 with socks5h. |
| `aiohttp` | 3.10.0 | Pre-3.10.x lacks socks5h scheme parsing. |

All entries ship with `unverified_baseline=True`; the PR3c operator playbook pins real installed versions and flips per entry. The `evaluate_library_compatibility(active_path, declared_libs)` helper emits one human-readable warning per declared library not on the allowlist; runtime is advisory only in v1.

---

## Mullvad credential indirection (Task #6)

To keep secrets out of `policy.json` / `config.yaml`, the wizard writes:

1. `~/.hermes/.env` — `MORDRED_MULLVAD_ACCOUNT=<value>` (mode 0600, parent dir 0700). Sole writer: `wizard/env_file_writer.py::DotEnvFileWriter`. Empty value → line removed. Refuses non-uppercase keys / values with newlines.
2. `~/.hermes/mordred/credentials/network.json` — env-var REFERENCES only:

```json
{
  "mullvad": {
    "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
    "relay_country": "auto",
    "killswitch": true
  }
}
```

Sole writer: `wizard/credentials_writer.py::JSONCredentialsWriter` (dir 0700, file 0600, atomic). Refuses non-env-var-shape values to prevent accidental secret persistence.

Phase 4 keyvault will replace the plaintext `.env` storage with AES-GCM-encrypted secrets unwrapped through Secure Enclave authorization (PATHS.md §191).

---

## Tor ControlPort optional extra (Task #5)

`pip install mordred-hermes[tor-control]` adds `stem>=1.8.0,<2` so `paths/tor.py::circuit_status_health(handle, *, controller_factory=None)` can perform a deep liveness check (cookie auth + `GETINFO circuit-status` → at least one `BUILT` circuit = healthy). Missing the extra collapses gracefully to the shallow `process.poll()` check. Strict-mode operators opt in via the runtime's `tor_health` injection; lenient/off operators don't need it.

`stem`'s last release was 2021-12. The optional-extra pattern bounds the supply-chain blast radius and makes future replacement (raw-socket cookie-auth) a small diff.
