# Mordred-Owned Filesystem Paths (Hermes-base)

> **Note**: This document defines the Mordred-owned paths on the `Hermes` foundation. The old OpenClaw-based version remains at `../../mordred/mordred-mvp-docs/PATHS.md` (deprecated).

All filesystem paths read or written by the Mordred distribution are isolated
under `~/.hermes/mordred/` (resolved profile-aware via Hermes's `get_hermes_home()`).
Each path has a single owning plugin; other plugins may access it only via internal Python APIs or shared file contracts.

This document is the primary reference per TODO.md §0.3. After plugin
scaffolding (TODO.md §0.4), a summary of each entry is also duplicated into
the owning plugin's `README.md`.

## Overview

| Path                                  | Owner (phase)                     | Writer                        | Reader                            |
| ------------------------------------- | --------------------------------- | ----------------------------- | --------------------------------- |
| `~/.hermes/mordred/audit.log`         | `mordred_privacy_check` (Phase 1) | privacy_check (single writer) | wizard (`audit tail/grep`)        |
| `~/.hermes/mordred/policy.json`       | `mordred_privacy_check` (Phase 1) | `mordred_wizard`              | privacy_check, llm_guard, network |
| `~/.hermes/mordred/credentials/`      | `mordred_network` (Phase 3)       | `mordred_wizard`              | (none currently — write-only)     |
| `~/.hermes/mordred/tor-data/`         | `mordred_network` (Phase 3)       | bundled `tor` process         | bundled `tor` process             |
| `~/.hermes/mordred/keyvault/`         | `mordred_keyvault` (Phase 4)      | keyvault (single writer)      | keyvault only                      |

Hermes config integration:

- The `plugins.mordred_*` section of `~/.hermes/config.yaml` is the canonical policy input (edited by the wizard)
- When placing API keys for Mordred in `~/.hermes/.env`, use the `MORDRED_*` prefix consistently

---

## `~/.hermes/mordred/audit.log`

**Owning plugin**: `mordred_privacy_check` (Phase 1)
**Purpose**: Access-controlled (mode `0600`), append-only auditable record of policy decisions, network-path switches, and keyvault operations.

> **H4 caveat**: v1 is **not tamper-evident**. File mode `0600` provides access control, not tamper detection. Any process running under the same UID can rewrite the log without leaving a trace. Tamper evidence (a per-entry HMAC chain, with the chain key wrapped by the keyvault DEK) is planned for v2 (see §Tamper detection roadmap below and SPEC.md §Threat Model "does NOT defend against").

### File contract

- **Format**: newline-delimited JSON (NDJSON). One line = one entry.
- **File mode**: `0600` (owner read/write only).
- **Rotation**:
  - Daily at UTC midnight to `audit.log.YYYY-MM-DD`.
  - Forced rotation when the current file reaches 10 MB.
  - Gzip-compressed after rotation (`audit.log.YYYY-MM-DD.gz`).
  - Deleted after 30 days.
- **Write exclusivity**: single-writer queue (in the Hermes process). Multi-process
  concurrency is explicitly out of scope for v1.
- **Encryption**:
  - Phase 1-3: plaintext (file mode `0600` is the only protection).
  - Post-Phase-4 new entries: AES-GCM encrypted with a keyvault-wrapped DEK,
    unwrapped via Secure Enclave authorization.
  - Existing logs written before Phase 4 stay plaintext until the user manually
    purges or re-encrypts (see TODO.md §4 DECIDE block and
    `hermes mordred audit purge --before YYYY-MM-DD`).

### Entry contract

Audit entries carry the following fields:

- `ts`: ISO 8601 UTC timestamp (e.g. `2026-04-29T12:34:56.000Z`)
- `event`: hook name (at `pre_install` wrapper invocation / `pre_tool_call` /
  `pre_llm_call` / `network_use` / `keyvault_*` / ...)
- `decision`: `allow` | `block` | `override` | `warn`
- `reason`: a fixed enum code — the canonical, complete list is
  [`POLICY.md` §Audit log `reason` enum (frozen)](./POLICY.md) and
  `src/mordred_hermes/privacy_check/_audit_reasons.py:ReasonCode`
  (typed `Literal`, drift-checked by mypy). Added incrementally since the
  Phase 1 step-0 freeze, across Phase 2 PR2 / Phase 3 PR1 / Phase 4 PR2
  (16 codes across Phase 1-3, plus Phase 4 PR2's
  `keyvault.recovery_digest_mismatch` /
  `keyvault.seed_display_aborted_screenshot`)
- `origin_skill?`: `{ id, version? }` — only when included in the Hermes `pre_tool_call` payload
- arbitrary event-specific fields (`tool_name`, `provider_override`, `path`, ...)

### Writer layer

- The single-writer implementation is `plugins/mordred_privacy_check/audit.py` (Python)
- The Writer abstraction is `class Writer(Protocol): def append(self, entry: dict) -> None: ...`
  - Phase 1: identity Writer (plaintext NDJSON)
  - Phase 4: factory swap to AES-GCM Writer in
    `plugins/mordred_keyvault/log_encryption.py`

### Consumer CLI

- `hermes mordred audit tail [-n N]` — show last N entries
- `hermes mordred audit grep <pattern>` — pattern match
- `hermes mordred audit decrypt --date YYYY-MM-DD` — Phase 4+, decrypts encrypted logs (Secure Enclave authorization required)
- `hermes mordred audit purge --before YYYY-MM-DD` — manual purge path for plaintext logs

### Tamper detection roadmap (v2)

v1 is not tamper-evident (see the H4 caveat above). Planned additions for v2:

- **Per-entry HMAC chain**: Add an `hmac` field to each NDJSON entry. `hmac_n = HMAC-SHA256(chain_key, hmac_{n-1} || entry_n_canonical_json)`. Rewriting an entry after the fact makes every subsequent HMAC unverifiable
- **Chain key protection**: The `chain_key` is wrapped with the Phase 4 keyvault's DEK and stored at `~/.hermes/mordred/audit.chain.wrap`. It is unwrapped via Secure Enclave authorization at Hermes process startup and kept resident in memory
- **Verification CLI**: `hermes mordred audit verify [--from YYYY-MM-DD] [--to YYYY-MM-DD]` re-walks the chain and reports anomalies
- **Phase 4 dependency**: Presupposes secure storage of the chain_key. While the Phase 4 keyvault remains macOS-only, Linux/WSL2 users cannot get tamper detection either (until master-password Tier 3 arrives in `v2-OS2`)

Implementation begins in v2. In v1, `0600` access control plus Phase 4 audit log encryption (which makes per-entry rewriting harder) serve as the interim defense.

### Multi-process write contention (v1 limitation, M1)

`hermes mordred install <skill>` is designed so that the wizard-CLI writes audit entries from **a process separate from the session process**. Since v1 assumes serialization via a single-process in-process queue, concurrent writes from a separate process can cause NDJSON interleaving / partial writes.

- **Detection**: `hermes mordred audit verify` (v2) attempts a JSON parse per line and reports failing lines with `corrupted=true`
- **Interim mitigation (v1)**: Each writer opens the file in `os.O_APPEND` mode and issues one `write()` call per line (relying on POSIX `O_APPEND`'s atomicity guarantee; no interleaving occurs as long as the entry is under the PIPE_BUF 4 KiB limit). Corruption risk remains in the rare case where an entry exceeds PIPE_BUF
- **Full resolution (v2)**: A single daemon writer over a Unix domain socket, or exclusive locking via `fcntl.flock`. To be re-evaluated in v2
- **Operational note**: Avoid concurrent audit-emitting activity in the session process (e.g., a large volume of `pre_tool_call`) while `hermes mordred install` is running. Since install is a one-off, short-duration operation, the collision probability is practically low

### Cross-references

- SPEC.md §Audit log policy
- PLAN.md §1.1 audit log format

---

## `~/.hermes/mordred/policy.json`

**Owning plugin**: `mordred_privacy_check` (Phase 1)
**Writer**: `mordred_wizard` (`hermes mordred configure` / `upgrade`)
**Readers**: `mordred_privacy_check` (cached in memory at `on_session_start`),
`mordred_llm_guard` (Phase 2), `mordred_network` (Phase 3)

### Purpose

Effective merged policy snapshot. The canonical source is the
`plugins.mordred_*` section of `~/.hermes/config.yaml`.
`policy.json` is a debuggable mirror written out by the wizard, with a consistent shape.

### File contract

- **Format**: JSON (UTF-8, 2-space indent). Not YAML (not intended for manual editing — this is a mirror output)
- **File mode**: `0600`
- **Write exclusivity**: the wizard is the sole writer. privacy_check is read-only
- **Reload**: `hermes mordred policy reload` (an internal function call; a fs watcher is not introduced in v1)
- **Canonical configuration**: The wizard edits the `plugins.mordred_*` section of `~/.hermes/config.yaml` via a `ruamel.yaml` round-trip (preserving comments and key order). `policy.json` is a scrubbed snapshot of that.

### Schema sketch (Phase 1)

```json
{
  "policy": "strict | lenient | off",
  "allow_cloud_llm": false,
  "cloud_provider_allowlist": [],
  "audit_log_path": "~/.hermes/mordred/audit.log",
  "local_llm_endpoint": "http://localhost:1234/v1",
  "local_llm_model_id": "...",
  "default_network_path": "tor | vpn | clearnet",
  "tor_binary_path": "...",
  "tor_socks_port": 9050,
  "tor_control_port": 9051,
  "mullvad_account_id_ref": "MORDRED_MULLVAD_ACCOUNT (env var ref, value comes from ~/.hermes/.env)",
  "mullvad_killswitch": true,
  "mullvad_relay_country": "auto",
  "no_proxy": ["localhost", "127.0.0.1", "::1"],
  "disable_ipv6": true,
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

The full schema reference treats [`POLICY.md §\`plugins.mordred_privacy_check\` config schema`](./POLICY.md) as the canonical source (landed in Phase 1.1 / 2026-05-10). The Phase 3 `disable_ipv6` and `provider_overrides` extensions are documented in that file's §`policy.json` Phase 3 fields. `provider_overrides` may only add internal providers; bundled baseline entries cannot be changed. Missing safety facts default conservatively, and malformed entries refuse strict + Tor startup or outbound API requests. The request-time check uses the provider in Hermes's `pre_api_request` payload, covering runtime overrides that are not present on disk.

### Defaults

- The default for new `configure` and existing-environment `upgrade` is `policy=lenient` (SPEC story 1; PLAN §1.1 configSchema)

### Consumer CLI

- `hermes mordred configure` / `upgrade` — writes
- `hermes mordred policy show` — display current values
- `hermes mordred policy explain <skill-id>` — explain decision for a skill
- `hermes mordred policy dry-run <skill-path>` — pre-install decision simulation
- `hermes mordred policy reload` — triggers in-process reload

### Cross-references

- PLAN.md §1.1 policy.json
- TODO.md §1.3 wizard plugin

---

## `~/.hermes/mordred/credentials/`

**Owning plugin**: `mordred_network` (Phase 3)
**Writer**: `mordred_wizard` (during `hermes mordred configure` Phase 3 questions)
**Readers**: none currently — this file is **write-only**. `mordred_wizard` writes it, but no module under `network/` reads `credentials/network.json` (`mordred_network` reads Mullvad settings from `policy.json` instead — `network/__init__.py:270-276`). A runtime reader is not yet implemented and will be wired up in a future phase.

### Purpose

Stores sensitive information needed in Phase 3, such as the Mullvad account number and Tor binary path. Once Phase 4 becomes available, this can migrate to AES-GCM encryption via `mordred_keyvault` (the interface is similar to the `Writer` abstraction).

### File contract

- **Directory mode**: `0700`
- **File mode**: `0600`
- **Phase 3**: plaintext JSON `~/.hermes/mordred/credentials/network.json`
- **Phase 4**: encrypted at the same path (DEK is keyvault-wrapped)
- **Alternative**: Simple secrets (e.g., the Mullvad account number) are placed in `~/.hermes/.env` as `MORDRED_MULLVAD_ACCOUNT=...` and referenced from `policy.json` via an env var ref

### Schema sketch (v1, finalized in Phase 3 PR3a / 2026-05-14)

The implementation is `wizard/credentials_writer.py::JSONCredentialsWriter` (canonical) — env-var REFERENCES only:

```json
{
  "mullvad": {
    "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
    "relay_country": "auto",
    "killswitch": true
  }
}
```

- The actual secret (a 16-digit account number) lives in `~/.hermes/.env` as `MORDRED_MULLVAD_ACCOUNT=...` (`wizard/env_file_writer.py::DotEnvFileWriter` is the sole writer, mode `0600` / parent dir `0700`)
- `credentials/network.json` holds only env-var references (see POLICY.md §Mullvad credential indirection). If a value in secret-like form (uppercase alphanumeric, etc.) is written, `JSONCredentialsWriter` rejects it with a `ValueError`
- Tor-related **configuration values** (binary path, SOCKS port, control port) live on the **`policy.json`** side and are not included in this credentials/ (Phase 3 PR3a). As for Tor's data directory, even though a *path value* may be referenced from config, the directory itself is a filesystem location owned by Mordred, and it is documented as an independent owned path in §`~/.hermes/mordred/tor-data/` of this doc
- Migration to AES-GCM encryption via `mordred_keyvault` is possible in Phase 4, but since the v1 fields above contain only env-var refs / advisory settings and no secret material, migration priority is low

### Cross-references

- SPEC.md §Plugin: `mordred_network`
- POLICY.md §Mullvad credential indirection
- PLAN.md §3.2 wizard additions

---

## `~/.hermes/mordred/tor-data/`

**Owning plugin**: `mordred_network` (Phase 3)
**Writer**: the bundled `tor` process (a Tor subprocess spawned by Mordred)
**Readers**: the bundled `tor` process

### Purpose

The DataDirectory of the bundled Tor process started by `mordred_network`. This path is passed to the `DataDirectory` directive in Tor's `torrc`, and Tor itself writes its consensus cache, keys, and state files here. Mordred's code does not directly read/write the contents of this directory — it owns the path, but only the Tor process operates on it.

### File contract

- **Path value**: `RuntimeConfig.tor_data_dir`. Resolved as `HERMES_BASE / "mordred" / "tor-data"` in `network/__init__.py:130` (with `network/runtime.py:99` defining the `RuntimeConfig` default), and passed to `render_torrc` / `TorHandle` at `network/runtime.py:441,468,480` during path bring-up
- **Created**: created by the Tor process the first time `mordred_network` brings up the Tor path
- **Lifecycle**: managed by the Tor process. Mordred is responsible only for supplying the path value

### Cross-references

- SPEC.md §Plugin: `mordred_network`
- PLAN.md §3.1 plugin: `mordred_network`

---

## `~/.hermes/mordred/keyvault/`

**Owning plugin**: `mordred_keyvault` (Phase 4)
**Writer**: keyvault plugin only (single writer)
**Readers**: keyvault plugin only. Other plugins access it only via the internal Python API
`mordred_keyvault.api.{generate,encrypt,decrypt,export_backup,import_backup,verify_digest}`.

### Purpose

Local persistence of keyvault state:

- wrapping-key identifiers (handles into Secure Enclave)
- wrapped DEK ciphertext
- metadata (key-ID list, generation timestamps, initial digest commitment)
- temporary file for backup export (deleted immediately after creation)

**Important**: the plaintext Seed Phrase / Passphrase / PoW / unwrapped DEK is
**never** persisted to disk. Memory only (Seed display auto-clears after 60 seconds).

### File contract

- **Directory mode**: `0700` (owner-only access)
- **Subordinate file mode**: `0600`
- **Created**: on the first call to `mordred_keyvault.api.generate`
- **Deleted**: only when the user explicitly runs `hermes mordred keyvault reset` (TBD)
- **Encryption**: the wrapped DEK inside the directory is protected by a Secure-Enclave-backed wrapping key. Unwrapping is only possible via `Security.framework`

### Expected substructure (Phase 4 PR4 step-0 freeze, 2026-05-15 — codex H3 / H4 corrected)

```
~/.hermes/mordred/keyvault/
├── .lock                                  # fcntl.flock target for write-side mutex (file mode 0600)
├── meta.json                              # {"version": 1, "keys": {"<key_id>": {...}}}
├── digests/
│   └── <key_id_hash_hex>.commit           # 32 bytes raw verification digest (mis-record evidence)
└── ciphertexts/
    └── <key_id_hash_hex>/
        └── <purpose_hash_hex>/
            └── <envelope_id>.gcm           # MREN envelope: 196+N bytes (per-ciphertext DEK)
```

- `key_id_hash_hex` = first 16 bytes of `SHA-256(key_id)` rendered as hex (32 chars). The cleartext `key_id` lives only inside `meta.json`, never as a path component (POLICY.md #19 "never the cleartext id" rule).
- `purpose_hash_hex` = first 16 bytes of `SHA-256(purpose)` rendered as hex.
- `envelope_id` = URL-safe base64 of 16 cryptographically-random bytes (~22 chars, no `/`, no `=`).
- File mode `0600` and directory mode `0700` are enforced on open via `os.open(path, O_NOFOLLOW)` + `fstat` mode check (symlink follow refused; mode mismatch raises `KeyvaultPermissionError`).
- All writes use atomic `<file>.tmp + fsync(tmp_fd) + os.replace + fsync(parent_dir_fd)` under `fcntl.flock(.lock)`.
- The pre-PR4 draft showed `keys/<keyId>.wrap`; that was the long-lived-DEK sketch. PR4 step-0 freezes the per-ciphertext DEK model (codex OD-1A) — each `.gcm` envelope embeds its own 127-byte MRKW wrap prefix. No standalone `keys/` directory in v1.

### Internal Python API (Phase 4 PR4 step-0 freeze, 2026-05-15)

Authoritative definitions live in SPEC.md §"PR4 API contract & MREN envelope wire format". Summary:

- `mordred_keyvault.api.prepare_generate(seed_phrase, passphrase, pow_bytes) -> (SeedDisplayHandle, expected_digest)` — in-memory only, no persistence
- `mordred_keyvault.api.confirm_generate(handle, user_confirmed_digest, *, key_id=None, ...) -> GenerateResult` — durable phase, rollback on failure (codex BLOCKER #2)
- `mordred_keyvault.api.generate(seed, passphrase, pow_bytes, expected_digest, *, ...) -> GenerateResult` — non-interactive convenience (tests / automation)
- `mordred_keyvault.api.encrypt(key_id, plaintext, purpose, *, ...) -> envelope_id` — managed storage; persists `.gcm` file
- `mordred_keyvault.api.decrypt(key_id, envelope_id, purpose, *, ...) -> bytes` — caller-supplied `purpose` required (cross-purpose replay defense, codex HIGH #2)
- `mordred_keyvault.api.export_backup(key_id, passphrase, *, ...) -> bytes` — full ciphertext-rewrap manifest (codex BLOCKER #1)
- `mordred_keyvault.api.import_backup(blob, passphrase, *, seed_phrase, pow_bytes, ...) -> str` — verify digest → decrypt manifest → re-wrap each DEK
- `mordred_keyvault.api.verify_digest(seed, passphrase, pow_bytes, *, expected) -> None` — split normalization applied

### Consumer CLI

- `hermes mordred keyvault init` / `list` / `verify-digest` / `recover --blob <path>`

### Pre-Phase-4 behavior

- In Phase 1-3, `~/.hermes/mordred/keyvault/` is **not created**
- The `mordred_privacy_check` skill install guard parses `metadata.mordred.requires_keyvault: true` into the decision record in Phase 1, but enforcement is wired in Phase 4 (TODO.md §1.1)

### Cross-references

- SPEC.md §Plugin: `mordred_keyvault`
- PLAN.md §4.1 plugin: `mordred_keyvault`
- TODO.md §4.1 `mordred_keyvault` plugin

---

## Migration from legacy OpenClaw paths

When `hermes mordred upgrade` detects `~/.openclaw/mordred/` from the OpenClaw era, it migrates as follows (Story 1.5). Each entry specifies its conflict-resolution policy (H5):

| Old path (OpenClaw) | New path (Hermes) | Processing | Behavior on conflict (H5) |
|-------------------|-------------------|------|-------------------|
| `~/.openclaw/mordred/audit.log` | `~/.hermes/mordred/audit.log` | append (old entries → appended to end of new file); the old path is kept and the user deletes it manually | **append-by-timestamp-window**: append only if the new file is empty or its oldest `ts` is newer than the old file's newest `ts`; if the ranges overlap, abort and require an explicit `--audit-merge=skip\|append-all\|abort` choice. Default is abort (to prevent duplicate append on a re-run, the idempotent rerun is detected via the marker file `~/.hermes/mordred/.audit-migrated-from-openclaw` and skipped) |
| `~/.openclaw/mordred/policy.json` | `~/.hermes/mordred/policy.json` + `plugins.mordred_*` in `~/.hermes/config.yaml` | re-shape the values and write them | **diff + prompt** (same as Story 1); `--reset` forces an overwrite; in batch / CI environments, explicitly specify `--policy-conflict=keep-existing\|overwrite\|abort` (default abort) |
| `~/.openclaw/mordred/keyvault/` | `~/.hermes/mordred/keyvault/` | copy (Phase 4 only. The Secure Enclave wrapping key can be used as-is on the same machine; on a different machine, go via `import_backup`) | **never overwrite**: abort if the new path already exists (overwriting key material is destructive); the user must manually take the old key through an `export_backup` → new-machine `import_backup` flow |
| `~/.openclaw/credentials/mordred-network.json` | `~/.hermes/mordred/credentials/network.json` | copy, decomposing into env var references as needed | **never overwrite**: abort if the new path already exists, requiring a manual merge |
| `plugins.entries.mordred-*.config` in `~/.openclaw/openclaw.json` | `plugins.mordred_*` in `~/.hermes/config.yaml` | JSON5→YAML conversion, preserving comments (`ruamel.yaml`) | **diff + prompt** (same as Story 1); `--reset` forces an overwrite; in batch, the `--policy-conflict` flag |

**Idempotency contract (H5)**: When `hermes mordred upgrade` is run a second time, if the marker file `~/.hermes/mordred/.audit-migrated-from-openclaw` (written on the first run) exists, audit migration is skipped (a no-op). This prevents duplicate appending of the same entries. If the user intentionally wants to re-run it, they should delete the marker or specify `--reset --audit-merge=append-all`.

The `--reset` flag forces every conflict-policy to `overwrite` (destructive — old data is deleted). In CI / automation environments, request a non-interactive mode that suppresses interactive prompts via `--non-interactive`; if a conflict-policy flag is not specified, fail fast.

---

## Access boundary discipline

- Mordred plugins **never directly read/write** a path owned by another plugin. They always go through internal Python APIs (`mordred_network.api.*`, `mordred_keyvault.api.*`, etc.) or shared file contracts (e.g., the wizard reads audit.log via `audit tail`, while privacy_check is the one writing it)
- Hermes core (`agent/`, `hermes_cli/`, `gateway/`, etc.) never references a Mordred-owned path at all (zero-PR commitment, `MIGRATION.md` §5). Even if hard-enforcement becomes necessary in v2 and a vendored fork extra (`mordred-hermes[hard-lock]`, `vendor/hermes/<version>/`) is introduced, the patch scope is kept to localized changes in existing Hermes modules, and Mordred-specific IDs, defaults, and recovery policy are kept on the plugin side rather than placed into core (including the vendored module)
- Each plugin is responsible for documenting the paths it owns / its internal API in its `README.md` (TODO.md §0.4 plugin scaffold)
