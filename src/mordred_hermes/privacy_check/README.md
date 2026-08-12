# mordred_privacy_check

Skill metadata enforcement, generic tool gating, sibling-integrity checks, and
shared audit logging.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/audit.log` — owns the shared audit stream; the keyvault
  can replace plaintext NDJSON with the encrypted `MRAL` writer.
- `~/.hermes/mordred/policy.json` — read-only; `mordred_wizard` is the sole
  writer.
- `~/.hermes/config.yaml` — reads `plugins.mordred_privacy_check`.

## Phase 1.1 surface

The heading is retained for existing links. The surface below is current.

### Hooks registered

- **`on_session_start`** loads policy, checks that privacy-locked sibling
  plugins are enabled, and records the degraded mode caused by Hermes's lack of
  per-skill origin data.
- **`pre_tool_call`** applies the strict generic tool-name policy. It returns a
  Hermes block verdict or `None`.

Strict sibling-integrity failures poison the process and raise a
`BaseException`-derived refusal so Hermes cannot silently swallow the block.
Per-skill policy is enforced at install time because the current
`pre_tool_call` payload contains `tool_name`, not `origin_skill`; see
[HOOK_PAYLOADS.md](../../../docs/dev/HOOK_PAYLOADS.md).

### Public Python API

| Module | Purpose |
| --- | --- |
| `policy` | Pure install and pre-tool decisions. |
| `skill_frontmatter` | Parse `metadata.mordred` from `SKILL.md`. |
| `install_wrapper` | Run skill installation through the policy and audit boundary. |
| `audit` | Shared `Writer` protocol and process-safe plaintext writer. |
| `_keyvault_probe` | Check keyvault readiness from metadata without opening a native backend. |
| `_runtime` | Cached policy state, active audit path, and the process poison flag. |
| `_audit_reasons` | Closed `ReasonCode` type shared by all plugins. |

### Configuration (under `plugins.mordred_privacy_check` in `~/.hermes/config.yaml`)

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `policy` | `strict`, `lenient`, or `off` | `lenient` | Select enforcement mode. |
| `allow_cloud_llm` | boolean | `false` | Shared strict-LLM policy input enforced by `mordred_llm_guard`. |
| `cloud_provider_allowlist` | list of strings | `[]` | Canonicalized cloud-provider allowlist. |
| `audit_log_path` | string | `~/.hermes/mordred/audit.log` | Override the audit path within the Hermes home. |

Invalid security-sensitive values fall back conservatively and emit a warning.

### Multi-process serialization

Audit writers combine a process-local lock with `fcntl.flock` on a stable
sidecar. The lock covers format checks, rotation, append, and rollback.
Encrypted writers additionally verify the active inode and header before
reusing an in-memory data-encryption key. Unsafe final paths and lock sidecars
are refused.

See [SPEC.md](../../../docs/dev/SPEC.md),
[POLICY.md](../../../docs/dev/POLICY.md), and
[PATHS.md](../../../docs/dev/PATHS.md) for the full contracts.
