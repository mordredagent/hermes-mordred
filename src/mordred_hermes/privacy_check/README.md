# mordred_privacy_check

Skill metadata enforcement and audit logging.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/audit.log` — single-writer NDJSON audit log (Phase 1 owner; Phase 4 adds AES-GCM encryption layer)
- `~/.hermes/mordred/policy.json` — reader (writer = `mordred_wizard`)

## Phase 1.1 surface

### Hooks registered

- **`on_session_start`** — loads policy snapshot from `~/.hermes/config.yaml plugins.mordred_privacy_check`, runs H3 Path B sibling-disable detection, emits one-shot `mordred.degraded.no_origin_skill` audit entry (per [HOOK_PAYLOADS.md §4](../../../docs/dev/HOOK_PAYLOADS.md)).
  - Strict + sibling-disable → audit `mordred.degraded.disable_unprotected` (decision `block`) + poison process + raise `MordredIntegrityRefused(BaseException)` (bypasses Hermes's `except Exception` guard without masquerading as an ordinary CLI exit).
  - Lenient/off + sibling-disable → audit warn entry, log warning, continue.
- **`pre_tool_call`** — generic strict-mode tool-name allowlist. Default blocklist `{web_fetch, web_search}` blocks under strict mode on the clearnet path. Returns `{"action": "block", "message": str}` or `None`. Per-skill enforcement is not possible — `origin_skill` is absent from the payload (HOOK_PAYLOADS §4); per-skill checks live in `install_wrapper.py`.

### Public Python API

| Module | Purpose |
| --- | --- |
| `policy.evaluate_install(*, policy_mode, network_requirements, requires_keyvault=False, keyvault_initialized=True)` | Pure decision for `hermes mordred install <skill>`. Covers `network_requirements` and `requires_keyvault` opt-in enforcement (TODO §4.1). |
| `policy.evaluate_pre_tool_call(*, policy_mode, tool_name, active_path)` | Pure decision for the `pre_tool_call` hook. |
| `skill_frontmatter.parse(skill_md_path)` | Read SKILL.md, return `SkillMetadata`. Tolerates missing `metadata.mordred.*`. |
| `_keyvault_probe.keyvault_initialized(home=None)` | Backend-free probe: True when the Mordred keyvault holds ≥1 key. Reads `meta.json` only; lazily imports `keyvault._storage`. |
| `audit.NDJSONWriter(path=...)` | Single-writer audit logger. Implements the frozen `Writer` Protocol (Phase 4 swaps to `EncryptedWriter`). |
| `install_wrapper.run(*, skill_path, policy_mode, audit, runner=..., keyvault_probe=...)` | Policy-gated wrapper for `hermes skills install <skill>`. `keyvault_probe` is consulted only for skills declaring `requires_keyvault: true`. |
| `_audit_reasons.ReasonCode` | Frozen `Literal` of the 30 audit reason codes (see `docs/dev/POLICY.md`). |
| `_runtime.poison(reason)` / `is_poisoned()` | Defense-in-depth poison flag — every subsequent `pre_tool_call` blocks. |

### Configuration (under `plugins.mordred_privacy_check` in `~/.hermes/config.yaml`)

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `policy` | `"strict"` \| `"lenient"` \| `"off"` | `"lenient"` | Invalid values fall back to `"lenient"` (logged warning). |
| `allow_cloud_llm` | bool | `false` | Phase 2 hookpoint — read but not yet wired. |
| `cloud_provider_allowlist` | list\[str] | `[]` | Phase 2 hookpoint. |
| `audit_log_path` | str | `~/.hermes/mordred/audit.log` | Tilde expansion supported. |

### Multi-process caveat (TODO M1)

The audit writer uses POSIX `O_APPEND` with per-write `os.write()` calls and a process-local `threading.Lock`. Atomic appends are guaranteed up to `PIPE_BUF` (4096 bytes) — entries are capped at 4000 bytes for safety margin. **Multi-process writers are not supported in v1**: two Python processes both writing to the same audit.log can interleave under load. See `docs/dev/PATHS.md §Multi-process write contention`. v2 plans either a Unix domain socket daemon writer or `fcntl.flock` exclusion.

See `docs/dev/SPEC.md §Plugin: mordred_privacy_check`, `TODO.md §1.1`, and `POLICY.md` for the full enum freeze.
