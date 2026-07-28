# mordred_llm_guard

Strict-mode local LLM enforcement. Registers a `mordred-local` synthetic
provider that points at a user-configurable OpenAI-compatible endpoint
(LM Studio / Ollama / vLLM), refuses session start under strict policy
when the configured primary is an agent harness (Codex / Claude CLI /
Cursor / ACP client) whose daemon traffic bypasses Hermes hooks, and
applies a refuse-only decision matrix at session start to keep
non-allowlisted cloud providers out under strict policy.

## Phase 2 scope (PR1 + PR2)

| Module | Status | Notes |
| --- | --- | --- |
| `_exceptions.py` | ✓ landed (PR1) | `MordredLocalUnreachable(Exception)`, `MordredHarnessRefused(BaseException)`, `MordredSessionRefused(BaseException)`. Two propagation regimes — see module docstring. |
| `_typing.py` | ✓ landed (PR1) | Narrow `PluginContext` Protocol mirroring `privacy_check/_typing.py`. |
| `local_adapter.py` | ✓ landed (PR1) | `build_mordred_local_profile()` / `register_mordred_local()`. **Explicit** registration (Codex B1 — no module-import side effect). PR2 re-invokes from `_on_session_start_enforce` to pick up `local_llm_endpoint` changes after `configure` reruns (Codex M1). |
| `health.py` | ✓ landed (PR1) | `probe(endpoint, transport, timeout)`. 2-second default; raises `MordredLocalUnreachable` on any failure. |
| `harness_detect.py` | ✓ landed (PR1) | `check_harness_primary(policy_mode, config_path, audit)`. Regex prefix match against `codex` / `claude-cli` / `cursor` / `acp-` (semver suffix allowed). |
| `enforce.py` | ✓ landed (PR2) | `check_session_provider(policy_mode, policy_json_path, active_provider, audit, health_probe)`. v1 refuse-only — see module docstring for the full decision matrix. |
| `__init__.py` | ✓ landed (PR1+PR2) | `register(ctx)` wires provider registration + 2 `on_session_start` callbacks (harness_detect FIRST, then enforce — registration order matters per HOOK_PAYLOADS.md §1). Audit writer cached via `functools.lru_cache` (Codex M2). |

## Deferred to v2

- **Former `transport.py` module** — removed because Hermes core owns the streaming pipeline
  (`agent/error_classifier.py` handles `httpx.RemoteProtocolError`), so a
  plugin-side wrapper cannot reliably emit
  `policy.strict.local_stream_interrupted`. Reintroduced when upstream
  adds a streaming hook.
- **`MordredLocalStreamInterrupted` exception** — kept out of
  `_exceptions.py` to prevent silent half-implementations. The audit
  reason code stays in the freeze enum for forward compatibility.
- **Auto-swap (`policy.strict.provider_override_at_session_start`)** —
  needs a pre-resolve hook upstream OR a vendored fork (`[hard-lock]`
  extra, Tier B in UPSTREAM.md).
- **Per-turn `pre_llm_call` override** — HOOK_PAYLOADS.md §5 confirms
  this is structurally impossible in Hermes v0.11.0.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/policy.json` — reader (`local_llm_endpoint`,
  `local_llm_model_id`, `cloud_attempt_action`, `policy`,
  `allow_cloud_llm`, `cloud_provider_allowlist`). Wizard is the sole
  writer.
- `~/.hermes/config.yaml plugins.mordred_llm_guard.harness_primary` —
  reader (free-form string declared by the user / wizard).
- `~/.hermes/mordred/audit.log` — writer (NDJSON append via the shared
  `privacy_check.audit.NDJSONWriter`). POSIX `O_APPEND` keeps writes
  atomic up to 4000 bytes per entry; multiple plugins safely share the
  file in v1.

## Cross-references

- `docs/dev/SPEC.md` §`Plugin: mordred_llm_guard` / §Story 4
- `docs/dev/PLAN.md` §"Phase 2 — LLM Enforcement"
- `docs/dev/HOOK_PAYLOADS.md` §5 (pre_llm_call constraints)
- `docs/dev/POLICY.md` §Audit log reason enum (frozen)
- `docs/dev/TODO.md` §Phase 2 PR1 prep findings
