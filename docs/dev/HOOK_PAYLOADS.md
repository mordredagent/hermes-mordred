# Mordred — Hermes Hook Payload Verification Reference

> **Status**: Phase 0.8 source-code verification (2026-05-10, PR `docs/mordred-hermes-phase0.8-hook-verify`).
> **Source of truth**: `hermes-agent` v0.11.0 (release date 2026-04-23) installed at `~/.hermes/hermes-agent/`, which is what `mordred-hermes`'s `hermes-agent>=0.11.0` resolves to.
> **Drift watch**: `./hermes_cli/` at the repo root is an **un-tracked v0.12.0 preview clone** kept for development convenience. Findings here are anchored to v0.11.0; cross-version drift is monitored by `.github/workflows/upstream-check.yml` (weekly Monday 03:00 UTC).

---

## Why this doc exists

`docs/dev/TODO.md` §0.8 (Phase 0 acceptance gate's final unresolved items) is **"Verify Hermes hook payload with real code"**. Phase 1.1 / 2.1 / 3.1 plugin implementations depend on payload shape and return format, so we consolidate findings in one place here.

All findings are the result of reading **`~/.hermes/hermes-agent/`** (v0.11.0). Line numbers are anchored to v0.11.0 — each time upstream revs, CI (`upstream-check.yml`) detects drift in the VALID_HOOKS set and files an issue. Line number drift is absorbed by bumping this document.

---

## 1. `VALID_HOOKS` set and hook ordering guarantee

**Source**: `hermes_cli/plugins.py` L60-96 (v0.11.0)

16 hooks: `pre_tool_call`, `post_tool_call`, `transform_terminal_output`, `transform_tool_result`, `pre_llm_call`, `post_llm_call`, `pre_api_request`, `post_api_request`, `on_session_start`, `on_session_end`, `on_session_finalize`, `on_session_reset`, `subagent_stop`, `pre_gateway_dispatch`, `pre_approval_request`, `post_approval_response`.

**Hook ordering guarantee** (`PluginManager.invoke_hook()` at L968-1002):
- Callbacks are invoked in **registration order** (`for cb in callbacks` over a list built by `register_hook()` at L463: `self._manager._hooks.setdefault(hook_name, []).append(callback)`).
- **No priority system**.
- Plugin **load order** (and therefore registration order on each hook):
  1. Bundled — `<repo>/plugins/<name>/`
  2. User — `~/.hermes/plugins/<name>/`
  3. Project — `./.hermes/plugins/<name>/` (if `HERMES_ENABLE_PROJECT_PLUGINS=1`)
  4. **Pip / entry-point — `hermes_agent.plugins`** ← Mordred lives here
- Mordred plugins therefore **always run AFTER** all bundled/user/project plugins on every hook (`plugins.py` L588 step 4 in `discover_and_load`).

**Implication for SPEC §3.1 bootstrap order**: there is no priority knob in v0.11.0. Mordred's `mordred_network` `on_session_start` runs after any bundled plugin's `on_session_start`, so a polling fallback (`wait_for(api.status().ready, timeout=5s)`) is the right pattern — there is no upstream alternative.

**Mordred opt-in caveat** (TODO §0.5 acceptance gate L124 reaffirmed):
- Entry-point plugins are gated by `plugins.enabled` allow-list in `~/.hermes/config.yaml` (`plugins.py` L598, L641-655).
- A Mordred plugin loaded via entry-point but absent from `plugins.enabled` is recorded with `enabled=False` and **`register()` is not called**.
- `hermes mordred upgrade` (Phase 1.3) **must** add all 6 keys
  (`mordred_privacy_check`, `mordred_wizard`, `mordred_llm_guard`,
  `mordred_network`, `mordred_keyvault`, `mordred_e2e`) to
  `plugins.enabled` for the system to function.

## 2. Plugin disable detection (`hermes plugins list --disabled` equivalent API)

**Source**: `hermes_cli/plugins.py` L108-121 (`_get_disabled_plugins`); `hermes_cli/plugins_cmd.py` L646-696 (`_discover_all_plugins`).

**Findings**:
- `_get_disabled_plugins()` reads `~/.hermes/config.yaml` `plugins.disabled` list — usable directly from Mordred for H3 Path B sibling-disable detection.
- `hermes plugins list` does **NOT** show entry-point plugins (its `_discover_all_plugins()` at `plugins_cmd.py` L662-696 only scans `<repo>/plugins/` and `~/.hermes/plugins/` directories — no entry-point traversal).
- The `list` subcommand also has **no `--disabled` flag**. Disabled state is shown inline via `[red]disabled[/red]` cell.

**Implication for Phase 1.1 H3 Path B (strict-mode startup refusal)**:
```python
# In each Mordred plugin's on_session_start
from hermes_cli.plugins import _get_disabled_plugins
from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused

disabled = _get_disabled_plugins()
SIBLINGS = {"mordred_network", "mordred_privacy_check", "mordred_llm_guard",
            "mordred_keyvault", "mordred_wizard"}
disabled_siblings = SIBLINGS & disabled
if policy == "strict" and disabled_siblings:
    audit("mordred.degraded.disable_unprotected", disabled=sorted(disabled_siblings))
    raise MordredIntegrityRefused(
        f"Mordred strict mode: sibling plugins disabled: {sorted(disabled_siblings)}"
    )
```

This works without a wrapper — `_get_disabled_plugins` is module-level (single underscore). For defensive isolation Mordred can also read the config directly:
```python
from pathlib import Path
import yaml
cfg = yaml.safe_load(Path("~/.hermes/config.yaml").expanduser().read_text())
disabled = set(cfg.get("plugins", {}).get("disabled", []))
```
Note: `~` must be expanded (Python's `open()` does NOT expand `~` for you). Prefer `hermes_constants.get_hermes_home()` when importable.

**Implication for Phase 1.3 wizard UX (TODO L124 deferred item)**:
A `hermes mordred plugins list` wrapper CLI is required because `hermes plugins list` shows none of the Mordred plugins. The wrapper should:
1. Call `PluginManager.list_plugins()` (`plugins.py` L1008-1027) which **does** include entry-point plugins
2. Filter to keys starting with `mordred_`
3. Render with the same Rich table conventions

## 3. Dynamic plugin disable in running session (TODO §0.8 L105)

**Source**: `hermes_cli/plugins.py` L537-554 (`discover_and_load`).

`discover_and_load(force=False)` short-circuits via `self._discovered` cache. Mid-session edits to `~/.hermes/config.yaml`'s `plugins.disabled` are **not propagated** to a running session unless an explicit `discover_plugins(force=True)` call is made (L1067-1073). Hermes core does not re-discover automatically.

**Implication**: H3 Path B's design (refuse-at-startup only) is correct. Mid-session disable cannot be detected without polling; v1 declines this and accepts the limitation.

## 4. `pre_tool_call` payload

**Source**: `hermes_cli/hooks.py` L113-119 (`_DEFAULT_PAYLOADS`); `hermes_cli/plugins.py` L1085-1121 (`get_pre_tool_call_block_message`); `run_agent.py` L9009-9016 (production call site); `model_tools.py` L633-634; `tools/terminal_tool.py` L1924-1925.

**Kwargs (production)**:
| field         | type             | source                    |
|---------------|------------------|---------------------------|
| `tool_name`   | `str`            | LLM tool-call name        |
| `args`        | `dict[str, Any]` | LLM tool-call arguments   |
| `task_id`     | `str`            | optional, defaults `""`   |
| `session_id`  | `str`            | optional, defaults `""`   |
| `tool_call_id`| `str`            | optional, defaults `""`   |

**`origin_skill` is NOT in the payload (v0.11.0)**. TODO §0.8 L96 question definitively answered: **per-skill policy via `pre_tool_call` is impossible without upstream changes**. Mordred plugins must operate on tool-name allowlist only when `pre_tool_call` is the path; per-skill enforcement happens earlier at `hermes mordred install` (Phase 1.1 wrapper CLI) where the SKILL.md is parsed before invocation.

**Block return shape** (`plugins.py` L1097): `{"action": "block", "message": str}`. First valid block wins; non-`block` returns are ignored. Other keys (e.g. `"action": "warn"`) are silently ignored — Mordred MUST emit audit log entries itself (no upstream support for warn-without-block).

## 5. `pre_llm_call` payload and override return shape

**Source**: `hermes_cli/hooks.py` L129-136 (defaults); `run_agent.py` L10303-10313 (production call site); `plugins.py` L976-986 (return-value semantics).

**Kwargs (production)**:
| field                  | type    | notes                                         |
|------------------------|---------|-----------------------------------------------|
| `session_id`           | `str`   |                                               |
| `user_message`         | `str`   | original user message                         |
| `conversation_history` | `list`  | full prior messages                           |
| `is_first_turn`        | `bool`  |                                               |
| `model`                | `str`   | e.g. `"gpt-4"`, `"claude-sonnet-4-6"`         |
| `platform`             | `str`   | `"cli"`, `"gateway"`, ACP platform name, etc. |
| `sender_id`            | `str`   | gateway sender id, defaults `""`              |

**`provider` is NOT in `pre_llm_call`**. The hook is **context-injection only**: callbacks may return `{"context": str}` or a plain string to inject into the user message (per docstring at `plugins.py` L976-986). **Provider override is NOT supported via this hook**.

### 🔴 Phase 2 design implication (MAJOR)

The Mordred SPEC §Story 4 / `mordred_llm_guard` plan assumed `pre_llm_call` could return a provider-override directive. **This is false in v0.11.0.** Three usable mechanisms remain:

**(a) `pre_api_request`** has `provider`, `model`, `base_url`, `api_mode` (see `run_agent.py` L10747-10763 and `hooks.py` L146-160). But it is also **observer-only** — return values are discarded at the call site (`_invoke_hook(...)` is invoked without capturing results, exceptions swallowed). **Cannot override.**

**(b) `pre_tool_call` block on every tool call** when policy says cloud LLM is forbidden — but this only blocks tool execution, not the LLM call itself, so the cloud LLM still receives the user's message before the block fires.

**(c) Config-time provider re-mapping**: `mordred_llm_guard.on_session_start` rewrites `~/.hermes/config.yaml`'s active provider to point at the local `mordred-local` synthetic provider before any LLM call happens. This requires the `register_provider`-style API on `PluginContext` and is outside the scope of this verify; it should be the design baseline for Phase 2.

**Recommended Phase 2 redesign** (to be discussed in Phase 2 DECIDE blocks):
- `mordred_llm_guard.on_session_start`:
  1. Detect strict policy + non-allowlisted current provider
  2. Either (i) refuse to start (hard fail with clear error), or (ii) swap the active provider to `mordred-local` via `register_provider` + config patch
  3. Audit `policy.strict.provider_override_at_session_start` or `policy.strict.session_refused`
- Per-call dynamic override (the original design) is **deferred to a v2 vendored fork** if it's still needed after the session-start swap proves insufficient.

This is a SPEC-level change, captured in §`Plugin: mordred_llm_guard` of SPEC.md.

## 6. `pre_gateway_dispatch` payload and return action shape

**Source**: `gateway/run.py` L3573-3605 (production call site); `hermes_cli/plugins.py` L74-81 (docstring).

**Kwargs**:
| field           | type           |
|-----------------|----------------|
| `event`         | `MessageEvent` |
| `gateway`       | `GatewayRunner`|
| `session_store` | session store  |

**Return shape** (`gateway/run.py` L3586-3605):
- `{"action": "skip", "reason": str}` — drop message, no reply (`return None` at L3597)
- `{"action": "rewrite", "text": str}` — replace `event.text` (`event = dataclasses.replace(event, text=_new_text)` at L3601), continue dispatch
- `{"action": "allow"}` — explicit allow, break out of plugin loop
- `None` — equivalent to allow

**Iteration semantics**: first `skip` short-circuits the gateway. `rewrite` mutates and breaks. `allow` breaks. Multiple plugins are evaluated in registration order; **Mordred can only veto/rewrite if no earlier-loaded plugin already returned skip/rewrite/allow on the same event**.

This matches SPEC §3 expectations — no design changes required.

## 7. `pre_approval_request` / `post_approval_response` payload

**Source**: `tools/approval.py` L34-56 (`_fire_approval_hook`); L1054-1062, L1136-1145, L1191-1199, L1203-1209 (call sites); `hermes_cli/plugins.py` L82-95 (docstring).

**`pre_approval_request` kwargs**:
| field           | type        | notes                              |
|-----------------|-------------|------------------------------------|
| `command`       | `str`       | the dangerous command              |
| `description`   | `str`       | combined description from patterns |
| `pattern_key`   | `str`       | primary matched pattern            |
| `pattern_keys`  | `list[str]` | all matched patterns               |
| `session_key`   | `str`       |                                    |
| `surface`       | `Literal["cli", "gateway"]` |                    |

**`post_approval_response` kwargs**: same as above, plus `choice: Literal["once", "session", "always", "deny", "timeout"]`.

**Return values are IGNORED** (`approval.py` L51 — `invoke_hook(hook_name, **kwargs)` with no result capture; docstring: "Observers only: return values are ignored. Plugins cannot veto or pre-answer an approval from these hooks (use pre_tool_call to block a tool before it reaches approval)").

This matches SPEC expectations: Mordred uses these for audit-log emission only. Vetoing must happen at `pre_tool_call` upstream of approval prompt.

## 8. Subprocess spawn API and proxy env passing (TODO §0.8 L101-103)

**Source**: `tools/environments/local.py` L186-213 (`_make_run_env`), L339-372 (`_run_bash`); `tools/code_execution_tool.py` L1003-1072 (`_SAFE_ENV_PREFIXES` + spawn); `tools/environments/local.py` L107 (`_HERMES_PROVIDER_ENV_BLOCKLIST`); `tools/env_passthrough.py`; `tools/browser_tool.py` L1469-1502.

### 8.1 Two distinct env-filter regimes (CRITICAL distinction)

Hermes does NOT use one consistent env-passing pattern. There are **two distinct regimes** with **opposite default behavior** for proxy vars:

**Regime A — blocklist-style (allows by default)**: `tools/environments/local.py:_make_run_env` and `tools/browser_tool.py` build env from `dict(os.environ | self.env)` and only **strip** entries on a known LLM-provider blocklist. `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` are **not** in `_HERMES_PROVIDER_ENV_BLOCKLIST` (`local.py` L19-104), so proxy vars pass through cleanly. Affected: terminal_tool, browser_tool, environment backends.

**Regime B — allowlist-style (drops by default)**: `tools/code_execution_tool.py` L1003-1025 builds a minimal `child_env` only from entries matching an explicit prefix list:
```python
_SAFE_ENV_PREFIXES = ("PATH", "HOME", "USER", "LANG", "LC_", "TERM",
                      "TMPDIR", "TMP", "TEMP", "SHELL", "LOGNAME",
                      "XDG_", "PYTHONPATH", "VIRTUAL_ENV", "CONDA",
                      "HERMES_")
```
**`HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` do NOT match any of these prefixes** and are therefore **silently dropped** from the child env. The only way they reach a code-execution child is via the `tools.env_passthrough` registry (`code_execution_tool.py` L1015-1019: `if _is_passthrough(k): child_env[k] = v`).

The `_HERMES_FORCE_` prefix escape hatch only works in Regime A — `code_execution_tool.py` does **not** strip the prefix before passing, so `_HERMES_FORCE_HTTPS_PROXY` would land in the child without being renamed.

### 🔴 Phase 3 design implication (MAJOR — flagged by Codex review on PR #9)

Without explicit mitigation, **agent-issued `execute_code` subprocesses make network calls outside the selected Tor/VPN tunnel** even after `mordred_network.api.use(path)` mutates `os.environ`. This is a security-relevant blind spot in the original Phase 3 design.

**Required mitigations for Phase 3 `mordred_network.api.use(path)`**:
1. Register the four proxy vars at plugin initialisation via the `tools.env_passthrough` registry so `code_execution_tool.py` lets them through. Concretely, Mordred imports `from tools.env_passthrough import register_passthrough` (or equivalent — confirm exact API name when implementing) and registers `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` early in `register(ctx)`.
2. Audit each new code_execution child against the active Mordred path: emit `network.code_exec_proxy_missing` (block under strict, warn under lenient) if `_is_passthrough` is False at session start.
3. Document this exception in SPEC §M3 alongside the live_subprocess_count audit field.

### 8.2 Implications for M3 (transitive proxy-env failure mode)

For Regime A (terminal, browser, environment backends):
- Mordred's `mordred_network.api.use(path)` mutating `os.environ` **WILL** propagate to **subsequent spawns** (env constructed fresh each spawn).
- Already-running long-lived subprocesses keep their **frozen env from spawn time**.
- The audit `network_use` event's `live_subprocess_count` field design (TODO L296) is sound and necessary.

For Regime B (code_execution): Mordred MUST register proxy vars in the env_passthrough registry; `os.environ` mutation alone is insufficient.

### 8.3 Spawn-site classes (out of 285 total subprocess sites)

| class                                          | files (representative)                                                            | regime | mitigation                              |
|------------------------------------------------|-----------------------------------------------------------------------------------|--------|-----------------------------------------|
| Terminal / shell execution                     | `tools/terminal_tool.py`, `tools/environments/{local,docker,ssh,singularity}.py` | A      | `os.environ.update({...})` sufficient   |
| **Code execution sandbox**                     | `tools/code_execution_tool.py`                                                    | **B**  | **Must register via env_passthrough**   |
| Browser daemon                                 | `tools/browser_tool.py`, `hermes_cli/browser_connect.py`                          | A      | `os.environ.update({...})` sufficient   |
| Audio / voice / transcription                  | `tools/voice_mode.py`, `tools/transcription_tools.py`                             | A (no `env=` kwarg → full `os.environ` inherit) | mostly N/A (local audio device)         |
| User-initiated CLI utilities (gateway, doctor) | `hermes_cli/{gateway,doctor,dump,plugins_cmd,...}.py`                             | A      | NO (run pre-bootstrap)                  |

---

## Cross-cutting findings → SPEC.md updates

| TODO §0.8 L# | Item                            | Verified? | SPEC.md update                                                                                                |
|--------------|---------------------------------|-----------|---------------------------------------------------------------------------------------------------------------|
| L96          | `pre_tool_call` `origin_skill`  | ❌ absent | Update §Plugin-Only Architecture L103 — `origin_skill` is **NOT** in payload; per-skill policy must rely on the wrapper CLI |
| L97          | `pre_llm_call` provider info    | ❌ absent | **MAJOR**: §Story 4 / §`mordred_llm_guard` redesign — provider override via `pre_llm_call` is impossible      |
| L98          | `pre_gateway_dispatch` actions  | ✅ matches docstring | No change                                                                                                     |
| L99          | approval payload                | ✅ matches docstring | No change                                                                                                     |
| L100         | hook order guarantee            | ✅ registration order, entry-point loaded last | Update §3.1 bootstrap to confirm polling fallback is the only path                                            |
| L101-103     | subprocess env snapshot vs live | ⚠️ **partial** — snapshot per spawn confirmed, but `code_execution_tool.py` strips proxy vars (allowlist filter) — found by Codex review on PR #9 | §M3 needs to call out the **code_execution exception** and the env_passthrough mitigation requirement (see §8.1) |
| L104         | `--disabled` API                | ⚠️ partial — direct config read needed | Update §Plugin-disable protection: use `_get_disabled_plugins` or direct yaml read                                 |
| L105         | dynamic disable propagation     | ❌ no propagation without `force=True` | Update §Plugin-disable protection: confirms refuse-at-startup-only design is correct                          |

## Out of scope (deferred to a follow-up "live verify" task)

Runtime tests requiring API keys, real network, or specific local-LLM endpoints (TODO §0.8 L106-117): network provider behavior under HTTPS_PROXY (anthropic / openai / gemini / mordred-local / bedrock / vertex), SOCKS5h library compat (httpx / urllib3 / aiohttp version boundaries), Wireshark/Tor circuit-log validation. These will be tracked in a separate issue and gated behind `MORDRED_LIVE_*=1` integration tests in Phases 2-3.

---

## Maintenance

- This doc is **anchored to v0.11.0**. When `upstream-check.yml` flags `VALID_HOOKS` drift, re-verify the affected hook(s) and bump line citations.
- The unrelated repo-root `./hermes_cli/` (v0.12.0 preview) is **not authoritative** — do not use it for Mordred verification work.
- All findings here should reach SPEC.md (cross-cutting table above). Drift between this doc and SPEC.md is a bug.
