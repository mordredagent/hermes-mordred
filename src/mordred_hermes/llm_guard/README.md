# mordred_llm_guard

Strict-mode local LLM enforcement. Routes all LLM calls to a local OpenAI-compatible
endpoint (e.g., LM Studio / Ollama) when policy is `strict`, with optional cloud
allowlist passthrough.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/policy.json` — reader (`allow_cloud_llm`, `cloud_provider_allowlist`)
- `~/.hermes/mordred/audit.log` — writes override decisions via shared writer

## Phase 0 status

Scaffold only. `register(ctx)` is a no-op. Phase 2.1 wires:
- `mordred-local` synthetic provider adapter (Hermes provider SPI)
- `pre_llm_call` override handler (policy × provider × allowlist matrix)
- `on_session_start` harness-primary detection (Codex / Claude CLI / Cursor / ACP)
- `MordredLocalUnreachable` / `MordredLocalStreamInterrupted` failure modes (M2)

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_llm_guard` and TODO §2.1.
