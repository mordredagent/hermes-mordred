# Codex seventh-pass review: direct tool calls option (PR #265, 2026-10-23)

Response: SHIP; the one P3 is recorded in TODO ("Direct-tools CLI wording when only the probe ran") and the branch was merged after this pass.

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox.
Commit reviewed: `ca872dc4a` (PR #265, branch `feat/direct-tools-option`; only `3c321f3d4..ca872dc4a`, the hermes-agent 0.13.0 floor fix: the `hermes config get` probe and `hermes_cli_unsupported`).

VERDICT: SHIP

Validation: four focused tests and 32 in-memory protocol checks with the installed hermes-agent 0.19.0 merge, lookup and formatting functions; the broader pytest run was blocked before collection by the read-only sandbox; no live 0.13.0 or 0.21.5 execution.

## Findings (condensed)

1. **P3: a probe-only success reports a write that never occurred.** `src/mordred_hermes/wizard/direct_tools.py:317`. When the file on disk differs but Hermes's resolved value already matches, `set_direct` returns without writing, yet the CLI prints `off -> on (hermes config set ...)`, and the `off` path claims an unset. Fix: return a changed/no-change result, have the CLI say that Hermes already reads the requested state, and add CLI tests for both probe-only outcomes. Nonblocking.
   - Response: recorded in `docs/dev/TODO.md` under "Imported message provenance" for a follow-up; the route answer (`restart_required: true`) is unaffected.
