# mordred_privacy_check

Skill metadata enforcement and audit logging.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/audit.log` — single-writer NDJSON audit log (Phase 1 owner; Phase 4 adds AES-GCM encryption layer)
- `~/.hermes/mordred/policy.json` — reader (writer = `mordred_wizard`)

## Phase 0 status

Scaffold only. `register(ctx)` is a no-op. Phase 1.1 wires:
- `pre_tool_call` hook (per-skill / generic allowlist; strict-mode `web_fetch` / `web_search` blocklist on Clearnet)
- `on_session_start` hook (policy snapshot + sibling-disabled detection, H3 Path B fail-closed)
- `install_wrapper.py` (`hermes mordred install <skill>` SKILL.md frontmatter check)
- `audit.py` single-writer NDJSON logger (rotation, gzip, 30-day retention, mode 0600)

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_privacy_check` and TODO §1.1.
