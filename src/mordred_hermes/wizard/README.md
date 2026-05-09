# mordred_wizard

`hermes mordred …` CLI surface.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/policy.json` — sole writer (readers: privacy_check / llm_guard / network)
- `~/.hermes/config.yaml` `plugins.mordred_*` sections — round-trip via `ruamel.yaml`

## Phase 0 status

Scaffold only. `register(ctx)` is a no-op. Phase 1.3 wires:
- `ctx.register_cli_command("mordred", ...)` with argparse subparser tree
  (configure / upgrade / install / network / policy / audit / keyvault)
- `configure.py` (Mordred-specific prompts via `prompt_toolkit`)
- `upgrade.py` (Story 1 / 1.5 migration; OpenClaw → Hermes path move per PATHS.md §migration)
- `policy_writer.py` / `policy_explainer.py`

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_wizard` and TODO §1.3.
