# mordred_wizard

`hermes mordred …` CLI surface — the user-facing entry point for Mordred
privacy configuration, migration, install gating, audit log inspection,
and plugin discovery.

See also: `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_wizard`,
`mordred-docs/mordred/PATHS.md`, `mordred-docs/mordred/POLICY.md`.

## Subcommand reference

Two equivalent entry points exist while Hermes 0.11 lacks entry-point CLI
wiring (the gap is documented in `cli.py:main` docstring):

- `hermes-mordred <COMMAND>` — standalone console-script (works today).
- `hermes mordred <COMMAND>` — will start working once Hermes 0.12+ ships
  entry-point CLI wiring; no plugin code change needed.

### `configure [--non-interactive]`

Run interactive Mordred setup. Writes `~/.hermes/config.yaml`
(`plugins.mordred_*` sections, round-trip via ruamel.yaml) and
`~/.hermes/mordred/policy.json` (the wizard-owned mirror).
`--non-interactive` fails fast on any prompt (CI / scripted use).

Implementation: `configure.py`.

### `upgrade [--reset] [--non-interactive] [--audit-merge=...] [--policy-conflict=...]`

Idempotent migration covering both Story 1 (existing Hermes install
upgrade) and Story 1.5 (OpenClaw → Hermes migration when
`~/.openclaw/mordred/` is detected).

H5 conflict resolution flags (see `PATHS.md §OpenClaw migration`):

- `--audit-merge={skip,append-all,abort}` — audit-log timestamp overlap policy.
- `--policy-conflict={keep-existing,overwrite,abort}` — `plugins.mordred_*`
  section conflict policy.
- `--reset` — force `overwrite` on every conflict (overrides the marker).
- `--non-interactive` — fail fast when a conflict policy is not pre-specified.

Implementation: `upgrade.py` + `openclaw_migration.py`.

### `install <skill>`

Install a skill through the Mordred policy gate. Delegates to
`privacy_check.install_wrapper.run` so the install decision is identical
to the runtime hook. Exit codes:

- `0` — allow / warn outcome, install subprocess succeeded.
- non-zero — install subprocess returncode forwarded.
- `2` — `InstallBlocked` raised (strict-mode block). Reason is printed
  to stderr; the underlying audit entry was written before the raise.

Implementation: `install_dispatch.py`.

### `policy {show,explain,dry-run,reload}`

Read-only inspection helpers (the `reload` subcommand resets the cached
in-process `PluginState` only).

- `policy show` — print resolved `policy.json`.
- `policy explain <skill_id>` — explain the install decision for a known
  skill id (resolved against `~/.hermes/skills/` and `./.hermes/skills/`).
- `policy dry-run <skill_path>` — evaluate a SKILL.md without installing.
- `policy reload` — clear cached state so the next hook re-reads
  `~/.hermes/config.yaml`. Does NOT clear the poison flag.

Implementation: `policy_explainer.py`.

### `audit {tail,grep}`

Read-only inspection of `~/.hermes/mordred/audit.log` (privacy_check is
the sole writer; PATHS.md row policy). Encrypted Phase 4 logs are
detected by non-`{` header and produce a "use audit decrypt" stderr
message.

- `audit tail -n N` — print the last `N` NDJSON entries.
- `audit grep PATTERN` — Python regex over raw NDJSON lines. Exit codes:
  `0` (hit), `1` (no match / missing log), `2` (invalid regex).

`audit {decrypt,purge}` remain Phase 4 stubs.

Implementation: `audit_cli.py`.

### `plugins list`

List discovered Mordred plugins (those whose `key` starts with `mordred_`).
Closes the §0.5 L128 UX gap — Hermes 0.11's `hermes plugins list` does
not show entry-point plugins.

Primary path queries `hermes_cli.plugins.PluginManager`. Fallback reads
`~/.hermes/config.yaml` `plugins.enabled` when the manager API is
unavailable.

Implementation: `plugins_list.py`.

### `network {use,status}` / `keyvault {init,list,verify-digest,recover}`

Phase 3 / Phase 4 stubs. Subcommands parse cleanly but raise
`NotImplementedError("Phase 3 ...")` / `("Phase 4 ...")` so users get a
clear deferred message instead of "invalid choice".

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

| Path | Mode | Notes |
|---|---|---|
| `~/.hermes/config.yaml` | read+write | round-trip via ruamel.yaml; comments / key order preserved |
| `~/.hermes/mordred/policy.json` | **sole writer** | privacy_check / llm_guard / network read this mirror |
| `~/.hermes/mordred/audit.log` | read only | privacy_check writes; wizard reads via `audit tail`/`audit grep` |
| `~/.hermes/mordred/.audit-migrated-from-openclaw` | sole writer | H5 idempotency marker, ISO-8601 UTC timestamp |

OpenClaw legacy paths (Story 1.5 migration source; read-only):

- `~/.openclaw/mordred/{audit.log,policy.json,credentials/,keyvault/}`
- `~/.openclaw/openclaw.json`

## Internal API

| Module | Surface |
|---|---|
| `configure` | `configure.run(setup_runner, prompt_io, policy_writer, non_interactive)`, `cli_handler(ns)` |
| `upgrade` | `UpgradeOptions`, `run(options, policy_writer)`, `cli_handler(ns)` |
| `openclaw_migration` | `OpenClawState`, `detect()`, `migrate(state, options)` |
| `install_dispatch` | `run(skill_arg, state, runner)`, `cli_handler(ns)` |
| `policy_writer` | `PolicySnapshot`, `PolicyWriter.write(snapshot)`, `.upsert_mordred_sections(snapshot)` |
| `policy_explainer` | `show()`, `explain(skill_id)`, `dry_run(skill_path)`, `reload()` + `cli_*` adapters |
| `audit_cli` | `tail(n, log_path)`, `grep(pattern, log_path)`, `cli_tail(ns)`, `cli_grep(ns)` |
| `plugins_list` | `run(config_path)`, `cli_handler(ns)` |

## Fixture catalog

Test fixtures under `tests/fixtures/` are shared with `privacy_check`:

- `clearnet_skill/` — declares `network_requirements: clearnet`, blocked in strict mode.
- `tor_skill/` — declares `network_requirements: tor`, allowed in strict mode.
- `missing_metadata_skill/` — no `metadata.mordred.*`, blocked in strict, warned in lenient.

Wizard-specific tests (`test_upgrade.py`, `test_openclaw_migration.py`,
`test_install_dispatch.py`, `test_audit_cli.py`, `test_plugins_list.py`,
`test_configure.py`, `test_policy_explainer.py`, `test_policy_writer.py`)
seed all wizard-owned paths under `tmp_path` so no real `~/.hermes` state
is touched.
