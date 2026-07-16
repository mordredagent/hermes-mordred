# mordred_wizard

`hermes mordred …` CLI surface — the user-facing entry point for Mordred
privacy configuration, migration, install gating, audit log inspection,
and plugin discovery.

See also: `docs/dev/SPEC.md` §Plugin: `mordred_wizard`,
`docs/dev/PATHS.md`, `docs/dev/POLICY.md`.

## Subcommand reference

Two equivalent entry points exist while Hermes 0.11 lacks entry-point CLI
wiring (the gap is documented in `cli.py:main` docstring):

- `hermes-mordred <COMMAND>` — standalone console-script (works today).
- `hermes mordred <COMMAND>` — will start working once Hermes 0.12+ ships
  entry-point CLI wiring; no plugin code change needed.

### `status [--json]`

At-a-glance dashboard: policy mode, network path (configured + live
runtime state), keyvault (initialised / key count / hardware helper),
and the four at-rest encryption targets. Side-effect-free — on-disk
reads and PATH lookups only; never prompts, never touches the Secure
Enclave or TPM.

Implementation: `status_cli.py`.

### `configure [--non-interactive] [--policy=...] [--harness=...] [...]`

Run interactive Mordred setup. Writes `~/.hermes/config.yaml`
(`plugins.mordred_*` sections, round-trip via ruamel.yaml) and
`~/.hermes/mordred/policy.json` (the wizard-owned mirror).
`--non-interactive` is flag-driven (no prompts): `--policy` /
`--allow-cloud-llm` / `--cloud-allowlist` / `--local-llm-endpoint` /
`--local-llm-model-id` / `--cloud-attempt-action` / `--harness`, each
seeded from the existing policy.json + config.yaml so a bare re-run
keeps prior answers.

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
- `audit purge --before YYYY-MM-DD` — delete rotated `audit.log.<date>`
  files dated strictly before the cutoff (manual cleanup of pre-Phase-4
  plaintext history). Never touches the active `audit.log`; non-dated
  rotation files are left alone. Exit codes: `0` (done), `2` (bad date).

- `audit decrypt --date YYYY-MM-DD` — decrypt the `MRAL`-encrypted audit
  log file(s) for a UTC date through the Secure-Enclave authorization
  boundary and print entries as JSON. Exit codes: `0` (decrypted), `1`
  (no file / corrupt / denied prompt / missing key), `2` (bad date).

Implementation: `audit_cli.py`.

### `plugins list`

List discovered Mordred plugins (those whose `key` starts with `mordred_`).
Closes the §0.5 L128 UX gap — Hermes 0.11's `hermes plugins list` does
not show entry-point plugins.

Primary path queries `hermes_cli.plugins.PluginManager`. Fallback reads
`~/.hermes/config.yaml` `plugins.enabled` when the manager API is
unavailable.

Implementation: `plugins_list.py`.

### `extension pair [--timeout=SECONDS]`

Generates a browser-extension pairing code and waits for it to be consumed.
**Deferred in this standalone repo**: it imports `gateway.extension_pairing`,
the Hermes-fork counterpart to this plugin (WebSocket server, chat/crypto/RPC
bridges) — see `docs/dev/ROADMAP.md` §"Browser-extension gateway counterpart
(deferred)". Until that ships alongside `mordred-hermes`, this command fails
closed with exit code `2` and a clear stderr message instead of a raw
`ImportError`.

Implementation: `extension_pair_cli.py`.

### `keyvault {list,verify-digest}`

Backend-free keyvault inspection (Phase 4 PR8). Both only read the
on-disk keyvault layout (`meta.json` + `digests/<hash>.commit`) — no
Secure-Enclave `NativeBackend`, no `cryptography`.

- `keyvault list` — print each key's cleartext id, on-disk hash and
  `created_at`. The verification digest (key material) is never printed.
- `keyvault verify-digest` — print the full 32-byte verification digest
  of every key, hex-encoded, for offline cross-checking. Exit codes:
  `0` (all read), `1` (empty vault / unreadable `digests/<hash>.commit`).

Implementation: `keyvault_cli.py`.

### `keyvault {init,recover,reset}`

Backend-coupled keyvault commands (Phase 4 PR10) — they build the
production Secure-Enclave `_SecKeyBackend`.

- `keyvault init` — generate a 24-word BIP39 Seed Phrase + seed-bound
  PoW, prompt for the Passphrase, display the Seed under a network
  blackout, and finalize once the operator confirms the verification
  digest computed offline. By default, the generated Seed is also
  SE-encrypted at rest for HD wallet reuse across sessions; pass
  `--paper-only` to keep the Seed strictly offline and never persist it.
  Also provisions the audit-log wrapping key so the encrypted-audit
  factory engages afterward.
- `keyvault recover --blob <path>` — restore a keyvault from an
  `export_backup` blob: prompts for the Seed Phrase + Passphrase,
  recomputes the seed-bound PoW, and calls `api.import_backup`.
- `keyvault reset` — **irreversibly** destroy all key material: delete
  every Secure-Enclave wrapping key (each `meta.json` key plus the
  well-known default + audit-log ids) and remove the on-disk keyvault
  directory. The interactive path requires the operator to type a
  confirmation phrase; `--yes` skips it for scripted use. Recovery is
  only possible afterward via `keyvault recover` with the backed-up Seed
  Phrase, Passphrase and blob.

Exit codes: `0` (done), `1` (any refusal — see the command's stderr).

Implementation: `keyvault_cli.py`.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

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

All `run()` / `migrate()` entries take keyword-only arguments (declared
after `*,`); `detect()` is the only positional entry.

| Module | Surface |
|---|---|
| `configure` | `run(*, setup_runner, prompt_io, policy_writer, non_interactive=False, with_hermes_setup=False) -> ConfigureResult`; `cli_handler(ns)` |
| `upgrade` | `UpgradeOptions`; `UpgradeReport`; `run(*, options, policy_writer, target_snapshot=None, openclaw_base=DEFAULT_OPENCLAW_BASE) -> UpgradeReport`; `cli_handler(ns)` |
| `openclaw_migration` | `OpenClawState`; `detect(openclaw_base: Path) -> OpenClawState`; `migrate(*, openclaw_base, policy_writer, options) -> Story1_5Action` |
| `install_dispatch` | `run(*, skill_arg, state, runner=_default_runner) -> int`; `cli_handler(ns)` |
| `policy_writer` | `PolicySnapshot`; `PolicyWriter.write(snapshot)`; `PolicyWriter.upsert_mordred_sections(sections: Mapping[str, Mapping[str, Any]])` |
| `policy_explainer` | `show()`, `explain(skill_id)`, `dry_run(skill_path)`, `reload()` + `cli_*(ns)` adapters |
| `audit_cli` | `tail(*, n, log_path=None)`, `grep(*, pattern, log_path=None)`, `purge(*, before, audit_dir=None)`, `cli_tail(ns)`, `cli_grep(ns)`, `cli_purge(ns)`. `log_path`/`audit_dir` `=None` resolves the active writer path via `privacy_check._runtime.get_active_audit_path()` so reads/purges follow the writer's configured `audit_log_path`; pass an explicit value to override (e.g. tests) |
| `keyvault_cli` | `list_keys(*, home=None) -> int`, `verify_digest(*, home=None) -> int`, `cli_list(ns)`, `cli_verify_digest(ns)`. Backend-free reads over `meta.json` + `digests/<hash>.commit`; `home=None` resolves the Hermes home via `_hermes_home()` |
| `plugins_list` | `run(*, config_path=DEFAULT_CONFIG_PATH) -> int`; `cli_handler(ns)` |

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
