# state.db at-rest encryption (SQLCipher) — design notes

Status: phases 0 (feasibility spike), 1 (startup hook under Hermes Desktop)
2 (`mordred_hermes.dbcrypt`, all of Hermes's databases), 3 (conversion of
an existing home, `hermes-mordred databases encrypt`), 4 (monitor), 5 (status
line) and the reverse conversion (`databases decrypt`) done; phases 6–7 not
started.

## Goal

Hermes's databases are plaintext SQLite: the conversation store `state.db`
(messages, three FTS5 indexes, session titles, system prompts) and its
siblings (`shared-state.db`, `projects.db`, `response_store.db`,
`memory_store.db`, `verification_evidence.db`, `kanban.db`,
`cron/executions.db`, `cron/deliveries.db`,
`telemetry/shared_metrics/metrics.sqlite3`, the same set per profile home).
Encrypt all of them with SQLCipher, keyed from the key Mordred already
manages, without forking Hermes. Only Python opens them (no Node/Electron
SQLite access in Hermes Desktop or the TUI).

## Key

No new key is created or stored. The SQLCipher key is derived from the
existing agent-memory key (`HERMES_MEMORY_KEY`, already sealed in the vault
and injected into every Hermes process at startup):

    key  = HKDF-SHA256(HERMES_MEMORY_KEY, info="mordred sqlite v1")
    salt = HMAC-SHA256(key, "mordred sqlite salt v1")[:16]

One key and salt for every database, so copies and renames Hermes makes
(backups, quarantines, staged exports) stay readable. The salt has to be
supplied explicitly because the file header is kept in plaintext (below).
The key is resolved on the first keyed `connect()`; if `HERMES_MEMORY_KEY` is
not in the environment yet, the vault-sealed `.env` is injected then, and the
plugin's later injection is skipped (one vault unlock per process).

## Mechanism

- `sqlite3` is replaced process-wide (in `sys.modules`, before Hermes imports
  it) by a module built from `sqlcipher3.dbapi2`, with the stdlib constants
  SQLCipher's module lacks. Replacing only `connect` is not enough: Hermes
  catches `sqlite3.DatabaseError` etc. 494 times and needs the exception and
  `Connection` types to match.
- `connect()` keys every database in Hermes's home and profile homes
  (`*.db`, `*.sqlite[3]` and the copies beside them such as
  `state.db.pre-update-….bak`; not `-wal`/`-shm`/lock files), except in
  directories that hold other programs' files (`installs/`, `tools/`,
  `hermes-agent/`, `mcp-installs/`, `skills/`, `desktop*/`, `cache/`,
  `mordred/`, `vault/`, `logs/`, ...). Nothing outside the home is in scope
  (Chrome's cookie store, the user's project databases), except an existing
  file that *is* one of our encrypted databases (a copy Hermes staged
  elsewhere). Without the key an in-scope database is refused rather than
  opened, so Hermes can never create a plaintext replacement.
- Armed by `<home>/mordred/db-encryption.marker` (phase 3 writes it after
  converting every database). Unarmed, nothing changes. macOS only.
- `PRAGMA cipher_plaintext_header_size = 112`: Hermes reads fields of the
  100-byte SQLite header directly from the file (format string, page size,
  `application_id` at offset 68 for its "file was replaced" guard, the full
  header in repair probes). With the default fully-encrypted header, or with
  32 plaintext bytes, Hermes either quarantines the file as invalid or
  refuses all writes with `StateDbReplacedError`. 112 is the smallest
  multiple of 16 covering the header; the extra 12 bytes are the page-1 B-tree
  header (no row data).
- The replacement must happen before Hermes imports `sqlite3`, i.e. from the
  `.pth` bootstrap. Phase 1 made that bootstrap run under Hermes Desktop.

## Phase 0 results (spike, synthetic data in a throwaway HERMES_HOME)

`sqlcipher3-wheels` 0.5.x on CPython 3.14 / macOS arm64: SQLCipher 4.12.0,
SQLite 3.51.1, FTS5 and the `trigram` tokenizer available.

| Hermes operation (real Hermes code) | plaintext DB, SQLCipher lib | encrypted DB |
|---|---|---|
| `SessionDB()` writable open (preflight, quarantine check, schema) | ok | ok |
| `list_sessions_rich`, `get_session`, `get_messages`, `get_messages_as_conversation` | ok | ok |
| `search_messages` English (FTS5) / Japanese (trigram) | ok | ok |
| `create_session` + `append_message`, then search the new row | ok | ok (after header fix) |
| `set_meta` / `get_meta`, close, reopen | ok | ok (after header fix) |
| `hermes_cli.backup_sqlite.preflight_state_db` (Desktop pre-update backup) | ok | ok; the backup is encrypted too |
| File readable by plain `sqlite3`? | — | no (`file is not a database`), before and after the run |

Opening the encrypted DB **without** the key: `SessionDB()` and the backup
preflight fail with `database disk image is malformed`; no quarantine and no
new plaintext file in that run. Hermes's other corruption-recovery paths
(startup watchdog, `hermes doctor` repair) are not covered yet; phase 4's
monitor is the backstop.

Differences to handle in phase 2:

- SQLite 3.51.1 < 3.51.3: Hermes warns about the WAL-reset bug and keeps WAL.
  Track a `sqlcipher3-wheels` build on SQLite ≥ 3.51.3.
- No `Connection.setconfig` (Python 3.12+ stdlib API): Hermes falls back to
  its < 3.12 path (retain quarantined connections via ctypes). Worked in the
  spike; needs a soak test.
- Missing module constants (`SQLITE_CONSTRAINT_TRIGGER`,
  `SQLITE_LIMIT_VARIABLE_NUMBER`, `SQLITE_CORRUPT_VTAB`,
  `SQLITE_CONSTRAINT_FOREIGNKEY`) are filled from the stdlib module.
- The optional `cjk_unicode61` FTS5 tokenizer is a loadable extension built
  for the stdlib SQLite; loading it into SQLCipher is untested (not installed
  on the dev machine).

Caution for anyone repeating the spike: importing Hermes modules in a foreign
interpreter imports `hermes_bootstrap`, which builds a managed environment for
`HERMES_HOME` and relaunches the script (it also rebuilt the web UI in the
Hermes checkout once). Stub `hermes_bootstrap` in `sys.modules` first.

## Phase 1 (done)

Mordred's `.pth` gates matched only console-script names, but Hermes Desktop
starts Hermes as `python -I -c …` and processes `.pth` files from
`hermes_bootstrap` while `sys.argv[0]` is `-c`, so none of Mordred's startup
guards ran there. The gates now also engage when `hermes_bootstrap` is being
imported; the PluginManager wrapper is deferred to a post-import hook because
the Hermes checkout is not on `sys.path` at that moment; `hermes_home()`
honours `HERMES_HOME` before Hermes is importable.

## Phase 2 (done)

`mordred_hermes.dbcrypt` (`_policy`, `_key`, `_shim`), installed first thing
by the runtime `.pth` bootstrap; `sqlcipher3-wheels` in the `macos` extra.
End-to-end with Hermes's own code (stubbed bootstrap, throwaway home): four
databases converted, then `SessionDB` read / English and Japanese search /
append / search the new row / reopen, plain reads of `shared-state.db`,
`projects.db`, `cron/executions.db`, and the Desktop backup preflight all
work; every file, including the emergency backup, is unreadable to the stdlib
module.

## Phase 3 (done)

`dbcrypt._migrate` converts an existing home (Mordred installed later):
discover every in-scope database (skipping other programs' directories),
classify plaintext / encrypted / unreadable, refuse if another process has any
open (`lsof`), then prepare every encrypted copy (`sqlcipher_export`, carrying
over `application_id`, `user_version` and WAL mode — rollback-journal mode
instead when SQLCipher's SQLite has the WAL-reset bug, as Hermes itself
chooses for new databases) and verify it
(`quick_check`, same tables and row counts). Only then: write a journal, arm,
swap with `os.replace`, drop the old sidecars, remove the journal. A failure
while preparing changes nothing; a crash after arming is completed from the
journal on the next start. `hermes-mordred databases encrypt` runs it now, or
schedules it (`db-encryption.pending`) when Hermes has the databases open; the
runtime bootstrap then converts before the process opens any database (other
starting processes wait on `db-encryption.lock`). Verified end-to-end on a
throwaway home with Hermes's own code.

## Phases 4 and 5 (done), and decrypting back

- `dbcrypt._monitor.check` (component `dbcrypt`, hooks `on_session_start` and
  `pre_llm_call`, i.e. every turn): when armed, it reports a process without
  the SQLCipher module, a missing key, a left-over journal, and any Hermes
  database the *stdlib* `sqlite3` can read (opened `mode=ro&immutable=1`, so
  the probe creates no sidecars). Top-level files are re-listed every check,
  the full walk is cached for five minutes. A violation is audited once per
  process and kind (`mordred.db_encryption.violation`), broadcast to Hermes
  Desktop, and either stops the turn (strict: a `MordredIntegrityRefused`
  subclass, which escapes Hermes's hook guard) or is added to the turn's
  context so the model tells the user (lenient).
- The `mordred.databases` system-prompt section states the checked status:
  encrypted, scheduled (not active yet), or the violation.
- `databases decrypt` (`_migrate.decrypt_all`) mirrors the conversion: prepare
  and verify every plaintext copy, journal, swap, then disarm; scheduled for
  the next start (`db-decryption.pending`) when Hermes has the databases open.
  An interrupted run is completed from the journal before anything else at
  startup (no key needed).
- Gotcha found while testing: reading an encrypted file without the right key
  usually raises `DatabaseError`, but with the plaintext header SQLite
  sometimes parses the encrypted page as a schema and the random bytes end up
  in the error message, which the `sqlite3` module fails to decode — a
  `UnicodeDecodeError`. Every probe treats both as "not this format".

## Remaining phases

6. Desktop page step and both uninstall modes (decrypt back / erase).
7. Redact message previews (`msg=`) from `logs/agent.log`.
