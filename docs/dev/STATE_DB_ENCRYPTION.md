# state.db at-rest encryption (SQLCipher) — design notes

Status: phase 0 (feasibility spike) and phase 1 (startup hook under Hermes
Desktop) done; phases 2–7 not started.

## Goal

Hermes's conversation store `<home>/state.db` (messages, three FTS5 indexes,
session titles, system prompts) is plaintext SQLite. Encrypt the whole file
with SQLCipher, keyed from the key Mordred already manages, without forking
Hermes.

## Key

No new key is created or stored. The SQLCipher key is derived from the
existing agent-memory key (`HERMES_MEMORY_KEY`, already sealed in the vault
and injected into every Hermes process at startup):

    key  = HKDF-SHA256(HERMES_MEMORY_KEY, info="mordred state.db v1")
    salt = HMAC-SHA256(key, "mordred state.db salt v1")[:16]

The salt has to be supplied explicitly because the file header is kept in
plaintext (below).

## Mechanism

- `sqlite3` is replaced process-wide (in `sys.modules`, before Hermes imports
  it) by a module built from `sqlcipher3.dbapi2`, with the stdlib constants
  SQLCipher's module lacks. Replacing only `connect` is not enough: Hermes
  catches `sqlite3.DatabaseError` etc. 494 times and needs the exception and
  `Connection` types to match.
- `connect()` keys only `state.db` and the backups Hermes writes next to it
  (`state.db.*`, not lock files). Every other database stays plain SQLite.
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

## Remaining phases

2. Production shim + dependency (`sqlcipher3-wheels`, macOS extra), keyed
   from the vault-injected key; refuse to open state.db when the key is
   missing instead of letting Hermes create a plaintext file.
3. Migration (`sqlcipher_export` while Hermes is stopped; encrypted backup
   first; verify, then swap).
4. Monitor: at session start and before every model call, verify state.db is
   encrypted and no quarantined/plaintext copy appeared; block (strict) or
   warn (lenient) and notify.
5. Live status line in the system prompt.
6. Desktop page step and both uninstall modes (decrypt back / erase).
7. Redact message previews (`msg=`) from `logs/agent.log`.
