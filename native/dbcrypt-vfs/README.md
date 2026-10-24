# SQLCipher VFS feasibility probe

This is diagnostic instrumentation, not the production Windows checked VFS.
Normal I/O delegates to SQLCipher's default VFS. The SHM denial experiment
proves an owned callback can refuse mapping before that delegation, and that
the refused write does not commit. It does not prove DACL, reparse, hardlink,
sharing, or crash-safe native filesystem mediation.

The extension uses the loading SQLCipher connection's `sqlite3_api_routines`
and links no SQLite library. It returns `SQLITE_OK_LOAD_PERMANENTLY` and
registers its diagnostic functions for subsequent connections. The runner
closes the bootstrap connection before testing encrypted rollback/WAL I/O,
Japanese trigram FTS, keyless refusal, and SHM denial.
Bootstrap initialization publishes no SQL function callbacks before permanent
loading succeeds. Reserved-name collisions refuse before publication; failed
VFS/auto-extension registration is rolled back. A subprocess regression checks
all three reserved names and verifies later connections remain usable.

## Build and run

Use matching public SQLite API headers from the installed driver's source
distribution. For the currently locked `sqlcipher3-wheels==0.5.7`, the source
archive SHA-256 is
`5fd344abba62c487c4d857a6fb55cb8dff8a97d4c4fbb4f9394b473e8e315dee`.
Its `src/sqlcipher/sqlite3.h` is present directly; extract `sqlite3ext.h` from
the `Begin file sqlite3ext.h` / `End of sqlite3ext.h` section of its matching
`sqlite3.c`. Keep headers and downloaded/build artifacts outside the repository.
Record their hashes, the driver version, compiler identity and build command.
Changing the driver requires rechecking this source/header provenance.

From an x64 MSVC environment (the script also discovers installed build tools):

```powershell
& ./native/dbcrypt-vfs/build.ps1 -OutputDirectory $env:DBCRYPT_BUILD_ROOT -SqliteIncludeDirectory $env:DBCRYPT_HEADER_ROOT
$env:MORDRED_DBCRYPT_PROBE_LIBRARY = "$env:DBCRYPT_BUILD_ROOT/mordred_dbcrypt_probe.dll"
uv run python tools/dbcrypt_vfs_probe.py --output "$env:DBCRYPT_EVIDENCE_ROOT/probe.json"
```

The explicit library path is required; no DLL is selected from a working
directory or downloaded automatically. Copy the runner, tests and compiled
diagnostic DLL outside the checkout for installed-wheel acceptance. Set
`MORDRED_DBCRYPT_PRODUCT_PREFIX` to the expected source or wheel install root.
The native test is
`tests/integration/test_dbcrypt_windows_vfs_probe.py`, gated by
`MORDRED_DBCRYPT_VFS_PROBE=1` and an existing synthetic
`MORDRED_DBCRYPT_TEST_ROOT` whose basename starts with `mordred-dbcrypt-`.
Run it with `uv run pytest -o addopts= -m integration -s` under a credentialed,
non-elevated Windows user. Neither this test nor the runner accesses real
Telegram, IMAP, native custody keys, or a production Hermes home.

## AWS control

`tools/dbcrypt_acceptance_control.py arm` creates a private receipt and starts
an independent local supervisor. It verifies a future deadline (at most two
hours), credentials lasting beyond cleanup, stopped instance state, and a
live supervisor before admitting `start`. The supervisor begins stopping
one minute before the deadline and retries while preserving failure evidence.
Keep the controller computer awake and connected for this bounded run.

Use one controller host and one OS operator identity for these two instances.
The private canonical admission directory
`~/.cache/mordred-dbcrypt-control/` serializes starts across worktrees and
receipt paths and retains an ownership record until cleanup finishes. Do not
delete its records or start these hosts from another controller while a run
is admitted. EC2 tags alone are not a conditional ownership lock.

A start with an uncertain result remains supervised and keeps its ownership
until actual activation becomes visible and is stopped. A stale `stopped`
observation never retires an uncertain start. The guard can therefore remain
active beyond the requested deadline while the provider result is unresolved;
the deadline is a stop-request deadline, not a guarantee against AWS API
unavailability or unbounded eventual consistency. Investigate an unresolved
run without deleting its receipt or admission record. Evidence-write failures
trigger cloud cleanup using retained validated run identity; the guard retries
and retains ownership until evidence persistence recovers.

The two retained instance IDs, AWS profile `intmax-dev` and region
`ap-southeast-1` are allowlisted. A receipt's token must match the EC2 owner
tag before a started instance can be stopped. Preexisting running instances
and another task's token refuse. A lost start response is still a start
intent requiring cleanup. `stop` waits for observed stopped state; `verify`
queries EC2 again. Never delete the receipt/supervisor while a run is active.
Receipts and supervisor logs contain operational metadata, never exported
AWS credentials. Live results belong in the existing CI validation log after
execution; an import or diagnostic probe pass alone is not product support.
