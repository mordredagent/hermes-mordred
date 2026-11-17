# SQLCipher VFS feasibility probe

## Checked VFS implementation candidate (UNVERIFIED)

`vfs.c` and `checked_io.c` are a separate owned-handle implementation candidate,
not the delegating diagnostic probe below. Native database storage admission is
source-controlled: Linux, and Windows Server x64 (ServerStandard/ServerDatacenter,
including domain controllers) with the qualified sqlcipher3-wheels 0.5.7 driver
pair and the distribution-owned checked-VFS DLL, are admitted; Windows 10/11
Enterprise multi-session (ServerRdsh) and workstation editions are refused at
runtime. Admission is not acceptance: native platform acceptance evidence is
recorded separately in docs/dev/CI.md's manual validation log, and the Windows
native acceptance matrix is still pending.

Build with the same pinned headers described below, using `-Target Checked`.
`-Target CheckedTest` emits a distinct `_test.dll` with deterministic native
fault/creation-observer hooks; never distribute that artifact as a production
DLL. The default `-Target Probe` preserves the diagnostic build. All targets use
the caller's SQLite API table and no SQLite import/static library. The checked
implementation additionally links the Windows `Advapi32` security API.

```powershell
& ./native/dbcrypt-vfs/build.ps1 -Target CheckedTest -OutputDirectory $env:DBCRYPT_BUILD_ROOT -SqliteIncludeDirectory $env:DBCRYPT_HEADER_ROOT
$env:MORDRED_DBCRYPT_CHECKED_LIBRARY = "$env:DBCRYPT_BUILD_ROOT/mordred_dbcrypt_checked_test.dll"
$env:MORDRED_DBCRYPT_WINDOWS_VFS_TEST = '1'
# Existing, isolated ordinary-user root, basename mordred-dbcrypt-*.
$env:MORDRED_DBCRYPT_TEST_ROOT = $env:DBCRYPT_EVIDENCE_ROOT
uv run pytest -q -o addopts= -m integration tests/integration/test_dbcrypt_windows_vfs.py
```

Run the non-injection cases again against `-Target Checked` in a fresh Python
process (`-k 'not checkedtest and not injected_io and not every_creation and not inherited_dacl_race and not recovery_exclusive_lock and not shm_shared_lock'`). Do not load two compiled
versions into one driver process: duplicate VFS names and different SQLite API
tables intentionally refuse. A test-build pass does not qualify a release DLL.

The full native gate also requires `MORDRED_DBCRYPT_QUALIFICATION_MANIFEST`.
Missing special fixtures fail the gate. Its JSON schema is:

```json
{
  "schema": 1,
  "owner_sid": "<ordinary test SID>",
  "non_ntfs_root": "<owned fixed exFAT/FAT32/ReFS drive>:\\mordred-dbcrypt-<run>",
  "filesystem": "exFAT",
  "reparse_root": "<test root>\\qualification-reparse"
}
```

The NTFS reparse root must have the exact current-SID private DACL. It contains
`sentinel.bin` (exact bytes `mordred synthetic reparse target must not change\n`),
`direct-link.db` (file symlink to sentinel, tag `0xA000000C`), and
`unknown-tag.db` (non-Microsoft tag `0x00000042`, a non-null per-run GUID and
synthetic payload). Tests query actual volume information and reparse tags;
manifest labels alone are insufficient. Only an isolated owned VHD/drive and
owned objects may be provisioned. Preserve the unknown tag/GUID for cleanup,
remove owned reparse objects after handles close, then dismount/delete only the
owned VHD. No system-wide privilege or policy changes are needed by the tests.

CheckedTest's optional observer streams bounded snapshots directly from actual
I/O handles at creation, before/after writes, and before truncate/delete/close
and SHM unmapping. It does not reopen names, persist data, or export arbitrary
reads. Install/clear hooks only with no concurrent callbacks; borrowed handles
and buffers must not escape the callback. Snapshots are limited to 64 MiB and
fail the observing test on incomplete reads. Snapshot begin/success events
carry the expected byte length; incomplete snapshots emit a distinct failure
terminal and increment a sticky test-only counter, including size/allocation
and callback failures. Clearing the observer does not clear this evidence.
Acceptance checks the counter independently of permitted SQLite I/O refusals.
The observer negatives inject size/read/short-read failures after the race
baseline and require acceptance to fail. A separate synthetic plaintext control
must expose the committed marker's DELETE-journal before-image specifically at
a pre-delete/pre-truncate boundary; it cannot pass by detecting the main file.
Production Checked exports no observer, failure counter, or fault setter. Initialization fault stages 20/21/22 exercise the
actual entrypoint before VFS registration, before auto-extension registration,
and after successful auto-extension registration, including real rollback.

The extended suite adds multi-region WAL/SHM growth (>4096 frames), reader and
checkpoint/restart coordination in one and multiple processes, committed crash
recovery, lock-transition faults, API-library mismatch, native URI/path refusal,
and adversarial directory/DACL creation boundaries. These cases require new
native execution; earlier 27-test/16-production-case evidence does not cover
them. Use fresh processes and separate output directories for both DLL variants.

The bootstrap registers `mordred_checked_v1` permanently in the loading driver's
library. Explicit root leases hold ancestor handles without delete sharing;
close refuses with live database/sidecar handles. File creation supplies an
owner-explicit protected security descriptor in `SECURITY_ATTRIBUTES` before
visibility. Existing objects, all I/O, deletion and shared-memory mappings use
the validated handles, with no delegation to parent VFS file/SHM callbacks.

User URIs, network/device/drive-relative paths, alternate streams, ambiguous
names, untrusted ancestors, non-NTFS storage, reparse points, hardlinks and
non-private files refuse. All subdirectories beneath a root must also have the
exact private DACL. Memory temporary storage is set at connection creation;
disk temporary databases, subjournals and super-journals refuse. `ATTACH` and
`VACUUM` (which internally attaches a scratch database) currently refuse before
writes. The SQL authorizer forbids changing temporary storage to disk, and
both the SQL boundary and checked VFS refuse arbitrary extension loading.
The later connection gateway must prevent callers replacing the authorizer or
selecting a different VFS through raw driver APIs.

Source references for the locking ABI and Win32 behavior:

- [SQLite 3.51.1 Windows VFS](https://github.com/sqlite/sqlite/blob/version-3.51.1/src/os_win.c)
  and [rollback lock offsets](https://github.com/sqlite/sqlite/blob/version-3.51.1/src/os.h).
- [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
  and [file security](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
- [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
  and [SetEndOfFile mapping constraints](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setendoffile).

Portable path tests are evidence only for lexical admission. Native compiler,
ordinary-token NTFS races, injected failures, crash recovery, multiprocess
locking and independent security review remain required before qualification.

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

## Windows wheel build inputs

Windows x64 wheel and editable builds require MSVC x64 tools and explicitly
prepared SQLCipher 0.5.7 API headers. The package build hook never downloads
headers implicitly. Prepare them before installing the package:

```powershell
python tools/dbcrypt_build_headers.py --output-directory C:\build\mordred-headers
$env:MORDRED_SQLITE_INCLUDE_DIR = 'C:\build\mordred-headers'
uv build
```

The preparation command verifies the locked `sqlcipher3_wheels-0.5.7.tar.gz`
SHA256 (`5fd344abba62c487c4d857a6fb55cb8dff8a97d4c4fbb4f9394b473e8e315dee`),
extracts `sqlite3.h` and the `sqlite3ext.h` excerpt from its amalgamation, verifies
both header hashes, and writes `dbcrypt-headers.json` provenance alongside them.
For offline preparation, pass `--source-archive <downloaded-source.tar.gz>`;
verification remains mandatory. No SQLite implementation is extracted or linked.

The build hook validates and pins a private copy of these two headers, invokes
`build.ps1 -Target Checked`, verifies the resulting PE machine is AMD64, and
ships only the production bridge as
`mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll` in a
`py3-none-win_amd64` wheel. Missing headers/compiler, unsupported architectures,
compiler failures, missing output, or a wrong PE machine refuse the build.
The default `Probe` and `CheckedTest` targets never become the shipped bridge.
Non-Windows wheels retain their existing pure-Python tag. The sdist contains the
hook, preparation tool and native sources so it can build independently of the
checkout. Previously built native binaries are excluded from the sdist.

The `dbcrypt` extra retains its cross-platform SQLCipher floor of 0.5.4 and
constrains Windows to 0.5.7: native acceptance applies to a concrete driver,
header and bridge pair. The loader also checks that distribution version before
using a qualified production bridge. This constraint and successful packaging
are necessary but not sufficient for Windows runtime protection. The admission
statement in this file's introduction applies: `NATIVE_QUALIFIED` is true in
source, and acceptance is recorded separately. Ordinary capability and status do
not load the bridge, open SQL, authenticate custody or enroll a home.

Editable Python modules are imported from the checkout, while the forced native
asset is installed under site-packages. The locator therefore resolves only the
exact asset listed by the installed `hermes-mordred` distribution's file inventory,
validates its installation-root location, and refuses links/reparse points. It
returns unavailable when that owned artifact is absent; a source-tree DLL or a
diagnostic environment override cannot supply the production resource.

Normal `uv sync` / `uv run` tracks the packaging metadata, custom hook, header
preparation recipe, owned VFS C/header/PowerShell files, and the explicit
`MORDRED_SQLITE_INCLUDE_DIR` value as cache inputs, retaining the default source
directory presence key. Changing these inputs rebuilds the editable bridge.
External headers must still match the locked recipe. To force a rebuild after
replacing external inputs at the same location, use
`uv sync --refresh-package hermes-mordred --reinstall-package hermes-mordred`.
These cache/resource checks do not compile, load or qualify native code during
ordinary status rendering.
