# Cross-platform database encryption

Date: 2026-10-24

Status: Proposed design; independent builder review completed, user approval pending.

## Intent and decisions

Make Hermes conversation storage and Mordred's Telegram, mail, and activity
storage usable with SQLCipher on macOS, Linux, and Windows. The result must
preserve existing ciphertext and refuse unsafe access rather than recreate an
unreadable database or quietly store sensitive records in plaintext.

The user selected **Approach A: one shared dbcrypt protection layer** and Astra
for this design. Reducing macOS Touch ID prompts is a separate task. This
document proposes the remaining engineering choices; these are author choices,
not additional user decisions. It is a design, not an implementation plan.

The repository source of truth remains [SPEC](../../dev/SPEC.md),
[PLAN](../../dev/PLAN.md), [TODO](../../dev/TODO.md), and
[STATE_DB_ENCRYPTION](../../dev/STATE_DB_ENCRYPTION.md). Component changes land
separately under the repository's one-component-per-PR rule, targeting `dev`.
No Hermes upstream PR, fork, or upstream implementation dependency is proposed.

## Goals, non-goals, and approaches

Success covers root `state.db`, protected sibling databases, child-profile
databases, and `mordred.db`, including supported backups and sidecar files.
Hermes SessionDB, FTS, Japanese text, imports, search, and collectors must work
through the installed distribution. Encryption working in isolation is not
completion of Telegram, mail, or activity support.

Preserve the current macOS SQLCipher format and existing macOS behavior. Keep
profile memory and Journey keys independent of the root database domain. Require
native Linux TPM or Windows CNG custody for managed homes, explicit enrollment,
and failure before writes when authority is missing or has changed.

Non-goals are cross-machine key portability, Linux/Windows portable recovery,
Touch ID changes, cloud synchronization, new account integrations, and encrypting
session JSONL or text logs through SQLCipher. Those files retain their existing
separate policy and must not be described as covered by database encryption.
Protection does not defend against an administrator, arbitrary malicious code
running as the same authorized Windows SID, or a compromised running process.

**A — shared dbcrypt, selected.** Extend the existing key, connection, migration,
monitoring, and lifecycle boundary. All consumers use that boundary. This keeps
one ciphertext format and one root database authority but requires careful
cross-component sequencing and an early Windows native-I/O feasibility gate.

**B — an independent Mordred-only SQLCipher store.** Activity and imports could
share one explicit encrypted opener without requiring Hermes's global SQLite
shim or `state.db` encryption. This would narrow the initial port, but require
separate store lifecycle/monitoring and leave conversation copies of retrieved
history outside its protection. It was not selected.

## Current foundation and compatibility

[dbcrypt/_key.py](../../../src/mordred_hermes/dbcrypt/_key.py) currently resolves
an environment key and caches the derived key without root identity scoping.
[keyvault/_memory_key.py](../../../src/mordred_hermes/keyvault/_memory_key.py)
already provides native memory-key routing, including Linux and Windows.
The design connects those capabilities without introducing a Linux/Windows file
vault, environment-key port, or ambient fallback for a managed home.

Keep the existing derivation exactly: HKDF-SHA256 with length 32, `salt=None`,
and `info=b"mordred sqlite v1"`; derive the 16-byte SQLCipher salt as
`HMAC-SHA256(database_key, b"mordred sqlite salt v1")[:16]`. Preserve the
112-byte plaintext header. That header exposes SQLite metadata, not row content;
its presence cannot prove that a database is plaintext or correctly encrypted.
Any future format change requires a separately reviewed, explicit migration.
Keep the Python 3.11 minimum and the repository's current CI compatibility
requirements. Wheel availability alone does not expand the supported runtime,
filesystem, or operating-system matrix.

## Root database ownership and runtime authority

One root-owned database marker describes one encryption domain across shared
root databases and all child profiles. Resolve the root from trusted repository
path policy, validate its physical identity, and use the ROOT native memory key
as the database key source. A child's independent memory/Journey key must never
be substituted for the root database key. Root native memory custody must be
explicitly enabled before database protection can be enrolled.

The marker identifies the versioned format, root binding, custody provider, and
key generation without recording secrets. Establishment and adoption verify
existing protected databases before accepting the binding. Existing macOS homes
retain the authority that decrypts their current databases; ambiguous historical
profile/key combinations require explicit reconciliation, never silent rekeying.

Replace the process-global cache with a runtime authority bound to the physical
root identity, owner identity (Windows SID where applicable), provider, and key
generation. It may retain the resolved database key only while its shared runtime
lease is valid. Native custody resolution and revalidation use short scopes;
Windows canonical-path and custody locks are never held for connection lifetime.

Freeze the acquisition order as root database lease, root native custody locks
in their existing internal order, then database operation locks in canonical path
order. Lifecycle callers must acquire the exclusive database lease before native
custody mutation; no path may reverse this order or upgrade a shared lease in
place. When exclusion cannot be obtained, refuse or require a clean restart.

The shared lease lasts for the process's protected-database runtime, including
held connections and cursors. Migration, adoption, decryption, and key lifecycle
operations require the exclusive lease. Cooperative lifecycle changes therefore
cannot replace authority underneath active protected database runtimes.

During a valid runtime lease, revalidation before admitting operations and
committing writes checks non-interactive owner/binding/generation metadata and
the wrapped-key or authoritative-record identity. It does not repeat native
private-key unwraps or add a macOS Touch ID prompt for every query or commit.
Check previously opened connections and cursors too. An invalid or missing
authority record, generation change, or validation failure makes the runtime
terminal: prevent further SQL, invalidate held cursors, roll back where possible,
close connections, and require fresh authority acquisition. Merely clearing the
next-connect cache is insufficient.

Fresh native key resolution belongs to initial runtime authority acquisition,
explicit authenticated diagnostics, and maintenance/recovery operations that
acquire new authority. A root/generation change requires stopping the old runtime
and acquiring authority in a new one. Short custody scopes serialize with native
mutation; metadata that cannot be safely observed non-interactively refuses
rather than silently weakening validation or prompting on each statement.

This assurance has a deliberate limit: disappearance or inaccessibility of a TPM
or native private key need not be immediately visible to metadata checks while
the derived database key is already in RAM. It cannot cryptographically revoke
that cached key. Detectable metadata loss or an actual native access failure
refuses on detection; fresh acquisition must prove native access. Acceptance
must distinguish those cases from immediate hardware revocation, which is not
promised. No failure permits fallback or database repair.

## Windows native-I/O feasibility gate

The existing Windows `_private_fs` checks do not secure SQLCipher's subsequent
pathname-based opens. Prechecking a filename, then handing it to SQLite, leaves
an unprotected identity/creation boundary. Windows support depends on closing it.

Author choice: investigate a narrow native VFS bridge loaded through the SAME
SQLCipher connection's extension API. Use its `sqlite3_api_routines` interface,
not exported Python-extension symbols or a second SQLite DLL. Bootstrap on an
in-memory connection, keep the VFS registration and DLL valid while any protected
connection exists, and use SQLite's persistent-extension mechanism as required.
Disable further arbitrary extension loading after trusted initialization.

Before broader implementation, test the current Windows wheel on the authorized
AWS instance: ABI compatibility, extension loading, persistent registration, the
actual selected VFS, and observed database/journal/WAL/SHM callbacks. In particular,
prove that `xShmMap` and `xShmUnmap` cannot delegate to unchecked pathname opens.
An importable SQLCipher module or successful encrypted SELECT is not this proof.

The bridge must enforce exact handle identity, owner/DACL policy, reparse refusal,
and hardlink policy on the database and every companion file. Cover `xOpen`,
`xDelete`, rollback journals, WAL, SHM, temporary and super-journals, truncation,
rename/recovery operations, and parent-directory identity. Supply a validated
private DACL atomically at creation, or prove equivalent trusted inheritance;
creating broadly accessible files and fixing their ACL afterward is unacceptable.
Pin sensitive temporary storage to memory and
verify that supported operations cannot spill plaintext into unmanaged scratch
files, or supply an equally checked encrypted temporary-file path.

Protected connections must force the approved VFS. URI parameters, `ATTACH`,
backup destinations, and auxiliary connections cannot select another VFS or escape
scope. Classify Windows drive paths and URI forms before any open; accept only
the initial supported fixed local NTFS scope. Reject UNC/network paths, device
namespaces, unsupported filesystems, and ambiguous spellings until separately
validated. Unsupported or unknown capability fails closed.

Initial Windows acceptance is x64 Windows Server on the identified AWS host with
an ordinary, non-elevated user token. It does not establish Windows 11/Desktop
support. If the current wheel cannot enforce the boundary, Windows remains
unsupported pending a reviewed packaging or native-adapter change; it must not
ship with a best-effort Python precheck.

Technical references: [SQLite extension loading](https://www.sqlite.org/loadext.html),
[VFS](https://www.sqlite.org/vfs.html),
[I/O methods](https://www.sqlite.org/c3ref/io_methods.html), and
[sqlcipher3-wheels](https://pypi.org/project/sqlcipher3-wheels/).

## Migration, monitoring, backup, and lifecycle

Keep the existing prepare, verify, arm, swap, and recovery journal model, with
equally atomic decryption. Inventory the root, child profiles, recognized backup
locations, and sidecars completely. Unknown entries, unreadable directories,
inconsistent markers, or ambiguous recovery state stop conversion. Startup readers
must respect the migration state before opening any scoped database.

Replace direct POSIX `flock` and hardcoded `/usr/sbin/lsof` assumptions with OS
adapters. Linux combines cooperative runtime leases with reliable `/proc` holder
inspection. Windows needs native shared/exclusive leases plus verified holder,
sharing, and rename behavior. Incomplete holder visibility is refusal, not proof
of inactivity. File replacement occurs only with exclusive authority and confirmed
quiescence; preserve crash recovery through every durable migration transition.

Monitor a live database through the same SQLite library that owns its connections.
Do not use plain file probes or another SQLite library: closing an independent
POSIX descriptor can drop process-associated SQLite locks. Verification requires
the real SQLCipher key and schema checks. Wrong keys, plaintext where encryption
is required, incompatible schemas, and wrong root/profile bindings must refuse
without recreating, quarantining into a new empty database, or overwriting data.

Backups and restores preserve encryption and authority bindings and pass the
same destination and filesystem checks. Record managed encrypted backups as key
dependencies. Preserve `mordred.db` rollback-journal requirements and the existing
WAL-reset vulnerability guard; do not enable WAL just because it is available.
Crash tests must cover both database contents and the migration/backup inventory.

Put database-dependence checks at the LOW-LEVEL keyvault deletion/mutation boundary,
so direct APIs, CLI, uninstall, reset, disable, purge, and rotation cannot bypass
them. Refuse key destruction or replacement while protected or pending databases,
recovery journals, or registered encrypted backups still depend on that generation.
First restore/decrypt or explicitly migrate dependencies under exclusive authority;
only then may memory teardown or helper removal proceed. Rotation of dependent
databases is not implicit in ordinary native-key reset.

Arbitrary offline or external backups cannot be exhaustively discovered. State
this limitation explicitly: deleting the last native key can make those backups
unrecoverable. A clean managed inventory proves only that inventory, not universal
backup absence. Portable Linux/Windows recovery is outside this scope.

Status is read-only and must not unwrap keys, create custody, or enroll a root.
Report configuration, observable dependencies, and capability checks separately
from authenticated readiness. Driver import alone cannot claim readiness; checks
requiring native authentication belong to an explicit diagnostic/use operation.

## Consumer slices and dependency boundaries

Activity and imports use the shared protection gate with no plaintext fallback.
Windows must validate activity directories, peer/import sources, and backup
destinations through checked filesystem operations. Exercise inserts, search,
deduplication, restart, and backup/restore against real SQLCipher.

Telegram already has Linux/Windows credential foundations. Port migration,
destination handling, and forget paths as well as normal collection. Its account
credentials remain distinct from the root database key and must survive neither
an unintended role substitution nor unsafe plaintext temporary storage.

Mail credentials currently depend on macOS. Add an independent native mail role
before enabling Linux/Windows collection. Windows currently validates an exact
`memory`/`audit`/`telegram` role set: extending it requires an explicit versioned
schema migration that preserves existing roles. Never reuse the Telegram key for
mail. IMAP credentials and stored mail records have separate custody purposes.

## AWS acceptance matrix and evidence

Use existing resources in AWS profile `intmax-dev`, region `ap-southeast-1`:

| Platform | Existing instance | Configuration |
| --- | --- | --- |
| Linux | `i-095cbe655c196c749` | `t3.medium`, UEFI TPMv2, `ami-051b6fcf03fe035eb` |
| Windows | `i-00f4db5c3a204906b` | `t3.large`, UEFI TPMv2, `ami-05171b2d13ab22cba` |

STS and EC2 metadata were checked on 2026-10-24; both instances were stopped.
There is no guest/runtime acceptance result from this design work. Linux has no
IAM instance profile; reuse pinned SSH and existing admitted access. Windows has
an existing instance profile and a prior SSM/credentialed ordinary-user SSH harness.
SSM inventory returned no entries while stopped; actual guest access is unverified.

At implementation time, arm an external bounded auto-stop BEFORE starting either
instance. Reuse existing access without unnecessary IAM or ingress changes. Use
synthetic private homes and fresh sdist-built wheels installed outside the checkout.
Run complete affected modules separately against the source install and a fresh
installed wheel, recording provenance and outcomes for both environments.
Do not modify production homes or port 7788. Exercise the real NitroTPM/CNG key
source and record package location, driver/native versions, token, and filesystem.

| Acceptance area | Required evidence on each claimed platform |
| --- | --- |
| Real storage | Hermes SessionDB/FTS and Japanese text; activity, Telegram, mail import/search |
| Authority | Wrong/lost key on acquisition; metadata loss and generation change with held connections; no per-operation unwrap; distinguish cached-key hardware-loss limits |
| Filesystem | Sidecars, checked destinations, path/URI/ATTACH escape refusal; Windows native hooks |
| Concurrency | Multiprocess readers/writers, migration exclusion, holder uncertainty, crash recovery |
| Persistence | Backup/restore, process restart, reboot, actual EC2 stop/start with native custody |
| Lifecycle | Direct low-level and CLI disable/purge/reset/rotation/uninstall refusal with dependencies |
| Cleanup | Independently confirm instances stopped and inventory residual test resources |

Mocks establish collector storage behavior, not successful use of real accounts.
Live Telegram, IMAP, and LLM gates remain separate and must be labeled accordingly.
Record executed live results in the existing CI validation log only after execution;
do not manufacture a historical live-validation entry for this design or AWS inventory.

## PR sequence and remaining decisions

Land the cross-component specification first. Then establish the Windows VFS
feasibility gate and root-authority/lifecycle contracts; capability-dependent work
cannot claim Windows support before those gates pass. Follow with separate dbcrypt,
keyvault credential-role, activity/import, Telegram, and mail component slices in
dependency order, then installed-package acceptance and documentation reconciliation.
Each security-sensitive slice needs complete affected test modules and relevant
explicit live gates; run one full regression at final integration, per CI policy.

Author calls are a root-wide database domain, fixed local NTFS for initial Windows
support, fail-closed VFS feasibility, independent mail credentials, and no portable
Linux/Windows recovery in this scope. Builders may select internal APIs and native
packaging details consistent with these boundaries. VFS viability and actual AWS
guest access remain evidence questions; failure narrows claimed support rather
than relaxing the security boundary. After user approval, write the implementation
plan with concrete tests, file ownership, and the independently reviewable PR slices.

Independent builder review identified one material ambiguity: metadata/generation
validation versus repeated native authentication. The runtime-authority section
now fixes that assurance level, authentication events, and cached-key revocation
limits. Windows VFS viability and guest connectivity remain explicit execution
gates, not presumed implementation or acceptance results.
