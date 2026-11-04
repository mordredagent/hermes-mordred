# Maintenance and performance validation — 2026-11-04

## Scope and provenance

The combined delivery starts at dev `0574053bb` and preserves component commits
for Windows fixture setup, database admission, import-history/search reads,
acceptance tooling and Unix test isolation. PR #295 remains separate and is
unchanged. The documentation-first designs were merged in PRs #292 and #294.

All current integration work uses its own editable environment at
`hermes-mordred-maintenance-combined/.venv`, CPython 3.11.15 on macOS arm64.
Mordred resolves from that worktree's `src`; upstream Hermes resolves inside
that same environment. An initial critical check used Python 3.14.7; subsequent
focused/static verification uses 3.11.15, matching the controlled comparison.

## Controlled Unix comparison

This is historical evidence for clean source `9caa72eb0`, not a timing claim
for the later combined revision or the additionally reduced tests. The original
same-host runs were serial, with no competing benchmark suite; both had xdist
installed and used the same interpreter, dependencies, source, markers and
coverage options. Separate private homes and coverage/report paths were used.

Machine: macOS 26.6.2 arm64, 10 logical CPUs. Dependencies: hermes-agent 0.19.0,
pytest 9.0.3, xdist 3.8.0, execnet 2.1.2, pytest-cov 7.1.0, coverage 7.14.0.
Serial started at 12:38:33 UTC (load 3.85/3.04/2.91, sampled CPU 13.7%);
parallel at 12:52:34 UTC (load 3.36/3.53/3.21, sampled CPU 11.9%). These load
observations do not establish an idle machine or hosted performance guarantees.

Both commands used `uv run pytest -q --cov=mordred_hermes`, XML/JSON coverage,
JUnit and a temporary exact-node report plugin. Serial added `-n 0`; parallel
added `-n 2 --dist=loadfile --max-worker-restart=0`. Existing addopts remained.

| Evidence | Serial | Two processes |
| --- | ---: | ---: |
| Process elapsed | 840.762s | 492.137s |
| Pytest session elapsed | 838.606s | 490.820s |
| Collection per process | 2.783s | 4.266s / 4.257s |
| Passed / skipped | 14,781 / 300 | 14,781 / 300 |
| Covered / executable lines | 55,670 / 60,732 | 55,670 / 60,732 |
| Combined coverage | 91.6650% | 91.6650% |

Elapsed reduction: **41.4654%** (14m00.8s → 8m12.1s). Recomputing the comparison
from the retained raw artifacts confirmed identical ordered collection manifests,
exactly one execution of every node/phase, terminal outcomes, skip reasons,
coverage file sets, executed-line sets and statement denominators. No lost or
added covered line was found. Worker coverage is combined, not averaged.

Private local artifacts: temporary directory
`mordred-additional-A-benchmark-rxbeigb1` under the macOS temporary root;
`metadata.json`, `comparison.json`, and each mode's `start.json`, `finish.json`,
collection manifests, `reports.jsonl`, JUnit, logs and coverage JSON/XML.
The comparison was independently recomputed during this integration. These
local files are not hosted CI evidence and are not permanent public artifacts.

## Resource ownership and rollout

| Resource | Owners | Isolation / resolution |
| --- | --- | --- |
| Ambient Hermes home and frozen defaults | Root conftest / all test files | Genuine workers create private homes before collection; serial and nested serial keep explicit caller homes; only worker-owned homes are cleaned. |
| Gateway test port 7799 | `extension/test_extension_serve_shutdown.py` | Whole-file scheduling keeps all owners together; child processes are reaped before fixture teardown. No production 7788 bind is introduced. |
| Other local HTTP/LLM/IMAP/socket peers | Extension API/serve/activity, local LLM, IMAP modules | Inspected binds use port 0; each test owns and closes its listener. |
| Package builds | `test_packaging_native.py`, `test_dbcrypt_packaging.py` | Private output/cache roots and outside-checkout source/wheel environments; no shared output path. |
| Native/build fixtures | Build-script tests and `hatch_build.py` | Script tests copy into temporary roots; wheel staging uses unique temporary directories; non-Windows hook exits without compiling. Live/native gates stay explicit. |
| Import-time product defaults | `tests/conftest.py` | No module-level product import; real workers refuse pre-frozen product modules. Extension fixture-closure guard remains active. |

The workflow enables the flags only for non-critical Linux/macOS default suites
and the Hermes floor suite. Step IDs, both floor deselections, platform workers,
Windows four-shard selection, feature/package/docs suites, live gates, timeouts,
acceptance schema and coverage floor remain unchanged. Local default pytest
remains serial. Worker crashes fail visibly without replay. The first hosted
current-context run must establish Linux/macOS/floor behavior; the macOS result
alone is not evidence for other platforms.

## Other component evidence

- Search now selects hits and hydrates a bounded prefix in one public protected
  read/snapshot. Tests cover independent candidate/output limits, zero hits,
  WAL interleaving, next-call freshness, refusal and full integrity checks on
  each actual protected open. The profiled three-result accounting is two opens
  to one, eleven application executes to eight, with five SELECTs retained.
- Database admission removes only duplicate pre-lock metadata observations.
  PID refusal precedes inherited locks, and full post-lock/callback checks and
  authenticated integrity scans remain. No integrity cache is introduced.
- Audit preflight fixtures keep real enrollment, checked writes, size/list/link
  refusal, decryption/native tripwires and unchanged bytes. The prior focused
  three-case local run passed in 0.30s; its containing pack passed 103 cases
  with eleven native-Windows skips. This is not a native Windows speed claim.
- Acceptance tools retain the compatibility facade, per-physical-copy imports,
  current-call dependency capture and copied input closure. Synthetic sequence
  and stop-receipt validation is not native acceptance.

## Current integration verification

Critical feedback passed 24 cases. The complete affected integration pack exited
0 with two-process file scheduling. Ruff check/format (930 files), strict mypy
(416 files), both import contracts and shellcheck passed before the additional
test/code reduction. The initial independent review found no Critical,
Important or Minor issues in that scope. The expanded reduction and final
integration evidence are recorded after their own validation below.

## Remaining device gates

No current macOS Secure Enclave, Linux TPM, Windows CNG/VFS source-and-wheel
acceptance, native Windows status contention or live Telegram/account acceptance
was run for this delivery. Ordinary SQLCipher tests, injected Windows paths,
synthetic evidence and hosted CI cannot close those hardware/account gates.
No production Hermes home or production gateway port was used for validation.
