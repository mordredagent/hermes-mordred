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

## Approved additional test and code reduction

The user approved the [reduction design](../specs/2026-11-04-test-reduction-design.md)
and requested its inclusion in this same PR. This deliberately changes collection
identity/count; it is separate from the historical all-node-equivalent Unix
comparison above.

| Repeated execution | Before → after | Retained verification owner |
| --- | ---: | --- |
| Duplicate Windows syntax / plain Linux layout | 2 → 0 additional cases | Portable shared-source syntax check / stronger misleading-text Linux metadata case |
| Duplicate late Telegram cancellation | 2 → 1 | Existing secret scenario now also checks request, UI and notification outcomes |
| Older import completion happy paths | 2 → 0 additional cases | Both stronger stale-poll races now also check repeated and changed-count idle responses |
| Vault failure lifecycle | 4 → 2 | Expired and busy cover the two branches; closed-code wording checks remain |
| DirectTools generic refusal lifecycle | 7 → 1 | One real component refusal plus all seven independent literal wording checks |
| Mail generic setup refusal lifecycle | 15 → 3 | IMAP-hint, mail-specific and shared wording representatives; all fifteen literal phrases checked through the pure mapping |
| Secret value × admitted field kind | 90 → 32 | All thirty secret values plus the other two field branches; ordinary field/operation checks remain |
| Standalone historical span executions | 119 → 86 | Thirty-three overlapping inputs run the identical independent span assertion inside existing exact-output corpus cases |

Complete desktop pack: **343 → 318 cases**. Complete activity contract pack:
**810 → 719 cases**. Total: **116 fewer selected executions**, retaining every
unique behavior and all 119 independent historical span inputs. Runtime ownership
instrumentation observed every original historical input. Diagnostic covered file,
line and denominator sets were unchanged: desktop **482/482 covered lines**,
activity **1,595/1,595**. These focused diagnostic runs intentionally disabled the
whole-package coverage floor; they do not replace final >=80% acceptance.

The change shares seven identical numeric tree-text walkers and removes two
repeated full Node preparation runs. Two string-only walkers retain their
original semantics. Fifty redundant positional callback protocol declarations
were replaced by exact Callable field annotations; all default, keyword-only
and variadic contracts remain, including `_python`. This removes **201 tooling
lines**; test sources shrink by **54 lines**, for **255 net source lines removed**
relative to the pre-cleanup integration. No unproven runtime dead-code deletion
was made. Independent AST/call-site review verified the callback contracts.

Final focused outcomes: desktop **318 passed**, activity **719 passed**, complete
acceptance-tool pack **475 passed**; CLI help, Ruff, strict mypy (416 files),
import contracts and shellcheck passed. Seven process-local injected faults were
detected by retained checks: missing refresh, missing form clearing, lost busy
flow, applied late-cancelled response, wrong mail wording, field-specific secret
bypass, and lost historical spans while public exact-output expectations remained
correct. No production file was mutated for these probes. The independent review
found no Critical or Important issues; its documentation nit was corrected.

Desktop focused elapsed was 14.28s before and 28.65s after; activity was 32.46s
before and 83.89s in the final passing after run. **No new cleanup speedup is
claimed.** Unchanged common desktop tests slowed together. An intermediate
activity run under observed load 31.48 on ten CPUs failed the existing
`test_the_text_redactor_is_linear_on_hostile_input` and
`test_qualified_redaction_is_linear_on_hostile_input` wall-time ratio assertions
(717 passed, two failed, 236.06s). Both tests, their timing helper and activity
runtime were unchanged. They subsequently passed with wall/CPU sampling, then
the complete 719-case module passed. Load/scheduling sensitivity is supported;
the precise original failure timeline was not captured. Thresholds, timeouts,
skip conditions and runtime code were not altered to obtain green.


## Final local integrated regression

At source freeze `fae8b3b3ed856207be794ccb92cdca0d4570657c`, one complete
combined default regression passed: **14,688 passed, 300 skipped, 24 warnings**,
exit 0, **1,045.50s**. Combined coverage was **91.67%**, above the unchanged
80% floor. The 300 skip-reason counts match the original controlled baseline;
no new skip reason was introduced. The integration now selects 14,988 cases
versus 15,104 before the approved reduction.

Command: `uv run pytest -n 2 --dist=loadfile --max-worker-restart=0
--cov=mordred_hermes --cov-report=xml:<owned-path>
--cov-report=json:<owned-path> --junitxml=<owned-path>
-o junit_family=xunit1 --durations=15`, with an owned `COVERAGE_FILE` and
unchanged configured strict markers / integration exclusion. No concurrent
owned suite or build was running. Initial host load was 9.66/11.71/11.02 on
ten logical CPUs. This observed duration is not a repeat of the earlier
controlled comparison and supplies no additional speedup claim.

Final repository Ruff/format, strict mypy, import contracts, shellcheck and
documentation links passed. A subsequent fixture-only correction is recorded below; its fresh full regression and current-head hosted acceptance are recorded in the PR.
Hosted acceptance for the current PR head/base remains a separate pre-merge
requirement; its immutable run/artifact identity is recorded in the PR.


## Hosted CI fixture correction

The first hosted run `41847141538` at head `21bc15ce` passed Linux 3.11/3.13,
the Hermes floor and all four Windows workers. macOS failed only
`test_every_free_text_field_is_redacted_at_ingest`, so CI acceptance correctly
refused the incomplete matrix. All four explicit redacted-field assertions
passed; the final whole-record substring check failed. `raw_event` used a random
UUID, and that identity or its derived SHA-256 digest can coincidentally contain
the four-digit PIN `4821`. A process-local forced colliding UUID reproduced the
same failure before the fix.

The test now supplies one fixed valid UUID. All leak assertions, input secrets,
redaction calls and product code remain unchanged. The forced-collision test
then passed, and the complete containing module passed **719 cases in 80.64s**
with unchanged covered-line sets. The fixture correction adds three test lines;
current cleanup totals above include that adjustment. Fresh full local and
hosted validation runs are required for the new head; no successful worker
manifest from the failed first context is reused for acceptance.

First-run observed successful Unix pytest steps: Linux 3.11 **730s**, Linux 3.13
**713s**, Hermes floor **362s**. The three audit preflight cases passed on
Windows with a testcase-duration sum of **4.263s**, versus **30.193s** in prior
run `41820354815`. These are different hosted runs/revisions, not a controlled
Windows speed guarantee or acceptance for the failed whole-run context.

## Hosted macOS runner fallback

At head `a306a87f6`, run `41852281876` attempts 1 and 2 could not acquire the
hosted macOS arm64 runner. Both produced the explicit GitHub annotation
"The job was not acquired by Runner of type hosted even after multiple attempts"
and arm64 capacity notices. All other selected platforms passed in attempt 1;
CI acceptance correctly rejected the incomplete matrix. No successful earlier
worker manifest is reused for a later attempt or head.

The `macos` job now uses `macos-26-intel`. The first actual runner image was
`macos-26-arm64`, so the macOS generation remains 26. [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists the supported Intel label. Job/check identity, Python 3.11 floor, selected
cases, two-process command, coverage floor, strict typing, status guard, Swift
and TPM builds, timeouts, acceptance schema and all live gates are unchanged.
A scoped independent review found no ARM-only default-test skip or relevant
architecture-specific runtime branch introduced by this PR; T2 Intel Macs are
explicitly supported by the native test boundary. No native runtime/helper source
was changed.

This is an infrastructure fallback, not identical hardware coverage: dependencies
and native helpers now compile/run for Intel, and hosted ARM compilation is not
established. Earlier local ARM results remain labeled by their actual source
freeze; they do not become hosted ARM or live-device acceptance. A fresh complete
accepted run for the resulting head/base is still required before merge.

The post-fixture local full run at `a306a87f6` completed **14,687 passed,
300 skipped, one failed**, 24 warnings, 1,619.91s. The unchanged
`test_each_adversarial_shape_stays_near_linear[ja-target-joints]` measured 0.508s
for the small shape and 2.791s for the large shape: its approximately 5.5x ratio
was within the growth bound, but its separate unchanged 2.0-second absolute
budget failed. Host load was observed above 24 on ten CPUs during this run.
The failure is retained in the record; no budget or selector is weakened.
The complete containing property module is rerun separately, with its result
and the final exact-head hosted acceptance recorded in the PR.
