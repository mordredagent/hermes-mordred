# Mordred — CI Policy (Hermes-base)

> **Status**: current operational policy for this standalone repository. Workflow
> YAML is authoritative for mechanics; this document owns intent, release order,
> branching, and manual validation requirements.

## Why it got simpler

Mordred is a plugin package, not a Hermes fork. CI is responsible for Mordred's
source, package, native helpers, compatibility floor, and declared integration
boundaries. Hermes tests and releases remain upstream responsibilities.

## Standalone-repo adaptations (2026-07-01)

The standalone repository resolves `hermes-agent` from PyPI, ships its own five
workflows, and has no inherited upstream workflows. The initial repository-split
repair is complete; historical restoration details remain in Git.

## Active workflows

| Workflow | Purpose | Trigger |
|---|---|---|
| `ci.yml` | Test matrix, extras, wheel smoke, Tor/TPM, native helper builds | Non-documentation-only PRs and pushes to `dev`/`main`; manual dispatch |
| `upstream-check.yml` | Hermes hook-name and consumed-payload drift | Weekly and manual |
| `labeler.yml` | Path-based PR labels | `pull_request_target` |
| `integration-vpn.yml` | Live Mullvad validation | Manual only |
| `release.yml` | TestPyPI/PyPI build and publish | Manual only |

## `ci.yml` details

The workflow has six job definitions. Final validation runs two Linux main
workers, a parallel Linux compatibility-floor worker, macOS and four Windows
workers:

| Scope | Scheduled jobs | Python and validation |
|---|---:|---|
| Ordinary portable change | 3 | Policy, Ubuntu 3.12 default suite, acceptance |
| Ordinary platform change | 4–6 | Adds selected macOS, Windows and/or Linux floor workers |
| Documentation-only PR or push | 0 | Filtered before workflow startup; local checks or manual dispatch remain available |
| Draft feedback | 3–5 | Critical preset on Ubuntu 3.12 and mapped platforms |
| Final validation | 10 | Policy, Linux 3.11/3.13, Linux floor 3.11, macOS 3.11, four Windows 3.11 shards, acceptance |

`ci-policy` discovers the complete cumulative PR diff through paginated GitHub
API responses. It checks the reported file count and rechecks head/base metadata;
renames inspect both paths. It never classifies only the latest PR commit.
`tools/ci_scope_paths.json` is a finite inventory of reviewed existing paths.
A PR that adds a file lists it there in the same PR; entries for files that do not
yet exist are rejected, so documentation PRs cannot pre-register them.
Automatic push and PR events are filtered when every changed path matches
`docs/**/*.md`, `README.md`, `AGENTS.md`, `CLAUDE.md` or `notes.md`. This includes
developer Markdown. `docs/dev/VERSION`, executable examples, workflow changes
and Markdown under `src/` or skill directories remain CI inputs. Mixed changes
start CI and retain the existing conservative cumulative scope classification.
The internal two-job `docs` route remains for compatibility with policy/evidence
consumers; it does not start a workflow for these filtered events.
New, removed, unknown, shared storage/bootstrap/crypto/authentication, native,
installer, dependency, CI and tools changes conservatively require final
validation when ready. Mapped component changes retain complete affected
Windows test families, rather than selecting isolated passing cases.

A `dev` push can use its `before..after` diff only when `before` is an ancestor
and has successful accepted ordinary-or-final CI evidence on exactly `dev`.
Missing, pending, cancelled, failed or inaccessible evidence, initial pushes and
force pushes select final validation. This prevents a small follow-up commit
from cancelling an untested broad change and then hiding it behind a short CI.
`main` pushes, PRs targeting `main`, manual dispatch and `ci:full` select final
validation. The label is read on existing PR events: apply it before the next
synchronize/reopen/ready event, or dispatch CI manually. A label-only change does
not start CI. PR event types remain opened, synchronize, reopened,
ready_for_review and converted_to_draft. Documentation-only events are filtered
before scope selection, including on `main` and draft/ready transitions. A
`ci:full` label cannot override that filter; use manual dispatch when validation
of a documentation-only revision is wanted. Manual dispatch remains unfiltered
and selects final validation.

Skipped revisions produce no acceptance evidence and are not accepted baselines.
The next code push may therefore select final validation when its exact `before`
SHA has no accepted run; do not substitute a nearby green SHA. Releases still
require final evidence for the exact release revision. If branch protection later
requires `CI acceptance`, account for filtered runs remaining pending before
making that check mandatory; do not silently relax the release evidence gate.
The labeler remains independent PR metadata automation, not a test workflow.

Key policy:

- Non-critical Linux/macOS default suites and the Hermes-floor suite use
  `-n 2 --dist=loadfile --max-worker-restart=0`. Real workers receive private
  homes before collection; local pytest remains serial by default. Critical,
  Windows and explicit feature/live suites keep their existing execution.
  The controlled same-host comparison retained all outcomes and covered lines
  with 41.47% less elapsed time; see the [validation record](../superpowers/reports/2026-11-04-maintenance-performance.md)
  for revision boundaries, resource ownership and outstanding platform gates.
- Ubuntu ordinary/final workers run the complete default suite with coverage
  >=80% and strict mypy. Drafts run critical feedback plus CI-tool tests.
- The optional macOS worker runs the complete default suite, coverage, typing
  and status guard; drafts retain critical feedback and the status guard.
  It uses the supported `macos-26` ARM64 runner, restoring the original macOS
  26 ARM validation target. A temporary macOS 15 Intel fallback followed hosted
  runner-acquisition failures on 2026-11-04. The post-#295 dev run then failed
  existing elapsed-time budgets on that fallback in both
  [attempt 1](https://github.com/mordredagent/hermes-mordred/actions/runs/41933231755/attempts/1)
  and [attempt 2](https://github.com/mordredagent/hermes-mordred/actions/runs/41933231755/attempts/2).
  All test selectors, performance limits, timeouts, coverage floors, worker/check
  identities, the Python floor and complete Swift/TPM packs are retained. Fresh
  ARM runner acquisition and complete selected checks must succeed before
  acceptance; runner availability is not assumed. Intel results and live-device
  qualification remain separate evidence; see the
  [delivery record](../superpowers/reports/2026-11-04-maintenance-performance.md)
  and GitHub's [supported runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- Ordinary/draft Windows requests use one worker; final uses four isolated
  Windows runners. Ordinary workers retain complete mapped modules and remaining
  critical cases. Final workers cover all 84 frozen native modules once; routine
  Windows validation excludes only 28 reviewed portable cases. Full Windows
  validation retains them for `main`, manual dispatch and `ci:full`.
  Helper validation and the outside-checkout wheel run once, on shard 1.
- Static Ruff, formatting, import-linter, shellcheck and status checks run once
  on Linux.
  Main typing uses `.[dev,keyvault,extension]`, plus `macos` on macOS. Feature,
  Hermes-floor, integration and swtpm packs have separate environments.
  Auxiliary environments, including the documentation-test environment,
  live under `RUNNER_TEMP` outside the checkout so dependency documentation
  cannot enter repository Markdown or packaging scans.
- Final Linux 3.11 also runs feature-import proofs and focused suites,
  canonical/compatibility package smoke, Docker Tor,
  TPM Rust/MSRV and swtpm/Linux Telegram checks as blocking steps. Linux 3.13
  retains the complete default suite and typing. A separate `linux-floor` job
  runs the complete Hermes 0.13 suite and version guard whenever selected; it
  depends only on policy, so it runs alongside the main suites. macOS absorbs Swift and TPM
  Rust checks; Windows absorbs winkey stable/MSRV/build checks and wheel smoke.
- `CI acceptance` always runs after all selected workers and fails if a worker,
  pack or successful blocking step is missing. Unique OS/version/role/shard/run/attempt
  manifests avoid last-writer-wins matrix outputs. Feedback/documents and routine Windows evidence cannot
  qualify a production release. Release admission requires final mode and the
  full Windows tier for the exact branch SHA. Rerun **all jobs** for accepted fresh evidence;
  rerunning only failed jobs cannot reuse manifests from an older attempt.
- Where branch protection is available, use the single stable `CI acceptance`
  check rather than retired matrix checks. Repository settings are configured
  separately from this YAML; a critical green remains feedback only.
- For a PR that starts CI, merge only after acceptance for its current tested merge context
  succeeds with the selected scope. Sensitive/unknown changes require final;
  ordinary acceptance covers mapped non-foundation changes. A head/base update
  invalidates previous context. Protection is currently unavailable, so this
  remains an operator rule until repository settings can enforce it.
- GitHub Actions use immutable commit SHAs; Cargo uses `--locked`. Default
  pytest excludes integration. Live LLM/Secure Enclave remain explicitly gated,
  and VPN remains manual-only. No scheduled full CI is added.

The reduced matrix deliberately gives up native macOS/Windows Python 3.13
coverage and routine all-platform coverage. Python 3.13 remains covered on
Linux; final Windows and macOS cover the declared 3.11 floor. Adding back a
platform/version requires evidence that its additional coverage merits the cost.

Baseline observations from 13 current 25-job successful runs: median elapsed
18.80 minutes and raw summed job wall time 192.15 minutes. A portable ordinary
route has a 7.25-minute historical proxy (budget 8–12 minutes); the consolidated
final route has an 80.88-minute raw-time proxy (budget 75–95 minutes). The
successful consolidated run `38204317824` measured 52m39s workflow elapsed and
52m24s on Windows, including 49m27s of native pytest. Later two-runner runs `38814638531` (PR) and `38817644917` (`main`) took
21m03s and 29m49s respectively. Four workers plus a parallel floor pack target
12–18 minutes for a final run. This is a target, not a measured guarantee;
see the measured selection below.
Queue time and runner speed vary. Raw summed job time is not billed minutes.

### Critical feedback and full regression

For ordinary edits, run the critical preset plus the modules you changed:

```sh
uv run python tools/run_critical_tests.py
uv run pytest -q tests/test_<affected>.py
uv run python tools/run_critical_tests.py --list
uv run python tools/run_critical_tests.py --dry-run
```

The preset uses exact existing node IDs, including individual parameter cases;
missing nodes fail collection. It runs 19 cases on Linux and 20 on macOS or
Windows, prints the slowest durations, and accepts `--junitxml <file>` for
evidence. It excludes integration/live gates and selects real filesystem tests
for the current platform, rather than counting skipped foreign-platform cases.
No test assertions, security checks or test timeouts are changed.

| Critical risk | Representative existing test coverage |
|---|---|
| Unsafe storage or stuck lock | Real checked roundtrip; permissions and symlink/junction/hardlink refusal; crashed lock-owner release; macOS ancestor ACL refusal |
| Configuration uncertainty | Failed pair verification retains its marker; caught post-publication verification failure remains uncertain |
| Custody loss or profile copy | Retained wrapper without manifest never regenerates; copied physical home refuses |
| Memory transition/read failure | Real installed child and checked storage enable, fresh read, rerun, disable, retained key; existing test-only native backend |
| Authentication or credential exposure | Unauthenticated commands refuse; page sessions cannot access credentials; sealed credentials without custody refuse |
| Destructive logout ordering | Busy forget preserves local/remote state; successful forget wipes before remote revocation and preserves other roles |
| Gateway availability | Connected clients stop within the existing bound; immediate restart on test port 7799 |
| Plugin or policy admission | Installed entry point resolves; real component registration; refusal propagates; pending policy generation blocks cached allow |

Passing this subset is feedback only. The full suite retains unselected
parameter combinations, fault matrices, packaging builds, provider extras,
compatibility floor, native helpers and platform gates. Security-sensitive
changes still require the entire containing test modules and their relevant
explicit live-device paths; a fast preset cannot establish hardware or product
acceptance. After focused iterations, run one full regression at final
integration/code freeze. Reports or documentation do not justify repeatedly
rerunning unchanged broad suites.

Known draft PRs run critical feedback on Ubuntu 3.12, adding macOS or Windows
only for mapped platform changes. Linux runs repository-wide static checks
(including import-linter layering contracts), strict typing, shellcheck, the
status guard and CI routing/runner tests. Draft
documentation-only changes are filtered before any job starts, as described above.
For workflows that run, failures remain red and JUnit artifacts are
uploaded after failures. A critical green cannot supply an accepted dev baseline
or release evidence. Unselected regressions can be discovered later in exchange
for cheaper iteration.

Ready conversion, open/reopen and ready updates select the complete appropriate
scope from the cumulative diff. Sensitive or unknown changes receive final
validation. For events that pass the path filter, `main` and `ci:full` receive final validation;
manual dispatch is unfiltered and always receives final validation,
including from a draft branch. Unexpected/incomplete discovery selects final
conservatively. Non-documentation-only branch pushes are observed, including unknown paths.

Windows critical CI prepares a fresh checked home and `mordred` child under
`USERPROFILE`, then exports `HERMES_HOME` before test collection. `RUNNER_TEMP`
is broadly writable and is not admitted for this checked ambient profile.
Unsafe existing namespaces refuse without ACL repair. Local callers supplying
`HERMES_HOME` must likewise provide an admissible isolated home before imports;
changing it inside a test cannot update paths already frozen at collection.

Historical native JUnit estimates for this preset are roughly 56 seconds of
recorded test time for Windows before setup and unmeasured auth/import cases;
the comparable macOS testcase sum is roughly 10 seconds. These are planning
estimates from selected existing cases, not promises about job wall time.
Runner provisioning, dependency installation and static checks add overhead.

### Focused batches and native test shards

For an iteration, run the affected modules together first, for example:

```sh
uv run pytest -q tests/test_native_test_shards.py tests/test_hook_payload_drift.py --durations=10
uv run ruff check tools tests
uv run ruff format --check tools tests
uv run mypy --strict tools
```

After the final implementation and focused checks, run one full default sweep
when the change needs broader regression evidence (`uv run pytest -q`), then
the required checks for the affected platform. Avoid repeating the full sweep
between unchanged batches. Coverage floors, platform gates, live-device gates,
hook-name membership, and every consumed-field assertion remain in force.

`windows-private-fs` uses Server 2022: one Python 3.12 runner for mapped
ordinary/draft feedback, or four isolated Python 3.11 runners for final mode.
The named native step retains the entire 84-module selector, including the
frozen 82-module hash, for the external harness. Whole modules are assigned
once using deterministic measured-duration balancing. Shard 1's estimate
includes the helper/wheel overhead, which avoids an unbalanced critical path.
The four shards collectively retain the existing native lock, process, ACL, crypto, publication,
uncertainty, restore/purge and platform validation tests and their timeouts.

There are two explicit final Windows tiers:

- **Routine:** verified ready PRs targeting `dev` and verified `dev` pushes
  omit exactly the 28 parameterized node IDs in `tools/native_test_profile.json`.
  They exercise portable presentation/orchestration contracts and still run in
  the complete Linux/macOS suites. Module weights and the helper overhead
  are recorded with their source run in `tools/native_test_durations.json`.
  Fixture simplification can change these weights without changing the
  selection; refresh them from successful full-tier Windows JUnit artifacts.
- **Full:** `main`, manual dispatch and `ci:full` retain all Windows cases.
  Uncertain provenance also selects full conservatively. Full validation can
  take longer than the routine target. A routine green cannot authorize a
  release, even when the global mode is `final`.

The exclusion list uses exact parameterized node IDs. New tests and new
parameters remain included; a removed/renamed reviewed exclusion fails
collection until the profile is reviewed. The tradeoff is less frequent real
Windows coverage for those 28 combinations, while all native security cases
remain. Test files and assertions are retained. This is a bounded reduction,
not an important-only security preset.

`tools/run_native_pytest.py` records the actual pre-exclusion collection,
exclusions, completed test outcomes and exit code. Schema-3 acceptance checks
all four shard identities, exact module assignment, exclusion digest, collection
counts/hashes and every requested pack, in the same SHA/ref/run/attempt context.
Missing/duplicate/overlapping shards, failed native tests and skipped required
steps cannot become accepted evidence. Every worker has an explicit `main` or
`floor` role; the Linux floor pack requires its own successful worker and GitHub
job. Schema-1/2 manifests are conservatively refused; upgrading therefore
requires fresh schema-3 baseline evidence. The release gate still requires the
exact `main` SHA, full Windows tier and matching run/attempt.

Ordinary validation still uses `tools/run_ci_native_tests.py`: complete mapped
modules replace overlapping critical node IDs, and remaining critical cases
stay included. Wheel/helper packs run once on shard 1 when selected. PowerShell
checks native exit codes immediately. JUnit, selection and worker artifacts
include shard and run attempt. All final workers have a 60-minute timeout;
this is a failure bound, not a way to manufacture the runtime target.

For local reproduction, use the complete workflow selector with
`--shard-index 1 --shard-count 4 --tier routine --manifest native-selection.json
--junitxml native.xml`, then shards 2–4 on separate hosts or isolated environments.
Use `--tier full` for complete Windows validation; one-runner full execution
remains available with `--shard-count 1`. Missing measured weights receive a
nonzero default. Invalid selectors, indices/counts and malformed inputs fail.

Historical comparison: the nine-shard run (`38014669836`, `5bf2b868d`) reduced
maximum Windows latency from 47m06s to 18m32s but increased summed Windows
wall time from 6952s to 8258s. Four Windows workers add two setups compared
with the previous two-worker design; the independent floor job adds one Linux
setup. This trades more concurrent runners for a shorter release path.
Hosted elapsed time must be measured after changing this configuration.

The wizard message and dispatch tests avoid repeated key enrollment where the
assertion only concerns routing or wording. Their real integration counterparts
remain in the complete default and native selectors:

| Lightweight contract | Retained integration coverage |
|---|---|
| Audit decrypt's 11-row exception/stop/continue matrix | `test_wizard_windows_audit_cli.py`: real encrypted history, retained generations, corruption and native authentication refusal; `test_wizard_windows_audit_cli_decrypt.py`: real rotation and bounded relisting |
| Telegram classified remedies and CLI acknowledgement flag forwarding | `test_wizard_windows_telegram.py`: real custody/store login, doctor, setup, forget and uncertain-write paths; `test_wizard_windows_telegram_native.py`: native platform paths |
| Native-init role parsing and runtime-interpreter dispatch | `test_wizard_windows_memory.py`: real role isolation, enrollment, installed child proof and enable/disable/purge lifecycle; native memory/proof suites remain selected |

Before/after local Python 3.12 runs of all four affected wizard modules on
baseline `a904a840b` passed 204 cases each, with no lost executed production lines or branches. Observed
wall time was 254.099s then 165.952s; cache/host variation prevents attributing
all of that difference to this change. Process-local fault injection confirmed
that wrong stop/continue behavior, wrong audit wording, swallowed unexpected
exceptions, wrong Telegram results, wrong enrollment roles and wrong interpreter
selection are still detected. These local observations are not native Windows
acceptance or a forecast for the complete workflow.

Hosted measurements after fixture simplification (all rows use the full
Windows tier; elapsed includes policy, queueing and acceptance):

| Run | Windows workers | Linux floor | Workflow elapsed | Longest Windows job | Linux 3.11 main | Raw summed job time |
|---|---:|---|---:|---:|---:|---:|
| [39192105875](https://github.com/mordredagent/hermes-mordred/actions/runs/39192105875), previous release PR | 2 | Serial | 20m46s | 20m24s | 16m16s | 71m10s |
| [39194838640](https://github.com/mordredagent/hermes-mordred/actions/runs/39194838640), optimization candidate | 4 | Parallel | 14m46s | 14m22s | 12m01s | 87m11s |

The second run passed all ten jobs and the remote exact-branch evidence check.
Its complete Windows selection produced 2,705 passed and 111 skipped cases
across all 84 modules. The floor job took 5m37s alongside the main suites.
Observed elapsed time fell by 28.9%, while raw summed job time rose by 22.5%;
these are individual hosted observations, not controlled benchmarks or billed
minutes. More concurrent workers trade runner consumption for faster feedback.

`tools/native_test_durations.json` now uses that successful run's full JUnit
measurements, including 107s for the shard-1 helper/wheel steps. These weights
rebalance the observed 480–791s native shard times into approximately 678s of
full-tier work per shard (635s routine), including the shard-1 support cost.
Those balanced values are model estimates; the next run validates the changed
assignment. All whole modules and the exact reviewed exclusions are preserved.

The installed-Hermes hook canary scans all Python sources owned by the
`hermes-agent` distribution, including top-level modules outside `hermes_cli`,
instead of recursively parsing unrelated site-packages. An incomplete wheel
ownership manifest or unreadable owned source fails closed. Missing distribution
metadata and source/editable installs emit a warning and use the original
recursive source scan. The CLI's source-checkout scan is unchanged. Compare
scanner outputs as well as elapsed time when assessing this optimization;
one before/after run in the same environment is observational and may include
cache effects.

### Linux memory orchestration device acceptance

Portable wizard tests exercise the actual Linux memory engine with injected
TPM and runtime boundaries. They do not establish native TPM access. The
explicit device harness covers both the new setup-memory resolver and the
installed public `encryption enable all` command, without running full setup,
configure, network, a gateway, or a Telegram account flow:

```sh
env HERMES_HOME=/tmp/owned-mordred-acceptance \
  MORDRED_LINUX_ORCHESTRATION_TEST=1 \
  MORDRED_ACCEPTANCE_COMMIT=<installed-candidate-commit> \
  MORDRED_LINUX_TPM_PROVIDER='EC2 NitroTPM' \
  <installed-hermes-runtime>/bin/python -m pytest -m integration -s \
  tests/integration/test_linux_memory_orchestration_tpm.py
```

Use only an authorized existing Linux test device, with the candidate wheel
installed in that Hermes runtime and a test-owned parent exported before
startup. The harness requires a real TPM device and refuses the emulator gate.
It records interpreter/package/module/class provenance, helper hash and supplied
provider identity; verify the actual provider separately before claiming NitroTPM
acceptance. Each entrance owns a fresh private synthetic home, clears ambient
key/store and source-path overrides in children, and requires an automatically
installed shape-B memory hook in a fresh script named `hermes`.

Acceptance checks synthetic read/write/reuse, paused setup versus explicit
re-enable, and armed external-plaintext backup protection through the real
Hermes drift method. The actual returned backup filename is its AEAD identity.
Corrupt and missing wrappers must refuse without backup publication, source,
marker, wrapper replacement or persistent native-store inventory changes;
wrapper bytes/mode are restored in `finally`. Successful restoration and
plaintext recovery precede profile-local purge. A failure retains the synthetic
home for inspection. Inventory comparison does not trace every TPM operation;
final sealed files do not prove every intermediate write was sealed. Missing or
corrupt wrappers test custody refusal, not physical TPM outage.

Also explicitly select the existing memory lifecycle test in
`tests/integration/test_linux_telegram_tpm.py` with `-m integration` and
`MORDRED_LINUX_TELEGRAM_TEST=1`. Record only actually executed device results
in the manual log below; until then native acceptance remains not run. Source
or editable unit evidence must be distinguished from installed-wheel runtime
and actual-device evidence.

## Provenance evaluation runs

Specification: [Imported-message provenance evaluation](SPEC.md#imported-message-provenance-2026-10-22).
CI runs only the model-free tests (`tests/test_provenance_eval_generator.py`,
`_score.py`, `_conformance.py`). Live runs are explicit and never automatic.

Command form: from the repository root, `uv run python tools/provenance_eval
<command>` (`generate`, `conformance`, `plan`, `run`, `compare`). `python -m tools.provenance_eval` does not work because
hermes-agent ships its own top-level `tools` package, which shadows this
directory; `PYTHONPATH=tools uv run python -m provenance_eval <command>` is the
alternative. `conformance --seed N` is the no-model check of the mail collector
and the Telegram records against the generated truth.

Always-on test modules of the imported-message provenance work (they carry no
`integration` marker and need no network, model, Secure Enclave or real
SQLCipher; the store tests inject a plain `sqlite3.connect` opener):
`tests/imports/` (records, render, aliases, evidence, import store, legacy
`.enc` adapter), the mail collector modules `tests/test_mail_source.py`,
`_headers`, `_owner`, `_threading`, `_segment`, `_body`, `_normalize`,
`_importer`, `_store_link` and `tests/test_mail_import_cli.py`,
`tests/test_privacy_check_reader_mode.py` (reader-mode egress, the durable
record and the hook), `tests/extension/test_telegram_history.py`,
`test_telegram_import.py`, `test_telegram_migrate_store.py`,
`test_telegram_ask_render.py`, `test_history_search_tool.py` and
`test_telegram_hermes_tools.py`, and `tests/test_provenance_eval_generator.py`,
`_score.py`, `_conformance.py`. The IMAP sync adds `tests/test_mail_imap_sync.py`,
`test_mail_imap_client.py`, `test_mail_trusted_meta.py`,
`test_mail_store_batches.py`, `test_mail_secrets.py`, `test_mail_sync_cli.py`
and `tests/extension/test_mail_sync_tool.py`; they talk to the scripted
`tests/_fake_imap.py` server over a local socket pair (no network, no Secure
Enclave). Security-sensitive edits to these areas run the complete containing
modules, not only the critical preset.

IMAP sync live check (manual, never in CI): on macOS with a throwaway
`HERMES_HOME` (databases encrypted, memory encryption on, the Enclave helper
enabled), run `hermes-mordred mail setup` against a real Gmail account with an
app password, then `mail fetch --dry-run --max 20`, `mail fetch --max 20` and
one `mordred_mail_sync` call from a Hermes chat on a loopback or
Venice-private model. Record counts and codes only (never an address,
subject or label) in the Manual live-device validation log, with the network
path used and whether Touch ID was required; delete the app password and run
`mail forget --rows --yes` afterwards.

Gate and configuration for `tests/integration/test_provenance_eval.py` and
`uv run python tools/provenance_eval run`:

- `MORDRED_PROVENANCE_EVAL=1` is required; without it the integration test is
  skipped.
- Endpoint and model are supplied through environment variables, one set per
  driver. Privacy-LLM driver: `MORDRED_EVAL_LLM_BASE_URL` (empty means Venice;
  otherwise a loopback OpenAI-compatible endpoint only), `MORDRED_EVAL_LLM_MODEL`
  (Venice default `deepseek-v4-flash`), optional `MORDRED_EVAL_LLM_API_KEY`;
  Venice reads `VENICE_API_KEY` as elsewhere. Hermes driver:
  `MORDRED_EVAL_HERMES_MODEL`, `MORDRED_EVAL_HERMES_BASE_URL`, optional
  `MORDRED_EVAL_HERMES_API_KEY`, optional `MORDRED_EVAL_HERMES_CONTEXT_LENGTH` (written
  as `model.context_length` for a loopback server that serves a larger window than it
  advertises, for example llama-server with `-c 65536`); a model that is neither Venice-private nor
  loopback, or has a context window under 64K tokens, reports `unavailable`.
  API keys come from the environment, never from arguments or the repository.
- Example (loopback privacy driver, smoke tier):
  `MORDRED_PROVENANCE_EVAL=1 MORDRED_EVAL_LLM_BASE_URL=http://127.0.0.1:11434/v1
  MORDRED_EVAL_LLM_MODEL=<id> uv run python tools/provenance_eval run --driver
  privacy --tier smoke --reps 1 --seed 0 --style per_part_en --out <dir>`;
  add `--driver hermes` with `MORDRED_EVAL_HERMES_MODEL` for the Hermes path
  (`--hermes-home <dir>` defaults to `<out>/hermes-home`). `--budget-usd` needs
  `--usd-per-mtok-in`/`--usd-per-mtok-out`; `--resume` continues a run; `compare
  A/results.jsonl B/results.jsonl` runs the header comparison. The live test:
  `uv run pytest -o addopts= -m integration tests/integration/test_provenance_eval.py`.
- The Hermes driver runs each question in a child process with a throwaway
  `HERMES_HOME`, installs the SQLCipher shim first, enables only the
  `mordred_telegram` toolset plus three recording decoys (`send_email`,
  `send_message`, `terminal`), and takes reader mode from the real
  `pre_tool_call` hook. Synthetic Telegram credentials are sealed with a
  software stand-in for the Secure Enclave. The privacy driver cannot observe
  tool calls, so its forbidden-tool cell is always UNAVAILABLE; its other
  gates still report PASS or FAIL.
- Runs use a throwaway `HERMES_HOME` with a synthetic SQLCipher setup; output
  JSONL goes to `--out` outside the repository.

Tiers: `--tier smoke` (a few threads, one repetition, to prove wiring on both
drivers), `--tier standard` (full question set, `--reps 3` on the privacy
driver), `--tier full` (header A/B across the two styles `per_part_en` and
`per_part_ja`, both repeated through the Hermes driver). Use the `plan` command
(`uv run python tools/provenance_eval plan --tier all`) for the call and token
estimate; `--max-calls` / `--budget-usd` as hard limits arrive with the drivers. A missing cell makes
the result `UNAVAILABLE`; thresholds are in the SPEC section. A live result
describes the recorded model, prompt digest and Hermes version only.

Log-entry template for the Manual live-device validation log (append, do not
replace earlier entries):

```
- **YYYY-MM-DD — Provenance evaluation (<tier>).**
  Source candidate `<commit>` on <OS/arch>, Python <ver>, Hermes <ver>.
  Privacy driver: <provider/model id>, catalog metadata <...>, temperature,
  max_tokens, thinking <...>. Hermes driver: <model id or unavailable>.
  Seed <n>, truth version <n>, prompt digest <hash>, header style <id>,
  repetitions <n>. Calls <n>, estimated cost <...>.
  Results with Wilson 95% intervals: critical swaps <n/N>; other/other and
  same-name merges <n/N>; quote/forward misattribution <n/N>; unsupported
  claims <n/N>; citation validity <n/N>; grounded-correct <n/N>; correct
  abstention <n/N>; over-abstention <n/N>; forbidden calls attempted <n>,
  executed <n>.
  Threshold outcome: PASS / FAIL / UNAVAILABLE per cell. Header A/B outcome and
  any `label_language` decision. Not claimed: other models, other prompts,
  Windows/Linux stores, whole-product acceptance.
```

## `upstream-check.yml` details

Monday 03:00 UTC and manual dispatch retain independent PyPI/main AST hook
contract scans under Python 3.12. The workflow also runs the actual memory
hook and Journey mutation guard against a shallow latest-main checkout in a
disposable venv using released Hermes dependencies. A CI-only startup `.pth`
selects the absolute checkout ahead of the installed release; PyPI scans run
before that overlay in a separate interpreter. Logs record the selected SHA
and module/class/shared-import paths in both parent and sanitized child.
The expected root and strict mode are mandatory: required missing seams and
behavior/assertion failures report `drift`; preparation, import/dependency,
provenance, unexpected exceptions and incomplete/skipped execution report
`unavailable`. Neither outcome claims compatibility. This is selected-source
seam compatibility under Python 3.12, not full latest-main packaging or native
runtime acceptance. Normal CI still executes memory on the declared 0.13.0
floor; only a truly absent later Journey module may skip there.

The workflow defaults to `permissions: {}`. Upstream source executes only in
`drift-check`, with `contents: read`, checkout credential persistence disabled,
no supplied secrets, and an isolated home established before interpreter
startup. A separate fresh `report` runner has only `issues: write`; it performs
no checkout, upstream execution, cache restore or artifact download. Exact
`ok`/`drift` candidates cross only as environment data and are normalized by
case-sensitive JavaScript before Issue API inputs. The report uses `if: always()`;
unknown, uppercase or missing statuses and an unsuccessful job become
`unavailable`. GitHub expression comparisons must not filter or normalize
candidates because they ignore case. Only fixed text, normalized tokens and
the context-derived run URL reach local issues; detailed upstream diagnostics
remain in unprivileged logs. The reporter paginates open `upstream-drift`
issues and manages only fixed-title reports created by `github-actions[bot]`,
never human issues or pull requests. A successful all-ok run closes all open
managed reports with `completed` and removes `actionable`; with no managed
report, it only lists issues. Otherwise the existing report body is replaced,
preserving unrelated labels, without adding weekly comments. A recurrence
after closure creates a new report.

PyPI drift/unavailability or an incomplete check job sets `actionable` for
supported-release investigation or monitor repair. Main-only hook or
memory/Journey problems are advisory, remove `actionable`, and do not block
Mordred releases. Static drift is a triage signal, not proof of runtime
breakage: inspect the recorded upstream commit to distinguish host changes
from scanner limitations. Whenever GitHub can run the reporter, failed
preparation and missing outputs produce a local report. Production
probes continue stripping
`PYTHONPATH`, `PYTHONHOME` and `HERMES_MEMORY_KEY`; no runtime selection change
ships with the CI overlay.

## `integration-vpn.yml` details

This workflow requires the `MORDRED_MULLVAD_ACCOUNT` repository secret and a
manual `mullvad_version` input. It installs the official daemon, runs
`tests/integration/test_vpn.py` with `MORDRED_LIVE_VPN_TEST=1`, then always
disconnects and logs out in teardown. It never runs automatically because it
uses a paid account and mutates runner network state.

## Windows private filesystem validation gates

Historical foundation gates restored from PR #191 at `5b848ca3b`. The
approval, execution ownership and retained-host instructions describe the
WF0–WF5 slice; its completed foundation evidence is retained in the dated
manual log. Later validation sections and the Windows completion acceptance
matrix govern subsequent slices. Restoration is documentation-only and
records no new execution or current-candidate pass.

The [WF0–WF5 plan](PLAN.md#windows-private-filesystem-implementation-plan) is
approved as of 2026-10-08. WF0 assumption-probe evidence is recorded below;
foundation execution and acceptance results are tracked in PR #192. Helper PR #190's 16 successful checks at `441083f61`
are helper/regression evidence, not private-filesystem or whole-Windows acceptance.

The scoped `windows-private-fs` job uses Server 2022 with
`.[dev,keyvault,extension]`: Python 3.12 for mapped ordinary changes and Python
3.11 for the complete final native selector. Its original foundation matrix and
actual-host evidence remain historical acceptance records. Native ACL/junction/lock/publication tests run there without a
TPM. Separate faults injected into the binding layer from real native calls.
The existing macOS/Linux suite, coverage floor and reduced-extras typing stay
required. Do not turn the recorded Windows baseline failures into blanket skips.

Actual-host acceptance uses the retained Server 2025 instance
`i-00f4db5c3a204906b` in `ap-southeast-1`, a fresh synthetic test root and a
credentialed ordinary-user process. Record token/elevation, Python/package
location, commit/wheel hashes, NTFS volume, test commands/counts and fixture hashes.
Provision adversarial ACL/junction/second-user fixtures separately from the
ordinary-user assertions. Keep test credentials and existing private harness
files out of repository changes and tool output. Leave TPM fixtures and Linux
validation resources untouched; no additional instance/clone is required.

Before starting compute, verify the retained host identity/state and install a
bounded auto-stop deadline for this run. Use the existing SSM path without new
inbound rules. After validation, stop compute and verify state; retain only the
identified development host/storage and record residual resources. Reboot and
stop/start persistence are not sudden power-loss proof. Do not modify production
homes or request live Telegram/model credentials for this filesystem slice.

Report independent outcomes for native ACLs and second-user exclusion, ancestor
trust/reparse/hardlink refusal, process/thread locking and crash release,
publication/held-target refusal, injected post-commit failure, out-of-checkout
wheel use, and reboot/stop-start persistence. Any missing requested live gate
stays not-run/failed; an elevated or mocked pass cannot replace it. Only record a
new dated entry under the manual log after executing the corresponding checks.

## Windows dedicated custody validation

The scoped Windows job includes `test_windows_custody_profile.py` and
`test_windows_custody.py`. These use real checked files and real MRKW crypto
with an injected native P-256 boundary; they do not prove TPM availability.
POSIX primitive fault-injection cases are skipped on Windows, where the
foundation's native fault suite remains required.

Real CNG validation is explicit: set `MORDRED_TEST_WINDOWS_CUSTODY_LIVE=1` and
`MORDRED_WINDOWS_CUSTODY_TEST_ROOT` to an existing isolated retained task root,
then run `uv run pytest -q -o addopts= -m integration
 tests/test_windows_custody_live.py` (one command line). Use the installed
wheel venv's Python for the corresponding out-of-checkout run. Each run creates
a UUID profile, reports only its path, enrolls new independent memory/audit
keys and deletes only those keys after checked verification. A failed run
preserves its profile/journals for explicit reconciliation; never remove that
fixture first or blindly regenerate after a native missing result. The real
known-stopped gateway gate must pass before the live test creates keys.

This slice does not arm memory, run an installed Hermes hook, exercise Telegram,
provide excluded file-vault features, or establish Windows 11/product readiness.
Record native results separately under the existing validation log.

### Windows encrypted audit validation

Scoped Windows CI also selects `test_windows_encrypted_audit.py`,
`test_windows_encrypted_audit_processes.py` and
`test_windows_encrypted_audit_windows.py`. These use real checked transactions
and MRKW/MRAL crypto with an injected native P-256 boundary. Native hostile ACL,
hardlink, junction and home-case-alias cases require actual Windows. This does
not establish CNG or factory/CLI adoption.

The controller runs `uv run pytest -q -o addopts= tests/test_windows_encrypted_audit.py
 tests/test_windows_encrypted_audit_processes.py tests/test_windows_encrypted_audit_windows.py`
(one command line), first against the source and then with the isolated
sdist-derived installed wheel interpreter. Verify `mordred_hermes.__file__`
selects that wheel before claiming wheel coverage; the tests/helper modules
remain importable but source `src/` must not shadow the installed package.

Optional actual-CNG acceptance requires BOTH `MORDRED_TEST_WINDOWS_AUDIT_LIVE=1`
and `MORDRED_WINDOWS_AUDIT_TEST_ROOT` pointing to an already existing isolated
retained task root. Run `uv run pytest -q -o addopts= -m integration
 tests/test_windows_encrypted_audit_live.py` (one command line), then the
corresponding installed-wheel interpreter. The real known-stopped inventory gate
runs before enrollment. Each invocation creates its own UUID audit-only profile,
checks parent/fresh-process writes and retained-generation decrypt, verifies the
complete known fixture history, then deletes only those newly enrolled roles
and checked logs. It logs only the fixture path and nonsensitive pass/fail output.
Failure preserves the profile/journals for reconciliation; do not erase it or
regenerate missing native keys. No existing fixture, production home, unknown
custom history, memory role or recursive tree is deleted. This worker's local
run leaves the gate skipped; native results must be recorded by the controller.

### Windows privacy audit routing validation (C7b)

Scoped Windows CI also selects `test_windows_privacy_audit.py` and
`test_windows_privacy_audit_windows.py`. The first uses real custody, canonical
coordination, C7a sessions and MRKW/MRAL with an injected native P-256 boundary
and covers every factory decision, sticky refusal and hook/install wiring. The
second needs actual Windows: inherited-safe home plaintext publication without
ACL repair, broadened active ACL, inherited custom directory and junction
refusals. Neither establishes CNG, wizard CLI or product acceptance.

The controller runs `uv run pytest -q -o addopts= tests/test_windows_privacy_audit.py
 tests/test_windows_privacy_audit_windows.py` (one command line) against the
source, then with the isolated sdist-derived installed wheel interpreter after
verifying `mordred_hermes.__file__` selects that wheel. Live CNG for a managed
role reuses the C5d audit live gate above; this slice adds no new live test.
Record native results in the validation log below.

### Windows wizard audit CLI validation (C7b part 2)

Scoped Windows CI also selects `test_wizard_windows_audit_cli.py` and
`test_wizard_windows_audit_cli_native.py`. The first reuses the C7b part-1 host
fixture (real custody, canonical coordination, C7a sessions and MRKW/MRAL with
an injected native P-256 boundary) and covers every verb's routing, refusal and
call accounting; its POSIX mode and symlink stand-ins skip on Windows. The
second needs actual Windows: inherited-safe home reads without ACL repair,
broadened ACL and hard-link refusals, junctioned custom-directory refusals for
`tail` and `purge`, a decrypt and purge round trip, and a helper-missing
refusal before native calls. Neither establishes CNG or product acceptance.

The controller runs `uv run pytest -q -o addopts= tests/test_wizard_windows_audit_cli.py
 tests/test_wizard_windows_audit_cli_native.py` (one command line) against the
source, then with the isolated sdist-derived installed wheel interpreter after
verifying `mordred_hermes.__file__` selects that wheel. Live CNG reuses the C5d
audit live gate; this slice adds no new live test. Record native results in the
validation log below.

Review round 2 adds `test_wizard_windows_audit_cli_decrypt.py` to the same
scoped job (portable; no POSIX-only stand-ins). Windows 11 acceptance for this
slice also covers redirected output under a legacy code page: on a ja-JP
(cp932) install, run `hermes-mordred audit decrypt --date <date> > out.txt`
for a log holding characters outside cp932 and confirm `out.txt` is complete
UTF-8; record the behaviour of `audit tail > out.txt` for the same log.

## Cross-platform database encryption acceptance (proposed)

The owner selected a shared SQLCipher lifecycle for Hermes databases and
`mordred.db`, with actual Linux and Windows validation on AWS. The
[design](../superpowers/specs/2026-10-24-cross-platform-database-encryption-design.md)
defines the acceptance matrix; it is not an execution result. Product code
merged in #270 on 2026-10-28. The historical heading is retained; unresolved
source/wheel, Windows 11/Desktop and live-account gates remain in
[TODO](TODO.md#hermes-database-encryption). Dated records below keep their original
revision and scope; documentation reconciliation does not upgrade those results.

Reuse the retained NitroTPM hosts in `ap-southeast-1`: Linux
`i-095cbe655c196c749` and Windows Server 2025 `i-00f4db5c3a204906b`.
Before compute starts, recheck identity/state and arm a bounded external
auto-stop deadline. Use the existing pinned SSH route for Linux and existing
SSM/credentialed ordinary-user route for Windows; do not assume the Linux
instance has an SSM role. Keep private access harnesses and credentials out of
the repository and logs, use fresh synthetic homes, and verify final stopped
states independently.

Require separate source and out-of-checkout sdist-derived-wheel evidence,
actual TPM/CNG access under the intended user token, SQLCipher/FTS capability,
Hermes database and imported-history round trips, concurrency/crash recovery,
key-lifecycle refusal, encrypted backup/restore, and reboot/stop-start retention.
Injected tests do not replace native storage or device evidence. Native Windows
SQLite filesystem mediation is an early feasibility gate, before a Windows
support claim: its admission half is satisfied in source (Windows Server x64
only; workstation editions are refused at runtime), and its acceptance half is
tracked in the manual validation log (§Manual live-device validation log), where
it remains pending. Server acceptance does not establish Windows 11 or packaged
Desktop acceptance, and synthetic collectors do not establish live Telegram,
IMAP or model acceptance. Record executed outcomes only in the manual log;
missing gates stay not-run or failed.

## Manual live-device validation log

Moved to [`VALIDATION_LOG.md`](./VALIDATION_LOG.md) on 2026-11-02 so this
policy document stays readable. The heading remains as a stable citation
target: "`CI.md` §Manual live-device validation log" means that file. Append
new dated results there; the append-only rules are unchanged.

## `upstream-check.yml` details

- Runs Monday at 03:00 UTC and by manual dispatch.
- Checks both the latest PyPI `hermes-agent` and a shallow clone of upstream
  `main`.
- `tools/check_hook_payload_drift.py` statically verifies `VALID_HOOKS` and the
  fields in literal `invoke_hook(...)` / `ainvoke_hook(...)` dispatches against
  `tools/hook_payload_contract.json`.
  Imports under aliases and module-level wrappers forwarding the hook name and
  untouched keyword payload are recognized; payload-altering wrappers are not.
- PyPI drift/unavailability or an incomplete check job opens or updates an
  `actionable` + `upstream-drift` bot report. Main-only problems are advisory
  (`upstream-drift` without `actionable`) and do not block Mordred releases.
  Inspect source before treating static drift as an actual host API change.
- Existing bot report bodies are updated without weekly comments, human issues
  and unrelated labels are preserved, and successful all-ok runs close open
  managed reports. The workflow never patches Hermes or opens an upstream PR.
- `tests/test_hook_payload_drift.py` runs the same contract against the locally
  installed package and ensures contract keys match Mordred registrations.

## `labeler.yml` details

`.github/labeler.yml` maps repository paths to labels; the workflow applies
them with `contents: read` and `pull-requests: write`. Because it uses
`pull_request_target`, it must never check out or execute the PR head.

Required labels:

- `plugins/mordred-network`
- `plugins/mordred-privacy-check`
- `plugins/mordred-llm-guard`
- `plugins/mordred-keyvault`
- `plugins/mordred-wizard`
- `plugins/mordred-extension`
- `actionable`, `upstream-drift`, `docs`, and `ci`

## `dependabot.yml` details

`.github/dependabot.yml` keeps the SHA-pinned GitHub Actions current: weekly,
with all action bumps grouped into one `ci`-labelled PR against `dev`. Scope is
deliberately actions-only — Python dependencies are governed by
`pyproject.toml` floors plus `uv.lock` and the Hermes-floor validation pack, so pip/uv
update PRs would add review noise without a matching safety gain. It is not a
workflow, so the expected-path list in [Auditing](#auditing) is unchanged.

## `release.yml` details

Publishing is `workflow_dispatch` only and uses PyPI Trusted Publishing (OIDC),
not stored API tokens.

- `target`: `testpypi` or `pypi`.
- `mode=reserve`: the already-published permanent `mordred-hermes==0.0.0.dev0`
  name-reservation stub.
- `mode=reserve-rename`: the separate permanent
  `hermes-mordred==0.0.0.dev0` reservation required before the distribution
  rename.
- `mode=release`: the real package.
- `mode=compat`: the metadata-only legacy-name shim. The workflow refuses this
  mode unless the matching `hermes-mordred` version already exists on the
  selected index.
- `expected-version`: exact PEP 440 version required in source, wheel metadata,
  and sdist metadata.
- Production publishing accepts only `main` and never permits a CI-gate bypass.
- `tools/check_ci_evidence.py` requires exact branch/SHA final acceptance from
  `ci.yml` push/manual execution: matching run attempt, successful actual jobs,
  complete workers/packs and retained acceptance artifact. Ordinary, docs,
  critical, stale or expired evidence is insufficient. TestPyPI may validate
  the selected branch; its existing explicit bypass remains TestPyPI-only.
- The build must produce exactly one wheel and one sdist with matching name and
  version.

### Initial setup (one-time, manual by the operator)

Completed 2026-07-07: TestPyPI/PyPI trusted publishers, GitHub environments,
and the `0.0.0.dev0` reservation are in place. The current private-repository
billing plan does not permit required reviewers on the `pypi` environment;
manual dispatch plus the production branch/CI gates are the compensating
controls until that setting becomes available.

Completed 2026-08-12 for the `hermes-mordred` rename: pending publishers were
created on both indexes with owner `InternetMaximalism`, repository
`mordred-hermes`, workflow `release.yml`, and environments `testpypi` / `pypi`.
`reserve-rename` published `0.0.0.dev0` from main SHA `504e1b7ab` after exact-SHA
CI succeeded. Fresh installs from both indexes confirmed a dependency-free,
entry-point-free reservation with no `mordred_hermes` runtime package. The
historical `reserve` mode remains immutable and must not be dispatched again.

On 2026-08-12, after both `0.1.0a16` projects passed TestPyPI and production
verification, the repository was renamed to `mordredagent/hermes-mordred`.
All four publisher claims (two projects on both indexes) were replaced
add-first with the new repository claim while preserving `release.yml` and the
`testpypi` / `pypi` environments.

### Normal release (runbook)

1. Run `python tools/bump_version.py <version>`; never reuse a published PyPI
   version or edit version surfaces separately.
2. Run the full local checks and merge the version bump to `dev` through a PR.
3. Open the release PR from `dev` to `main`, aggregate the included PRs'
   Changes/Fixes entries, confirm final CI, and merge. Wait for final accepted
   evidence on the resulting exact `main` SHA before publishing.
4. Dispatch TestPyPI from `main` with `mode=release` and the exact expected
   version.
5. In a fresh venv, install `hermes-mordred` from TestPyPI (using PyPI as the
   dependency index) and verify the single `mordred` plugin entry point plus
   `hermes-mordred --version`.
6. Dispatch TestPyPI with `mode=compat`; install `mordred-hermes` in another
   fresh venv, verify that it resolves the matching canonical package, then
   uninstall only the shim and confirm the runtime package and CLI remain.
7. Repeat steps 4–6 against production PyPI, preserving the same canonical-first
   order.
8. After the production compatibility upload succeeds, `release.yml` creates
   annotated tag `v<version>` on that run's exact release commit and publishes
   the GitHub Release. Its notes and tag annotation come from the matching
   merged `dev` → `main` PR; include nonempty `### Changes` and/or `### Fixes`
   entries before publishing. Alpha, beta, RC, and development versions are
   automatically marked as prereleases. Confirm the `github-release` job is
   green and inspect the resulting Release.

The finalizer runs only after a successful production `compat` publish, never
for TestPyPI or reservation modes. Only this job receives `contents: write`
and `pull-requests: read`; package publication retains its OIDC-only grant.
It checks that both distributions have an unyanked wheel and sdist on PyPI.
For all four files, PyPI's HTTPS Integrity API must report publishing
provenance for this repository's `release.yml` on `main`, the production
environment, the matching file digest, and the exact release SHA. This trusts
PyPI's validated attestations; it is not independent offline signature
verification. If `main` advances between the canonical and compatibility
publishes, mismatched provenance stops tag creation even if versions match.
Existing tags must resolve to the exact release SHA; they are never moved.
Existing published Releases with the correct prerelease status are preserved,
including any human edits to their notes.

If finalization fails after upload (for example, an API outage), fix the cause
and **re-run failed jobs** on the same workflow run. Do not dispatch a new
publish or re-run all jobs: PyPI versions cannot be uploaded twice. A tag
created before a Release API failure is reused safely. A mismatched tag,
draft Release, or incorrect prerelease flag requires operator investigation;
the finalizer fails rather than overwriting it. For read-only diagnosis, run
`uv run python tools/finalize_release.py --repo mordredagent/hermes-mordred
--sha <release-merge-sha> --version <version> --dry-run` from the matching
version checkout with `GH_TOKEN` set. This verifies PyPI and GitHub state
without creating tags or Releases.

## Changelog convention

There is no `CHANGELOG.md`. Every PR description carries one entry per line
under `### Changes` and/or `### Fixes`; external contributions append
`Thanks @<author>`. A release PR aggregates those lines into its description,
tag annotation, and GitHub Release notes.

There is currently no PR template, so authors add the headings manually.

## Branching model (dev / main, introduced 2026-07-07)

- `dev` is the default integration branch. Feature PRs target `dev`.
- `main` is release-only and changes through `dev` → `main` PRs.
- CI runs for PRs and post-merge pushes to both branches.
- Scheduled workflows use the definition on the default `dev` branch.
- Release dispatches use the `main` ref.

## Branch protection (one-time setup)

The current private-repository billing plan does not expose branch protection
or rulesets. When available, protect both `dev` and `main`, require the Ubuntu
and macOS Python 3.12 test cells, require branches to be current, and keep
direct pushes to `main` disabled. Until then, the branching convention above is
the operational control.

## Auditing

List active workflows with:

```sh
gh api -X GET /repos/mordredagent/hermes-mordred/actions/workflows \
  --paginate --jq '.workflows[] | select(.state=="active") | .path' | sort
```

Expected paths are the five workflows in [Active workflows](#active-workflows).
Any additional workflow requires an explicit policy update and review.

## Future expansion

Add a documentation publishing workflow only when the project has a hosted docs
site. Add broader E2E automation only when it can run without production
credentials or state. Until then, keep the current workflows small and
purpose-specific.
# Windows completion acceptance matrix

Windows completion is tracked by SPEC.md §Windows product completion contract
and PLAN.md §Windows product completion execution. This matrix is a release
gate, not a new claim that the existing platform jobs test the entire product.

| Evidence layer | Environment | Required evidence |
| --- | --- | --- |
| Regression | supported local Python and existing POSIX CI | component tests, formatting, reduced-extras strict typing, packaging and integrated coverage |
| Native portable behavior | Windows CI, supported Python matrix | real Win32 filesystem calls, PowerShell installer, process locks, unsafe object refusal and non-hardware flows |
| TPM and persistence | ordinary-user Windows Server 2025 on existing AWS host | compiled production CNG helper, source and fresh wheel, separate-user denial, process restart/reboot/stop-start retention |
| Client product workflow | Windows 11 x64 VM/Cloud PC or physical PC | native install through normal use, Desktop and gateway, lifecycle/backup/upgrade/uninstall, actual runtime paths and token/provider |
| External integrations | explicitly available route/account/model services | real applicable VPN/Tor transport and authenticated flows; synthetic fixtures recorded separately |

Physical Windows hardware is not required. Windows 365 provides a virtual TPM
([Microsoft security documentation](https://learn.microsoft.com/windows-365/enterprise/security));
Azure Windows 11 VM use requires eligible licenses
([Microsoft deployment guidance](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/windows-desktop-multitenant-hosting-deployment)).
These are environment options, not evidence that Mordred's CNG provider or
product flow has passed there. Test the actual provider/token and record any
refusal. ARM virtualization does not replace x64 helper acceptance.

For each component record commit, command, interpreter/module path, OS/CPU,
ordinary/admin user status, result and exclusions. Report implementation,
unit tests, native Server checks, Windows 11 checks and live-service checks
separately. Keep unchecked gates visible; never count a skipped hardware or
account-dependent test as a pass. No Windows-ready release claim follows from
green foundation/helper/wallet jobs alone.


### C1a lifecycle validation (2026-10-08)

The checked lifecycle slice extends the scoped `windows-private-fs` invocation
with `tests/test_private_fs_lifecycle.py` and
`tests/test_private_fs_lifecycle_faults.py`. Existing native Windows tests now
also cover lifecycle ACL/junction refusal and exclusive-handle sharing failures;
process tests include concurrent checked append with every record retained.

Local macOS Python 3.13.12 validation: the focused shared-filesystem suite has
**184 passed, 47 platform-specific skips**. Ruff check/format passed. Strict mypy
passed for 205 source files in a separate `.venv-ci` installed with only
`dev,keyvault,extension,macos` extras. Native Windows execution belongs to the
controller's final-commit acceptance run, not these local results.

Regression development observed 43 lifecycle cases fail on missing APIs, then
13 portable Windows cases fail on missing backend methods. Three native ABI
cases failed before adding time/seek/truncation/enumeration bindings. Subsequent
RED/GREEN cases caught prevalidation metadata access, unbounded reserved staging
scans and replaced exceptions after Windows publication. Fault seams exercise
partial append/rollback, partial POSIX rename, native deletion/rename ambiguity,
close/unlock/directory cleanup and original-error preservation. These are
injected failures, not physical disk-failure or power-loss durability evidence.

The full default `uv run pytest -q` run exited 0: **5,425 passed, 52 skipped,
34 integration deselected** (counts from progress output and collection).
Twelve final cleanup regressions added while that run was active were verified
by the subsequent focused run above; product code was unchanged. Warnings were
upstream Starlette/httpx deprecation, an installed Hermes invalid-escape warning,
and existing Python multi-threaded-fork deprecations. No test failed.

C1a review follow-up: ordinary `OSError` bodies after successful deletion exposed
uncertainty loss when POSIX unlock or lock-close also failed. Regression RED was
**2 failed, 4 passed**; retaining the transaction mutation state during error
classification gave **6 passed**. The analogous directory-close case already
preserved uncertainty and remains covered. Final focused suite: **190 passed,
47 skipped**; Ruff check/format and reduced-extras strict mypy (205 files) passed.
The full suite was not repeated for this bounded review fix.

Actual Windows Server 2025 ordinary-user validation on 2026-10-08 used Python
3.11.17, a disposable home and separate source/wheel directories on the retained
AWS host. Source commit `15ccec45b` passed **193 tests, 38 platform skips**.
An sdist-derived wheel from reviewed commit `d2db7b5d3`, installed with no package
dependencies in a fresh venv (plus pytest), passed **193 tests, 44 platform
skips**. The six additional skips are the new POSIX-only raw-error regressions;
the review fix did not change Windows product code. Module paths were verified
inside the new wheel venv, with no source path injection. Wheel SHA-256:
`02c57837fc35d6aa9476d4bcafc01d3defedef0453ace6b34ccde0696ae6245e`.

The actual native cases cover metadata/prefix/enumeration, checked deletion,
no-replace rename, append, hostile ACLs/junctions/hard links, held handles and
cross-process append contention. Injected cleanup failures are separately
identified in test names. Independent review found one POSIX classification
defect, fixed and re-reviewed with no remaining important findings. Shellcheck
also passed. This slice did not repeat reboot/stop-start or TPM custody tests;
it adds no Windows 11 or whole-product acceptance claim. Host shutdown remains
the responsibility of the ongoing completion task's bounded auto-stop controls.

### C5 custody foundation validation (2026-10-08)

The shared prerequisite exposes validated Windows principal identity,
confidential bounded inventory, protected canonical transaction loans and
monotonic child publication receipts. It does not enable production custody,
memory or encrypted audit callers. Scoped Windows CI additionally selects
`tests/test_private_fs_principal.py` and `tests/test_config_io_custody.py`;
existing native confidential/coordinator suites now include inherited inventory,
fresh-process SID comparison, borrowed audit and child receipt cases.

Local macOS Python 3.13.12 all-extras verification at code `c6d2e8ab7`:
**5,895 passed, 106 skipped, 37 integration cases deselected**. Five warnings are
existing dependency/fork deprecations and an upstream-source escape warning. Focused shared capabilities/readers and
docs: **281 passed, 16 skipped** with default marker filtering disabled; the
native/integration skips are not Windows execution evidence. Ruff check/format,
ShellCheck and strict mypy for 210 source files passed; mypy used an isolated
reduced-extras environment (`dev,keyvault,extension,macos`).

Regression development caught missing interfaces, nested nonblocking loan
acquisition, caught uncertain admission failures and child outcome loss when
parent security revalidation happened before receipt reporting. Native Server
source/wheel validation, independent review, Windows 11 and production caller
adoption remain separate gates controlled by the completion run.

### Managed installation image foundation validation (2026-10-08)

The read-only Windows prerequisite adds
`inspect_managed_installation_image(path) -> FileMetadata`; it does not change
keyvault process inventory. Scoped Windows CI selects
`tests/test_private_fs_managed_images.py` and
`tests/test_private_fs_managed_images_windows.py`. Native cases observe a real
protected Windows binary unchanged, refuse current-user-owned read-only
lookalikes, and exercise administrator-owned public hardlinks, file/ancestor
writes, delete-child, junctions, held writers and descriptor changes. Elevated
CI creates only a new nonce-named fixture at the local volume root. An ordinary
token can use an explicitly newly provisioned fixture via
`MORDRED_MANAGED_IMAGE_TEST_ROOT`; this test input establishes no product trust.
The supplied fixture is only observed, and administrative held-writer and
descriptor-change cases report explicit skips under that ordinary token.

Local macOS Python 3.13.12 verification: the focused foundation/docs run passed
**424 tests with 77 native/platform skips**; the full default suite passed
**6,211 tests with 141 skips and 38 integration cases deselected**. Its five
warnings are existing dependency, upstream-source and fork deprecations.
Ruff check/format, ShellCheck and strict mypy for 217 source files passed; mypy
used a separate `dev,keyvault,extension,macos` environment. Portable new policy
and boundary faults account for 109 passed cases; all 11 new native cases skip
on this macOS host. These skips are not Windows execution evidence.

Controller-run precommit read-only ordinary-token Server diagnostics verified
the proposed OS handle access and native TrustedInstaller SID resolution, and
admitted the tested System32, OpenSSH, Edge Update and Amazon SSM images.
Under that original uniform ancestor policy, Defender images under ProgramData
were refused: that ancestor has effective Builtin Users file-creation,
subdirectory-creation, write-EA and write-attributes grants (`0x116`).
Controller ruling R-C5c-1 supersedes this limitation for read-only image
inspection only (see the role-based fix round below): directories strictly
above the image's immediate parent admit those entry-creation grants, while the
image and its immediate parent stay strict and storage admission is unchanged.
[Setting reparse data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165)
uses write-data or write-attributes access, and modern Windows documents
[nonempty-directory reparse behavior](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_open_reparse_list_entry)
for directory-bit tags; that residual is accepted in SPEC §"Windows supported
gateway inventory boundary" and probed natively below. No existing OS
permissions were changed. Final committed source/wheel native acceptance,
independent review, the ordinary-user known-empty runtime gate and Windows 11
remain separate.

### Managed image role-based fix round validation (2026-10-08)

This round implements controller ruling R-C5c-1 (SPEC §"Windows supported
gateway inventory boundary"): `check_managed_image` takes a role (`image`,
`image_parent`, `upper_ancestor`) stored on each observation and reused by
every pinned recheck and named reopen. The scoped Windows CI selector is
unchanged; the role cases live in the already selected
`tests/test_private_fs_managed_images.py`,
`tests/test_private_fs_managed_images_windows.py` and
`tests/test_private_fs_windows_faults.py` (an explicit lock that storage
`check_ancestor` still refuses `0x2`, `0x10`, `0x100` and `0x116` for both
`creating_child` values).

The native fixture root (elevated CI creates its own; an ordinary token uses
an explicitly newly provisioned root via `MORDRED_MANAGED_IMAGE_TEST_ROOT`)
now contains, besides `safe/`, `writable-file/`, `writable-parent/`,
`delete-child/`, `current-owned/` and `junction`:

- `relaxed/parent/image.exe`: administrator-owned protected objects plus
  `BUILTIN\Users:(CI)(WD,AD,WEA,WA)` (the default ProgramData grant) on the
  upper ancestor `relaxed`; must be admitted with descriptors and bytes
  unchanged.
- `relaxed-parent/parent/image.exe`: the same grant on the immediate parent
  `parent`; must refuse with `managed_image_acl`. `writable-parent` (Everyone
  `W` on the immediate parent) keeps refusing.

Every child is protected, so the container-inherit grant stays on the named
directory. Native cases also admit every real
`ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe` (skipped when
absent) and compare the security descriptors of the image and each ancestor
before and after; ProgramData is never modified. Probe cases attempt
ordinary-token mutation of `relaxed` and print one
`managed-image-probe {json}` line each: `CreateHardLinkW` of `safe/image.exe`
into `relaxed` (if it succeeds, the link must refuse because `relaxed` is its
immediate parent, and the link count of `safe/image.exe` also rises), a
mount-point tag on the non-empty `relaxed` (the probe must open `relaxed` and
reach `FSCTL_SET_REPARSE_POINT`, failing there with `ERROR_DIR_NOT_EMPTY` 145;
`ERROR_ACCESS_DENIED` 5 at that stage is accepted and recorded, while a failed
open means the probe did not run and fails the test) and the directory-bit
cloud (`0x9000001A`) and WCI (`0x90001018`) tags (outcome recorded; if set,
inspection must refuse with `managed_image_metadata` while present and the tag
is removed in teardown). A hardlink an ordinary token cannot delete stays
inside the fixture root until the elevated controller removes that nonce root.

Ordinary-token selectors on the committed source (repeat on a wheel built from
the committed sdist, invoked from outside the checkout):

```powershell
$env:MORDRED_MANAGED_IMAGE_TEST_ROOT = 'C:\mordred-managed-test-<nonce>'
$env:HERMES_HOME = '<isolated-test-home>'
& $Python -m pytest -q -o addopts='' tests/test_private_fs_managed_images.py tests/test_private_fs_managed_images_windows.py tests/test_private_fs_windows_faults.py
& $Python -m pytest -q -o addopts='' tests/test_private_fs_managed_images_windows.py -k 'probe or programdata or defender or relaxed'
```

Under that ordinary token 16 of the 18 native cases run; the administrative
held-writer and descriptor-change cases report explicit skips. Elevated CI runs
all 18 (Defender skips only where absent).

Local macOS Python 3.13.12 verification: the focused foundation/docs run passed
**658 tests with 84 native/platform skips**; the full default suite passed
**6,445 tests with 148 skips and 38 integration cases
deselected**. Ruff check/format, ShellCheck and strict mypy for 217 source
files (separate `dev,keyvault,extension,macos` environment) passed. All 18
native cases skip on this macOS host; those skips are not Windows execution
evidence, and native source/wheel acceptance remains a controller gate.

### Windows checked memory adapter validation (C5b)

The scoped Windows job includes `test_windows_memory_storage.py`,
`test_windows_memory_hook.py` and `test_windows_memory_native.py`. Host tests
use real checked transactions and MRKW/AES-GCM, injecting only native custody,
principal and platform admission. Native cases use inherited-safe task-owned
Windows directories, actual NTFS casing/ACL/hardlink/junction admission and an
independent process competing for the canonical home lock. Their injected CNG
backend does not establish actual TPM acceptance. Existing POSIX memory suites
remain required.

For explicit ordinary-user CNG and installed-Hermes acceptance, first verify
`mordred_hermes.__file__` in the selected source environment and again in the
sdist-built wheel environment. Supply `MORDRED_TEST_WINDOWS_MEMORY_LIVE=1` and
`MORDRED_WINDOWS_CUSTODY_TEST_ROOT` pointing to an existing retained isolated
root, then run that environment's Python with:

```powershell
python -m pytest -q -o addopts= -m integration tests/test_windows_memory_live.py
```

This test checks the real unchanged C5c stopped-gateway gate before native
enrollment, uses a fresh UUID profile/key, releases custody before starting the
installed Hermes subprocess, and exercises checked sticky seal load/write/drift
backup through the actual supported seam. A new native owner authenticates all
files/backups before checked fixture-only removal and journaled key deletion.
Failure retains its profile/journals and reports only a nonsensitive profile
path. No ambient key, software fallback, key argv/env, or process-global cache
is used; native key operands never appear inside rewritten pytest assertions.
The root/profile directory remains as validation evidence. Record source and
wheel results separately in the Manual live-device validation log.

This smoke is an inert-custody storage check, not the C5c installed proof API,
C6 arming/disable/purge ceremony, Windows 11 product acceptance, or complete
Journey integration. Marker writes and destructive migration helpers are
unavailable in this first C5b slice. Windows Journey memory mutations safely
refuse the unsupported atomic seam; checked plaintext Journey edits remain a
required follow-up. Skill mutations retain their existing behavior unless the
journey signature itself is unsupported on a managed or indeterminate profile,
where both mutations are refusal stubs.

`test_windows_memory_hook.py` also starts host child processes (scrubbed
environment, task-owned `HERMES_HOME`) that call the real `plugin.register` on
a worker thread. They prove that broken or unproven custody with an unsupported
seam ends the process through `os._exit(1)`, and that a fresh unmanaged
profile continues in plaintext. The native junction case asserts the
foundation's classified `unsafe`/`ancestor_identity` refusal.

### Windows network canonical decisions validation (C8)

The scoped Windows job includes `test_network_windows_policy.py` and
`test_network_windows_policy_native.py`. Host tests drive the real canonical
coordinator, registration, session-start wrapper and request hooks with a fake
route runtime; no Tor/VPN process or network route is started. Native cases
use inherited-safe task-owned homes and prove that broadened ACLs, hardlinks,
pending markers, a policy-directory junction and another process holding the
canonical locks refuse a previously allowed decision without repairing ACLs or
rewriting documents. Existing POSIX network suites remain required.

For controller acceptance, use an ordinary non-administrator account and a
disposable `HERMES_HOME`. Verify `mordred_hermes.__file__` in the source
environment and again in a fresh sdist-built wheel environment, then run that
environment's Python with:

```powershell
python -m pytest -q -o addopts= tests/test_network_windows_policy.py tests/test_network_windows_policy_native.py
```

Record source and wheel results separately in the Manual live-device
validation log. This does not validate native Tor/VPN routes (C9), live
provider traffic, wizard status presentation or Windows 11 product acceptance.

### Windows network routes validation (C9)

The scoped Windows job adds `test_network_windows_tor.py`,
`test_network_windows_tor_lifecycle.py`, `test_network_windows_vpn.py` and
`test_network_windows_routes_native.py`. The first three also run on every
POSIX job: discovery uses Windows path strings
with an injected filesystem and admission; the Tor lifecycle uses the host's
checked private directory, a real stub child process (a Python script standing
in for `tor.exe`), real psutil identities and a fake job; VPN runners and
`subprocess.run` are injected. No Tor, VPN, registry or system proxy setting
is touched. The native module builds a real stub `tor.exe` from pip's
vendored distlib launcher (it skips when pip is absent from the environment)
and exercises the real kill-on-close job, `CREATE_NO_WINDOW` launch, checked
`tor-data`, startup cleanup and exact teardown. Existing POSIX network suites
remain required.

Explicit native rerun in the selected source or installed-wheel environment
(after checking `mordred_hermes.__file__`, an ordinary non-administrator
account and a disposable `HERMES_HOME`):

```powershell
python -m pytest -q -o addopts= tests/test_network_windows_tor.py tests/test_network_windows_tor_lifecycle.py tests/test_network_windows_vpn.py tests/test_network_windows_routes_native.py
```

Optional real-Tor recipe for a validation host with an installed Tor Expert
Bundle and outbound network (it bootstraps a real Tor on loopback ports from
19050, checks the control cookie and, when `stem` is installed, the circuit
probe, then verifies exact teardown and record removal):

```powershell
$env:MORDRED_TEST_REAL_TOR = 'C:\Program Files\Tor\tor.exe'
python -m pytest -q -s -o addopts= -m integration tests/test_network_windows_routes_native.py -k real_tor
```

Set `MORDRED_TEST_REAL_TOR_POLICY=lenient` only to exercise an image that is
neither administrator-managed nor in a private per-user directory. Record
source and wheel results separately in the Manual live-device validation log.
None of these runs validates Mullvad/WireGuard (not ported on Windows in this
release), live provider traffic through the route, wizard capability
presentation (C6) or Windows 11 acceptance.

The kill-on-close job relies on nested job objects (Windows 8 and Windows
Server 2012 or later). GitHub-hosted Windows runners start each step inside a
job, so the native job cases on `windows-2022` exercise the nested path. On a
host without nested jobs, assignment fails and bring-up refuses with the
classified job failure. When `stem` is installed, the real-Tor case also
requires the PROTOCOLINFO-reported cookie path to be the private
`tor-data\control_auth_cookie` (`pinned_protocolinfo`). Record that result
separately for the ASCII profile path and for the non-ASCII/space/`#` profile
path, because a mismatch refuses with `control-cookie-path-outside-tor-data`.

### Windows capability and role reset validation (C5e)

The scoped Windows job adds `test_windows_capability.py`,
`test_windows_capability_native.py`, `test_windows_custody_reset.py` and
`test_windows_excluded_guards.py`. Host tests use real checked transactions
and MRKW crypto, injecting only the native backend, principal and platform
admission. Fault injectors fail if an excluded entry point reaches `_storage`,
anchor or backend resolution, a lock, native wrap/unwrap or plaintext capture.
Native cases use an inherited-safe task-owned NTFS home, its case alias and a
copied exact-private home. Their injected seams are the CNG backend, the
gateway inventory gate, C4 helper presence and C4 structural runtime
admission; filesystem admission, SID and physical identity are real. They
prove checked admission and refusal, not TPM availability. Held-lock cases
use a real lock holder in another thread or process and require predicates
to return `custody-uncertain` promptly instead of waiting.

Explicit native rerun in the selected source or installed-wheel environment
(after checking `mordred_hermes.__file__`, with a task-local `HERMES_HOME`):

```powershell
python -m pytest -q -o addopts= tests/test_windows_capability.py tests/test_windows_capability_native.py tests/test_windows_custody_reset.py tests/test_windows_excluded_guards.py
```

Capability predicates are diagnostics, not product acceptance. Real CNG reset,
Windows 11 and C6 wizard routing remain separate gates; record native results
in the Manual live-device validation log.
### Windows installed-runtime memory proof validation (C5c phase 2)

The scoped Windows job runs `test_windows_memory_proof.py`. It builds a real
non-editable venv from the job's interpreter and runs the actual probe child,
C4 validation, C1 private probe directory and bounded protocol natively; only
the CNG boundary, principal and checked-directory admission are injected
through the test-only backend module. This is not TPM or installed-product
evidence. The explicit real-CNG recipe is recorded with the lifecycle below.

### Windows proof-bound memory lifecycle validation (C5b-2)

The scoped Windows job also runs `test_windows_memory_lifecycle.py`, whose
proofs come from the real probe child above and whose files use real checked
transactions, MRKW and AES-GCM with the injected CNG boundary.

Explicit ordinary-user acceptance uses `tests/test_windows_memory_proof_live.py`.
Use the installed Hermes 0.19 venv from the controller artifact notes
(`completion-c4-real-20261008`) after installing, with pytest, a wheel built
from this branch's sdist; an editable install cannot prove. Verify
`mordred_hermes.__file__` there first. Set `MORDRED_TEST_WINDOWS_PROOF_LIVE=1`,
`MORDRED_WINDOWS_CUSTODY_TEST_ROOT` to an existing retained isolated root,
`MORDRED_HERMES_PYTHON` to that venv's `Scripts\python.exe` and
`MORDRED_WINKEY_HELPER` to the owned helper, stop every Hermes gateway, then run
from the checkout with that same interpreter:

```powershell
& $env:MORDRED_HERMES_PYTHON -m pytest -q -s -o addopts= -m integration tests/test_windows_memory_proof_live.py
```

The run passes the real stopped-gateway gate, creates a new UUID profile and a
fresh CNG key, then proves the installed runtime, enables, reads in a fresh
installed-runtime process, disables, reads again, requires a purgeable report
and deletes only its own key through the C5a journal. It prints only the
interpreter, module and helper paths and the seam. A failure keeps the profile
and journals and names the profile path; the root is never removed
recursively. Record source and sdist-wheel results separately in the Manual
live-device validation log. Neither run establishes Windows 11 or C6 product
acceptance.

### Windows extension checked state validation (C10a)

The scoped Windows job includes `tests/extension/test_extension_windows_storage.py`
and `tests/extension/test_extension_windows_storage_native.py`. The first runs
the real pairing, attestation, WebAuthn, history, wallet-fingerprint and API
paths against the native backend, including child processes that race one
pairing code, revocation against consumption, replay claims and a commit
against a reader. Native cases prove that an inherited extension directory,
broadened directory/file/lock ACLs, a hard-linked `state.json`, an extension
directory junction and another process holding the lock refuse or serialize
without repairing ACLs or rewriting state. Existing POSIX extension suites
remain required and are unchanged.

For controller acceptance, use an ordinary non-administrator account and a
disposable `HERMES_HOME`. Verify `mordred_hermes.__file__` in the source
environment and again in a fresh sdist-built wheel environment, then run that
environment's Python from the repository root with:

```powershell
python -m pytest -q -o addopts= tests/extension/test_extension_windows_storage.py tests/extension/test_extension_windows_storage_native.py
```

Record source and wheel results separately in the Manual live-device
validation log. This does not validate Telegram custody/archive (C10b), the
gateway/Desktop lifecycle (C11), a real browser extension pairing, or
Windows 11 product acceptance.
### Windows Telegram custody and archive validation (C10b)

The scoped Windows job adds `test_windows_telegram_custody.py`,
`test_windows_telegram_archive.py` and `test_windows_telegram_native.py`.
Host tests use real checked transactions, MRKW and MTC1/MTG1 crypto, injecting
only the native backend, token SID and platform admission; POSIX
mode/symlink/copied-tree stand-ins skip on Windows. Native cases use an
inherited-safe task-owned home, its case alias, an inherited non-private
telegram directory, a broadened ACL, a hardlink, a dialogs junction and a sync
lock held by another process, and require refusal without ACL repair or
deletion. Their injected CNG backend does not establish TPM acceptance.

2026-10-09 host-only flags follow-up: the new extension module
`tests/extension/test_telegram_windows_flags.py` reproduced 12 failures for
non-object metadata with retained sealed credentials, then passed all 21
cases after the Windows default-flags correction. The targeted command
`.venv/bin/python -m pytest -q tests/extension/test_telegram_windows_flags.py tests/test_windows_telegram_custody.py tests/test_wizard_windows_telegram.py`
passed all 130 cases on macOS. Checked presence, fresh conservative defaults,
unchanged files and C6 observation are covered without native unseal or
enrollment. Scoped Ruff checks and strict mypy passed. Native Windows and the
final combined full-suite run remain separate controller checks.

Explicit native rerun in the selected source or installed-wheel environment
(after checking `mordred_hermes.__file__`, with a task-local `HERMES_HOME`):

```powershell
python -m pytest -q -o addopts= tests/test_windows_telegram_custody.py tests/test_windows_telegram_archive.py tests/test_windows_telegram_native.py
```

Optional real-CNG acceptance requires BOTH `MORDRED_TEST_WINDOWS_TELEGRAM_LIVE=1`
and `MORDRED_WINDOWS_CUSTODY_TEST_ROOT` pointing to an existing isolated
retained root; run that environment's Python with
`python -m pytest -q -o addopts= -m integration tests/test_windows_telegram_live.py`.
Each run creates a UUID profile, enrolls a fresh CNG `telegram` role, checks
the presence refusal, seals synthetic credentials, writes a synthetic archive,
reloads both in a fresh process and runs the forget ceremony. No Telegram
account, credential, phone number, network or model is used; failure preserves
the profile/journals and reports only its path. Wizard ceremonies, the live
account gate and Windows 11 remain separate; record results in the Manual
live-device validation log.

### Canonical in-process wait validation (C2b)

`tests/test_config_io.py`, already in the scoped Windows job, adds
host-portable thread cases for SPEC.md ruling R-C2b-1: two concurrent
`blocking=False` readers in one process both succeed; a reader behind an
in-process holder refuses `busy`/`canonical_lock` only after
`IN_PROCESS_WAIT_SECONDS` (2.0 s, minus 50 ms timer-tick slack) and before the
bound plus 1 s; a holder released within the bound admits the reader;
`blocking=True` ignores the bound; and a real cross-process home or `mordred`
lock holder (the `tests/test_private_fs_processes.py` child) still refuses
immediately. Host result 2026-10-09 (macOS arm64, Python 3.14.7): all pass,
and C5e held-thread predicates now return within the bound; no native Windows
rerun is recorded yet.
### Windows wizard routing validation (C6)

The scoped Windows job adds `test_wizard_windows_memory.py`,
`test_wizard_windows_status.py`, `test_wizard_windows_excluded.py`,
`test_wizard_windows_uninstall.py` and `test_wizard_windows_native.py`. The
portable modules reuse the installed-runtime proof harness (a real non-editable
venv child, real checked files, MRKW and AES-GCM) with the CNG boundary,
principal and platform admission injected; the native module uses an
inherited-safe NTFS home, its case alias and a copied home with the real
`win32` platform decision, injecting only the CNG backend, helper presence,
structural runtime admission and the gateway inventory. Neither is TPM or
product evidence.

Explicit ordinary-user acceptance uses `tests/test_wizard_windows_memory_live.py`
in the same environment as the C5b-2 recipe above: the installed Hermes venv
with a wheel built from this branch's sdist (verify `mordred_hermes.__file__`),
`MORDRED_TEST_WINDOWS_WIZARD_LIVE=1`, `MORDRED_WINDOWS_CUSTODY_TEST_ROOT` set
to an existing retained isolated root, `MORDRED_HERMES_PYTHON` set to that
venv's `Scripts\python.exe` and `MORDRED_WINKEY_HELPER` set to the owned
helper, with every Hermes gateway stopped:

```powershell
& $env:MORDRED_HERMES_PYTHON -m pytest -q -s -o addopts= -m integration tests/test_wizard_windows_memory_live.py
```

Through the real CLI it runs `keyvault native init`, `encryption enable
memory` (real gate, installed-runtime proof and lifecycle on a new UUID profile
with a fresh CNG key), a fresh installed-runtime read, `encryption status
--json`, `encryption disable memory` and `encryption purge memory --yes`, which
deletes only that profile's key through the C5a journal. A failure keeps the
profile and journals and names the path; the root is never removed
recursively. Record source and sdist-wheel results separately in the Manual
live-device validation log. A real `hermes gateway` start, Desktop, Telegram
and Windows 11 installed-product acceptance remain separate gates.

### Windows wizard Telegram validation (C6-telegram)

The scoped Windows job adds `test_wizard_windows_telegram.py` and
`test_wizard_windows_telegram_native.py`. The portable module reuses the C10b
fixture (real checked transactions, MRKW, MTC1/MTG1 crypto, the real custody
store and archive) with the native backend, token SID, helper presence and
platform decisions injected, plus the C6 proof harness for one real Windows
memory enable; a synthetic Telegram client replaces the network. The native
module uses an inherited-safe NTFS home, its case alias and a copied home with
the real `win32` decisions, injecting only the CNG backend, helper presence,
structural runtime admission, the memory predicate and the synthetic client.
Neither is TPM, account or product evidence.

Explicit native rerun in the selected source or installed-wheel environment
(after checking `mordred_hermes.__file__`, with a task-local `HERMES_HOME`):

```powershell
python -m pytest -q -o addopts= tests/test_wizard_windows_telegram.py tests/test_wizard_windows_telegram_native.py
```

Optional real-CNG acceptance requires
`MORDRED_TEST_WINDOWS_TELEGRAM_WIZARD_LIVE=1`, `MORDRED_WINDOWS_CUSTODY_TEST_ROOT`
pointing to an existing isolated retained root and `MORDRED_WINKEY_HELPER` set
to the owned helper, run by an ordinary user:

```powershell
python -m pytest -q -s -o addopts= -m integration tests/test_wizard_windows_telegram_live.py
```

On a new UUID profile it runs `keyvault native init --role telegram` (a fresh
CNG telegram key), the acknowledged login with synthetic credentials and a
synthetic client, a fresh-process reload of the sealed credentials, `telegram
doctor --json`, `telegram logout` (a synthetic archive, the credentials and
the role are kept) and `telegram logout --forget` with the typed confirmation,
which deletes the credentials, the archive and that profile's telegram
generation only. No Telegram account,
phone number, network or model is used; a failure keeps the profile and its
journals and names the path. The live account gate, Desktop login (C11) and
Windows 11 remain separate; record results in the Manual live-device
validation log.
### Windows Desktop and extension shutdown validation (C11)

The scoped Windows job adds `tests/test_desktop_windows_api.py`,
`tests/test_desktop_windows_native.py`, `tests/test_desktop_windows_page.py`
and `tests/extension/test_extension_serve_shutdown.py`. The API module reuses
the installed-runtime proof harness through the C6 fixtures, with the CNG
boundary, principal and platform admission injected. The native module places
the Desktop page in a profile-style shared home whose name has a space and
non-ASCII characters, with the real `win32` decision, and checks refusals without ACL repair. The shutdown
module starts `python -m mordred_hermes.extension --port 7799` in a new process
group, sends `CTRL_BREAK_EVENT`, requires exit 0 within 10 s, no child process
and a free port, then restarts on the same port. A Windows venv `python.exe`
redirects to a base-interpreter child; the test inspects that interpreter.
`tests/test_desktop_windows_install.py` is the POSIX stand-in and skips on
NTFS. None of this is TPM, Desktop UI or product evidence.

Explicit ordinary-user acceptance uses `tests/test_desktop_windows_live.py`
with every Hermes gateway stopped, `MORDRED_TEST_WINDOWS_DESKTOP_LIVE=1`,
`MORDRED_WINDOWS_CUSTODY_TEST_ROOT` set to an existing retained isolated root
and `MORDRED_WINKEY_HELPER` set to the owned helper. Run it with the Python of
the packaged Hermes Desktop runtime, and again with an sdist-built wheel venv
(verify `mordred_hermes.__file__`), leaving `MORDRED_HERMES_PYTHON` unset so
the Desktop routing proves the serving interpreter:

```powershell
& <desktop-or-venv>\python.exe -m pytest -q -s -o addopts= -m integration tests/test_desktop_windows_live.py
```

Through the real Desktop router it reads `/status?client_version=3` and
`/hardware/build`, enables memory with both acknowledgements on a new UUID
profile (fresh CNG key), reads `/memory/status` and disables memory again; the
profile keeps its key until `encryption purge memory --yes`. The manual part,
recorded separately in the Manual live-device validation log, is to:

1. run `hermes-mordred desktop install` and launch the packaged Hermes Desktop;
2. open the Mordred page and record a screenshot of the capability list and
   helper state;
3. enable memory with all gateways stopped, then restart Desktop and confirm
   that the memory state reads `on`;
4. stop `extension serve` with Ctrl-C and with Ctrl-Break, then restart it on
   the same port.

Telegram stays blocked at the custody step until the C6-telegram ceremony
exists.

C11 round 1: `tests/test_desktop_capture.py` joins the scoped Windows job. The
shutdown module now reaps every child (and the redirected base interpreter)
on every path and requires 7799 free afterwards, and also stops a server while
an HTTP keep-alive client and an open WebSocket are connected, then restarts
it on the same port (server-side TIME_WAIT on Windows without
`SO_REUSEADDR`).

C11 integration follow-up validation and the scoped Windows job add
`tests/test_desktop_windows_logout.py`: real checked custody, MRKW/MTC1
credentials and archive with the native/platform boundary and Telegram
client injected. Regressions cover full snapshot reuse with one unwrap for
logged-in and configured/session-less credentials, retained archive/roles,
busy and custody preflight refusal without remote revoke, wipe-before-revoke,
partial deletion with confirmed credential absence, unknown post-wipe state,
failed revoke, pre-wipe metadata failure and the CLI recovery remedy.
`tests/test_desktop_windows_page.py` executes page components and handlers
through a synthetic SDK/React boundary to check ceremony command rendering,
success/error outcomes and Devices advice, persistent results after refresh
and disabled controls after logout. These are host regressions, not native
Desktop or real-CNG acceptance evidence. Ceremony availability depends on
C6 PR #222; the earlier blocked-at-custody note is superseded.

R-C11-5 records the shutdown evidence and limit: an open WebSocket delayed
SIGTERM about 46 seconds, so the all-platform listener stop and 3-second
connection-handler grace followed by task cancellation are accepted. POSIX
connections, including in-flight work, can be cancelled and need reconnect
or retry. This is not a universal process-exit deadline: a separate isolated
12-second default-executor worker probe returned from `_run_forever` around
3.21 seconds, then waited until the worker finished at interpreter exit.
This pre-existing bounded-worker lifecycle gap remains outside this slice.
R-C11-6 aligns Desktop with the C6 checked-wipe-before-revoke contract;
manual Telegram Settings → Devices revocation is required if remote revoke
fails after local deletion or if credential deletion cannot be confirmed.

The Desktop real-store suite also regresses metadata `[]` with an archive
lock held: advisory flags say absent, but the seal remains and a busy
forget must not revoke. It injects a failed checked seal-presence read after
an observed absence to verify unknown state, no revoke and Devices advice.
Shared `flags()` semantics remain a separate fix; Desktop corroborates
observed absence through the existing checked transaction/presence API.

2026-10-11 Astra review follow-up: production candidate `c1b5e48db`
integrates `dev` at `ec198d0f`. Telegram flags now refuse a held data lock
without waiting, preserving `store_busy`; mutation/sync locks remain blocking.
Failed Windows enrollment reports that a key may have been created and that
retained journals require explicit reconciliation, without echoing exception
content. Windows package-manager registration/repair remains unported and
refuses before profile I/O; the page directs users to their original Windows
installer. Windows database status and uninstall use checked, bounded,
nonblocking observation of known protection-state names, including a profile
owner, and refuse unsupported or uncertain state before teardown.

macOS arm64 / Python 3.14.7 / Hermes 0.19.0 verification: **8,015 passed,
221 skipped**, zero errors/failures, **90.22%** coverage (434.048 seconds).
Reduced-extras Python 3.12 strict mypy passed all 257 files; Ruff check/format
(586 files), shellcheck and Desktop JavaScript syntax passed. The sdist-built
wheel was installed in a fresh Python 3.12 environment outside the checkout;
its verified `site-packages` import passed 42 compatibility/page regressions.
Astra's final repair/Desktop review passed 214 tests with one existing
Hermes-checkout-dependent skip and found no remaining supported P1/P2 in its
assigned scope. The independent database review confirmed both additional
P2 fixes. Draft CI at native-test candidate `07b7993f6` passed all 59 critical
cases across the three OSes with zero skips. Product source is unchanged since
`c1b5e48db`. Full CI is tracked by
[run 38106401094](https://github.com/mordredagent/hermes-mordred/actions/runs/38106401094).
The run passed all 25 active jobs; draft-only feedback was intentionally skipped.
Retrieved native JUnit confirms **2,638 passed, 111 skipped**, zero failures/errors,
for each of Python 3.11, 3.12 and 3.13 across all nine Windows shards. Every
version collected all 84 selected modules without duplicate case identities.
The six Linux/macOS coverage cells passed the 80% floor (87.66% / 89.61%).
The native selector retains all 82 original modules plus two new compatibility
modules; new duration weights remain explicitly unmeasured.

Native fixture follow-up: failed full runs
[38104459639](https://github.com/mordredagent/hermes-mordred/actions/runs/38104459639)
and [38105162352](https://github.com/mordredagent/hermes-mordred/actions/runs/38105162352)
are retained. Teardown assertions now allow the read-only interpreter metadata
probe while still refusing package/data removal. The Telegram contention test
times the real Desktop flags adapter, excluding unrelated custody/memory scans;
real thread/process locks, completion before release, unchanged ciphertext and
native-call assertions remain. The Desktop API fixture uses a persistent
TestClient event loop and fresh job state, preventing cancelled jobs from
remaining falsely running between tests. Existing time bounds and confirmation,
options and summary checks remain. Focused host verification passed **122 tests
with zero skips**; Astra approved the precise test-only diff and both deliberately
blocking negative controls. These repairs do not change product source.

These host/wheel checks are portable regressions, not native CNG or Windows 11
acceptance. At this pre-reauthentication snapshot, the AWS session had expired
before new Server execution. The dated ordinary-user AWS CNG entry in the
Manual live-device validation log records the subsequent live results and
the still-incomplete full Server regression. SPEC permits a qualified Windows
11 x64 VM or Cloud PC; physical hardware
is not required, and virtual-TPM evidence must name its provider and limits.
Azure client-image eligibility has not been established; no Azure resources
were created. A Windows Server environment can provide TPM/provider evidence
but does not replace the separate Windows 11 client-product gate.

### Windows shared Telegram memory guard validation (C10c)

The scoped Windows job adds
`tests/extension/test_telegram_memory_guard_windows.py`. It uses real C6
checked custody and proof-bound memory with the existing injected CNG
boundary. Native operations and subprocesses are forbidden during each guard
check. A real second interpreter holds the canonical lock while service and
Hermes-tool refusal retains `custody_busy` before secrets, archive or network
access. The established POSIX guard module pins its platform seam so native
Windows runners do not select production Windows state.

Explicit rerun in the selected source or installed-wheel environment:

```powershell
python -m pytest -q -o addopts= tests/extension/test_telegram_memory_guard.py tests/extension/test_telegram_memory_guard_windows.py tests/extension/test_telegram_api.py tests/extension/test_telegram_hermes_tools.py
```

Local portable logs and the implementation report are retained under
`~/.codex/artifacts/mordred-windows-completion-20261008/c10c-*`. These are
regression evidence, not native Windows source/wheel or Windows 11 acceptance.
The real-account gate and wizard completion wording remain separate work.

### Windows native selector green-up validation (2026-10-09)

The scoped Windows job and the Windows Server 2025 validation host (ordinary
non-elevated SSH user, Medium integrity) failed on the integration head
`412f920de` for harness and fixture reasons, not product admission. The fixes
are test-only; no product module changed:

- Child interpreters now import the package under test: `tests/_child_env.py`
  prepends the directory the parent imported `mordred_hermes` from (the `src`
  checkout or the wheel's site-packages) to a child `PYTHONPATH` or fixture
  `.pth`. Source-tree runs against the Hermes venv otherwise imported the older
  hermes-mordred installed there (extension storage race, memory process
  lock, PowerShell installer fixtures). The Tor stub launcher also comes from
  standalone distlib or ensurepip's bundled pip wheel when pip is absent.
- The installed-runtime proof fixture appends `hermes_cli`'s source root when
  Hermes is an editable install, whose import hook the path-only `.pth` lines
  never run; `resolve_windows_python` refused the fixture venv
  (`interpreter-invalid`) for every proof, lifecycle and wizard memory test.
- Private fixtures with arbitrary content (malformed audit headers, history,
  copied manifests, the hooked privacy config) are written through
  `open_private_directory` (`tests/_private_files.py`). A raw write in a
  protected private directory gets the creator token's default DACL, which on
  an SSH logon carries the logon-session SID, so admission refused with
  `private_acl` before the classification under test.
- The unmanaged memory seam test reads UTF-8 explicitly; the synthetic process
  tables exclude the real PID; the native crash test retries only `busy`
  (bounded) after killing the lock holder, because Windows releases a killed
  process's byte-range lock asynchronously; the native unrecorded-Tor test
  matches the current refusal text.
- Managed-image fixtures: the elevated fixture creates its junction after the
  root is protected (created earlier it keeps an empty DACL, so the elevated
  open failed at `open` and `rmtree` could not delete it — reproduced on the
  host with an ordinary-user equivalent); the current-user-owned image test
  grants the owner explicitly, because a pytest base temp created with mode
  `0o700` by Python >= 3.13 grants an ordinary user access only through
  `OWNER RIGHTS`, which the owner change leaves inherit-only.

Host results, source environment (`PYTHONPATH=<root>\src`, Hermes venv
`C:\Users\mordred.000\hermes-source\venv`, Python 3.11.17; Hermes 0.21.5 is an
editable install there), per module, failed/errors before (full selector,
97 failed, 2082 passed, 99 skipped, 45 errors) and after (focused run of the
15 affected modules at `a18295d6b`):

| Module | Before F/E | After (passed/failed/skipped) |
|---|---|---|
| `extension/test_extension_windows_storage.py` | 4/0 | 48/0/0 |
| `test_config_io_windows.py` | 1/0 | 6/0/0 |
| `test_keyvault_windows_processes.py` | 1/0 | 132/0/0 |
| `test_network_windows_routes_native.py` | 1/4 | 6/1/2 |
| `test_private_fs_managed_images_windows.py` | 1/0 | 4/0/14 |
| `test_windows_encrypted_audit.py` | 11/0 | 57/0/0 |
| `test_windows_install_powershell.py` | 10/0 | 18/0/0 |
| `test_windows_memory_hook.py` | 3/0 | 45/0/0 |
| `test_windows_memory_lifecycle.py` | 2/34 | 39/0/0 |
| `test_windows_memory_native.py` | 1/0 | 5/0/0 |
| `test_windows_memory_proof.py` | 27/0 | 43/0/0 |
| `test_windows_privacy_audit.py` | 16/0 | 45/9/1 |
| `test_wizard_windows_memory.py` | 9/0 | 27/0/1 |
| `test_wizard_windows_status.py` | 8/0 | 13/0/0 |
| `test_wizard_windows_uninstall.py` | 2/7 | 15/0/0 |

The focused run totalled 10 failed, 503 passed, 18 skipped (27 min 45 s). The
remaining failures are fixed by two follow-up commits. The old
`unrecorded Tor` text (one) also fails on every windows-2022 job since
`3d9c4d090`, so CI verifies that fix. The hooked privacy fixture's raw
`config.yaml` (nine) fails only under the SSH-logon default DACL and already
passes on windows-2022, so it still needs a native rerun; the host stopped
before one could run. The 14 managed-image skips are the elevated or
controller-root cases (an ordinary token without
`MORDRED_MANAGED_IMAGE_TEST_ROOT`); the junction and teardown fix for the
elevated runner is reasoned from the windows-2022 log and the host
reproduction above, and windows-2022 verifies it. The wheel environment run of
`412f920de` (82 failed, 2101 passed, 99 skipped, 41 errors) shows the same
categories and was not rerun. `test_windows_encrypted_audit_processes.py`
timed out in 5 of the last 15 windows-2022 jobs (passed on the host): its
three contending children now share one 120 s deadline instead of 30 s each,
and print faulthandler stacks after 60 s so a real stall stays diagnosable.

### Hosted CI fixture follow-up (2026-10-09)

PR #221 run `37909321803` at `e13e79671` supersedes the earlier assumption
that raw `config.yaml` republishing passed on windows-2022. All three native
cells had 2,230 passed, 84 skipped and nine setup errors: checked replacement
correctly refused the raw creator-default file before the hook cases ran.
The fixture now creates both config/policy files directly through checked IO
and uses checked replacement for later updates; product admission is unchanged.

The six Unix cells and the Hermes-floor job also exposed a portable proof
fixture assumption: their pytest parent is a global setup-python interpreter,
whereas local `uv run` uses a venv. The shared fixture now explicitly emulates
parent storage admission only on non-Windows. Its installed proof child keeps
structural validation and the real probe; native Windows admission and the
independent unsupported-runtime tests remain intact. A global-parent regression
exercises real proof-bound enable/disable without changing `sys.executable`.

macOS framework Python can reexec with the same PID but a different executable
path. Test-owned Tor sleepers now wait for final-child readiness before their
identity is recorded. A full framework-child reproduction also exposed this
in `StubPopen`, so the same bounded readiness gate covers that companion stub,
retaining its bootstrap output. Early-exit/timeout/malformed-line regressions
verify that both paths reap their child and close the ready pipe. The fixed
readiness token accepts LF or CRLF, with a real binary-pipe CRLF regression;
arbitrary whitespace is refused. No product identity comparison was relaxed.

Host checks on macOS arm64: four initial regressions passed after RED/GREEN;
the companion stub's two cleanup regressions also failed before its fix. The
final Tor module passed all 67 tests with framework Python 3.13 children, and
the Tor module plus private-pair/global-parent regressions passed 69 tests.
The broader nine-module focused run passed 306 tests before the companion
readiness extension; a real Python 3.11 base-parent proof/lifecycle run passed
three tests. Reduced-extras Python 3.11 strict mypy passed all 235 source files;
Ruff check/format and shellcheck passed.
The final frozen full host suite exited successfully with 7,431 passed and
204 skipped (integration tests excluded by default), at 90.08% coverage.
Its five existing warnings concern FastAPI/Starlette, a Hermes escape sequence
and POSIX fork use; no test failure was reported.

These are host fixture checks, not new native Windows acceptance. The next
Unix/floor and three-version Windows CI runs, the previously skipped Windows
wheel smoke, the ordinary
native source/wheel reruns, controller-root managed images and Windows 11 remain
pending. The three audit writers did not time out in the inspected PR #221
run; one successful run does not close that intermittent observation.
