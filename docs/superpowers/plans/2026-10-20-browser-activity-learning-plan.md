# Browser activity and conditional learning — implementation plan

Status: implementation plan for the design in
`../specs/2026-10-19-browser-activity-learning-design.md` (revised after the
Fable review of 2026-10-19). This plan does not change the design; where the
design leaves an implementation choice open, the choice is recorded here.
Revised 2026-10-22 for the capture-policy decision (record everything except
secrets; see the design's "Decision log"): limits, retention and the
normalization paragraph below reflect the revised contract.

## Baseline verified on 2026-10-20

| Fact | Consequence |
|---|---|
| Mordred dev venv runs **hermes-agent 0.19.0** (`.venv`); the reference checkout at `../hermes-agent` is newer (`5fc490e2b3`+). | Every Hermes API is probed at runtime (`getattr`/`inspect.signature`), never assumed from a version string. |
| 0.19.0 has no `plugins/plugin_storage.py`; the checkout has `plugin_data_dir(name)` → `<home>/plugin-data/<name>/`. | Mordred resolves `<profile-home>/plugin-data/mordred/` itself, with an explicit `home` argument (the Hermes helper reads the process-global home, which the design forbids for queued work). |
| `dbcrypt._policy.in_scope` keys every `*.db` under the home except `DENY_DIRS`; `plugin-data` is **not** denied. | When database encryption is armed and the SQLCipher shim is installed, `sqlite3.connect(<home>/plugin-data/mordred/mordred.db)` is keyed automatically and the connection object carries `mordred_key`. The store verifies that attribute and refuses an unkeyed connection. |
| `sqlcipher3` is **not** installed in the dev venv; `jsonschema` is not installed either. | Unit tests use an explicit test-only opener (plain SQLite in a temp dir). Live encryption checks are a separate macOS step after `uv pip install sqlcipher3-wheels` into the dev venv. Mordred validates review output itself. |
| 0.19.0 `PluginContext` has `register_tool`, `register_cli_command`, `register_command`, `register_auxiliary_task` (no `inherit_from`), `register_hook`, `register_skill`, `ctx.llm`; no `register_system_prompt_section`. The checkout adds `task=` on `complete_structured`, `inherit_from` on `register_auxiliary_task`, and returns registration handles. | All optional surfaces are probed. `task=` is passed only when the signature has it. |
| 0.19.0 `on_session_end` payload: `session_id, task_id, turn_id, completed, interrupted, model, platform` (no `failed`, no exit reason). `on_session_finalize` from the gateway: `session_id, platform, reason`. | The hook contract lists only `session_id` for the hooks Mordred adds; `completed`/`interrupted` are read with `.get()`. |
| `extension/api.py` is 1,382 lines with a flat `dispatch`; ruff caps complexity (C901 ≤ 10, ≤ 12 branches, ≤ 50 statements) and mypy runs `--strict`. | New handlers live in `extension/activity_api.py`; `api.py` only gains a table entry and a principal check. |
| The operator repo has no WebSocket client library (no `websockets`, no `aiohttp`); `cdp_relay.py` already implements server-side RFC 6455 framing with the stdlib. | The operator's activity client is a small stdlib client (masking + handshake), mirroring the relay. |
| `tests/test_hook_payload_drift.py` requires `tools/hook_payload_contract.json` keys to equal the set of hook names Mordred registers anywhere. | Every new `register_hook` literal gets a contract entry in the same change. |
| `tests/test_mordred_plugin.py` and `tests/test_imports.py` pin `COMPONENTS` order and membership. | Adding the `activity` component updates both tests. |

## Scope boundaries (from the design, restated as checks)

- Storage: `<profile-home>/plugin-data/mordred/mordred.db` only. No `activity.db`, no tables in `state.db`.
- No plaintext fallback: if the protection gate fails for any reason, recording and reading refuse with a content-free code.
- Phases (`intended`, `dispatched`, `observed`, `cancelled`, `timed_out`) and results (`unknown`, `claimed_*`, `verified_*`) are separate fields; a model "done" is `claimed_success`; a timeout is `unknown` until separate evidence resolves it.
- No cron, no timers, no background review on hooks. Review runs on an explicit command, or at a task boundary only after a Mordred-owned surface grants a single-use launch permit after delivery.
- Ordinary Hermes sessions see only `admitted` lesson revisions through two bounded tools; raw events and candidates never enter a prompt through this feature's interfaces.
- No writes to MEMORY.md, USER.md, or any skill during adoption.
- Programs own scheduling, authentication, budgets and adoption; the two skills only describe recall and assessment procedure.
- Hermes core is unchanged.

## Component layout (Mordred)

```
src/mordred_hermes/activity/
├── __init__.py        register(ctx): component entry (hooks, tools, skills); nothing heavy at import
├── _paths.py          activity_dir(home), store_path(home)   (plugin-data convention, 0700/0600)
├── config.py          ActivityConfig.load(home) from plugins.mordred_activity in <home>/config.yaml
├── contracts.py       enums, limits, NormalizedEvent, normalize_event(), canonical_digest(), batch checks
├── _gate.py           check_protection(home) -> Refusal | None ; verify_keyed_connection(conn, path)
├── store.py           ActivityStore(path, opener): schema v2 (in-place v1→v2 migration), append_batch, episodes, status, retention,
│                      backup/restore, lessons/jobs/budget tables (phase 2/3 add their operations)
├── ingest.py          Receiver: ingest(principal, batch) -> reply frame dict (dedupe, conflict, revision)
├── peers.py           activity peer credentials (pair codes, tokens, revocation, fingerprint)
├── corrections.py     deterministic candidate from an explicit linked correction        (phase 2)
├── lessons.py         lesson revisions, states, validation records, adoption, suspension (phase 2)
├── retrieval.py       admitted-lesson search/get with response + session budgets        (phase 2)
├── tools.py           mordred_activity_search / mordred_activity_get registration        (phase 2)
├── review.py          jobs, leases, attempts, budget, tool-free reviewer, output checks  (phase 3)
├── boundary.py        trusted interaction registry, launch permits, hook callbacks       (phase 3)
└── skills/
    ├── activity-recall/SKILL.md
    └── activity-review/SKILL.md
src/mordred_hermes/extension/activity_api.py   WS handlers: activity_pair_init, activity_auth, activity_batch
src/mordred_hermes/wizard/activity_cli.py      `hermes-mordred activity …`
```

`plugin.py`: add `("activity", "mordred_hermes.activity")` after `e2e`, before `wizard`;
`COMPONENT_REQUIRED_HOOKS["activity"] = frozenset({"on_session_start"})`.

## Interfaces fixed for parallel work

### Protection gate (`_gate.py`)

```python
@dataclass(frozen=True)
class Refusal:
    code: str      # unsupported_platform | not_armed | unprotected_process | no_key | conversion_pending
                   # | unkeyed_connection | plaintext_store | profile_mismatch | schema_newer | busy
                   # | disk_full | collection_disabled | store_unavailable
    detail: str    # content-free, operator-facing

def check_protection(home: Path) -> Refusal | None   # dbcrypt: darwin, armed(root_home), shim installed,
                                                      # key resolves, no journal / pending markers
def open_store(home: Path) -> ActivityStore           # raises ActivityRefused(Refusal); production opener =
                                                      # sqlite3.connect (the shim) + verify_keyed_connection
```

`ActivityStore(path, opener)` takes the opener explicitly. Production code only ever
passes the opener built by `open_store` after the gate passed. Tests pass a plain
`sqlite3.connect` opener on a `tmp_path`; that seam is a constructor argument, never a
config key or environment variable.

### Store (`store.py`)

- Tables exactly as the design lists: `activity_meta`, `activity_events`, `activity_episodes`,
  `activity_review_jobs`, `activity_review_attempts`, `activity_lessons`, `activity_lesson_evidence`,
  `activity_uses`, `activity_budget`.
- `activity_meta` rows: `schema_version` (int, v1), `profile_home` (realpath string of the owning
  home), `store_generation` (random hex, set at creation, changed by restore).
- Every public method opens a connection, runs one transaction (`BEGIN IMMEDIATE`), commits,
  closes. `busy_timeout` 2 s. Never sets `journal_mode` (host choice stands).
- `append_batch(peer_id, producer_id, events: list[NormalizedEvent]) -> AppendResult`:
  `accepted`, `duplicates`, `episode_revisions: dict[str, int]`; raises `BatchConflict` on
  same `event_id` with a different `content_digest`; whole batch is one transaction.
- `backup(dest: Path)` uses `sqlite3.Connection.backup()` (the shim's keyed connection class
  encrypts the destination); `restore(src: Path)` verifies schema version ≤ supported, copies via
  backup API, resets leases, marks `calling` attempts `uncertain`, writes a new `store_generation`,
  and keeps `profile_home` bound to the restoring home (dangling Hermes session refs stay as-is,
  marked `unavailable`).
- `apply_retention(now)`: raw events older than `retention_raw_days` (365; `0` = never) not pinned by
  lesson evidence; candidates older than `retention_candidate_days` (90) with their evidence links;
  suspend a lesson whose pinned evidence is missing. Bounded (LIMIT per pass).

### Receiver (`ingest.py`)

```python
@dataclass(frozen=True)
class PeerPrincipal:
    peer_id: str          # "operator:<id>" for activity peers, "extension" for the paired extension
    kind: str             # "operator" | "browser"
    trust: str = "paired_peer"
    permitted_use: str = "learning"

class Receiver(Protocol):
    def ingest(self, principal: PeerPrincipal, batch: Mapping[str, Any]) -> dict[str, Any]: ...
```

`build_receiver(home: Path) -> Receiver` evaluates config + gate **per call** (not cached at
construction) so revocation/disable refuses immediately without touching the WS session.

### Wire protocol (extension API, versioned `activity_batch_v1`)

Pre-auth frames (allowed before `auth`):

```json
{"id": "p1", "type": "activity_pair_init", "code": "MORT-XXXXXXXX-XXXXXXXX", "label": "operator"}
→ {"id": "p1", "type": "activity_pair_complete", "peer_id": "operator:ab12…", "peer_token": "<base64url 32 bytes>"}
  | {"id": "p1", "type": "activity_pair_fail", "reason": "invalid_code|expired_code|used_code|storage_refused"}

{"type": "activity_auth", "peer_token": "…"}
→ {"type": "activity_auth_ok", "peer_id": "operator:ab12…", "capabilities": ["activity_batch_v1"]}
  | {"type": "auth_fail", "reason": "invalid_token|peer_revoked"}
```

A socket authenticated by `activity_auth` is an **activity principal**: only `activity_batch`
and `activity_status` are dispatched; everything else answers
`{"id": …, "type": "error", "reason": "activity_session_forbidden"}`. The paired extension
(`auth` with `ext_token`) may also send `activity_batch` (principal `extension`). The
localhost page principal is refused. Activity principals are revalidated on every frame
against the peer file fingerprint (like `_authentication_is_current`); a revoked or re-paired
peer gets `auth_fail: pairing_changed`.

Batch frame and reply:

```json
{"id": "b7", "type": "activity_batch",
 "batch": {"schema_version": 1, "producer_id": "<uuid per collector process>",
           "producer_kind": "operator", "events": [ <event>, … ]}}
→ {"id": "b7", "type": "activity_ack", "status": "ok", "accepted": 12, "duplicates": 0,
   "episode_revisions": {"<episode_id>": 4}}
  | {"id": "b7", "type": "activity_refused",
     "reason": "malformed|batch_too_large|event_too_large|conflict|sequence_regression|collection_disabled|store_unavailable|busy|store_full|peer_revoked|source_excluded"}
```

Limits: ≤ 100 events per batch, ≤ 16 KiB normalized per event (4 KiB before 2026-10-22), ≤ 256 KiB per batch (raw frame).
ACK only after commit. Same `event_id` + same canonical content → counted in `duplicates`, no
insert. Same `event_id` + different content → whole batch `conflict`.

Event (collector → receiver):

```json
{"event_id": "<uuid4>", "seq": 41,
 "episode_id": "<uuid4>", "attempt_id": "<uuid4>|null", "parent_attempt_id": "<uuid4>|null",
 "source": "operator|browser|hermes|user_correction", "actor": "human|agent|unknown",
 "observed_at": 1760950000.123,
 "phase": "intended|dispatched|observed|cancelled|timed_out|boundary|correction|gap",
 "action": {"op": "click|type|search|scroll|hscroll|key|navigate|back|forward|wait|close_tab|task_start|task_end|other",
            "target": "<≤120 chars, redacted>", "site": "<host>", "route": "</path/normalized>",
            "args": {"keys": ["Enter"], "pixels": 400, "field_kind": "search"}},
 "result": {"status": "unknown|claimed_success|claimed_failure|verified_success|verified_failure",
            "method": "page_signature_change|null", "evidence": ["<event_id>", …]},
 "quality": {"coverage": "selected_tab|partial|gap", "exclusions": ["sensitive_field"], "truncated": false,
             "page_sig_before": "<16 hex>|null", "page_sig_after": "<16 hex>|null"},
 "session_ref": {"hermes_session_id": null, "turn_id": null, "run_id": "<operator run id>|null"},
 "text": "<≤4000 chars; corrections, task boundaries, and what was typed in a non-sensitive type/search field>",
 "query": "<?query#fragment with credential parameters redacted|null>",
 "page_title": "<≤300 chars|null>", "page_text": "<≤8000 chars of visible page text|null>"}
```

Receiver normalization (`contracts.normalize_event`, revised 2026-10-22): keeps the query
string and fragment of every URL but redacts credential parameters (token, key, secret,
session, code, signature and the like, plus JWT-looking values; exclusion
`url_params_redacted`), keeps `route` as the path and the scrubbed suffix in `query` (1000),
lower-cases `site`, bounds `target` (120), `text` (4000), `page_title` (300), `page_text`
(8000), `args` (≤ 512 bytes canonical JSON, allowlisted keys only), rejects unknown enum
values, rejects `verified_*` results from collectors (only the receiver/verifier may set
them — collector `verified_*` is downgraded to `claimed_*` with an
`exclusions: ["verification_claim_dropped"]` mark), keeps typed text for `type`/`search`
ops unless `field_kind` is `sensitive` or missing (then `typed_text_dropped`), refuses
events whose `site` is an excluded host or one of its subdomains (`DEFAULT_EXCLUDED_SITES`
is empty, so every exclusion comes from `excluded_sites` in config) → `source_excluded` for
that batch. The receiver sets `trust` and `permitted_use` from the principal, never from the
payload.

Server keepalive `{"type": "ping"}` frames are sent on every socket; collectors ignore them.

### Peer credentials (`peers.py`)

Files under `pairing._ext_dir()` (`<home>/extension/`), written with `pairing._write_private`:

- `activity_pending.json` — pending pair codes `{code_digest: {expires_at, label, outcome}}`
  (purpose-bound; never consumed by `pair_init`, and `pair_init` codes are never consumed here).
- `activity_peers.json` — `{peer_id: {token_sha256, label, kind, created_at, revoked_at|null}}`.

Functions: `generate_peer_code(label) -> (code, expires_at)`, `handle_pair_init(code, label) ->
{peer_id, peer_token}`, `authenticate(peer_token) -> PeerPrincipal | None`,
`revoke(peer_id) -> bool`, `list_peers()`, `fingerprint() -> bytes | None` (digest of the peers
file content, for per-frame revalidation), `pair_outcome(code)` for the CLI poll.

### Operator wire client

`ws://127.0.0.1:7788/ext` (configurable), no `Origin` header (the server's origin check admits
header-less clients). Credential file `~/.config/mordred/activity-peer.json` (0600):
`{"server": "ws://127.0.0.1:7788/ext", "peer_id": "...", "peer_token": "..."}`.

## Delivery sequence and agent assignment

### Wave 1 (parallel)

- **A — Mordred activity core**: `_paths.py`, `config.py`, `contracts.py`, `_gate.py`,
  `store.py` (events/episodes/meta + backup/restore/retention + empty lesson/job/budget
  tables), `ingest.py`, `activity/__init__.py` (register: `on_session_start` no-op binder +
  skills placeholder), `plugin.py` component entry, tests
  (`tests/test_activity_contracts.py`, `tests/test_activity_store.py`,
  `tests/test_activity_gate.py`, `tests/test_activity_ingest.py`), updates to
  `tests/test_mordred_plugin.py`, `tests/test_imports.py`.
- **B — Mordred peers + WS API + CLI skeleton**: `peers.py`, `extension/activity_api.py`,
  `api.py` dispatch/principal changes, `ExtensionAPIServer(activity_receiver=…)`,
  `extension/__main__.py` wiring (`build_receiver(home)` imported lazily, failure → refusals,
  never a crash), `wizard/activity_cli.py` with `status`, `pair-operator`, `peers list|revoke`,
  `_cli_parsers._add_activity`, tests (`tests/test_activity_peers.py`,
  `tests/extension/test_activity_api.py`, `tests/test_activity_cli.py`).
- **C — Operator collector**: `src/mordred/activity.py` (recorder, bounded buffer, stdlib WS
  client, resend, gap markers), `src/mordred/activity_cli.py` (`mordred-activity pair|status`),
  hooks in `fara_runner.py` / `app.py` / `cdp_relay.py`, `extension/background.js` navigation
  observations, `pyproject.toml` script entry, tests (`tests/test_activity_recorder.py`,
  `tests/test_activity_client.py` with a fake server), `docs/activity.md`.

### Wave 2 (after wave 1 integrates)

- **D — Correction loop**: `corrections.py`, `lessons.py`, `retrieval.py`, `tools.py`, skills,
  CLI `correct|candidates|validate|adopt|reject|lessons`, `activity/__init__.py` tool/skill
  registration, tests.
- **E — Docs reconciliation**: SPEC/PLAN/TODO/PATHS/HOOK_PAYLOADS (+ contract JSON) without
  renaming headings; `docs/dev/POLICY.md` for any new audit reason codes.

### Wave 3

- **F — Conditional review**: `review.py`, `boundary.py`, `activity review` CLI, hook
  registration (`on_session_end`, `on_session_finalize`) with contract entries, launch-permit
  consumer in the extension `chat` handler (after `chat_end`), tests including the
  "zero LLM submissions from hooks/cron/shutdown" invariants.

### As shipped (recorded 2026-10-20 at docs reconciliation)

Deviations from the layout and assignment above, as found in the code:

- `PeerPrincipal` lives in `activity/contracts.py`; `ingest.py` and `peers.py` re-export it.
  `peers.EXTENSION_PRINCIPAL` is the principal of the paired browser extension.
- `activity/_schema.py` holds schema v2 (all nine tables; v1 stores gain three nullable
  `activity_events` columns on open) separately from `store.py`.
- `review.py` is a facade over `_review_output.py`, `_review_snapshot.py`, `_review_jobs.py` and
  `_review_run.py`; `activity.register` calls `boundary.register_hooks` (`on_session_start`,
  `on_session_end`, `on_session_finalize`) and `tools.register_tools`.
- The lesson CLI (`correct`, `candidates list|show|build`, `validate`, `adopt`, `reject`,
  `lessons list|show|suspend|retire|revise`) is `wizard/activity_lessons_cli.py`; the review CLI
  (`review [--dry-run|--episode|--retry]`, `jobs list`) is `wizard/activity_review_cli.py`; store
  maintenance (`backup --output`, `restore --input [--yes]`, `retention [--dry-run] [--json]`) is
  `wizard/activity_store_cli.py`. Restore without `--yes` is a preview (exit 2); a backup bound to
  another profile is `profile_mismatch`; an unwritable backup target is `destination_unavailable`.
- The receiver runs one bounded retention pass (limit 200) after a successful append, at most once
  per hour per store; `ActivityStore.plan_retention` backs `retention --dry-run`. It also creates
  the deterministic candidate for each collector `correction` event (at most 10 per batch) after
  the commit, so wave-2 corrections are not limited to the `correct` CLI.
- `activity_status` replies `{collection: enabled|disabled|unavailable, reason}`; the per-frame
  revalidation failure is `auth_fail: pairing_changed`; a `producer_kind` that differs from the
  credential's kind is `malformed`; `unsupported_schema` is an additional refusal reason.
- Four audit reason codes were added (`POLICY.md` rows 34–37): `activity.capture_refused`,
  `activity.lesson_adopted`, `activity.lesson_suspended`, `activity.review_attempt`.
  `activity.capture_refused` is emitted once per process and code by `activity/_capture_audit.py`
  (receiver refusals and recall-tool gate refusals).
- Review eligibility uses three distinct completed episodes as the repeated-procedure threshold;
  launch permits lapse after 300 s; `boundary.py` also registers the `mordred_activity_review`
  auxiliary task when the host offers `register_auxiliary_task`.
- No production surface passes `activity_llm` to `ExtensionAPIServer`, so `task_boundary` review
  is admitted by no shipped surface; `extension serve` keeps capture and explicit review.

The full list of design statements without code is in `docs/dev/SPEC.md`
§"Not implemented in this delivery".

### Verification

Mordred: `uv run ruff check src tests`, `uv run ruff format --check src tests`,
`uv run mypy --strict src tools scripts/keyvault_offline_digest.py`,
`uv run pytest -q tests/test_activity_*.py tests/extension/test_activity_api.py`,
`uv run python tools/run_critical_tests.py`, one full `uv run pytest -q` at integration.
macOS live check (separate, synthetic): temp `HERMES_HOME`, `sqlcipher3-wheels` installed in the
dev venv, store created through the real shim with a synthetic memory key, then the stdlib
`sqlite3` must fail to read `mordred.db` and its backup.

Operator: `.venv/bin/python -m pytest -q tests/test_activity_*.py`, then the existing suite.

Live paid model evaluation is out of scope for this plan and runs only when explicitly
requested with a configured budget.
