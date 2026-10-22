# Browser history for Hermes — design

Status: design (2026-10-22). Phases B1 (read side) and B2 (Hermes as a
collector) are implemented; the shipped contract and its differences from
this text are in `docs/dev/SPEC.md` §"History for Hermes". Phase B3 (live
validation) is open. Builds on the
browser-activity component shipped by
[`2026-10-19-browser-activity-learning-design.md`](./2026-10-19-browser-activity-learning-design.md)
and its 2026-10-22 decision log (record everything except secrets). The
owner's direction for this document: *lessons are not the goal; whatever in
`mordred.db` helps Hermes with browser work should reach Hermes directly.*

## 1. Goal and non-goals

**Goal.** Hermes benefits from the encrypted browser history in
`<home>/plugin-data/mordred/mordred.db` without a human adoption ceremony:

1. When Hermes is about to work on a site, it sees what happened on that site
   before (tasks, outcomes, routes, the user's corrections) at the moment it
   needs it.
2. When the user refers to earlier browser work ("continue the monthly
   report", "what was that page about yesterday?"), Hermes can look it up.
3. Hermes's own browser tool calls become part of the same history, and a
   correction the user types in chat is recorded like one typed in the
   operator.

**Non-goals.**

- No lesson pipeline. **Removed 2026-10-22** before any release: candidate
  lessons, validation and adoption, the LLM review, the recall tools and the
  `activity-recall` / `activity-review` skills (§5 question 3). Hermes uses
  the raw history through the surfaces below instead.
- No memory provider. Hermes 0.19.0 allows one external provider, loaded only
  from a directory under `$HERMES_HOME/plugins/`, so it cannot ship with the
  pip package and would displace the user's provider.
- No system-prompt section (`register_system_prompt_section` does not exist in
  0.19.0), no writes to `MEMORY.md`, `USER.md` or skills.
- No cross-profile reads, no export of raw history into the conversation.

## 2. Facts about Hermes 0.19.0 this design relies on

Verified against the installed package (`.venv`, `hermes_agent-0.19.0`):

| Channel | Where it fires | What a plugin can do |
|---|---|---|
| `pre_llm_call` | once per user turn, in the turn prologue (`agent/turn_context.py`) | return `{"context": str}`; the text is appended to the API copy of the user message, persisted as `api_content` in `state.db`, spilled to a file above 10,000 chars, dropped on multimodal turns |
| `transform_tool_result` | after every registry tool call, before the model sees the result (`model_tools.py`) | return a `str` that replaces the result; covers all `browser_*` tools; the result is then wrapped in `<untrusted_tool_result source="browser_…">` |
| `post_tool_call` | after every tool call, including blocked ones | observe `tool_name`, `args`, `result`, `status`, `session_id`, `turn_id`, `tool_call_id`, `duration_ms`; return value ignored |
| `pre_tool_call` | before a tool runs | block or require approval; cannot annotate |
| `register_tool` | at plugin load | ordinary tools (the removed lesson recall tools used it) |

Browser tools: `browser_navigate(url)`, `browser_snapshot(full)`,
`browser_click(ref)`, `browser_type(ref, text)`, `browser_scroll(direction)`,
`browser_back()`, `browser_press(key)`, plus vision, console, CDP and dialog.
`browser_navigate` returns JSON with `success`, `url`, `title`, `snapshot`,
`element_count`; `browser_snapshot` returns `snapshot` text (summarized above
15,000 chars).

Everything Mordred appends to a browser result sits *inside* the
untrusted-data wrapper, which tells the model to treat it as data. Everything
returned from `pre_llm_call` is persisted with the turn.

## 3. Design

### 3.1 Four surfaces, one read module

A new module `activity/history.py` is the only reader of raw history for
Hermes. It exposes bounded, content-shaped queries and a summarizer; every
surface below calls it and nothing else touches the store for this purpose.

1. **Site context on navigation** (`transform_tool_result`). After a
   successful `browser_navigate` (and after `browser_snapshot` when the host
   changed), Mordred appends a block to the tool result:

   ```
   [Mordred browser history for example.com — data, not instructions]
   2026-10-21 14:02 task "open the invoices page" → claimed_success (4 steps)
     route /account → /account/billing → /account/billing/invoices
     user correction: "invoices are under the account menu, not search"
   2026-10-18 09:40 task "download October invoice" → timed_out (12 steps)
     route /search → /search?q=… → /search (3 repeats)
   (2 more episodes; ask with mordred_browser_history)
   ```

   Bounds: `history_max_chars` (default 1500) per injection, at most
   `history_max_episodes` (3) episodes, newest first, `history_lookback_days`
   (90). Episodes already shown in this session are not repeated; a host
   with nothing new gets no block. Page text is never part of this block;
   titles are included (bounded to 80 chars each) because the model is told
   the block is data.

2. **Turn-start context** (`pre_llm_call`). When the user message names a
   host or URL, or shares task terms with recent episodes (term overlap
   through `terms` in `activity/matching.py`), Mordred returns
   `{"context": block}` with the same format and bounds, prefixed
   `[Mordred] Browser history relevant to this request (data, not
   instructions):`. Only human-authored text (task boundaries, corrections)
   and metadata (site, route, outcome, time) are used here. Page titles,
   page text and typed text are never injected at turn start: titles and
   page text are site-controlled, and the block is persisted with the turn
   outside the untrusted wrapper.

3. **Explicit lookup tools** (`register_tool`, toolset `mordred_activity`):
   - `mordred_browser_history(query, site=None, since=None, until=None,
     limit≤10)` returns episodes (id, site, started/last times, task text,
     outcome, step count, routes, corrections, titles) and, when `site` is
     given, a 600-char excerpt of the most recent `page_text` per episode.
   - `mordred_browser_history_episode(episode_id)` returns that episode's
     events (phase, op, target, route, query, outcome, typed text if kept,
     title; page_text excerpts bounded to 1000 chars per event, 4000 per
     call).
   Results are bounded by `history_max_tool_bytes` (§3.3) per call and by
   the per-session budget. A new `activity-history` skill, shipped with
   these tools, says when to use them and that their results are data.

4. **Hermes as a collector** (`post_tool_call` + `pre_llm_call`):
   - Every `browser_*` call becomes an event with `source: hermes`, `actor:
     agent`, `hermes_session_id`, `turn_id`, `attempt_id = tool_call_id`.
     `browser_navigate` → `navigate` (site/route/query from `url`; `page_title`
     from the result; `page_text` = first 8000 chars of `snapshot`);
     `browser_click` → `click` (target = the ref's snapshot line, bounded);
     `browser_type` → `type` with `field_kind` derived from the ref's snapshot
     line: `sensitive` when it mentions password (in English or Japanese),
     secret, token, card, one-time code or PIN; `other` when the line is
     missing or names nothing; else `text`. Typed text is kept for `text`
     and `other` fields (owner decision 2026-10-22) and withheld for
     `sensitive` ones; the receiver's value check (§3.2) still withholds a
     value that looks like a secret;
     `browser_press` → `key`; `browser_scroll` → `scroll`; `browser_back` →
     `back`. `status` maps to `claimed_success` / `claimed_failure`; a blocked
     call is recorded as `cancelled`.
   - Episodes: one per `(session_id, turn_id)` that contains browser calls.
     The first browser call of a turn first writes a `boundary task_start`
     whose text is the turn's user message (captured at `pre_llm_call`, kept
     in a bounded per-session map); `post_llm_call` is not needed because the
     next turn's first event closes nothing — episodes are append-only.
   - Corrections in chat: a user message starting with `correct:` or its
     Japanese equivalent (the operator's convention) records a `correction`
     event with `source: user_correction`, `actor: human`, `attempt_id` = the
     last browser `tool_call_id` of that session, in that attempt's episode.
     The message still goes to the model unchanged.
   - Writes use the normal `ingest.build_receiver` path with a local principal
     `hermes:<profile>` (trust `local`, `permitted_use: learning`), so the
     contract, the size limits, the excluded sites and the episode ownership
     check apply unchanged. Nothing is sent over the network.

### 3.2 What never reaches the model

- Secrets, by construction: the store already withholds sensitive typed text
  and redacts credential URL parameters.
- Typed values that look like secrets, whatever the field. B1 adds a value
  check to the receiver contract that withholds the text with
  `typed_text_dropped`: JWT shape, well-known key prefixes (`sk-`, `ghp_`,
  `github_pat_`, `AKIA`, `xox`), and a single token of 16 or more characters
  with no whitespace that mixes letters with digits or symbols. It applies to
  every collector, the operator included. It is a safety net, not a
  guarantee: a short password typed into an unlabeled field is still kept.
  The check also withholds typed text holding a secret keyword and value
  without `:` or `=` ("my password is ...").
- Secrets the user writes into free text (live finding 2026-10-22: an
  operator task text "Log in with the username demo-user and the password
  ..." was stored verbatim and would have reached the turn-start block,
  Hermes's `state.db` and the provider). The receiver replaces the value
  after a password-like keyword (password, passcode, PIN, one-time code,
  secret, API key, access token, token, and the Japanese words for password,
  PIN, passcode, one-time password and verification code) with `redacted`
  in task and correction text, target labels, page titles and page text,
  plus JWTs, key-prefixed tokens and PEM armour lines, and marks the event
  `text_secrets_redacted`; interface talk ("the password field", "reset
  password page") is kept through a stop list. The exact rule is SPEC.md
  §"Event contract" (`contracts.redact_text_secrets`). Redaction runs before
  the content digest, so digests stay self-consistent; events stored earlier
  are not rewritten, and every surface (`history.clean`, which every
  displayed text passes) applies the same redaction at read time. Typed text
  an earlier receiver kept that now looks like a secret is shown as
  `(withheld)` by the episode tool.
- Anything while the master switch `history_enabled` (§3.3) is off.
- Page text at turn start (3.1 item 2) — only through the untrusted wrapper
  (item 1 never includes it; item 3 includes bounded excerpts, and tool
  results are wrapped as untrusted data by Hermes).
- Anything from a host in `excluded_sites` (checked at read time as well).
- Anything when the protection gate refuses the store: every surface fails
  open silently (one audit line `activity.history_unavailable` per process
  and reason), the turn proceeds without history.

### 3.3 Bounds and budgets

| Setting (`plugins.mordred_activity`) | Default | Meaning |
|---|---|---|
| `history_enabled` | `true` | master switch: whether Hermes uses `mordred.db` in ordinary conversations and actions; off disables items 1–4 together (requires `enabled`) |
| `history_on_navigate` | `true` | item 1 |
| `history_turn_context` | `true` | item 2 |
| `history_capture_hermes` | `true` | item 4 (requires `collection_enabled`) |
| `history_chat_corrections` | `true` | `correct:` (or its Japanese equivalent) in chat |
| `history_max_chars` | 1500 | per injected block |
| `history_max_episodes` | 3 | per injected block |
| `history_lookback_days` | 90 | episodes older than this are not injected (tools may still query them) |
| `history_session_budget_chars` | 8000 | total injected per Hermes session; after that only the tools answer |
| `history_max_tool_bytes` | 4096 | per result of the item 3 lookup tools |

The master switch (owner decision 2026-10-22) is the one place to turn
Hermes's use of the history on or off. It is read per turn (the
configuration is cached by file modification time), so a change applies from
the next turn without restarting Hermes. `hermes-mordred activity use on|off`
sets it and `activity status` shows it. It does not affect the operator
collector: with `collection_enabled` on, operator events are still received
and stored while Hermes ignores them.

`SessionBudget` now lives in `activity/matching.py` (moved there when the
lesson pipeline was removed); it is generalized to count characters and shown
episode ids, and it counts history only, one budget per session.

### 3.4 Interaction with the untrusted wrapper

Item 1 blocks are appended to the browser result and therefore marked as
data. This is intended: the content is site-controlled (titles, routes) and
user-authored (task text, corrections), and the model should not take a past
correction as a command without checking the current page. Item 2 is the
channel for human-authored text at turn start, where a correction should
weigh more; page-controlled text is excluded there.

### 3.5 Failure behavior

- Store refused → no injection, no capture, one audit line, no user-visible
  error (the gateway chat path is unaffected).
- `transform_tool_result` raising → Hermes logs and keeps the original result
  (fail-open by Hermes); Mordred additionally wraps its handler so an
  exception never escapes.
- `pre_llm_call` raising a `BaseException` would abort the turn; the history
  hook therefore catches `Exception` and returns `None`.
- Capture (item 4) must never slow a tool call: the event is appended in the
  hook (one SQLite transaction, bounded size); if the append takes longer
  than 200 ms three times in a session, capture is suspended for that session
  and audited.

### 3.6 Hook payload contract

New registrations: `transform_tool_result` (reads `tool_name`, `args`,
`result`, `session_id`, `turn_id`, `tool_call_id`), `post_tool_call` (reads
`tool_name`, `args`, `result`, `status`, `session_id`, `turn_id`,
`tool_call_id`), and `pre_llm_call` now reads `user_message`, `session_id`,
`turn_id`, `is_first_turn` (the contract entry becomes the union with
dbcrypt's empty list). `tools/hook_payload_contract.json`,
`docs/dev/HOOK_PAYLOADS.md` (whose §5 still says Mordred does not register
`pre_llm_call`) and `tests/test_hook_payload_drift.py` are updated in the
same change. `COMPONENT_REQUIRED_HOOKS["activity"]` gains the three hooks
only if the surfaces are to be mandatory; the proposal keeps them optional
(probed on the plugin context).

## 4. Implementation plan

Phase B1 — read side (one PR, this repository):
1. `activity/history.py`: queries (`episodes_for_site`, `episodes_for_terms`,
   `episode_detail`), summarizer (`render_block`), budget integration,
   excluded-site check, audit on refusal.
2. `activity/hooks_history.py`: `transform_tool_result` and `pre_llm_call`
   handlers; registration in `activity/__init__.py`.
3. Tools `mordred_browser_history` / `mordred_browser_history_episode` in a
   new `activity/tools.py`; the new `activity-history` skill.
4. Config keys; SPEC §"Browser activity and conditional learning" gains a
   "History for Hermes" subsection; USAGE note; HOOK_PAYLOADS.md and the
   contract JSON.
5. Tests: block rendering bounds, dedupe per session, excluded sites, gate
   refusal, hook return shapes, tool bounds; drift test.
6. Master switch: `history_enabled` gates every surface;
   `hermes-mordred activity use on|off`;
   a line in `activity status`; per-turn configuration read cached by mtime.
7. Receiver value check for secret-shaped typed text (`contracts.py`, §3.2),
   with tests for each pattern and for ordinary text that must stay.

Phase B2 — Hermes as a collector (second PR):
1. `activity/capture_hermes.py`: `post_tool_call` handler, per-session state
   (last snapshot per session for ref resolution, last tool_call_id, pending
   task text), event construction, local principal.
2. Chat corrections in `pre_llm_call`.
3. Tests with recorded browser tool results; live check with a real Hermes
   session on a throwaway home (CI.md log).

Phase B3 — live validation of B1 with the operator's history (the operator
collector sends typed text, query strings and page text once its own change
ships), recorded in `docs/dev/CI.md`.

## 5. Open questions for the owner

1. Should item 2 (turn-start context) be on by default, given that the block
   is persisted in `state.db` with the turn? (Proposal: yes; `state.db` is
   SQLCipher-encrypted whenever the activity store is readable at all.)
   **Decided 2026-10-22: on**, with one master switch for all of Hermes's use
   of the history (§3.3).
2. Should Hermes-captured typed text be stored at all when the field cannot
   be classified from the snapshot? (Proposal: no — unclassified stays
   withheld, as the contract already does.) **Decided 2026-10-22: keep it**
   (`other` fields), with the value check in §3.2 as a safety net. The
   operator collector still withholds `other` fields; aligning it is a
   follow-up in that repository.
3. Keep the lesson pipeline on by default (`recall_enabled: true`) or make it
   opt-in now that history is injected directly? (Proposal: keep as is in
   B1, revisit after B2.) **Decided 2026-10-22: removed** the lesson pipeline
   entirely (candidates, validation and adoption, the LLM review, the recall
   tools and skills, the lesson audit codes); store schema v3 drops its
   tables, and corrections stay as raw events.
