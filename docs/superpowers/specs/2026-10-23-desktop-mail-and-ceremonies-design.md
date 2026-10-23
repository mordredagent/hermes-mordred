# Desktop mail and ceremony pages

Status: design draft for the owner and for the Codex (`gpt-6-astra`) design
review; nothing implemented yet. Branch `feat/desktop-mail-ceremonies`
(worktree `hermes-mordred-desktop`, based on `feat/imported-message-provenance`
because the mail code lives there). Author: Fable (design fork of the main
session). Review section to be appended after the Codex review.

Owner's request (2026-10-23, after running the macOS ceremonies and the first
Telegram sync from a terminal, and after `mail setup` failed with an opaque
`imap_auth_failed`):

> (translated from Japanese) Later, make the mail import, and these
> ceremonies too, operable from the Desktop through the Mordred plugin.

> (translated from Japanese) Explain this, the mail setup included, in the
> Desktop plugin, and improve the Desktop plugin's UI/UX as a whole.

The maintained docs carry no CJK text, so the quotes above are translations;
the original wording is in the session transcript. That is: make the mail collector (`mail setup`, `mail fetch`, `mail status`,
`mail forget`) and the macOS protection ceremonies operable from the Mordred
page in Hermes Desktop, with the explanations that were given in the terminal
today (what an app password is, where to make it, what Touch ID means) shown
on the page itself, and improve the page's UI and UX as a whole.

## Goal

A macOS owner who never opens a terminal can, from the Mordred page in Hermes
Desktop:

1. see at a glance what is protected, what is connected and how much history
   Hermes can search (counts only);
2. run the protection ceremonies in the right order with the reasons shown
   inline: the Secure Enclave helper, encrypted `.env` + memory (the recovery
   passphrase shown once), and the SQLite database encryption that
   `mordred.db` depends on ("converts at the next restart" when Hermes holds
   the databases, with the existing Restart control);
3. connect Telegram (unchanged flow, re-grouped) and connect a mailbox over
   IMAP with the same guidance the terminal gave today, fetch mail, see the
   counts, and remove the account again;
4. understand what to say in a Hermes chat ("sync my mail", history questions)
   and what Hermes does and does not see;
5. read every failure as a stable code with a remediation line, including the
   three Gmail login failure classes that today collapse into one
   `imap_auth_failed`, and the stale file-vault Keychain anchor that today
   crashes the ceremonies with a raw traceback.

Everything typed on the page (app password, Telegram codes, a Venice key)
keeps today's path: masked inputs → `ctx.rest()` → Mordred's local API in the
Hermes Desktop backend → sealed by the Secure Enclave. Nothing of it reaches
the chat, the model, the agent's tools, plugin storage, notifications or logs;
inputs are cleared after each submit; the page shows counts and codes only,
never an address, a subject, a name or a body.

## Non-goals

- Linux and Windows: their branches of the page keep today's behaviour. The
  new sections are shown only when the API reports `platform: "darwin"` and
  `hardware_kind: "secure_enclave"`; `mordred.db`, database encryption and
  the mail collector are macOS-only today.
- `mail import` (Takeout mbox / `.eml` files) from the page. It needs a file
  picker and a long-running job over a user-chosen path; the IMAP path covers
  day-to-day use. It stays a CLI command and is listed in the page's
  "Terminal only" note.
- A typed recovery passphrase. The page keeps generating the eight-word
  passphrase and showing it once (`/memory/enable` today); the terminal
  ceremony that asks the operator to type one twice is the CLI's behaviour,
  not the page's. See "Contradictions with the brief" at the end.
- The fix for the stale file-vault anchor itself. It is a separate `keyvault`
  PR (TODO entry "Stale file-vault anchor"); this design only makes the page
  recognise that state and show the remediation instead of a traceback.
- Changing reader mode, egress rules or what the Hermes tools return.
- A new bundler or framework for the page. `plugin.js` stays one plain ES
  module copied to `<home>/desktop-plugins/mordred/plugin.js` by
  `desktop/install.py` (no build step), importing only `@hermes/plugin-sdk`
  and `react`/`react/jsx-runtime` (the loader's import allowlist).

## Current state of the Desktop page (one page)

**Delivery.** `src/mordred_hermes/desktop/assets/desktop/plugin.js` (1456
lines, one ES module) is copied by `desktop/install.py` to
`<home>/desktop-plugins/mordred/plugin.js` at install time and re-placed at
every plugin start. `<home>/plugins/mordred/dashboard/plugin_api.py` is a shim
that imports `mordred_hermes.desktop.api.router`; Hermes's Desktop backend
(`hermes serve`) mounts it under `/api/plugins/mordred/` (session-token
protected, loopback only). The page talks to it with `ctx.rest()`.

**Page composition (macOS branch, `SetupPage`).** A 720 px column: `h2`
"Mordred setup", the tagline "Private, read-only Telegram for Hermes.",
`RepairPanel` (only when the API is unreachable or Mordred is missing from the
environment), `HealthLine`, `UpdatePanel`, then the numbered steps:

| n | component | API | notes |
|---|---|---|---|
| 0 | `HermesModelStep` | `/status` → `hermes_model` | Hermes's own chat model must be Venice private or local; gates everything below |
| 1 | `EnclaveStep` | `POST /hardware/build` (job `enclave`) | builds, signs, installs and probes the helper |
| 2 | `MemoryStep` | `POST /memory/enable` | one `FlowSession`: `env_decrypt_cli.enable` then `memory_cli.enable`; creates the vault with a generated 8-word passphrase returned once; optional body `unattended` |
| 3 | `LlmStep` | `POST /llm/venice`, `POST /llm/local` | the privacy LLM for `telegram_ask` |
| 4 | `TelegramStep` | `POST /telegram/login/start`, `/{flow}/code`, `/{flow}/password`, `/{flow}/cancel` | `LoginFlows` keeps the half-authenticated client in memory, TTL 600 s |
| 5 | `ImportStep` | `POST /sync`, `GET /sync` (polled every 3 s) | `TelegramService.start_sync`; counts come from the service's in-process summary |

Then `UninstallSection` (plan via `GET /uninstall/plan`, run as job
`uninstall`). `RestartHermesControl` relaunches the app through the Electron
bridge with a 30 s confirmation deadline and manual fallback text. The Windows
branch (`WindowsSetup`) is separate and untouched by this design.

**Step helper.** `Step({n, title, done, children})` renders a bordered
`section` with `h3` "`✓`/`n` title" and hides the children when `done`. There
is no "blocked" or "running" state; blocked steps are expressed by a
hand-written paragraph ("Set the question model first (step 3).").

**Backend conventions (`desktop/api.py`).** Bodies are validated by hand (no
pydantic, so a 422 never echoes a secret); expected failures answer HTTP 200
with `{"ok": false, "error": "<code>"}` and optional non-secret info keys;
long work runs through `_jobs.JobRegistry` (`_start_job(kind, work)`, one
running job per kind, `update`/`uninstall` exclude each other, progress via
`_emit("progress", …)` and terminal `plugin.mordred.job` events, poll with
`GET /jobs/{id}`); printed wizard output is captured per thread by
`_capture.captured_output()` (one capture per process at a time). `_status`
builds from `telegram_setup_cli.run_checks()` (`telethon`, `secure_enclave`,
`hardware`, `memory_encryption`, `login`, `privacy_llm`, `archive`,
`hermes_integration`), `hermes_model_check()` and the Telegram store flags; it
never unseals anything.

**Tests.** `tests/extension/test_desktop_api.py` mounts `api.router` on a
FastAPI `TestClient` with fakes patched onto module seams (`api._store`,
`api._FLOWS`, `api._home`, `api._JOBS`, `api.hermes_model_check`,
`memory_encryption_active`) and asserts codes-only bodies and that canaries
(api_hash, code, 2FA password, Venice key) never appear in responses.
`tests/test_desktop_windows_page.py` checks `plugin.js` without Hermes: it
parses as an ES module (`node --check`), label tables (`MESSAGES`, `REASONS`,
`CAPABILITY_LABELS`, `STEP_LABELS`) cover every code the API can return, no
readiness is derived from English text, and `render_page()` runs components
through a tiny Node harness that stubs `Button`/`Checkbox`/`Input`/`Fragment`
and the hooks. Any new SDK import must be added to that harness.

**What is missing for the owner's request.** No mail section, no database
encryption step, no store-backed counts (the Telegram counts are 0 after a
backend restart until `dialogs()` runs), no grouping or state model, the
tagline still says "Telegram", every explanation is a sentence inside a
button's step, and a stale vault anchor surfaces as `memory_encryption_failed`
with no remedy.

## Information architecture of the improved page

### Layout

One scrolling column (max 760 px), four groups in a fixed order, each a
`section` with an `h2` and an `aria-labelledby`, preceded by an overview card.
Group and step titles are stable identifiers used by the page tests; the copy
below is final English and is not localised (the page has no i18n today).

```
Mordred                                   [health line] [Update panel, one line]
Private Telegram and mail for Hermes, encrypted on this Mac.

┌ Overview ───────────────────────────────────────────────────────────────┐
│ ● Hermes chat model     e2ee-deepseek-v4-flash (Venice private)          │
│ ● Protection            Secure Enclave · memory encrypted · databases on │
│ ● Telegram              connected · 3 chats · 25 messages               │
│ ○ Mail                  not set up                                      │
└─────────────────────────────────────────────────────────────────────────┘

1  Protect this Mac
   1.1 Secure Enclave helper                      ✓ done
   1.2 Encrypt Hermes memory and secrets          ✓ done
   1.3 Encrypt Hermes databases                   → next

2  Connect
   2.1 Hermes chat model                          ✓
   2.2 Question model (Venice private or local)   ✓
   2.3 Telegram (read-only)                       ✓ connected
   2.4 Import Telegram messages
   2.5 Mail over IMAP                             blocked: needs 1.3

3  Ask Hermes
   What to say, what Hermes sees, terminal-only commands.

4  Maintenance
   Update · Repair · Uninstall
```

The `RepairPanel` keeps its place at the very top when the API is unreachable
or Mordred is missing (nothing else renders then, as today).

### Overview card

Four rows, each `StatusRow({dot, label, detail, target})`: a coloured dot
(`●` done / `◐` partial / `○` not started / `!` attention, drawn with
`currentColor`/`var(--ui-accent)`/`var(--destructive)` so both themes work),
the label, a detail sentence built only from status fields, and a "Go" link
that scrolls to the group (`element.scrollIntoView`, then focuses the group
heading). Details:

- Hermes chat model: `hermes_model.model` and kind; "not private" in
  attention state.
- Protection: three facts joined with " · ": "Secure Enclave" /
  "helper missing", "memory encrypted" / "memory not encrypted",
  "databases on" / "databases off" / "databases: converting at next restart".
- Telegram: "connected · N chats · M messages" from `imports.sources.telegram`
  (store counts), or "not connected", or "connected · nothing imported yet".
- Mail: "account <label> · N messages · last fetch <relative time> (complete |
  partial | <code>)" or "not set up". The label is the owner's opaque label
  (`work`), never an address.

### Step cards and their states

`Step` grows a `state` prop replacing the boolean `done`:

| state | visual | behaviour |
|---|---|---|
| `done` | `✓` in the title, muted border, body collapsed into a one-line summary (not hidden: a "Change" / "Details" toggle opens it) | e.g. 1.2 shows "On · recovery passphrase shown on 2026-10-23" (no date today: "On") |
| `next` | accent-coloured left border, body open | the first not-done step in reading order |
| `todo` | plain, body open | later steps that are not blocked |
| `blocked` | plain, body replaced by the reason line and a "Go to step X" button | reason is a code from a `BLOCKERS` table (`needs_hermes_model`, `needs_enclave`, `needs_memory`, `needs_databases`, `needs_restart`, `needs_login`, `needs_question_model`), never free text from the API |
| `running` | spinner glyph, controls disabled, `role="status" aria-live="polite"` progress line | jobs and long calls; survives page re-open through `status.jobs` |
| `attention` | `var(--destructive)` left border, body open with a `FailureNote` | a failed job or a refusal that needs the owner |

Every step keeps a collapsible "Why?" block: a native `<details>` with a
`<summary>` ("Why this step?"), so it is keyboard-operable and announced by
screen readers without extra code.

### Group 1 — Protect this Mac

**1.1 Secure Enclave helper** (`EnclaveStep`, as today). Why: "Mordred seals
your Telegram login, your mail app password and the encryption keys with a
key that never leaves this Mac's Secure Enclave. The helper is a small signed
program that talks to it."

**1.2 Encrypt Hermes memory and secrets** (`MemoryStep`, as today, plus the
key-policy choice and the stale-anchor remedy). Body before enabling:

> Hermes keeps what it learns about you in memory files and its API keys in
> `.env`. This step moves `.env` into Mordred's encrypted vault and encrypts
> the memory files. You get a recovery passphrase once: it is the only way to
> read these files if this Mac is lost or the Secure Enclave key is gone.
>
> ☐ Ask for Touch ID every time Hermes unlocks the vault
>   (off by default: Hermes Desktop starts its backend in the background, and
>   an unlock it cannot answer would start Hermes without its secrets. With
>   this off, the key opens silently while you are logged in. Your Telegram
>   and mail keys are separate and keep their own Touch ID setting.)
>
> [Turn on memory encryption]   (may show a Touch ID prompt)

The page sends `{unattended: !askEveryTime}` (default `unattended: true`).
After success the passphrase card is shown as today ("Write this down… shown
only once"), with the "I have written it down" checkbox and Continue; the step
then shows "Restart Hermes to finish" with `RestartHermesControl` inline
(today the restart hint is only a toast).

Failure with `vault_anchor_stale` renders the `FailureNote` with the remedy
from the API (see the API section): "A Mordred vault was removed from this
Mac earlier, but its Keychain anchor remains, so the vault cannot be created.
In Terminal run `security delete-generic-password -s mordred-hermes.vault.anchor -a <identity>`
and try again. Nothing was changed." The identity is the hash
`vault_identity(<home>/mordred/vault)`, not a secret. A copy button copies the
command.

**1.3 Encrypt Hermes databases** (new `DatabasesStep`). Why:

> Hermes stores your chats (`state.db`), projects and cron history in SQLite
> files. Mordred's own store for imported Telegram and mail history
> (`mordred.db`) only opens when these files are encrypted too, with the same
> key as the memory files. Encryption happens on disk; Hermes keeps working
> as before.

Body: a table of the databases from `databases.databases` (`relative`,
`state`: "plaintext" → "will encrypt", "encrypted", "encrypted or unreadable",
"missing"), a note when `plaintext_backups > 0` ("N backup archive(s) in your
Hermes home may contain plaintext copies; delete them when you no longer need
them"), and the button **Encrypt databases** → `POST /databases/encrypt
{dry_run: false}`. The dry run is implicit: the table *is* the preview (it is
read on every status refresh with no key and no Touch ID), so no separate
"preview" button is needed.

In Hermes Desktop the backend always holds the databases open, so the answer
is `action: "scheduled"`; the step then shows, in `running`-like styling but
without a spinner: "Scheduled. Hermes Desktop keeps its databases open, so
they are encrypted the next time Hermes starts, before it opens them. Restart
now:" + `RestartHermesControl`. After the restart the status reports
`armed: true` and the step is `done` ("On · 4 databases encrypted"). Until the
restart, steps 2.4 (Telegram import) and 2.5 (Mail) are `blocked` with
`needs_restart` ("Restart Hermes Desktop to finish step 1.3"); the Telegram
import step explains that on macOS the import writes to `mordred.db` once the
databases are encrypted. `action: "encrypted"` (possible only when nothing
holds the files, e.g. a CLI-started backend) goes straight to `done`.

### Group 2 — Connect

**2.1 Hermes chat model** (`HermesModelStep`, as today, moved here from
"step 0"): still the gate for everything that reads history. Its "Why?"
block: "Everything Hermes reads goes to its chat model. Telegram and mail
history are offered to Hermes only when that model is a Venice private model
(no retention) or a model running on this Mac."

**2.2 Question model** (`LlmStep`, as today).

**2.3 Telegram** (`TelegramStep`, as today; the api_id/api_hash guidance
becomes a "Why?" block: "Telegram requires every third-party client to
register an app. The app is yours; its api_id and api_hash identify it, not
you. They are sealed with your login.") Done summary: "Connected · log out /
disconnect in Settings → Devices on your phone, or `hermes-mordred telegram
logout` in Terminal" (macOS has no logout button today; unchanged).

**2.4 Import Telegram messages** (`ImportStep`, as today, with store counts).
The result line reads from `imports.sources.telegram` ("3 chats · 25 messages
in Mordred's store") instead of the in-process summary, so it is right after a
backend restart. The days field keeps its default 3 with a hint "30 for a
useful first import; 0 is not accepted here, use the terminal for all
history".

**2.5 Mail over IMAP** (new `MailStep`). Four sub-states: not set up, setup in
progress (flow), set up, forgetting.

Not set up:

> Mordred can fetch your mail read-only over IMAP and add it to the same
> encrypted store as Telegram, so Hermes can answer questions about it.
> Hermes never sees a subject, name, address or body: it only gets counts.
>
> **Before you start (Gmail).** Create an *app password*: turn on 2-Step
> Verification for your Google account, then open
> https://myaccount.google.com/apppasswords and create one for "Mordred".
> Google shows it as four groups of four letters; paste it with or without the
> spaces. Mordred never needs your Google account password, and you can
> revoke the app password at any time in the same place. Other providers call
> this an app-specific password.
>
> Mail address      [________________________]
> Other addresses that are yours (comma-separated, optional)
>                   [________________________]
> IMAP server       [imap.gmail.com         ]  (filled in for Gmail addresses)
> Account label     [work]  (a short name for this mailbox in Mordred, not an address)
> App password      [••••••••••••••••]
> ☐ Allow syncing without Touch ID (for scheduled syncs; otherwise each fetch
>   asks for Touch ID)
>
> [Connect mailbox]  (logs in once, read-only; may show a Touch ID prompt)

`Why?`: "Your address and the app password are sealed by the Secure Enclave
on this Mac. Each fetch unseals them, logs in with TLS, reads new mail and
logs out: nothing is marked read, moved, deleted or sent. Gmail: Mordred reads
All Mail with its labels, so mail you sent is recognised as yours. Other
servers: the inbox and the sent folder."

On a generic server without a marked sent folder the flow returns
`step: "folders"` and the card shows a list of folder names with radio
buttons ("Which folder holds your sent mail? (optional)") and **Finish**. On
success: toast "Mailbox connected (read-only)." and the card moves to "set
up".

Failure copy by code and hint (see the API section for the enum):

| code / hint | shown |
|---|---|
| `imap_auth_failed` / `authentication_failed` | "The server rejected the address or the app password. Check that the app password was created while signed in to the same Google account as this address, that the address is the account's primary sign-in address (not an alias or a 'send as' address), and that 2-Step Verification is on. A Workspace administrator can turn off IMAP or app passwords for the organisation, and Advanced Protection disables app passwords. Nothing was stored." |
| `imap_auth_failed` / `server_alert` | "The server refused the login with an alert. For Gmail this usually means an app password is required (not the account password) or that Google wants a sign-in in the browser first. Open https://myaccount.google.com/apppasswords, create a new app password and try again. Nothing was stored." |
| `imap_auth_failed` / `login_disabled` | "This server does not allow password login over IMAP. Nothing was stored." |
| `imap_auth_failed` / `gmail_app_password_length` | "A Gmail app password is exactly 16 letters. What you pasted has a different length, so it is probably the account password or incomplete. Nothing was sent to the server." |
| `imap_auth_failed` (no hint) | "The login was refused. Nothing was stored." |
| `imap_unreachable` | "The server could not be reached (network, Tor or VPN path). Nothing was stored." |
| `sync_in_progress` | "A mail fetch or import is running (from Hermes or Terminal). Try again when it finishes." |
| `mail_already_configured` | "A mailbox is already set up. Remove it below first." |

Set up:

> Account **work** · Gmail (All Mail with labels) · Touch ID on each fetch
> Last fetch: 2 hours ago (complete) · 1,240 messages in Mordred's store
>
> [Fetch new mail]  ☐ also older mail since [2026-01-01]
>
> Result (counts only): inserted 37 · duplicates 0 · skipped 2 · partial: yes
> → "Fetch again to continue".
>
> Say **"sync my mail"** in any Hermes chat to do this from the chat; Hermes
> sees only these counts.
>
> ▸ Remove this mailbox …
>     ☐ Also delete the fetched mail from Mordred's store
>     [Remove]  (type "delete my data" when deleting mail)

The result block renders exactly the keys of `FetchResult.as_dict()` that are
non-zero/non-null, in a fixed order, plus the `partial` sentence; nothing
else can appear (the serializer is closed). `[Fetch new mail]` is disabled
while a `mail_fetch` job runs ("Fetching… up to 10 minutes; approve the Touch
ID prompt if it appears"), and the page polls `GET /jobs/{id}` with
`pollJob()`.

### Group 3 — Ask Hermes

A card with copy only:

> **In any Hermes chat.** Ask about your Telegram or mail history the way you
> would ask a colleague: "What did Tanaka say about the invoice last week?" —
> Hermes searches Mordred's encrypted store with the `mordred_history_search`
> tool and quotes each fact with its evidence line (who wrote it, when). Say
> **"sync my mail"** to fetch new mail; Hermes sees counts only.
>
> **What Hermes sees.** Only the lines Mordred returns for your question,
> each headed by the speaker and date, and never a secret: the login, the
> app password and the keys stay on this Mac. The chat model must be a Venice
> private model or a local model, or the tools are not offered.
>
> **Terminal only.** `hermes-mordred mail import` (Takeout files),
> `hermes-mordred telegram sync --days 0` (all history), `hermes-mordred
> telegram logout`, and `hermes-mordred status` for the full report.

### Group 4 — Maintenance

`UpdatePanel`, `UninstallSection` and (when needed) `RepairPanel` as today,
under one heading. The update panel's one-line state ("Mordred 0.3.0a4 is up
to date") stays near the page title as well, since it is the first thing an
owner looks for; the full panel lives here.

### Platform gating

| API facts | page |
|---|---|
| `platform === "darwin" && hardware_kind === "secure_enclave"` | the layout above |
| `hardware_kind === "tpm"` (Linux) | today's Linux list, unchanged (no 1.3, no 2.5); the overview card shows "Databases: not available on Linux", "Mail: not available on Linux" |
| `hardware_kind === "cng"` (Windows) | `WindowsSetup`, untouched |

The page asks for `client_version=4`; an API that answers without the new
keys (`databases`, `imports`, `mail`) is an older Mordred, and the page then
renders the new steps as "Update Mordred to use this" (attention state with
the update panel link), never as "done" or "blocked".

### Light/dark, keyboard, screen readers

- Colours only through `currentColor`, `CanvasText`, and the theme variables
  the SDK documents (`--ui-accent`, `--ui-text-secondary`,
  `--ui-text-tertiary`, `--ui-stroke-secondary`, `--destructive`); the two
  remaining hex colours in `plugin.js` (`#b91c1c` in `FailureNote` and the
  uninstall box) become `var(--destructive, #b91c1c)`.
- Every control is a real `button`/`input`; inputs carry `aria-label` equal to
  their visible label; the masked inputs keep `autoComplete: 'off'`.
- Progress lines are `role="status" aria-live="polite"`; failures are
  `role="alert"`; after a submit the page moves focus to the result or the
  failure note (`ref.current.focus()` on a `tabIndex: -1` container).
- "Why?" blocks are `<details>/<summary>`; group navigation from the overview
  card focuses the group heading (`tabIndex: -1`).
- No new named import from `@hermes/plugin-sdk`. A named import that the
  installed Hermes Desktop does not export fails the module link and the whole
  page disappears, so the overhaul uses `Button`, `Checkbox`, `Input`, `host`
  and the three area constants only, and plain elements for dots, badges,
  tables and details. (`tests/test_desktop_page.py` pins the import line.)

## Backend API design (`src/mordred_hermes/desktop/api.py`)

All new routes follow the module's rules: hand-validated bodies, HTTP 200 with
`{"ok": false, "error": code}` on expected failures, codes from closed sets,
no echo of any input, blocking work through `asyncio.to_thread` or a job,
printed output captured and discarded with `_quiet`.

### `GET /status?client_version=4`

Unchanged keys for `client_version <= 3`. With `client_version >= 4` on
macOS the response adds:

```json
"databases": {"supported": true, "armed": false, "pending": false, "journal": false,
              "databases": [{"relative": "state.db", "state": "plaintext"}, …],
              "plaintext_backups": 0},
"imports":   {"available": true, "code": null,
              "sources": {"telegram": {"conversations": 3, "messages": 25, "parts": 25},
                          "mail": {"conversations": 0, "messages": 0, "parts": 0}}},
"mail":      {"configured": false}
```

- `databases` comes from `dbcrypt._migrate.discover(home, key=None)` plus
  `armed(home)`, `pending_path`/`journal_path` and `plaintext_backups`: no
  key, no Touch ID, no capture. `state` is one of `plaintext`, `encrypted`,
  `unreadable` (the page labels it "encrypted or unreadable"), `missing`. On
  Linux/Windows `{"supported": false}`.
- `imports` comes from `imports.store.open_import_store(home).status()["sources"]`
  (per-source counts; no Telegram or mail secret is needed, the store is
  opened through the SQLCipher gate like `mail status`). A gate refusal is a
  state, not an error: `{"available": false, "code": "not_armed" |
  "conversion_pending" | "unprotected_process" | "no_key" | "plaintext_store"
  | "store_unavailable" | "busy", "sources": {}}`. This is the Desktop answer
  to the TODO entry "CLI counts after the Telegram archive moved to
  `mordred.db`": the page never reads `index.enc`, so it needs no sealed key.
- `mail` is `wizard.mail_sync_cli.imap_status(store, MailSecretStore().flags())`
  when the store is available (label, `gmail`, `scope`, `touch_id`,
  `last_fetch {at, error, partial}`, cursors), else the flags only
  (`{"configured": true, "account": "work", "gmail": true, "scope": ["all"],
  "touch_id": true, "last_fetch": null}`). Never the address.

`jobs` already lists running jobs; the page uses `kind` (`mail_fetch`,
`enclave`, `update`, `uninstall`) to restore `running` states after a
re-open.

### `POST /databases/encrypt`

Body `{"dry_run": bool}` (default false). Steps, mirroring
`wizard.databases_cli.databases_encrypt` without printing:

1. Not macOS or `sqlcipher3` missing → `databases_unsupported`.
2. `KeyProvider()()` is `None` → `databases_key_missing` (page: "Finish step
   1.2 and restart Hermes first").
3. `discover(home, key)`; `todo` = plaintext ones. Response always carries
   `databases` (as in status) and `plaintext_backups`.
4. `dry_run` → `{"ok": true, "action": "dry_run"}`.
5. No `todo` → `{"ok": true, "action": "nothing", "armed": armed(home)}`.
6. `_migrate.holders(paths)` unknown or non-empty → `_migrate.schedule(home)`
   → `{"ok": true, "action": "scheduled", "restart_required": true}`. In
   Hermes Desktop this is the normal answer: the backend itself holds the
   files.
7. Else `_migrate.migrate(home, key, arm=arm)` in a thread →
   `{"ok": true, "action": "encrypted", "converted": n, "unreadable": n,
   "restart_required": false}`; `MigrationBusy` → schedule as in 6;
   `MigrationError` → `databases_failed` (nothing changed).

The key unwrap may show a Touch ID prompt when the vault key is attended.
`GET /databases/status` returns the `databases` object alone (the page calls
it after the restart control, when the full status is too heavy).

### `POST /memory/enable` (existing; two additions)

- The page sends `unattended` explicitly (default `true`); the route already
  forwards it to `FlowSession(unattended=…)`.
- Before returning `memory_encryption_failed`, the route classifies the stale
  anchor: `root = vault_cli._resolve_root(None)`; if
  `not vault.artifacts_present(root)` and
  `default_anchor_store().read(vault_identity(root)) is not None` (both
  read-only; the Keychain read is the same one `ensure_initialised` just
  made, so it adds no prompt), answer
  `{"ok": false, "error": "vault_anchor_stale", "anchor_identity":
  "mordred-hermes.vault.<16 hex>", "remedy": "security delete-generic-password -s mordred-hermes.vault.anchor -a mordred-hermes.vault.<16 hex>"}`.
  The identity is a hash of the vault path, not a secret. The real fix
  (refusing to trust an anchor without artifacts, and a scoped reset) stays in
  the `keyvault` PR; once it lands, the ceremony itself returns a code and
  this classification becomes a pass-through.

### Mail setup flow: `imports/mail/setup_flow.py`

A step-wise object the CLI and the page share, modelled on
`extension/telegram/login_flow.py`:

```python
@dataclass
class MailSetupFlow:
    flow_id: str
    creds: MailCredentials          # address, app_password, host, 993, own addresses, account, gmail=False, mailboxes={}
    presence: bool                  # Touch ID per use
    folders: tuple[ListEntry, ...]  # from LIST, selectable ones; empty on the Gmail path
    gmail: bool
    step: Literal["folders", "done"]
    created: float                  # TTL 600 s, like LoginFlow

class MailSetupFlows:
    def __init__(self, secret_store, *, connect=connect, lock=fetch_lock, home=hermes_home, clock=time.monotonic): ...
    def start(self, *, address, imap_host, account, extra_addresses, app_password, presence) -> MailSetupFlow
    def finish(self, flow_id, *, sent: str | None) -> MailSetupFlow
    def cancel(self, flow_id) -> None
```

`start`: validate (`_own_address`, `valid_host`, `ACCOUNT_RE`, ≤20 extra
addresses, password 1–256 printable chars, Gmail whitespace stripped; on
`imap.gmail.com` a stripped length ≠ 16 raises `MailSetupError("imap_auth_failed",
hint="gmail_app_password_length")` before any connection), refuse when
credentials are already sealed (`mail_already_configured`; the owner removes
them first), `secret_store.ensure_key(require_presence=presence)` (fails
before the server is contacted, as the CLI does), then under `fetch_lock(home)`
one read-only login (`connect` → `login` → `list_mailboxes` → `logout`). Gmail
(`X-GM-EXT-1`): choose All Mail as `_choose_mailboxes` does, seal at once,
`step = "done"`. Generic server with a `\Sent` special-use folder: seal,
`done`. Generic server without one: keep the flow in memory (password
included, in the flow object only), return `step = "folders"` with the
selectable entries (`name` as an opaque id, `display` sanitised like
`_term_safe`). `finish(sent=…)`: re-take the lock, seal `MailCredentials` with
`{"inbox": …, "sent": …}`, `done`. Nothing is written before the seal; a
refusal leaves no file (today's `mail setup` guarantee, now tested on the flow).

`MailSetupError(code, hint=None)` codes: `invalid_address`, `invalid_host`,
`invalid_account`, `invalid_password`, `too_many_addresses`,
`mail_already_configured`, `mail_setup_flow_expired`, `sync_in_progress`,
`store_path_unsafe`, `tee_unavailable`, `tee_auth_cancelled`,
`imap_unreachable`, `imap_auth_failed`, `imap_protocol`,
`imap_command_refused`, `routing_unavailable`, `egress_unsupported`.

`wizard/mail_sync_cli.cmd_setup` becomes a thin driver over
`MailSetupFlows` (prompts → `start` → optional `_pick` → `finish`), so the two
entry points cannot drift; its printed lines stay as they are, plus the hint
(`mail refused (imap_auth_failed: authentication_failed)`).

### IMAP failure hints (`imports/mail/imap.py`)

`ImapError` gains an optional `hint: str | None` (closed enum
`IMAP_HINTS = {"authentication_failed", "server_alert", "login_disabled",
"gmail_app_password_length"}`; anything else is `None`). `ImapSession.login`
derives it from the response code only: `str(exc)` of
`imaplib.IMAP4.error` is matched with `^\[([A-Z][A-Z0-9-]{1,30})\]` (RFC 5530
codes such as `AUTHENTICATIONFAILED`, `AUTHORIZATIONFAILED`, `EXPIRED`,
`PRIVACYREQUIRED`, `CONTACTADMIN`, and Gmail's `ALERT`): `AUTHENTICATIONFAILED`
→ `authentication_failed`; `ALERT` → `server_alert`; `LOGINDISABLED`
capability → `login_disabled`; no bracketed code → `None`. The free text after
the code is never kept, logged or returned (Gmail's alert text contains a
support URL and sometimes the account name). `FetchStop`/`FetchResult` are
unchanged (`error: "imap_auth_failed"`, the serializer is closed); the hint is
carried only by `MailSetupError` and, in `mail fetch`'s text output, printed
after the code when present.

### Mail routes

| route | body | answer |
|---|---|---|
| `POST /mail/setup/start` | `{"address", "imap_host"?, "account"? (default `mail`), "extra_addresses"?: [..], "app_password", "touch_id"?: bool (default true)}` | `{"ok": true, "flow_id", "step": "done" \| "folders", "gmail": bool, "account", "folders"?: [{"id", "display"}]}`; errors `{"ok": false, "error": code, "hint"?: hint}` |
| `POST /mail/setup/{flow_id}/finish` | `{"sent": id \| null}` | `{"ok": true, "step": "done"}` |
| `POST /mail/setup/{flow_id}/cancel` | — | `{"ok": true}` |
| `POST /mail/fetch` | `{"max"?: 1–2000 (default 2000), "since"?: "YYYY-MM-DD", "mailbox"?: "all"\|"inbox"\|"sent", "dry_run"?: bool}` | job `mail_fetch`: `{"ok": true, "job_id", …}`; on completion `progress.result` = `FetchResult.as_dict()`; `result.error` set → job `failed` with that code |
| `POST /mail/forget` | `{"rows": bool, "confirm"?: "delete my data"}` | `{"ok": true, "had_credentials", "deleted_messages", "cursors_deleted", "warnings": [codes]}` |
| `GET /imports/status` | — | the `imports` and `mail` objects of `/status` (light refresh for the mail card) |

Gates on every mail route: macOS; `_require_memory()` (memory encryption on);
for fetch and forget the import store gate is applied inside
`run_fetch`/`forget` (codes pass through). `/mail/fetch` uses
`FetchOptions(max_messages, roles, since, dry_run, budget_s=DESKTOP_BUDGET_S
(600.0, the CLI's), via="desktop")` and `imap_sync.default_env(home)`; the job
runs `run_fetch` in a thread with `job.run_sync`. Progress is not streamed
(`run_fetch` has no progress callback); the job's `progress.message` says
"Fetching new mail… up to 10 minutes" and the page shows elapsed time.
`JobBusy` for `mail_fetch` answers `mail_fetch_busy`; a fetch from the chat
tool or the CLI at the same time answers `sync_in_progress` from the writer
lock (same lock, `<home>/mordred/mail/.lock`). `forget` reuses the CLI's
`_identity` / `_forget_target` / `_locked_forget` moved to
`imports/mail/forget.py` as `forget(secret_store, home, *, account=None,
rows=False) -> Forgotten`; `rows: true` requires `confirm == PURGE_PHRASE`
checked before anything is read (same rule as `/uninstall`).

Canaries in tests: the address, extra addresses, the app password and folder
display names (generic path) must never appear in `/mail/fetch`,
`/mail/forget`, `/status`, job views, `plugin.mordred.job` events, logs or
captured output; folder names appear only in the `folders` step of
`/mail/setup/start`.

### New `MESSAGES` entries (page)

```
databases_unsupported, databases_key_missing, databases_failed, databases_busy,
vault_anchor_stale, mail_already_configured, mail_setup_flow_expired, mail_fetch_busy,
mail_not_configured, invalid_address, invalid_host, invalid_account, invalid_password,
too_many_addresses, imap_auth_failed, imap_unreachable, imap_protocol,
imap_command_refused, routing_unavailable, egress_unsupported, import_store_unavailable,
not_armed, conversion_pending, unprotected_process, no_key, plaintext_store, busy,
credentials_changed, credentials_left, key_left, account_unknown, fetch_failed,
run_failed
```

plus `IMAP_HINTS` (the four hints) and `BLOCKERS` (the seven blocked reasons)
as explicit tables, covered by the page test the way `MESSAGES` is today. The
existing `sync_in_progress` text becomes "A Telegram import or a mail fetch is
already running."

### Concurrency summary

| actor | lock / slot | concurrent attempt sees |
|---|---|---|
| `/mail/fetch` job | job kind `mail_fetch` + mail writer lock | `mail_fetch_busy` (page) / `sync_in_progress` (CLI, tool) |
| `mordred_mail_sync` (chat) | mail writer lock | `sync_in_progress` from the page's fetch or setup |
| `mail import` / `mail forget` (CLI) | mail writer lock | `sync_in_progress` |
| `/mail/setup/start`, `/finish` | mail writer lock during probe/seal only | `sync_in_progress` |
| `/databases/encrypt` | none (always "scheduled" in Desktop); `_migrate` has its own journal | second call: `action: "scheduled"` again, idempotent |
| `/memory/enable` | `FlowSession` in one thread; `memory_cli` custody lock | `custody_busy` / `memory_operation_in_progress` (existing) |

## Test plan

API (`tests/extension/test_desktop_api.py`, extended; fakes on module seams,
no network, no Enclave):

- `/status?client_version=4` carries `databases`, `imports`, `mail`; v3 does
  not; a gate refusal is `imports.available: false` with the code, never a
  500.
- `/databases/encrypt`: `dry_run`; holders busy → `scheduled` and
  `schedule()` called once; free → `encrypted` with counts; `MigrationBusy`
  → scheduled; `MigrationError` → `databases_failed`; no key →
  `databases_key_missing`; Linux → `databases_unsupported`.
- `/memory/enable` failure with artifacts absent and anchor present →
  `vault_anchor_stale` with `remedy` naming the identity; artifacts present
  → plain `memory_encryption_failed`.
- Mail setup: Gmail path seals in `start`; generic path with `\Sent` seals in
  `start`; generic without → `folders` then `finish`; `cancel` and TTL expiry
  leave nothing sealed; `mail_already_configured`; every `MailSetupError`
  code and hint passes through; `touch_id: false` → `ensure_key(require_presence=False)`;
  the canary address/password/folder names never appear outside the
  `folders` list; a failing `start` leaves `<home>/mordred/mail` without
  `credentials.*`.
- `/mail/fetch`: validation (`max`, `since`, `mailbox`), runs as a job with
  `via == "desktop"` and the CLI budget, result on the job, `error` → job
  failed with that code, second call while running → `mail_fetch_busy`,
  writer lock held by a fake CLI → `sync_in_progress`.
- `/mail/forget`: `rows` without the phrase → `forget_confirm_mismatch`
  before any read; warnings propagate (`key_left`, `account_unknown`).

Library:

- `tests/test_mail_setup_flow.py` (new): the flow with `tests/_fake_imap.py`
  (scripted server over a socket pair, already used by
  `test_mail_imap_sync.py`): both paths, folder pick, auth failure hints from
  `[AUTHENTICATIONFAILED]` / `[ALERT]` / none, `LOGINDISABLED`, the Gmail
  length pre-check never connects, lock contention, TTL, cancel, nothing
  sealed on failure, `__repr__` of the flow never prints secrets.
- `tests/test_mail_imap_client.py` (extended): `ImapError.hint` derivation
  keeps no server text (a canary in the alert text is absent from
  `str(exc)`, `repr(exc)` and the log).
- `tests/test_mail_sync_cli.py` (extended): `cmd_setup` drives the flow and
  prints the hint after the code; `mail fetch` text output prints the hint.

Page (`tests/test_desktop_page.py`, new POSIX counterpart of
`test_desktop_windows_page.py`, same `block()`/`render_page()` helpers moved
to `tests/_desktop_page.py`):

- the module parses; the import line is exactly the allowlisted names;
  `client_version=4` is requested; the macOS layout is chosen by `platform`
  and `hardware_kind`, never by text;
- every code in the API's closed sets (`MailSetupError` codes, `IMAP_HINTS`,
  `imap_sync.ERROR_CODES`, gate codes, databases codes, `BLOCKERS`) has an
  entry in `MESSAGES` / `IMAP_HINTS` / `BLOCKERS`;
- step states come from status fields (`databases.armed`, `imports.available`,
  `mail.configured`, `jobs[].kind`), with a table-driven test over a dozen
  status fixtures asserting the state of every step;
- the mail inputs are cleared after a submit (success and failure); the
  fetch button is disabled while a `mail_fetch` job is in `status.jobs`;
  the result block renders only `RESULT_FIELDS` keys;
- the stale-anchor failure note renders the remedy from the response; the
  databases step shows the restart control on `scheduled`;
- no hex colour literal outside the `var(--…, #…)` fallbacks.

Manual live checklist for the owner (macOS, the production profile, after the
existing backup; recorded in `docs/dev/CI.md` §Manual live-device validation
log):

1. Open the Mordred page: overview shows the current production facts
   (model private, helper installed, memory on, databases on, Telegram 3
   chats / 25 messages, mail not set up).
2. Mail setup with the Gmail app password: success → "set up" card; then
   deliberately wrong password → `imap_auth_failed` / `authentication_failed`
   with the remediation text and nothing stored (`ls ~/.hermes/mordred/mail`).
3. Fetch new mail (`max 100`): counts shown, Touch ID prompt appeared,
   `hermes-mordred mail status` agrees with the page.
4. In a chat: "sync my mail" → counts only; a history question quotes
   evidence lines.
5. Remove the mailbox with rows: `mail status` shows 0 mail rows and no
   credentials.
6. On a throwaway `HERMES_HOME` with plaintext databases: the databases step
   shows "will encrypt", Encrypt → "scheduled", Restart → `armed`.
7. Light and dark theme screenshots of every state; VoiceOver reads the step
   titles, states and the failure note.

## Documentation changes (headings to add; never rename an existing one)

- `docs/user/USAGE.md`
  - under `### \`desktop\` — Mordred setup page in Hermes Desktop`: new bold
    paragraphs **The page's groups.**, **Database encryption from the page.**,
    **Mail from the page.**, **What the page never shows.**
  - under `#### Sync new mail over IMAP (\`mail setup\`, \`mail fetch\`, \`mail forget\`)`:
    a step **0. From Hermes Desktop** before step 1, and a paragraph on the
    `imap_auth_failed` hints after the exit-code paragraph.
  - under `### 4.3 Touch ID prompts — why several per command, and how to silence them`:
    one sentence that the Desktop page creates the file-vault key unattended
    unless "Ask for Touch ID every time" is ticked.
- `docs/user/TELEGRAM.md`, `## Set up (once, about 5 minutes)`: the "In
  Hermes Desktop" paragraph mentions the groups and that database encryption
  and mail live on the same page.
- `docs/user/QUICKSTART.md`: a note under the macOS order table that steps
  4–9 can be run from the Mordred page in Hermes Desktop (the table rows are
  unchanged).
- `docs/dev/SPEC.md`: new `## Desktop mail and ceremony pages (2026-10-23)`
  with `### Page structure and states`, `### Mail setup flow`,
  `### IMAP failure hints`, `### Databases from the page`,
  `### Imports status`; additive bullets under `### IMAP sync (2026-10-22)`
  (the hint enum) and `### Telegram setup and interface compatibility`
  (`client_version=4` keys).
- `docs/dev/PLAN.md`: `## Desktop mail and ceremony pages implementation`
  (stages = the PRs below) and a bullet under `### IMAP sync (2026-10-22)`
  for `setup_flow.py` / `forget.py`.
- `docs/dev/TODO.md`: replace the body of the "Desktop operability (owner
  request 2026-10-23)" entry with the PR checklist and correct its location
  claim (the Desktop page is `desktop/assets/desktop/plugin.js` through the
  Hermes Desktop plugin REST bridge, not `extension/web/index.html`); add
  "Desktop `mail import` (file picker)" and "typed recovery passphrase on the
  page" under "Later (not scheduled)"; the "CLI counts" entry notes that the
  page reads per-source counts from the store.
- `docs/dev/HOOK_PAYLOADS.md`: nothing (no hook payload changes; the
  `mail.fetch` audit entry gains `via: "desktop"` as a value of an existing
  key, documented in the SPEC section).
- `docs/dev/PATHS.md`: no new file (flows are in memory); the
  `<home>/mordred/mail/.lock` row gains "the Desktop page" in its holders
  column.
- `docs/dev/CI.md`: `tools/ci_scope_paths.json` entries for
  `src/mordred_hermes/imports/mail/setup_flow.py`, `forget.py`,
  `tests/test_mail_setup_flow.py`, `tests/test_desktop_page.py`,
  `tests/_desktop_page.py`; a live-validation log template for the checklist
  above.

## PR split

| PR | component | contents | tests | depends on |
|---|---|---|---|---|
| D1 docs | docs | SPEC/PLAN/TODO/USAGE/TELEGRAM/QUICKSTART/PATHS/CI changes above, `ci_scope_paths.json`; this design doc | `tests/test_docs_links.py` | — |
| D2 mail library | `imports/mail` (+ its `wizard/mail_sync_cli.py` driver) | `imap.py` hints, `setup_flow.py`, `forget.py`, `cmd_setup`/`cmd_forget` driving them, hint printing in `fetch` | `test_mail_setup_flow.py` (new), `test_mail_imap_client.py`, `test_mail_sync_cli.py`, `test_mail_secrets.py`, full `test_mail_imap_sync.py` (security-sensitive) | D1 |
| D3 page framework | `desktop` (page only) | `Step` states, `BLOCKERS`, overview card, groups, "Why?" blocks, a11y, colours, `client_version=4` with graceful "update Mordred" rendering; no new backend | `tests/_desktop_page.py`, `tests/test_desktop_page.py` (new), `test_desktop_windows_page.py` (harness moved, unchanged assertions) | D1 (can run in parallel with D2) |
| D4 desktop backend + sections | `desktop` (api + page) | `/status` v4, `/databases/*`, `/imports/status`, `/mail/*`, `vault_anchor_stale`, `DatabasesStep`, `MailStep`, store-backed Telegram counts, new `MESSAGES`/`IMAP_HINTS` | `tests/extension/test_desktop_api.py` (full module: security-sensitive), `tests/test_desktop_page.py` | D2, D3 |
| K1 keyvault (separate, already in TODO) | `keyvault` | `ensure_initialised`/`init` refuse a stale anchor with a code; scoped file-vault reset; `status` line | keyvault tests | independent; D4's classification becomes pass-through |

D2 and D3 are implementable in parallel by two subagents (different files:
`imports/mail/*` + `wizard/mail_sync_cli.py` versus `desktop/assets/desktop/plugin.js`
+ page tests). D4 is one subagent after both merge into the branch; its page
half is small once D3's framework exists. Each PR runs
`uv run python tools/run_critical_tests.py`, the changed modules, `ruff`,
`mypy --strict`, and the full containing test modules for D2 and D4; one full
regression at the end of D4.

## Risks and open questions (with defaults)

1. **SDK exports differ between Hermes Desktop versions.** A named import the
   installed Desktop lacks breaks the whole page at link time. Default: no
   new `@hermes/plugin-sdk` imports; dots, badges, tables and details are
   plain elements styled with theme variables. Revisit when the page can
   feature-detect (`import * as sdk` is not allowed by the loader either).
2. **The Desktop backend always holds the databases**, so `/databases/encrypt`
   only ever schedules, and the conversion runs in the dbcrypt startup hook
   of the next `hermes serve`. Default: design for `scheduled` as the normal
   path and verify once live (checklist item 6) that the hook runs in the
   Desktop backend; if it does not, the step tells the owner to run
   `hermes-mordred databases encrypt` in Terminal with Hermes quit (the CLI
   text already exists).
3. **Touch ID from a background job.** An attended mail key prompts from the
   backend process while the owner looks at the page; the helper times out
   after 120 s (`tee_auth_cancelled`). Default: keep per-fetch Touch ID as
   the default (it is the credential the owner cares most about), say so on
   the button, and offer the unattended checkbox at setup only (changing it
   later needs forget + setup, as the CLI today; TODO entry exists).
4. **Folder names on the generic-IMAP path.** They are server metadata, not
   mail content, but they can be personal. Default: show them only in the
   `folders` step (sanitised, ≤200 chars), as the CLI prints them; Gmail
   never reaches that step.
5. **Generated versus typed recovery passphrase.** The page generates eight
   BIP-39 words and shows them once; the owner typed their own in the
   terminal today. Default: keep the generated passphrase on the page (already
   implemented and tested, stronger than most typed ones); a "choose my own"
   option is listed under "Later".

## Contradictions with the brief, found while reading the code

- The brief (and the TODO entry) locate the Desktop page at
  `extension/web/index.html` over the paired loopback gateway. That file is
  the browser-extension launcher page (wallet, pairing), rebuilt from the
  `mordred-extension` repository. The Mordred page in Hermes Desktop is
  `src/mordred_hermes/desktop/assets/desktop/plugin.js` with
  `src/mordred_hermes/desktop/api.py` behind Hermes's plugin REST bridge; this
  design targets that, and D1 corrects the TODO entry.
- The brief asks for an env-vault route "passphrase twice, unattended by
  default". `/memory/enable` already creates the vault *and* seals memory in
  one `FlowSession`, with a generated passphrase shown once and an
  `unattended` body flag. The design keeps that route and adds the default
  and the stale-anchor code rather than a second ceremony route.
- The brief suggests reading Telegram counts "when `index.enc` is version 2".
  `index.enc` can only be read with the sealed Telegram key (Touch ID). The
  store's per-source counts (`ImportStore.status()["sources"]["telegram"]`)
  need no Telegram secret, so the page uses those; the CLI TODO can do the
  same.
- `/sync` (Telegram import) already exists on the page; today's terminal run
  used `--days 30`, while the page's default is 3 days. The design keeps the
  field and adds the hint, no new route.

## Revision after the Codex design review (2026-10-23)

The review (`docs/superpowers/reviews/2026-10-23-desktop-mail-ceremonies-codex-design-review.md`,
verdict REVISE) is resolved as follows. Where a resolution changes an earlier
section, the text here wins; SPEC is updated to match (D1).

### Protect this Mac

- **F2 — the recovery passphrase must be delivered before anything can fail.**
  `/memory/enable` no longer runs the env and memory ceremonies in one call.
  New `POST /vault/enable {unattended: bool}` = `encryption enable env`
  (creates the file vault, enrolls `.env`, returns `{"ok": true,
  "passphrase": [...8 words...]}` once, in the response only, never in a job
  or event). The page shows the passphrase card with "I have written it
  down" before anything else is enabled; only then does step 1.2b call
  `POST /memory/enable` (now memory-only, idempotent, answers `vault_required`
  when the vault does not exist). A `/vault/enable` on an existing vault
  answers `vault_exists` (no new passphrase: the one shown at creation is the
  only one). Partial failure of the memory half therefore never loses the
  phrase; the step shows "Vault created, memory encryption failed (<code>);
  retry" and retries call only `/memory/enable`.
- **F3 — stale anchor.** The diagnosis must not call
  `default_anchor_store().read()` (it can migrate a legacy item into the
  helper store, deleting the legacy one, and may prompt). The route reads the
  two stores separately and without migration: `KeychainAnchorStore().read(id)`
  (legacy, in-process) and the helper store's plain read. Response:
  `{"ok": false, "error": "vault_anchor_stale", "anchor_store": "legacy" |
  "helper", "anchor_identity": "mordred-hermes.vault.<16 hex>"}`. The page
  shows the `security delete-generic-password -s mordred-hermes.vault.anchor
  -a <identity>` command ONLY for `anchor_store: "legacy"` (the helper
  service is not visible to `security`); for `"helper"` it says "an anchor
  from an earlier installation is held by the hardware helper; this needs the
  Mordred release with `keyvault` anchor reset (K1)". No "nothing changed / no
  prompt" promise is made. `artifacts_present` stays the heuristic until K1
  defines the locked diagnosis; the classification becomes a pass-through
  once K1 lands.
- **F8 — databases step algorithm.** Three cases, decided by `armed(home)`
  and the discovery result (`key=None` for the preview; the key only for the
  act):
  1. not armed, no plaintext file (fresh or already converted by the CLI) →
     `_migrate.migrate(home, key, arm=True)` arms without converting →
     `action: "armed"`;
  2. not armed, plaintext files, holders present or unknown (the Desktop
     backend always holds them; `_migrate` also refuses a process holding a
     runtime lease) → `schedule(home)` → `action: "scheduled",
     restart_required: true` (startup converts only while NOT armed, which is
     the case here);
  3. armed, plaintext file(s) found (a new or restored file in a protected
     home) → `action: "attention", code: "plaintext_in_armed_home"` with the
     CLI instruction (quit Hermes, `hermes-mordred databases encrypt`);
     scheduling is useless here because startup skips pending conversion when
     armed.
  `MigrationBusy` → case 2; `MigrationError` → `databases_failed`.
- **F13 — databases status schema.** With `key=None` discovery yields
  `plaintext` or `unreadable` (ciphertext) and omits absent files. The status
  object is `{"supported", "armed" (persisted intent), "encrypt_pending",
  "decrypt_pending", "journal", "runtime_protected" (the gate's
  `check_protection(home)` is `None` in this process), "databases":
  [{"relative", "state": "plaintext" | "unreadable"}], "plaintext_backups"}`.
  The page says "Database encryption: on (N files encrypted or unreadable)"
  only when `armed && runtime_protected`; "armed, conversion pending at the
  next restart" when `encrypt_pending`; "decryption pending" when
  `decrypt_pending`; "journal present, run `hermes-mordred databases status`
  in Terminal" when `journal`; never "N databases encrypted".

### Status and polling

- **F7 — read-only status path.** `/status` never initialises the import
  schema and never unlocks anything: it uses a new
  `imports.store.open_import_store_readonly(home)` that runs the gate, opens
  the file through `keyed_opener`, verifies the schema with a plain read
  (`import_meta` select, no `BEGIN IMMEDIATE`; a missing schema is reported
  as `{"available": false, "code": "store_uninitialised"}`), and reads the
  counts. The gate's key check in this path is `"HERMES_MEMORY_KEY" in
  os.environ` (the Desktop backend has it injected at start); a provider that
  would unlock the vault is not called (`no_key` otherwise). The page
  coalesces refreshes (one in flight, next one queued) and polls counts at
  most every 10 s while a job runs; the 3 s job poll uses `GET /jobs/{id}`
  only. Tests: contention with a running fetch (writer lock held) still
  answers counts; no key in the environment → `no_key`, no prompt, no
  plaintext fallback.
- **F16 — closed projections.** `/status.mail` and `/imports/status` are
  built by explicit projection functions (`_mail_projection(flags, status)`,
  `_imports_projection(status)`) that copy only named keys with type checks
  (ints, bools, codes from the closed sets) and drop everything else; the gate
  refusal set is mapped completely (`not_armed`, `conversion_pending`,
  `unprotected_process`, `no_key`, `plaintext_store`, `store_unavailable`,
  `busy`, `profile_mismatch`, `schema_newer`, `unkeyed_connection`,
  `store_uninitialised`, `unsupported_platform`). Tests feed a canary extra
  field and corrupt metadata.
- **F18 — what the counts mean.** `imports.sources.<source>` are totals
  across accounts; the page labels them "in Mordred's store (all accounts)".
  `/status.telegram_archive` reports `{"legacy_dialogs": N}` when
  `index.enc` is version 1 with dialogs (read from the index metadata only;
  if that needs the sealed key, the field is `null` and the page says
  "archive state unknown until the next import"); when `legacy_dialogs > 0`
  the Telegram import step shows "your Telegram history is still in the
  older archive; run `hermes-mordred telegram migrate-store --commit` in
  Terminal to move it into Mordred's store" and never "nothing imported".
- **F19 — last attempt vs last success.** `imap_sync` persists
  `last_attempt {at, error, partial}` separately from `last_success {at}`
  (closed keys, written under the writer lock after checking the setup
  identity). The mail card shows both when they differ.
- **F12 — state after reopen or restart.** Precedence: status facts →
  `status.jobs[].kind` (`running`) → transient page state. Memory/vault
  enable and the Telegram import are not registry jobs; their `running` state
  lives only in page state during the request. A job that disappears
  (backend restart) renders `attention` with `job_not_found`. `/mail/fetch`
  while a `mail_fetch` job runs returns the existing job (`already_running:
  true`), mirroring `_jobs` behaviour (F10). Shutdown with a running fetch is
  bounded by the IMAP budget plus the store write; the page says "about 10
  minutes".

### Mail setup, fetch, forget

- **F4 — atomic admission.** `MailSetupFlows.start` takes the writer lock
  for the configured check AND the probe; `finish` re-takes the lock and
  re-checks "no credentials sealed" (`mail_already_configured`) and the TTL.
  The Desktop forget route calls `flows.cancel_all()`; a CLI forget cannot
  reach the backend's flows, so a stale `finish` within the TTL after a CLI
  forget re-seals (documented residual window, bounded by the TTL and the
  page cancelling flows on unmount).
- **F5 — no residue.** `MailSecretStore.store` writes temporary files and
  renames in order, removing both on failure; a sealed file without metadata
  is reported by `flags()` as the residue state `credentials_left`, which the
  page shows with "Remove" (forget works on residue). "Nothing was stored" is
  shown only for refusals raised before the seal.
- **F6 — requested vs effective Touch ID policy.** `ensure_key` returns the
  effective policy; `store` records it. A leftover key with no sealed
  credentials is deleted and recreated with the requested policy; if that is
  impossible → `touch_id_policy_mismatch`.
- **F11 — flow lifetime.** Reap on every call, at most 2 live flows
  (`mail_setup_busy`), references dropped on finish/cancel/expiry, redacted
  reprs. Cleanup never needs the protection gate.
- **F14 — hint parsing.** The code is taken from `exc.args[0]` (bytes or
  str), matched at the start, free text discarded. `FetchResult` keeps its
  closed `as_dict()`; the hint travels on a separate attribute for the CLI.
- **F15 — provisional credentials.** The probe result is a provisional
  object; `MailCredentials` is built after the selection. The folder step
  carries `question: "all_mail" | "sent"` (Gmail without a detectable All
  Mail folder asks which folder it is, as the CLI does); the submitted id is
  validated against the flow's choices (`invalid_selection`); `selection:
  null` is accepted for the `sent` question ("No sent folder").
- **F17 — forget scope and recovery.** The confirmation text says "deletes
  every message imported under account <label>, including Takeout imports".
  `/mail/forget` accepts `account` for retries when credentials or metadata
  are gone (validated against `ACCOUNT_RE`), returns the residue codes
  (`credentials_left`, `key_left`, `account_unknown`); credential-only forget
  does not require the import store (only `rows: true` does).
- **F21 — chat sync is not advertised as the reliable path** until the
  bridge recipe (PR #259, commit 279db8d07) is validated on the production
  model: the card says "Fetch new mail here. You can also say 'sync my mail'
  in a chat; if Hermes cannot reach the tool, see the USAGE note on
  `tools.tool_search`".
- **F24 — acceptance order.** The wrong-password test runs BEFORE the
  successful setup (after it, the answer is `mail_already_configured`). The
  page fetch has a "Fetch at most N messages" field (default 2000, 1-2000)
  so the checklist's 100-message fetch is possible. Coverage is added for
  `/imports/status`, `/databases/status`, `/vault/enable`, setup
  finish/cancel, residue, restart (`job_not_found`) and malformed bodies.

### Page

- **F9 — the privacy boundary, stated correctly.** Three statements replace
  "Hermes never sees a subject, name, address or body": (a) secrets typed on
  the page never reach the chat, the model, tools, storage or logs; (b) a
  mail sync gives Hermes counts only; (c) asking Hermes about mail or
  Telegram makes it read the matching messages through
  `mordred_history_search`, after which that chat runs in reader mode. Used
  in the Ask Hermes card, the mail card and USAGE.
- **F20 — secret inputs** (new and existing: Telegram api_hash, Venice key,
  app password) are cleared on success, failure, cancellation and unmount;
  tested.
- **F22 — `Step` compatibility.** The Windows components keep passing
  `done`; `Step` maps `done` → `state` so the Windows branch and its test
  stay unchanged except for the deliberately updated `client_version`
  assertion.
- **F25/F26 — accessibility and baseline.** "Go" links have contextual names
  ("Go to Protect this Mac"); toggles carry `aria-expanded`/`aria-controls`;
  state is announced as text, not only a glyph; the folder choice is a
  `fieldset`/`legend` radio group; polling never remounts sections or resets
  focus (tested). All three bare `#b91c1c` literals become
  `var(--destructive, #b91c1c)`.
- **F1 — 422 echo.** Every secret-bearing route (new and existing:
  `/telegram/login/*`, `/llm/venice`, `/vault/enable`, `/mail/setup/*`,
  `/mail/forget`, `/uninstall`) reads the body itself (`await
  request.json()` inside try/except) and answers `{"ok": false, "error":
  "invalid_body"}` for malformed JSON or a non-object body, so FastAPI's
  validation error (which echoes `input`) can never fire for them. Tests post
  a JSON array and malformed JSON containing a canary to every such route.
  The page's `call()` never shows response text, only `explain(code)`.

### Process

- **F23 — PR mechanics.** `tools/ci_scope_paths.json` entries are added by
  the PR that creates the file (PLAN already says so; D1 was corrected). D2
  and D3 run in separate worktrees; the integrator (the main session) merges
  D2 then D3 into the design branch and resolves the shared
  `ci_scope_paths.json`. Component boundaries hold: F5/F6/F14/F19 live in
  `imports/mail` (D2); F3 touches only the desktop route (the store reads are
  existing APIs); K1 stays separate. Coverage floor 80 % applies to every PR.
- **F10 — concurrency table, corrected.** Same-kind job → the existing job
  is returned; memory/vault ceremonies are serialised by a module-level lock
  in `api.py` (`memory_operation_in_progress`); database migration from the
  backend is always `scheduled` (the backend holds a runtime lease).

Open after this revision (answers to the review's five questions): (1) the
passphrase is delivered by `/vault/enable` before anything else runs and
acknowledged on the page; (2) K1 is a prerequisite only for helper-held
anchors, legacy anchors keep the documented command; (3) the read-only store
path above; (4) flows expire on every call, forget cancels them, residue has
codes and a Remove action, leftover keys are recreated; (5) counts are
labelled as store totals, the legacy archive is detected, chat sync is
advertised only after the bridge validation.
