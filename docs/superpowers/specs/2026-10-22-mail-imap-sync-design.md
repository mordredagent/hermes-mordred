# Mail IMAP sync through Hermes

Status: design approved by the owner on 2026-10-22 ("do it the easy way, via
Hermes"); implementation in progress on `feat/imported-message-provenance`.
Author: Fable (main session). Reviewed by: Codex (`gpt-6-astra`), see the
review section at the end once it exists.

## Goal

The owner says "sync my mail" in a Hermes chat. Mordred fetches new mail over
IMAP, normalizes it with the existing mail collector, writes it into
`mordred.db` through the existing import path, and Hermes receives counts only.
No mail body, subject, name or address ever enters Hermes's context, Hermes's
`state.db`/session JSONL, Mordred's logs or the audit log.

This replaces the manual Takeout export for day-to-day use. Takeout/`.eml`
import stays as the bulk/offline path.

## Non-goals

- OAuth / Gmail API (later; a TODO entry exists). App passwords over IMAP are
  enough for Gmail and most providers and need no Google Cloud project.
- Sending mail, marking mail read, moving or deleting mail. The collector is
  strictly read-only on the server.
- Linux/Windows. `mordred.db` is macOS-only today; so is this feature.
- Letting Hermes fetch mail with its own tools (`himalaya`, the email gateway
  plugin). Those put bodies into Hermes's context and are out of scope.

## Threat model (what this design must hold against)

1. Private mail text reaching Hermes: the tool result, exceptions, audit
   entries and logs carry counts and content-free codes only.
2. A compromised or confused Hermes model abusing the tool: the tool takes no
   free-text argument (only `max_messages`), cannot choose the account, the
   server or the mailbox, and cannot send anything. It is not a reader tool
   (it returns no private text) and may run in reader mode.
3. Credential exposure: the app password is typed on a TTY, sealed with the
   same keyvault custody as the Telegram credentials (Secure Enclave on
   macOS), unsealed per fetch and dropped afterwards; never in argv, env,
   config.yaml, logs or the database.
4. Server-side tampering: TLS with certificate verification; the client never
   follows referrals or STARTTLS downgrades (implicit TLS on 993 only).
5. Network policy bypass: the IMAP connection uses Mordred's egress discipline
   (no ambient proxy, the same socket rules as Venice/Telegram clients).
6. Data retention surprises: nothing is written to disk except the encrypted
   store; a failed run leaves an `import_runs` row in `failed` state and no
   half-written thread (per-thread transactions); no temp files.

## Data flow

```
Hermes chat ──"sync my mail"──▶ Hermes model ──tool call──▶ mordred_mail_sync
                                                          │ (counts in, counts out)
Mordred ◀────────────────────────────────────────────────┘
  │ unseal mail credentials (fresh, Touch ID on macOS)
  │ IMAP4_SSL via egress socket factory ─▶ provider
  │ EXAMINE mailbox, UID SEARCH > cursor, UID FETCH BODY.PEEK[] (+ Gmail ext)
  │ RawMessage bytes in memory ─▶ imports.mail.normalize/plan_import
  │ StoreLinker (Sent-only anchors) ─▶ ImportStore.write_thread (run journal)
  │ cursor = (UIDVALIDITY, last UID) ─▶ import_meta
  └ audit mail.fetch {counts}
```

The CLI `hermes-mordred mail fetch` runs exactly the same function as the tool.
The tool is a thin wrapper; there is one implementation.

## Components

### `imports/mail/imap.py` (collector)

- Stdlib `imaplib.IMAP4_SSL` with an `ssl.create_default_context()`; port 993;
  host and port come from the sealed credentials, never from the model.
- Connection creation goes through the egress helper Mordred's other outbound
  clients use, so the network component's rules apply. If no helper is
  reusable for raw sockets, the collector builds the socket itself with the
  same policy checks and the design records why.
- Read-only protocol usage, enforced by the implementation and asserted by
  tests: `EXAMINE` (never `SELECT`), `UID SEARCH`, `UID FETCH` with
  `BODY.PEEK[]` (never `BODY[]`, which sets `\Seen`), no `STORE`, no `COPY`,
  no `EXPUNGE`, no `APPEND`. The fake server used in tests fails the test on
  any other command.
- Gmail path: when `CAPABILITY` lists `X-GM-EXT-1`, select `[Gmail]/All Mail`
  (localized servers are discovered via `LIST` + `XLIST`/special-use `\All`)
  and fetch `X-GM-LABELS X-GM-THRID X-GM-MSGID` with the body. Labels are
  injected into the message as an `X-Gmail-Labels` header and the thread id
  as `X-GM-THRID`, so `owner.classify` produces `gmail_label_sent` exactly as
  with Takeout, and threading uses the same key.
- Generic path: iterate `INBOX` and the sent folder (special-use `\Sent`, else
  a short list of common names). Messages from the sent folder get a
  synthetic `X-Gmail-Labels: Sent` and the evidence code `imap_sent_folder`
  (quality `api_identity`, the server vouches for the folder).
- Cursor per (account, mailbox): `UIDVALIDITY` and the highest fetched UID,
  kept in `import_meta` under `mail.imap.<account>.<mailbox>.uidvalidity` and
  `.uid`. A changed `UIDVALIDITY` resets the cursor to 0; idempotent writes
  make the re-fetch harmless. First run with no cursor starts from the newest
  `max_messages` UIDs (not from UID 1) so a huge mailbox does not block the
  first sync; `--since` and later runs extend backwards only on request.
- Caps: batches of at most 200 UIDs per FETCH; messages over 25 MiB are
  skipped and counted; a per-run cap (`max_messages`, default 2000); a wall
  clock budget so a stalled server cannot hang Hermes (socket timeout 30 s,
  run budget 10 min). Bodies live in memory only until `write_thread`.
- Output: an iterator of `RawMessage` compatible with the existing sources,
  plus a `FetchStats` (per mailbox: seen, fetched, skipped_oversize,
  cursor_reset) that the report prints as counts.

### `imports/mail/secrets.py` (credentials)

- Sealed payload: `{address, app_password, imap_host, imap_port,
  own_addresses}`; logical role `mordred-hermes.mail.credentials.v1`, same
  custody as the Telegram role on macOS (Enclave-wrapped data key). Windows
  custody roles are frozen by C5a; this feature refuses there with
  `unsupported_platform` until a role is added.
- Unsealed fresh per fetch (`fresh=True` pattern from `telegram sync`); the
  unsealed object is zeroed/dropped when the fetch ends. The memory-encryption
  guard that gates Telegram applies: without `encryption enable memory`, fetch
  refuses with `memory_encryption_required`.
- The account label used in uids is the short opaque label chosen at setup
  (default `mail`), never the address.

### Normalization and store (reused, unchanged)

`plan_import(sources=[imap iterator], account, own_addresses, sent_label,
linker=StoreLinker)` → `write_thread` per thread under one `run_begin("mail")`
→ `run_commit` with counts. Dry run performs the plan without opening a run.
Own addresses from the sealed payload are merged into `import_accounts` as
`mail import` does.

### CLI (`wizard/mail_cli.py`, split into `mail_sync_cli.py` if needed)

```
hermes-mordred mail setup [--imap-host H] [--imap-port P] [--account LABEL]
hermes-mordred mail fetch [--max N] [--mailbox M] [--since YYYY-MM-DD] [--dry-run] [--json]
hermes-mordred mail status [--json]
```

- `setup` prompts for the address and the app password on a TTY (refuses
  without one), asks for own addresses (the account address is always one),
  performs one read-only login + `CAPABILITY`, then seals. Exit 1 on refusal,
  2 on bad arguments.
- `fetch` prints the counts-only report plus `inserted/duplicates/revised/
  conflicts/skipped` and the cursor summary. Same exit codes as `mail import`.
- `status` adds the account label, last fetch time, cursor summary, whether
  the Gmail path is active. Never the address.
- Audit: one `mail.fetch` event per run, counts and a code only.

### Hermes tool `mordred_mail_sync`

- Registered beside `mordred_history_search`. Arguments: `max_messages?`
  (int 1–2000). Nothing else is model-controlled.
- `check_fn`: store gate passes, mail credentials sealed, Hermes model is
  Venice-private or loopback (same endpoint rule as the other Mordred tools).
- Result: `{inserted, duplicates, revised, conflicts, skipped, mailboxes:
  int, cursor_reset: bool, gmail: bool, note}`. Errors: `{error: <code>}` with
  codes `mail_not_configured`, `memory_encryption_required`,
  `import_store_unavailable`, `imap_auth_failed`, `imap_unreachable`,
  `imap_protocol`, `run_failed`, `unsupported_platform`.
- Reader mode: listed in `READER_ALLOWED` because its arguments carry no
  session data and its result carries no private text; it does not taint.
  The owner's flow "sync, then ask" therefore works in one chat, and "ask,
  then sync" also works.
- Concurrency: one fetch at a time per home (the same lock discipline as
  `telegram sync`); a second call returns `sync_in_progress`.

## Failure modes and codes

| Situation | Code | Effect |
|---|---|---|
| Not macOS | `unsupported_platform` | setup/fetch/tool refuse |
| Database encryption not armed | `not_armed` (gate) | fetch/tool refuse, nothing written |
| Memory encryption off | `memory_encryption_required` | fetch/tool refuse |
| No sealed credentials | `mail_not_configured` | fetch/tool refuse; setup hint |
| Wrong password / revoked app password | `imap_auth_failed` | refuse; nothing written |
| DNS/TCP/TLS failure | `imap_unreachable` | refuse |
| Server misbehaves (bad literal, parse error) | `imap_protocol` | run marked failed; committed threads stay |
| Another fetch running | `sync_in_progress` | refuse |
| Store write error mid-run | `run_failed` | `import_runs` failed; cursor not advanced past the last committed batch |

The cursor advances only after the batch's threads are committed, so a crash
re-fetches at most one batch.

## Tests (offline)

- A scripted fake IMAP server (`imaplib.IMAP4` over a socketpair, or
  monkeypatched `IMAP4_SSL`) that records every command and fails the test on
  `SELECT`, `STORE`, `COPY`, `EXPUNGE`, `APPEND` or a non-PEEK body fetch.
- Gmail path with labels and thread ids; generic two-folder path; cursor
  persistence and `UIDVALIDITY` reset; batch boundaries; oversize skip; first
  run newest-N; `--since`; run budget timeout.
- Credential round trip with the fake keyvault backend the Telegram tests use;
  TTY refusal; `status` never prints the address.
- Canary strings (bodies, subjects, names, addresses) never appear in stdout,
  stderr, caplog, audit entries or the tool result.
- Tool `check_fn` matrix; reader-mode allowance; `sync_in_progress`.
- Live (manual, recorded in CI.md): one real Gmail app-password fetch on a
  throwaway home, counts only.

## Open questions for review

1. Should the first run default to newest 2000 or to "everything since 90
   days"? The design picks newest-N for predictability.
2. `[Gmail]/All Mail` includes Spam/Trash? No (they are separate folders), but
   it includes archived mail; the owner wanted everything, so that is intended.
3. Should `mordred_mail_sync` be denied while another reader session is active
   in the same process? The design says no; writes go only to the encrypted
   store and the result is counts.
4. Run budget 10 min inside a Hermes tool call: is that acceptable UX, or
   should the tool return early with `partial: true` after 60 s and let the
   next call continue from the cursor? Leaning to the latter.
