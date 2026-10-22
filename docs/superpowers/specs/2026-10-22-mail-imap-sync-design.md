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

## Revision after the Codex design review (2026-10-22)

Codex (`gpt-6-astra`, read-only run) reviewed the sections above against the
code. The findings below are adopted and override the earlier text where they
differ. The full review is kept with the session notes; this section records
the decisions.

### Trusted collector metadata, never injected headers

The collector does not modify the raw message bytes (so `source_revision`
digests stay comparable with Takeout imports) and does not inject
`X-Gmail-Labels`/`X-GM-THRID` headers, because `headers.py` trusts the first
embedded occurrence and an attacker-supplied header would win. Instead
`RawMessage` carries an optional `trusted: TrustedMeta(labels, thread_id,
folder_role)` filled only by the IMAP collector. When present, `normalize` and
`owner.classify` use it and ignore the embedded label/thread headers entirely.
Gmail system labels arrive as `\Sent`, `\Draft`, `\Spam`, `\Trash`,
`\Inbox`, `\Important`, `\Starred` and custom labels in modified UTF-7; the
collector recognises system labels on the wire before decoding anything and
keeps them as a distinct type, then decodes the custom labels, so
`gmail_label_sent` is emitted only for the real `\Sent` system label (a custom
label that decodes to `\Sent` or ` \Sent ` never classifies) and every label
of a message is inspected, whatever its position.

### Conservative evidence for generic servers

A generic server's sent folder (special-use `\Sent` per RFC 6154, chosen at
setup time, never guessed at fetch time) identifies folder purpose, not
verified authorship. Messages from it get evidence `imap_sent_folder` with
quality `source_claimed`, they are owner for display, and they are NOT quote
anchors (`link.ANCHOR_EVIDENCE` stays Sent-label only). `XLIST` is not used.
If the server offers no special-use folder, `mail setup` lists the folders
and asks the operator to pick one (or none); the choice is sealed with the
credentials. Folders other than the chosen ones are not fetched in this
version; `status` reports that scope.

### Atomic publication and cursor

Readers expose only committed runs, so the fetch uses one `import_runs` row
per batch (at most 200 messages, at most 64 MiB of literals). Each batch is
one store transaction: threads written, conversation rows merged, the batch's
run committed, and the cursor (`uidvalidity`, `uid`) updated together through
`ImportStore.write_batch(run_id, threads, *, conversations, meta_updates,
counts)` (the implementation review showed that per-thread transactions
followed by a separate `commit_batch` let a failed batch hide a revised row
and leak merged participants, dates and counts). A crash therefore
re-fetches at most one batch, never advances the cursor past unpublished
rows, and never changes a published row or conversation field. Cursor keys fit the store's key grammar (at most four lowercase dotted
components): `mail_imap.<account>.<sha256(mailbox)[:12]>` with a JSON value
`{"mailbox_digest", "uidvalidity", "uid", "epoch"}`. A changed `UIDVALIDITY`
starts a new epoch in the same transaction. The forward cursor and the
historical backfill (`--since`) are separate state; backfill never moves the
forward cursor. Backfill walks UIDs downward from the lowest one it covered,
whatever the dates, records the day it covered, and re-scans that range for
the missing days when a later `--since` is wider. A per-run cap used up by
one mailbox never moves a later mailbox's cursor (the run is `partial`).
`UID SEARCH UID <last+1>:*` can return the last UID itself; the collector
filters it out. Sizes are checked with a preliminary `UID FETCH
(RFC822.SIZE)` so oversize messages are skipped before any literal is
downloaded, and because a server can lie about them, the client also checks
every literal's announced length before reading it: over 25 MiB it is drained
and counted, over the response's 64 MiB (batches are planned at 48 MiB of
announced sizes) or the run's byte budget the connection is aborted. At fetch start, an `open` run for source `mail` left by a crash is
marked `failed` and its rows are reclaimed by the store's existing rule.
`upsert_conversation` merges rather than replaces: `last_message_at` is the
maximum, participants are unioned, `message_count` is recomputed from the
store. Each batch is planned with the store's thread keys for stored copies
of the messages it contains (never for ids it only references), and the store
lets Sent evidence win: a stronger sent-copy evidence revises a stored record
even with identical bytes, a weaker copy never replaces a stored sent record.
Planning joins no stored conversation by reference, so replies and parents
split across batches need the store (the
second-pass review's failing case: C, then B, then A, each naming only its
parent, left two conversations). The store therefore keeps every synced
message's referenced ids in `import_mail_refs(source_uid, ref_message_id)`
(indexed by `ref_message_id`; schema v2, a v1 store is upgraded in place by
`ImportStore.initialize`), and `write_batch` merges, in the batch's
transaction, the conversations connected to each new message M: those of the
stored messages M references and those of the stored messages that reference
M. `ImportStore.merge_conversations(survivor, others)` repoints the message
rows, unions the participants, keeps the maximum `last_message_at`, recounts
`message_count` and drops the emptied rows; the survivor is the conversation
holding the earliest-dated message (then the smaller `conv_uid`), and a
conversation keyed by a Gmail thread id is never folded into another (Gmail's
thread ids stay authoritative, as in `threading.build_threads`). Two threads
that never reference each other stay apart. After the third-pass review the
references are taken only from a copy that is written or from an identical
copy (same bytes revision and content digest), which records them for a
stored message that has none yet (a v1 row: a `--since` re-fetch attaches
them, since they cannot be recovered from the stored data); a rejected
weaker or different copy contributes none, so it cannot connect unrelated
threads. Because `References` is attacker-controlled the merge is guarded:
only the last 10 referenced ids count, a conversation is folded only when it
shares a participant with the new message's (the account owner never
counts), and nothing is merged for a message whose fold would take more than
one conversation that already holds several messages (`merge_skipped`). After
the fourth-pass review the same guard function (`imports/mail/merge_guard.py`)
also decides the grouping of each batch before it is written, and copies the
store will not write (duplicates and rejected copies, told beforehand by
`ImportStore.classify_incoming`) take no part in it. After the fifth-pass
review that grouping has two phases, so a crafted message cannot be weighed
before the reply chains it names have formed: each message first joins its
direct parent in the batch (or its siblings under an absent parent) when the
two share a participant, then its other references are weighed by the guard
in date order against those groups. After the sixth-pass review a reply
without `In-Reply-To` takes its last `References` id as its direct parent,
siblings under an absent parent join only with the same participants, direct
parents are joined ancestors first and other references fewest first, and no
union joins two groups that both already hold several messages, so neither
the batch's order nor a forged date lets one crafted message bridge threads.
A store created before
import schema v2 has no stored references for the messages it already holds,
so a later-arriving parent cannot join them until those children are fetched
again (`mail fetch --since <date>` re-fetches identical copies, which attach
their references); this limitation is kept.

### Counts-only output, enforced by a fixed serializer

Neither the tool nor `mail fetch --json` reuse `DryRunReport.as_text/as_json`,
which list addresses. A dedicated `FetchResult` serializer with an allowlist of
integer and boolean fields is the only output path: `{inserted, duplicates,
revised, conflicts, skipped_oversize, batches, mailboxes, gmail, cursor_reset,
partial, partial_reason, excluded_history, error}` (the implementation adds
`fetched`, `skipped`, `dry_run` and, after the second-pass review, `abandoned`:
the tool gave up waiting for its worker, see below; after the third-pass
review, `merge_skipped`: messages whose reference merge a guard held back;
after the fourth-pass review, `lock_retained`: the abandoned worker keeps the
writer lock).
`error` and
`partial_reason` are drawn from a closed enum. `imaplib.Debug` stays 0;
exceptions are mapped to codes and never stringified into results, logs or
audit.

### Transport and egress

`extension/egress.py` resolves a route (direct or proxy), it does not provide
sockets. The collector resolves the route for the sealed host and then builds
its own connection: direct TCP, or SOCKS5 with remote DNS (`socks5h`) and
proxy authentication from the route; any other proxy kind refuses with
`egress_unsupported`. TLS is implicit on port 993 with
`ssl.create_default_context()`, certificate verification on and SNI set to
the sealed hostname; STARTTLS and referrals are never followed. Only port 993
is accepted (setup and every credential load check it). When the route has
proxy credentials, only authenticated SOCKS5 is offered; a proxy that answers
"no authentication" is refused (`egress_unsupported`). Authentication is
`LOGIN` inside the TLS connection only; `AUTHENTICATE` is not allowlisted, so
nothing can negotiate a weaker mechanism. A VPN drop or reset surfaces as
`imap_unreachable` and the run fails cleanly.

### Credential custody

Credentials use the same hardware-only custody boundary as the production
Telegram path (`extension/telegram/tee.py`), not the cached vault store. The
unsealed secret lives in one scope for the duration of a fetch; Python cannot
guarantee zeroization of immutable strings, and the design does not claim it.
`mail forget --yes` removes the sealed credentials and cursors; `mail forget
--rows --yes` additionally deletes the account's rows via `delete_source`.
Rows and cursors are deleted first and the credentials last, under the writer
lock that `mail setup` also takes; the target label is re-checked under the
lock (a credentials `setup_id`), so a concurrent setup is never undone, and
`--account LABEL` retries the deletion once the credentials are gone. The
credentials are deleted whatever their flags say: `credentials.meta.json`
missing or corrupt (a setup or forget interrupted between the two files) no
longer hides a sealed file from forget. The sealed file, the flags and the
Enclave key are deleted, the unknown label is reported (`account_unknown`,
exit 1; rows and cursors need `--account LABEL`), forget never reports
success while a credential file remains (`credentials_left`), and an Enclave
key it could not delete is reported (`key_left`, also by a retry that finds no
credential file left) and deleted by a retry.

### Tool hardening

`mordred_mail_sync` validates its single argument strictly (integer 1-2000,
booleans and unknown keys rejected with `invalid_request`) and repeats every
gate inside the handler. It is added to `privacy_check.egress.FIRST_PARTY_TOOLS`
(fixed destination in code) as well as `READER_ALLOWED`, because
`READER_ALLOWED` alone still runs the level rules that block unknown tools
under lockdown; it is not a reader tool and does not taint. The IMAP client
wrapper enforces a runtime command allowlist: `CAPABILITY`, `LOGIN`, `LIST`,
`EXAMINE`, `UID SEARCH`, `UID FETCH` with `BODY.PEEK` and metadata items only,
`NOOP`, `LOGOUT`, each with its argument shape, and no argument containing
CR, LF or NUL; anything else raises before it is sent. The scope promise is "the sync path never puts mail text into Hermes";
`mordred_history_search` returns text by design.

### Partial returns and cancellation

The tool stops after about 60 seconds and returns `partial: true` with
`partial_reason: "time_budget"`; the cursor already holds the committed
progress, so the next call continues. The deadline is absolute: it is checked
before every IMAP command (and between batches), and an in-flight command is
cut at a hard deadline at most 30 seconds later by a watchdog that shuts the
socket down, because a socket timeout alone resets on every byte a trickling
server sends. The same bounds cover connection establishment, armed before
the route is resolved: the route lookup and `getaddrinfo` each run in a
daemon helper thread that is waited for only until the hard deadline or a
cancellation (a stalled lookup is abandoned), the TCP connect is non-blocking
and polled, each address for at most `min(op_timeout, remaining)`, and the SOCKS5
exchange and the TLS handshake read from a socket the watchdog and a
cancellation shut down; a connection not open by the hard deadline is
`imap_unreachable`. A cancelled tool call cancels the fetch (the socket is
shut down and a resolver wait woken at once) and waits for the worker at most
the remaining budget plus 30 seconds, absorbing repeated cancellations only
until then, so a cancellation always completes; after the fourth-pass review
that bound includes abandoning the fetch. A worker still running 40
seconds after the budget (stuck where the session's bounds cannot reach) is
cancelled and abandoned as a daemon thread; the call returns `partial: true`,
`partial_reason: "cancelled"` and `abandoned: true` with zero counts. Before
returning, the handler fails the worker's open run (counts `{"abandoned": 1}`;
`write_batch` refuses a late batch inside its transaction), refuses its later
store writes and releases the writer lock it held, so the next call proceeds
while the abandoned worker is still blocked. After the fourth-pass review the
later writes are refused inside their transactions, and when the run cannot be
failed in time (the store busy) or a write is still in flight, the lock is kept
by the abandoned worker until it exits (`lock_retained: true`; a call meanwhile
is `sync_in_progress`). The CLI keeps a 10 minute budget.

### Open questions, decided

1. Newest 2000 by UID on the first run; `excluded_history` reports how many
   older UIDs were skipped and `--since` backfills on request.
2. `[Gmail]/All Mail` includes archived mail and excludes Spam and Trash;
   docs say exactly that.
3. No process-wide denial for concurrent reader sessions.
4. About 60 seconds with `partial` for the tool; the CLI keeps the long budget.

### Added tests

Forged embedded `X-Gmail-Labels`/`X-GM-THRID` headers ignored when trusted
metadata exists; modified UTF-7 and system-label decoding; special-use
discovery and setup-time selection; preliminary size fetch skips oversize
without a literal; per-batch atomic publication (crash between batches leaves
the cursor at the last committed batch); `UID n:*` self-inclusion filtered;
conversation merge semantics; fixed serializer rejects any unknown field; route
resolution to direct and SOCKS5h and refusal of other proxies; TLS context
settings; command allowlist violations; time-budget partial return with the
worker joined; `mail forget` with and without `--rows`. After the second-pass
review: a resolver that never answers, a TCP connect that never completes, a
proxy that never answers the method selection and a TLS peer that never
answers the handshake, each ending at a 0.2 s budget's hard deadline
(`imap_unreachable`) and at once on a cancellation, with no watchdog or
non-daemon thread left; a cancellation during a stalled resolver, repeated
cancellations of a worker that ignores them, and an abandoned worker's
counts-only result; chains fetched in reverse and mixed orders ending as one
conversation, independent threads staying apart, Gmail thread ids staying
authoritative, a failed batch rolling its merge back; the v1 to v2 upgrade;
`mail forget` with corrupt or missing flags, after a partial deletion, with a
sealed file it could not remove and with an Enclave key it could not delete.
