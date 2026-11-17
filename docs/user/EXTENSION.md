# Mordred — browser extension guide

> **Status**: preview. This page covers the packaged localhost WebSocket server,
> browser approval, encrypted gateway chat, history, and wallet bridge. For the
> general Mordred setup, start with [`QUICKSTART.md`](./QUICKSTART.md).

## Install

Complete the [Quickstart](./QUICKSTART.md) first. The installer selects `macos`
or `keyvault` for the current platform and adds both the extension server and
Ethereum wallet dependencies with `--with-extension`:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension
```

Add `--version VERSION` to the command after replacing `VERSION` with the exact
PyPI release you need. When rerunning the installer, repeat the same feature
options and version pin.

The browser client is a separately distributed
[Chromium Manifest V3 bundle](https://github.com/mordredagent/mordred-extension-dist):

```sh
git clone https://github.com/mordredagent/mordred-extension-dist.git
```

Open `chrome://extensions` (or the equivalent page in Brave, Arc, or Edge),
enable Developer mode, choose **Load unpacked**, and select the cloned `dist/`
directory. There is currently no published Firefox bundle.

## Start and approve a browser

Stock `hermes-agent` does not host or automatically start the Extension API.
Start the packaged server in the foreground:

```sh
hermes-mordred extension serve
# WebSocket: ws://127.0.0.1:7788/ext
```

The server refuses non-loopback hosts. If port 7788 is occupied, inspect its
owner first. Reuse it only when it is a known Mordred Extension API; otherwise
stop the conflicting process. The published Chromium bundle is authorized for
port 7788 only:

```sh
lsof -nP -iTCP:7788 -sTCP:LISTEN
# For the bundled localhost page, tests, or a custom extension build only:
hermes-mordred extension serve --port 7799
```

An alternate port requires a custom extension build whose manifest permits and
client configuration selects that port.

There is no pairing code. Open the extension popup and choose **Connect**. The
popup shows a six-character check code, and the Mac that runs Hermes asks for
Touch ID (or the login password) with the same code in its prompt. Approve only
when the two codes match. That single prompt is the whole approval; afterwards
the browser reconnects without asking.

On macOS the approval key is a Secure Enclave key, so the Mac running Hermes
must be the one where you approve. List or remove approved browsers with:

```sh
hermes-mordred extension devices
hermes-mordred extension devices --remove DEVICE_ID
```

Removing a browser needs no approval and closes its open connections.

The `Web page:` line printed at startup contains a private URL fragment. Copy
the complete URL, including `#token=...`, when opening the bundled localhost
page. The fragment is not sent in the HTTP request and is removed from browser
history before the app starts.

## Security model

The server validates the TCP peer, `Host`, and `Origin`; only loopback clients,
supported browser-extension origins, and the private localhost page are
admitted. A connection begins with `auth_challenge`; the browser answers with
a hello signed by its own non-extractable device key.

Three keys are involved:

- **V**, the approval key, is a Secure Enclave key that needs Touch ID or the
  login password for every signature. It signs endorsements and nothing else.
- **H**, the Hermes identity key, is a Secure Enclave key that needs no prompt.
  It signs every handshake reply and is itself endorsed by V.
- **D**, the browser's device key, is trusted while an endorsement by V names
  it.

The extension pins V at its first approval and refuses a Hermes whose replies
do not chain to it. Each socket derives its own session key from an X25519
exchange.

V and H, and the list of removed browsers, are stored in the Mordred vault. The
endorsements themselves are stored in `~/.hermes/extension/devices.json`, so
approving a browser asks for Touch ID only once, for V's signature. Nothing in
that file needs the vault's protection. Every endorsement is checked against V
when it is read. A removed browser's endorsement is recorded in the vault, so
copying it back into the file does not restore the browser. Deleting the file
only means the browsers must be approved again.

For wallet requests, the browser cannot select an arbitrary chain or RPC URL.
Both must match the operator-selected values in
`~/.hermes/extension/wallet.json` or the built-in endpoint for that chain. RPC
transport rejects local/private targets and redirects, pins validated direct
DNS answers, and follows the route selected by Mordred's network component
(`plugins.mordred_network`).

Before returning a message signature or broadcasting a transaction, Hermes
recovers the actual signer and verifies that it still matches the address shown
in the approval prompt.

`personal_sign` prompts distinguish a readable message from an opaque payload.
A bare 32-byte digest — a Safe transaction hash, a meta-transaction — is
labelled as unverifiable and warns that the signature alone may authorize
contract actions or asset movement off-chain. Only a payload that decodes to
readable text is described as moving no assets.

The localhost page response carries `Content-Security-Policy` (script and style
pinned by hash, `frame-ancestors 'none'`, `connect-src` limited to the page's
own loopback WebSocket), `X-Frame-Options: DENY`, `Referrer-Policy:
no-referrer`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`,
so the page holding the launch-fragment token cannot be framed and its token
cannot leak through a referrer.

Client-visible errors are stable codes. Exception detail (file paths, backend
and provider messages) is written to the Hermes log instead of the reply.

## Supported messages

`auth_ok.capabilities` currently advertises `discord_channel_resolve_v1`,
`telegram_import_v1`, `activity_batch_v1`, `recall_v1`, `recall_words_v1`,
`recall_events_v1`, `recall_events_selection_v1` and `imports_v1`. These names describe protocol support; they do not prove
that Discord credentials, Telegram extras/login/private LLM, memory custody,
or a particular platform's native/live acceptance gates are ready.

| Message | Behavior |
|---|---|
| `auth_challenge` / `ping` | Server-initiated authentication challenge and application keepalive. |
| `auth2_hello` | The browser's signed hello. Answered by `auth2_ok` for an approved browser, or by `auth2_unendorsed` with the check code. |
| `device_enroll` | Asks the owner at the Mac to approve the browser of the pending hello. |
| `auth` | Validates the bundled localhost page's process token. |
| `chat` | Streams a Hermes agent turn as `chat_chunk*` plus `chat_end`. |
| `encrypt` / `decrypt` | Encrypts or decrypts extension message payloads. |
| `channel_key_set` | Stores an encrypted per-channel gateway key from the paired extension. |
| `slack_setup` | Validates and stores Slack bot/app tokens for the next Hermes restart. |
| `discord_channel_resolve` | Resolves channel/thread metadata with the configured bot token; returns `discord_channel_resolve_result`. |
| `telegram_status` / `telegram_sync` / `telegram_dialogs` | Read-only importer status, synchronization and dialog listing; return the matching `*_result` messages. Account labels and dialog titles are sealed to the extension key. |
| `telegram_ask` / `telegram_ask_cancel` | Private-model answer stream (`telegram_ask_meta`, `telegram_ask_chunk`, `telegram_ask_end` or `telegram_ask_error`) and cancellation. |
| `accounts_request` | Returns the selected wallet address and chain ID, resolved at most once per minute (repeat requests are served from that snapshot, so a burst cannot drive repeated Touch ID prompts). |
| `sign_request` | Produces a frozen approval prompt before any keyvault signing. |
| `sign_approve` | Signs only the request captured by the matching prompt. |
| `history_get` / `history_clear` | Reads or clears encrypted-at-rest conversation history. |
| `recall_query` / `recall_open` / `recall_dismiss` | Finds the user's own stored messages (`mordred.db` import tables) that match a page selection, opens a part with its neighbours, or hides a conversation from recall for seven days. Return `recall_result` / `recall_opened` / `recall_dismissed`. The selection must arrive sealed to the extension key and cards and context leave sealed; there is no model in the path, and excerpts are substrings of stored text. A store held by another connection past the busy timeout (for example while the topics are being rebuilt) answers `store_busy`, which the extension retries; any other refused store is `import_store_unavailable`. Page sessions are refused. |
| `recall_events` | The stored events and topics holding the typed words (`mode: "words"`, the default), or a page selection (`mode: "selection"`): searched as typed when short, otherwise by the events that share enough of its nouns (weighted by rarity), so a selection about something never discussed finds nothing. Returns `recall_events_result`, sealed both ways like `recall_query`. Reads the prebuilt topic store; no model runs per search. Page sessions are refused. |

Large history reads return the newest complete suffix with `truncated: true`;
stored history is not modified. `history_result` also carries `status`
(`ok`, `empty`, `unavailable`, `undecryptable`) so a client can tell an empty
conversation from history that a re-pairing left unreadable; `turns` stays a
list in every case. Unreadable history is not preserved: the next chat turn
saves over it, because the key that sealed it is gone and no surface can ever
decrypt it again.

## Gateway message encryption

Slack and Discord gateway commands use the context-bound `ENC:v3` wire. The
authenticated data binds direction, platform, channel, and thread, preventing a
reply from being replayed as a command or moved to another conversation.

On mandatory-E2E platforms, plaintext, malformed tokens, mixed plaintext and
ciphertext, and legacy v1/v2 gateway commands are rejected before reaching the
agent. Encrypted commands receive encrypted replies with the same channel key.
Deploy a v3-capable browser extension and Mordred server together.

With Mordred enabled, `send_message` and standalone cron delivery (including
fallback after a failed live-adapter send) encrypt text for bound Slack/Discord
channels and remembered encrypted conversations. Discord threads may inherit
their parent's key without changing the destination. Missing/conflicting keys,
unknown destinations and send failures return an error; they do not retry in
plaintext. A partial send can leave encrypted chunks already posted, and Hermes
may retry delivery using its existing policy.

These protected standalone requests reject attachments before posting any text.
New protected Discord forum posts are also refused; send to an existing thread.
Other destinations keep Hermes's ordinary behavior. E2E startup refuses an
unsupported Hermes standalone-sender interface; restart with a supported Hermes
version rather than running without the guard.

Protection of other live-adapter methods, including edits, streaming edits,
attachments and interactive prompts, is still pending. Use the protected text
send paths for confidential output.

The complete wire contract is in [`SLACK_E2E.md`](../dev/SLACK_E2E.md).

## Standalone behavior

`extension serve` binds the Hermes runtime installed by the `hermes-agent`
dependency, so chat invokes the real agent. A stub handler appears only when
that runtime cannot be imported, and startup logs state which handler was
selected.

On macOS, `hermes-mordred extension agent install` starts the server at every
login (a LaunchAgent in `~/Library/LaunchAgents`), and launchd starts it again
when it exits with an error; a clean stop stays stopped. `extension agent
status` shows whether it runs, `extension agent uninstall` removes it, and its
output goes to `<HERMES_HOME>/logs/extension-serve.log`.

- Each Hermes home gets its own agent (`com.mordred.hermes.extension` for
  `~/.hermes`, the same name plus a short hash for any other home).
- The plist holds no secret: it copies `HERMES_HOME`, `PATH`, `PYTHONPATH`,
  `LANG` and the `MORDRED_*` settings from the installing shell, except names
  with a `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSPHRASE`, `HASH` or
  `CREDENTIAL(S)` part. Keep secrets in the vault's `.env`. A development home
  that keeps them in a shell file passes `--env-script FILE`; the agent sources
  it at each start, so the values never enter the plist.
- macOS privacy protection keeps login services out of `~/Documents`,
  `~/Desktop`, `~/Downloads` and iCloud Drive, so `install` refuses a home,
  `--env-script` or interpreter inside them (the agent could only fail there).
- At start the server asks for Touch ID to open the vault. With nobody at the
  Mac it runs with the vault locked until the extension's **Unlock** button
  (below).

Elsewhere, run `extension serve` in a terminal or a process supervisor
(systemd), or use a gateway that explicitly includes the Extension API.

Ctrl+C and SIGTERM shut the standalone server down cleanly.

### Starting with the vault locked

The vault holds the server's `.env` secrets and the browser trust state (the
approval keys and the list of approved browsers), so no browser is admitted
while it is closed. `extension serve` binds the port first, then opens the
vault once, which asks for Touch ID (or the login password).

- **Prompt approved:** the server runs as before.
- **Prompt refused or not answered** (the helper gives up after 120 s): the
  server keeps running with the vault locked. It answers every browser hello
  with `auth_fail: vault_locked` at once, without a prompt, so an extension
  retrying on its own never raises Touch ID. The extension shows "Hermes is
  locked" with an **Unlock** button; that button sends a hello with
  `"unlock": true`, and only such a hello (from an extension origin) asks for
  Touch ID again, one prompt at a time. Once the vault is open, browsers are
  admitted and the recall topics updater starts.
- **Vault not trustworthy** (a missing anchor next to vault files, a failed
  integrity check, an unreadable `.env`): the server stops with exit code 1 and
  a content-free message, as it did when this check ran before binding.

### Local models for recall

Recall works without a model: search, events and topics are built by
counting. Two local, OpenAI-compatible servers (loopback only) add to it:

| Settings | Used for | When it runs |
|---|---|---|
| `MORDRED_RECALL_AGENT_ENDPOINT`, `MORDRED_RECALL_AGENT_MODEL` | recommendations under a search (a small model) | always: a search waits for it |
| `MORDRED_RECALL_LLM_ENDPOINT`, `MORDRED_RECALL_LLM_MODEL` | stored headlines and the topic splits, in the background (a large model) | see below |

The large model never answers a search directly; it only writes lines that are
stored. With `MORDRED_RECALL_LLM_COMMAND` set to the command that starts its
server (split like a shell line, run without a shell), Hermes starts the
server when the updater finds lines or questions to ask, and stops it once it
has been unused for `MORDRED_RECALL_LLM_IDLE_SECONDS` (default 300); stopping
Hermes stops it too. Its output goes to `<HERMES_HOME>/logs/recall-model.log`.
A server already answering at the endpoint that Hermes did not start is used
but never stopped. Material the model answered without a usable line is not
asked again for six hours, so it cannot keep the server running. Use absolute
paths in the command (the LaunchAgent starts in the Hermes home), for example:

```bash
export MORDRED_RECALL_LLM_ENDPOINT=http://127.0.0.1:8081/v1
export MORDRED_RECALL_LLM_MODEL=$HOME/models/bonsai/models/Ternary-Bonsai-2-27B-mlx-2bit
export MORDRED_RECALL_LLM_COMMAND="$HOME/models/bonsai/.venv-vlm/bin/python -m mlx_vlm.server \
  --model $MORDRED_RECALL_LLM_MODEL --host 127.0.0.1 --port 8081 --enable-thinking"
```

Without `MORDRED_RECALL_AGENT_*` the recommender falls back to the large
model, which then has to be running whenever recommendations are wanted; give
the recommender its own small model before letting Hermes stop the large one.
The extension's feature list shows the large model as available ("started
only while there is work") while it is stopped.

## Gmail: sign in with Google

The extension imports Gmail after the owner signs in with Google; there is no
app password to create. Hermes runs the sign-in itself (OAuth 2.0 for installed
apps): it listens on `127.0.0.1` on a free port, the extension opens Google's
consent page, and Google sends the browser back to that loopback address with a
one-time code. Hermes exchanges it (with a PKCE verifier only it holds) for a
refresh token, seals the token with the Enclave key like an app password (Touch
ID), and starts the first import. Every fetch turns the refresh token into a
short-lived access token and logs in with `AUTHENTICATE XOAUTH2`; the session
stays read-only (`EXAMINE`, `BODY.PEEK[]`).

Hermes needs a Google Cloud OAuth client of type **Desktop app**, created once:

1. In Google Cloud Console, create a project and enable the **Gmail API**.
2. Configure the OAuth consent screen (External; add your own Google account as
   a test user) with the scopes `https://mail.google.com/`, `openid` and `email`.
3. Create an OAuth client ID of type *Desktop app* and copy its ID and secret.
4. Give them to Hermes, in the environment
   (`MORDRED_GMAIL_CLIENT_ID`, `MORDRED_GMAIL_CLIENT_SECRET`) or in `config.yaml`:

```yaml
plugins:
  mordred_mail:
    gmail_client_id: 1234-abc.apps.googleusercontent.com
    gmail_client_secret: GOCSPX-...
```

Without a client the extension shows that Gmail sign-in is not set up
(`gmail_oauth_unconfigured`). IMAP accepts no narrower scope than
`https://mail.google.com/`. While the consent screen is in *Testing*, Google
expires the refresh token after 7 days; a fetch then fails with
`gmail_oauth_expired` and the owner removes the mail setup and signs in again.
Requests to Google follow Hermes's egress route; a SOCKS-only route (Tor) is
refused (`egress_unsupported`).

## Memory in chat

Every chat turn from the extension (its chat screen and the chat under a
search) is searched in `mordred.db`: the few matching events (when, which
tool, which chat, the stored headline and a short quote) are added to the
user's message for the model. The model can ask for more with the
`mordred_memory_search` tool; the `mordred:recall` skill tells it how to use
both. Telegram and hidden chats never appear.

Imported text reaches the model only when it may read it: a loopback model, or
a Venice model Venice labels private. Before the first block is added, the
session enters reader mode (as when a reader tool runs), so it can no longer
write files, run commands or send messages; start a new session for such work.

The Mordred plugin must be enabled (`plugins.enabled: [mordred]`). The search
runs on the `extension` platform by default; configure it in `config.yaml`:

```yaml
plugins:
  mordred_recall:
    turn_context: true                 # false: never add the block
    turn_context_platforms: [extension] # cli, tui, desktop also possible
```

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `address already in use` | Inspect port 7788. Reuse a known Mordred Extension API or stop the conflicting process; stock Hermes does not provide this API. |
| Published extension cannot connect on port 7799 | Use port 7788, or build a custom extension whose manifest and client configuration permit 7799. |
| `web app not built` | Reinstall the PyPI wheel; released wheels include the bundled page. |
| Reconnects with close code `1002` / `invalid_server_frame` | Update and reload the browser extension and Mordred together, then restart the server. |
| The popup waits for approval but no prompt appears on the Mac | Check that `extension serve` runs on the Mac where you are signed in; the prompt appears there. |
| A browser stopped connecting after Hermes moved to a new vault | The extension refuses a changed approval key. Remove the agent in the popup and connect again. |
| Wallet command says the extra is missing | Install `ethereum` in the same Hermes venv and restart the server. |
| Background chat cannot open sealed secrets on macOS | The file-vault key may be attended. `enable-se` cannot change its policy. Keep the server foreground, or preserve the complete vault plus recovery passphrase and re-key a copied vault on a genuinely fresh device/profile with `vault recover`; never delete the working store first. See [`USAGE.md` §4.3](./USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them). |

## Related references

- [`USAGE.md` — extension command](./USAGE.md#extension--browser-extension-approval-and-server-preview)
- [`SLACK_E2E.md`](../dev/SLACK_E2E.md)
- [`ROADMAP.md` — lifecycle integration](../dev/ROADMAP.md#remaining-browser-extension-gateway-integration)
- Server entry point: `src/mordred_hermes/extension/api.py`
