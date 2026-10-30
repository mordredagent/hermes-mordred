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
`telegram_import_v1`, `activity_batch_v1` and `recall_v1`. These names describe protocol support; they do not prove
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
| `recall_query` / `recall_open` / `recall_dismiss` | Finds the user's own stored messages (`mordred.db` import tables) that match a page selection, opens a part with its neighbours, or hides a conversation from recall for seven days. Return `recall_result` / `recall_opened` / `recall_dismissed`. The selection must arrive sealed to the extension key and cards and context leave sealed; there is no model in the path, and excerpts are substrings of stored text. Page sessions are refused. |

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

The complete wire contract is in [`SLACK_E2E.md`](../dev/SLACK_E2E.md).

## Standalone behavior

`extension serve` binds the Hermes runtime installed by the `hermes-agent`
dependency, so chat invokes the real agent. A stub handler appears only when
that runtime cannot be imported, and startup logs state which handler was
selected.

The server does not start automatically. Hermes currently has no plugin boot
hook for long-running services, so use one of these deployment models:

- Run `extension serve` explicitly in a terminal or process supervisor.
- Use a compatible legacy/custom gateway only when it explicitly includes the
  Extension API.
- Install a launchd/systemd unit whose command is the full
  `hermes-mordred extension serve` path.

Ctrl+C and SIGTERM shut the standalone server down cleanly.

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
