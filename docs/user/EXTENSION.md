# Mordred — browser extension guide

> **Status**: preview. This page covers the packaged localhost WebSocket server,
> browser pairing, encrypted gateway chat, history, and wallet bridge. For the
> general Mordred setup, start with [`QUICKSTART.md`](./QUICKSTART.md).

## Install

The server needs the `extension` extra. Add `ethereum` for wallet signing and
`messaging` for terminal QR rendering:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 --upgrade \
  "hermes-mordred[macos,extension,ethereum,messaging]"
```

On Linux, replace `macos` with `keyvault`.

## Start and pair

Start the server in the foreground:

```sh
hermes-mordred extension serve
# WebSocket: ws://127.0.0.1:7788/ext
```

The server refuses non-loopback hosts. If port 7788 is already owned by a full
Hermes gateway, the extension API may already be running. Otherwise choose a
different local port:

```sh
lsof -nP -iTCP:7788 -sTCP:LISTEN
hermes-mordred extension serve --port 7799
```

In a second terminal, generate a pairing code and wait for the browser
extension to consume it:

```sh
hermes-mordred extension pair
hermes-mordred extension pair --timeout 300
```

`pair` prints a `MORT-...` code and, with the `messaging` extra, a terminal QR.
The standalone server and a full Hermes gateway share
`~/.hermes/extension/pending.json`, so either can consume the code.

The `Web page:` line printed at startup contains a private URL fragment. Copy
the complete URL, including `#token=...`, when opening the bundled localhost
page. The fragment is not sent in the HTTP request and is removed from browser
history before the app starts.

## Security model

The server validates the TCP peer, `Host`, and `Origin`; only loopback clients,
supported browser-extension origins, and the private localhost page are
admitted. A connection begins with `auth_challenge` and is bound to the pairing
token generation that authenticated it. Re-pairing or clearing pairing state
revokes existing privileged sessions.

Chromium extensions can additionally register a WebAuthn credential. Firefox
transport remains available, but Firefox WebAuthn registration is refused until
the protocol can carry its stable browser-specific ceremony origin and RP ID.

For wallet requests, the browser cannot select an arbitrary chain or RPC URL.
Both must match the operator-selected values in
`~/.hermes/extension/wallet.json` or the built-in endpoint for that chain. RPC
transport rejects local/private targets and redirects, pins validated direct
DNS answers, and follows the route selected by `mordred_network`.

Before returning a message signature or broadcasting a transaction, Hermes
recovers the actual signer and verifies that it still matches the address shown
in the approval prompt.

## Supported messages

| Message | Behavior |
|---|---|
| `pair_init` | Consumes a one-time pairing code and establishes the shared key. |
| `chat` | Streams a Hermes agent turn as `chat_chunk*` plus `chat_end`. |
| `encrypt` / `decrypt` | Encrypts or decrypts extension message payloads. |
| `accounts_request` | Returns the selected wallet address and chain ID. |
| `sign_request` | Produces a frozen approval prompt before any keyvault signing. |
| `sign_approve` | Signs only the request captured by the matching prompt. |
| `history_get` / `history_clear` | Reads or clears encrypted-at-rest conversation history. |

Large history reads return the newest complete suffix with `truncated: true`;
stored history is not modified.

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
- Use a full Hermes gateway that already hosts the extension API.
- Install a launchd/systemd unit whose command is the full
  `hermes-mordred extension serve` path.

Ctrl+C and SIGTERM shut the standalone server down cleanly.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `address already in use` | Inspect port 7788; reuse the full gateway or select another port. |
| `web app not built` | Reinstall the PyPI wheel; released wheels include the bundled page. |
| Reconnects with close code `1002` / `invalid_server_frame` | Update and reload the browser extension and Mordred together, then restart the server. |
| QR code is absent | Install the `messaging` extra or enter the printed `MORT-...` code manually. |
| Wallet command says the extra is missing | Install `ethereum` in the same Hermes venv and restart the server. |
| Background chat cannot open sealed secrets on macOS | Recover onto a fresh unattended key as described in [`USAGE.md` §4.3](./USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them). |

## Related references

- [`USAGE.md` — extension command](./USAGE.md#extension--browser-extension-pairing-and-server-preview)
- [`SLACK_E2E.md`](../dev/SLACK_E2E.md)
- [`ROADMAP.md` — lifecycle integration](../dev/ROADMAP.md#remaining-browser-extension-gateway-integration)
- Server entry point: `src/mordred_hermes/extension/api.py`
