# Telegram in Hermes — private, read-only

Ask Hermes about your own Telegram messages — "what did we decide last week?",
"summarize my chat with Alex", "did anyone send the contract?" — without your
messages ever reaching a model you did not choose.

- **Read-only.** Mordred can list your chats and read history. It cannot send,
  edit, delete, react, mark chats as read, or show you as online.
- **Hardware sealed.** Your Telegram session and keys use macOS Secure Enclave
  or Linux/Windows TPM 2.0. They are opened only when needed and never cached. macOS
  can require Touch ID; Linux/Windows have no per-use user-presence prompt.
- **Encrypted at rest.** Imported messages are stored AES-256-GCM encrypted
  under hashed file names, and are never committed to git.
- **Only Venice or this host reads them.** Questions are answered by a
  Venice.ai *private* (no-retention) model or by a model running on this host.
  Nothing else can be configured.

## Requirements

- macOS with Secure Enclave (Apple silicon or T2) and Xcode command-line tools,
  or Linux with a usable TPM 2.0 supporting P-256 ECDH. Ubuntu 24.04 x86_64
  with EC2 NitroTPM has been exercised; other TPM implementations need validation.
- Hermes with the Mordred plugins and the `telegram` extra
  (re-run the installer with `--with-telegram`).
- A Venice.ai API key, or a local OpenAI-compatible model server
  (Ollama, LM Studio, llama.cpp) on `127.0.0.1`.
- Your own Telegram API application from <https://my.telegram.org> →
  *API development tools* (`api_id` and `api_hash`).

**Native Windows preview:** follow the [Windows TPM workflow](./USAGE.md#native-windows-tpm-workflow)
and install the `telegram` extra. Run `keyvault enable-winkey` before
`telegram setup`; setup offers `keyvault native init --role telegram` and
memory encryption. Login requires acknowledgement of machine-bound custody
(interactive, or `--acknowledge-machine-bound`). There is no portable recovery
or per-use prompt; losing the TPM, account or profile loses local credentials
and archive access. Ordinary-user Server/NitroTPM synthetic flows are validated;
live-account, packaged Desktop and Windows 11 acceptance remain open
([evidence](../dev/CI.md#manual-live-device-validation-log)).

On Linux, install Rust, `pkg-config`, `libtss2-dev`, and the `telegram` extra.
The user running Hermes must be able to open `/dev/tpmrm0` (normally via the
`tss` group; start a new login after changing group membership). EC2 requires
a NitroTPM-enabled AMI and instance; a generic Linux instance may have no TPM.

Linux memory uses a dedicated TPM-wrapped key. Setup does not create a file
vault, encrypt `.env`, or issue a recovery passphrase. **There is no portable
recovery for this memory key or the Telegram session.** Losing the TPM state
loses access, even with an EBS snapshot. To move memory, run
`hermes-mordred encryption disable memory` while the original TPM is usable,
then transfer the restored plaintext securely. Re-enable keeps the original key;
`encryption purge memory` removes it only after restoring current memory files
and makes old encrypted backups unreadable. `keyvault reset` refuses while this
memory key remains: use `encryption purge memory` first if you intend to remove
it. Uninstall with data purge handles that order automatically. If a memory
directory or file is unreadable, repair its access permissions and retry; the
commands retain the key instead of treating the failed scan as an empty store.

Stop running Hermes gateways before enabling Linux memory encryption, then
restart them after setup. Install this Mordred build in the interpreter that
actually runs Hermes; set `MORDRED_HERMES_RUNTIME_PYTHON` if it cannot be found.
The setup verifies both its memory hook and real TPM unwrapping in that runtime.

## Set up (once, about 5 minutes)

**In Hermes Desktop (recommended).** The installer places a Mordred setup
page (`hermes-mordred desktop install` does the same). The page is enabled
automatically; restart Hermes Desktop and open
**Mordred** in the sidebar (or ⌘K → "Mordred: Set up private Telegram"). The
page walks through the same steps with buttons and masked fields; what you
type goes straight to Mordred on this host — never into the chat, the model,
logs or plugin storage. On macOS it shows the vault recovery passphrase once: write it
down. Linux/Windows display the TPM recovery limitation instead.

**In a terminal.**

```sh
hermes-mordred telegram setup
```

The guided setup:

1. builds the platform hardware helper if it is missing and enables encrypted memory;
2. logs in to Telegram — you type your phone number, the login code Telegram
   sends you, and your two-step verification password (never stored);
3. asks which privacy LLM to use (Venice or a local model);
4. offers a first import: personal chats and groups, the newest 500 messages
   per chat. Later imports fetch only new messages.

Then **restart Hermes Desktop or the gateway** so it loads the Telegram tools.

Tip: set `TELEGRAM_MORDRED_APP_ID` and `TELEGRAM_MORDRED_APP_HASH` in your
shell before `setup` to skip typing them.

## Use it

**Hermes Desktop / Hermes chat.** Just ask:

> What did the team decide about the budget on Telegram last week?

Hermes uses the `telegram_ask` tool. On macOS, approve Touch ID if requested. Hermes
receives only the privacy LLM's answer — not your messages. The tools appear
only when the chat's model is a Venice private model or a local model; with
any other model they are hidden and refused.

**Browser extension.** Open ⚙ → ✈️ Telegram to import, pick chats, and ask.

**Keep it up to date.**

```sh
hermes-mordred telegram sync                    # default: last 3 days, pinned first, no archived / large groups
hermes-mordred telegram sync --days 30          # a longer window (remembered for next time)
hermes-mordred telegram sync --include-archived # also the Archived Chats folder
hermes-mordred telegram sync --all              # everything, all history (slow)
```

Nothing is downloaded twice: each chat remembers the newest message already
checked, chats with nothing new are skipped without a single request, and an
interrupted sync resumes where it stopped. Options you pass are remembered, so
a plain `sync` repeats them. With
`--days N`, chats idle for longer than N days are not even opened. Groups with
more than 100 members are skipped unless you pass `--include-large-groups`
(or set the threshold with `--large-group-size N`).

## Check health

```sh
hermes-mordred telegram doctor
```

By default, `doctor` reads metadata only — no Touch ID, no message content,
no account name. A configured privacy LLM is reported as **connection not
checked**; this does not mean its server is reachable or accepts requests.

To test the saved local endpoint, model and API key:

```sh
hermes-mordred telegram doctor --probe-llm --json
```

This explicitly unseals credentials (macOS may request Touch ID) and sends
one fixed synthetic prompt to the saved local model. It never reads the
message archive or sends a probe to Venice. The probe has a 30-second total
HTTP deadline and a 64-token output limit; loading a slow model or spending
the budget on reasoning can therefore fail this check. Success requires a
completed stream with visible answer text. Failure reports the connection
origin, error type, HTTP status when available, and a fix hint.

## Privacy details

| Question | Answer |
|---|---|
| Where is my Telegram session? | `~/.hermes/mordred/telegram/credentials.sealed`, sealed by a Secure Enclave or TPM key. Useless on any other machine. |
| Where are my messages? | `~/.hermes/mordred/telegram/`, AES-256-GCM encrypted per chat segment, git-ignored. |
| Who can read them? | You (through the device key) and the privacy LLM you chose, for the messages relevant to each question. |
| What is sent to Venice? | Only the messages selected for a question. By default sender names, chat titles, e-mail addresses and phone numbers are replaced with aliases first. Names written inside messages are sent as written. |
| Does Hermes see my messages? | No. Hermes receives the privacy LLM's answer, marked as untrusted content. |
| Can a message trick the AI into doing something? | The privacy LLM has no tools. Hermes is instructed never to act on answers. |
| Secret chats? | Not available — Telegram keeps them on the device that created them. |
| Media? | Not downloaded; only a placeholder such as `[photo]`. |
| Does it need `keyvault init`? | No. Telegram uses its own hardware key. |

## Change the privacy LLM

```sh
hermes-mordred telegram venice --model qwen3-6-27b          # another Venice private model
hermes-mordred telegram local-llm --endpoint http://127.0.0.1:11434/v1 --model qwen3
```

These Telegram privacy-LLM settings are separate from the main Hermes model.
Starting another server, changing its port, or switching the Hermes model
does not update the saved Telegram endpoint. Use the exact model identifier
served by that endpoint. The endpoint is the API **base URL**, usually ending
in `/v1`; Mordred appends `/chat/completions` and does not add `/v1` for you.

For a local server that requires a key, use hidden input:

```sh
hermes-mordred telegram local-llm --endpoint http://127.0.0.1:8080/v1 --model my-model --api-key
```

`--api-key` prompts; it does not take a plaintext command-line value.
Alternatively, `--api-key-env LOCAL_MODEL_API_KEY` imports a key once from
that environment variable. The key is sealed with the Telegram credentials;
the runtime does not read it from the environment. Missing, empty or invalid
key input leaves the existing settings unchanged.

With no key option, an existing key is kept only if the normalized endpoint
is unchanged. Changing the host, port, scheme or base path clears that key;
provide it explicitly for the new endpoint if required. Use `--clear-api-key`
with `--endpoint` and `--model` to remove a key explicitly. Only one of the
three key options may be used at a time.

Under Mordred's `strict` LLM policy, allow Venice by adding `"venice"` to
`cloud_provider_allowlist` (with `allow_cloud_llm: true`) in
`~/.hermes/mordred/policy.json`.

## Troubleshooting

| Message | What to do |
|---|---|
| `tee_unavailable` | `hermes-mordred keyvault enable-se` on macOS; `enable-tpm` on Linux; `enable-winkey` on Windows |
| `tee_auth_cancelled` | Touch ID was declined; ask again when ready. |
| `archive_empty` | `hermes-mordred telegram sync` |
| `telegram_session_revoked` | The session was ended from another device: `telegram logout`, then `telegram setup`. |
| `hermes_model_not_allowed` / `hermes_model_not_private` | Switch the Hermes chat to a Venice private model or a local model. |
| `venice_model_not_private` | `hermes-mordred telegram venice --model <private model>` |
| `routing_unavailable` | Your Tor/VPN route is down; nothing was sent. |
| `local_llm_unauthorized` | The local server returned HTTP 401. Set the correct key with `telegram local-llm --endpoint <base-url> --model <id> --api-key`, then run `telegram doctor --probe-llm`. |
| `local_llm_unavailable` | Inspect the tool's `detail` or the `telegram.ask.failed` audit event. `connection_failed`: verify the saved port and server; `timeout`: check loading/generation speed; HTTP 404: verify the model and `/v1` base path; HTTP 5xx: check server health. Redirects are refused. |
| `local_llm_bad_request` | Reduce the selected messages or check the server's context limit and request compatibility. |
| `local_llm_bad_response` | The probe did not receive a complete OpenAI-compatible stream. Check the server and endpoint; partial text followed by a missing completion event is not healthy. |
| `local_llm_busy` / `local_llm_rate_limited` | The local server is busy or rate-limiting; retry when it is ready. |
| `llm_empty_answer` | No visible answer text was returned. Try fewer messages or a model that produces visible text within the output limit. |
| Hermes tries to open Telegram.app | Restart Hermes Desktop so the Telegram tools and instructions load, and decline any screen-control request. |

Local failure diagnostics retain the existing top-level error code and add
safe details. They include only the URL's scheme/address/port, never arbitrary
URL paths, response bodies, message text or API keys. `telegram.ask` with
`decision: allow` records permission before inference; it is not evidence of
a completed answer. A local transport failure records `telegram.ask.failed`.

## Stop or remove

```sh
hermes-mordred telegram logout            # end the session at Telegram; keep the encrypted archive
hermes-mordred telegram logout --forget   # also delete the archive, the sealed credentials and the hardware key
```

You can also end the session from any Telegram app: Settings → Devices.

Removing Mordred with `hermes-mordred uninstall` keeps the Telegram archive and
sealed credentials (and the session stays logged in) unless you add
`--purge-data` on macOS/Linux, which revokes the session and deletes the archive,
credentials and hardware key. See
[`USAGE.md` § Uninstall safely](./USAGE.md#uninstall-safely).

Windows uninstall retains Telegram data and custody even with `--purge-data`;
use `telegram logout --forget` separately. If remote revocation fails after
local deletion, end the session in Telegram Settings → Devices.
